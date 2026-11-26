"""Contact labels/avatars accumulate independently of media and are scoped to one account."""

import hashlib
import json
import sqlite3
from contextlib import closing
from uuid import uuid4

import pytest
from shared.contact_history import apply_snapshot, capture_avatars
from tests.conftest import make_android_db, make_archive_db, seed_android_db
from wab_viewer.main import create_app

NUMBER = "123456789"
JID = NUMBER + "@s.whatsapp.net"
PNG = b"\x89PNG\r\n\x1a\n"


def make_snapshot(parent, account, day, name=None, pic=None):
    snap = parent / f"snap-{day}"
    snap.mkdir()
    manifest = {
        "captured_at": f"2026-01-{day:02d}T00:00:00Z",
        "account_id": account,
        "snapshot_id": snap.name,
        "contacts": None,
        "avatars": [],
    }
    if name:
        manifest["contacts"] = "book.csv"
        (snap / "book.csv").write_text(f"{NUMBER},{name}\n", encoding="utf-8")
    if pic:
        digest = hashlib.sha256(pic).hexdigest()
        (snap / "photo.png").write_bytes(pic)
        manifest["avatars"] = [{"jid": JID, "sha256": digest, "path": "photo.png"}]
    (snap / "manifest.json").write_text(json.dumps(manifest))
    return snap


def test_history_order_repeat_and_viewer(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    with (
        closing(make_android_db(archive / "msgstore.db")) as db,
        closing(make_archive_db(archive / ".wa_media_archiver.db")) as a,
    ):
        seed_android_db(db, a)
        db.execute("UPDATE jid SET raw_string=?", (JID,))
        db.commit()
    account = str(uuid4())
    first = make_snapshot(tmp_path, account, 1, "Old Name", PNG + b"a")
    second = make_snapshot(tmp_path, account, 2, "New Name", PNG + b"b")
    missing = make_snapshot(tmp_path, account, 3, "Unknown")
    for snapshot in (second, first, second, missing):
        apply_snapshot(snapshot, archive, account_id=account)
    with closing(sqlite3.connect(archive / ".wa_media_archiver.db")) as db:
        assert db.execute(
            "SELECT name FROM contact_observations WHERE number=? ORDER BY stamp", (NUMBER,)
        ).fetchall() == [("Alice",), ("Old Name",), ("New Name",)]
        assert db.execute("SELECT COUNT(*) FROM avatar_observations").fetchone()[0] == 2
        assert (
            db.execute("SELECT folder FROM contacts WHERE number=?", (NUMBER,)).fetchone()[0]
            == "Alice (00123456789)"
        )
    with create_app(archive).test_client() as client:
        chat = client.get("/api/chats").json[0]
        assert chat["display_name"] == "New Name"
        assert chat["avatar_digest"] == hashlib.sha256(PNG + b"b").hexdigest()
        pic = client.get("/api/avatars/" + chat["avatar_digest"])
        assert pic.mimetype == "image/png" and pic.data == PNG + b"b"
        assert client.get("/api/avatars/invalid").status_code == 404
        assert client.get("/api/avatars/" + "0" * 64).status_code == 404
    other = str(uuid4())
    oth_snap = make_snapshot(tmp_path, other, 4, "Bob")
    with pytest.raises(ValueError, match="different account"):
        apply_snapshot(oth_snap, archive, account_id=other)
    with pytest.raises(ValueError, match="different account"):
        apply_snapshot(first, archive, account_id=other)


def test_invalid_avatar_rolls_back_contact_refresh(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    make_archive_db(archive / ".wa_media_archiver.db").close()
    account = str(uuid4())
    first = make_snapshot(tmp_path, account, 1, "First")
    apply_snapshot(first, archive, account_id=account)
    broken = make_snapshot(tmp_path, account, 2, "Second", PNG + b"a")
    (broken / "photo.png").write_bytes(PNG + b"x")
    with pytest.raises(ValueError, match="digest"):
        apply_snapshot(broken, archive, account_id=account)
    with closing(sqlite3.connect(archive / ".wa_media_archiver.db")) as db:
        assert (
            db.execute("SELECT display_name FROM contacts WHERE number=?", (NUMBER,)).fetchone()[0]
            == "First"
        )


@pytest.mark.parametrize(("raw_jid", "expect_phone"), [(JID, NUMBER), (NUMBER + "@lid", "")])
def test_legacy_folder_placeholder_and_lid(tmp_path, raw_jid, expect_phone):
    with (
        closing(make_android_db(tmp_path / "msgstore.db")) as db,
        closing(make_archive_db(tmp_path / ".wa_media_archiver.db")) as a,
    ):
        seed_android_db(db, a)
        db.execute("UPDATE jid SET raw_string=?", (raw_jid,))
        db.commit()
        a.execute("UPDATE contacts SET display_name='',folder='Unknown (00123456789)'")
        a.commit()
    with create_app(tmp_path).test_client() as client:
        chat = client.get("/api/chats").json[0]
        assert chat["phone_number"] == expect_phone
        if expect_phone:
            assert chat["display_name"] == "+" + expect_phone
        else:
            assert chat["display_name"].startswith("Unknown Contact")
        info = client.get(
            "/api/chat-info", query_string={"chat_id": chat["id"], "chat_type": "contact"}
        ).json
        assert (info["number"] or "") == expect_phone
        assert info["display_name"] == ("+" + expect_phone if expect_phone else "Unknown Contact")


def test_mac_map_filters_preserves_unassigned_and_checks_assets(tmp_path):
    account, other = str(uuid4()), str(uuid4())
    stage = tmp_path / "snapshot"
    stage.mkdir()
    image = tmp_path / "image"
    image.write_bytes(PNG + b"data")
    map_path = tmp_path / "map.json"
    data = [
        {"account_id": account, "file": "image", "jid": JID},
        {"account_id": account, "file": "image", "jid": None},
        {"account_id": other, "file": "missing", "jid": JID},
    ]
    map_path.write_text(json.dumps(data))
    observed = capture_avatars(stage, map_path, account)
    assert {r["jid"] for r in observed} == {None, JID}
    assert len(list((stage / "avatars").iterdir())) == 1
    data[0]["sha256"] = "0" * 64
    map_path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="changed"):
        capture_avatars(stage, map_path, account)


@pytest.mark.parametrize("native_link", [False, True])
def test_avatar_requires_native_jid_or_native_phone_mapping(tmp_path, native_link):
    with (
        closing(make_android_db(tmp_path / "msgstore.db")) as db,
        closing(make_archive_db(tmp_path / ".wa_media_archiver.db")) as archive,
    ):
        seed_android_db(db, archive)
        db.execute(
            "UPDATE jid SET raw_string=?,user=? WHERE _id=1", ("9999999999@lid", "9999999999")
        )
        db.execute("INSERT INTO jid (_id, user, raw_string) VALUES(2,?,?)", (NUMBER, JID))
        if native_link:
            db.execute("INSERT INTO jid_map VALUES(1,2)")
        else:
            db.execute(
                "CREATE TABLE lid_display_name(lid_row_id INTEGER, display_name TEXT, username TEXT)"
            )
            db.execute("INSERT INTO lid_display_name VALUES(1,?,NULL)", ("+" + NUMBER,))
        db.commit()
    account = str(uuid4())
    snap = make_snapshot(tmp_path, account, 1, "Known", PNG + b"x")
    apply_snapshot(snap, tmp_path, account_id=account)
    with create_app(tmp_path).test_client() as client:
        chat = client.get("/api/chats").json[0]
        assert bool(chat.get("avatar_digest")) == native_link


@pytest.mark.parametrize(
    ("chat_id", "native_jid", "expected_phone"),
    [
        ("opaque", JID, NUMBER),
        (NUMBER, NUMBER + "@lid", ""),
        (NUMBER, None, NUMBER),
        ("deleted_contact", None, ""),
    ],
)
def test_preserved_contact_phone_uses_original_identity(
    tmp_path, chat_id, native_jid, expected_phone
):
    from wab_viewer.preserved import _preserved_contact

    with closing(make_archive_db(tmp_path / "archive.db")) as db:
        db.row_factory = sqlite3.Row
        label, phone = _preserved_contact(db, chat_id, native_jid)
        assert phone == expected_phone
        assert label == ("+" + expected_phone if expected_phone else "Unknown Contact")
