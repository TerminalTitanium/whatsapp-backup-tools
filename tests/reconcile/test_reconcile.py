import base64
import csv
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from tests.conftest import make_android_db
from wab_archiver.android_handler import build_query
from wab_capture import reconcile


@pytest.fixture
def sample(tmp_path):
    db = tmp_path / "android.db"
    mac = tmp_path / "mac"
    mac.mkdir()
    data = b"Matching local photograph content"
    digest = hashlib.sha256(data).digest()
    src_path = "Media/WhatsApp Images/phone.jpg"
    (mac / "unrelated-name.bin").write_bytes(data)
    (mac / "phone.jpg").write_bytes(b"wrong")
    report = tmp_path / "missing.csv"
    entries = [
        (1, src_path, base64.b64encode(digest).decode()),
        (2, None, digest),
        (3, "Media/WhatsApp Images/nohash.jpg", None),
        (4, "Media/WhatsApp Images/no-mac-copy", "f" * 64),
        (5, "Media/WhatsApp Images/../outside", digest.hex()),
        (6, "Media/WhatsApp Images/SHARED", digest.hex()),
        (7, "Media/WhatsApp Images/shared", "a" * 64),
    ]
    with closing(make_android_db(db)) as conn:
        conn.execute("ALTER TABLE message_media ADD COLUMN file_hash")
        conn.execute("INSERT INTO jid(_id,user) VALUES(1,'example')")
        conn.execute("INSERT INTO chat(_id,jid_row_id) VALUES(1,1)")
        for mid, src, expected in entries:
            conn.execute(
                "INSERT INTO message(_id,chat_row_id,from_me,timestamp) VALUES (?,1,0,10000)",
                (mid,),
            )
            conn.execute(
                "INSERT INTO message_media(message_row_id,chat_row_id,file_path,file_hash,mime_type) VALUES (?,1,?,?,'image/jpeg')",
                (mid, src, expected),
            )
        conn.commit()
    with report.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["message_id", "file_path"])
        writer.writerows((mid, path) for mid, path, _ in entries if path and mid != 7)
        writer.writerow((8, "not-in-db"))
    return db, mac, report, digest.hex()


def command(tmp, sample, *extra):
    db, mac, report, _ = sample
    reconcile.main(
        [
            "--db",
            str(db),
            "--missing",
            str(report),
            "--mac-media",
            str(mac),
            "--account-id",
            "account-A",
            "--snapshot-id",
            "snapshot-A",
            "--output",
            str(tmp),
            *extra,
        ]
    )


def test_stage_is_hash_checked_and_pathless_links_are_importable(tmp_path, sample):
    db, mac, _, digest = sample
    initial = reconcile.sha256(db)
    output = tmp_path / "repair"
    previous = tmp_path / "attachment-map.tsv"
    previous.write_text(
        "message_row_id\tsha256\tarchive_input_path\n1\t" + digest + "\tmac/phone.jpg\n"
    )
    command(output, sample, "--previous-map", str(previous), "--stage")
    receipt = json.loads((output / "reconciliation.json").read_text())
    assert receipt["account_id"] == "account-A" and receipt["snapshot_id"] == "snapshot-A"
    assert receipt["source_db_sha256"] == initial == reconcile.sha256(db)
    assert receipt["derived_db_sha256"] == reconcile.sha256(output / "msgstore.db")
    assert receipt["counts"] == {"with_path": 1, "without_path": 1, "unresolved": 5}
    with closing(sqlite3.connect(output / "msgstore.db")) as fixed:
        paths = {row[0]: row[2] for row in fixed.execute(build_query(None, None, False))}
    for mid in (1, 2):
        apk_path = paths[mid]
        assert apk_path in receipt["files"]
        payload = output / "supplement" / apk_path
        assert payload.read_bytes() == (mac / "unrelated-name.bin").read_bytes()
        assert receipt["files"][apk_path] == {"sha256": digest, "size": payload.stat().st_size}
    with closing(sqlite3.connect(db)) as original:
        assert original.execute(
            "SELECT file_path FROM message_media WHERE message_row_id=2"
        ).fetchone() == (None,)
    with (output / "media-map.tsv").open() as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    assert len(rows) == 7
    assert rows[4]["status"] == "unresolved" and rows[5]["status"] == "unresolved"
    assert Path(rows[0]["mac_file"]).name == "unrelated-name.bin"


def test_read_only_report_and_output_collision(tmp_path, sample):
    output = tmp_path / "audit"
    command(output, sample)
    assert [p.name for p in output.iterdir()] == ["media-map.tsv"]
    with pytest.raises(SystemExit):
        command(output, sample, "--stage")
    assert [p.name for p in output.iterdir()] == ["media-map.tsv"]


def test_old_schema_and_live_journal(tmp_path, sample):
    db, *_ = sample
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("ALTER TABLE message_media DROP COLUMN file_hash")
    command(tmp_path / "v1", sample, "--stage")
    assert json.loads((tmp_path / "v1/reconciliation.json").read_text())["files"] == {}
    Path(str(db) + "-wal").write_bytes(b"synthetic active journal")
    with pytest.raises(SystemExit):
        command(tmp_path / "busy", sample)
    assert not (tmp_path / "busy").exists()


def test_extended_media_and_previous_map_are_independently_verified(tmp_path, sample):
    db, mac, report, digest = sample
    with closing(sqlite3.connect(db)) as conn:
        conn.executescript("""
            CREATE TABLE message_media_map(message_row_id INTEGER, media_row_id INTEGER);
            CREATE TABLE extended_media_data(row_id INTEGER PRIMARY KEY, file_path TEXT, file_hash BLOB);
            INSERT INTO message_media_map VALUES (401, 11);
        """)
        conn.execute(
            "INSERT INTO extended_media_data VALUES(11,?,?)",
            ("Media/WhatsApp Documents/new", bytes.fromhex(digest)),
        )
        conn.commit()
    with report.open("a") as stream:
        stream.write("401,Media/WhatsApp Documents/new\n")
    prior = tmp_path / "attachment-map.tsv"
    prior.write_text(
        f"sha256\tarchive_input_path\n{digest}\tmac/unrelated-name.bin\n{digest}\t../escape\n"
    )
    output = tmp_path / "stage"
    command(output, sample, "--previous-map", str(prior), "--stage")
    assert (output / "supplement/Media/WhatsApp Documents/new").read_bytes() == (
        mac / "unrelated-name.bin"
    ).read_bytes()


def test_aborted_copy_cleanup(tmp_path, sample, monkeypatch):
    def wrong_copy(src, dst):
        dst.write(b"changed mid transfer")

    monkeypatch.setattr(reconcile.shutil, "copyfileobj", wrong_copy)
    output = tmp_path / "partial"
    with pytest.raises(SystemExit):
        command(output, sample, "--stage")
    assert not output.exists()


@pytest.mark.parametrize(
    "value,expected",
    [
        (b"!" * 32, "21" * 32),
        (b"!" * 31, ""),
        ("💬", ""),
        ("ab" * 32, "ab" * 32),
        (base64.b64encode(b"A" * 32).decode(), "41" * 32),
        ("YQ==", ""),
    ],
)
def test_stored_hash(value, expected):
    assert reconcile.stored_hash(value) == expected


def test_saved_recovery_uses_native_digest_on_later_snapshot(tmp_path, sample):
    import logging
    import shutil

    from wab_capture.recovered import materialize_recovered, remember_repair, replay_paths

    db, mac, _, digest = sample
    bundle = tmp_path / "bundle"
    command(bundle, sample, "--stage")
    receipt = json.loads((bundle / "reconciliation.json").read_text())
    archive = tmp_path / "archive"
    archive.mkdir()
    remember_repair(archive, bundle, receipt, bundle / "msgstore.db")
    # External extraction can be moved elsewhere without affecting this working archive.
    shutil.rmtree(bundle)
    shutil.rmtree(mac)
    new = tmp_path / "new-working.db"
    shutil.copy(db, new)
    view = tmp_path / "input"
    view.mkdir()
    materialize_recovered(archive, view)
    with closing(sqlite3.connect(new)) as conn, conn:
        conn.execute("UPDATE message_media SET message_row_id=999 WHERE message_row_id=2")
        conn.execute(
            "UPDATE message_media SET file_path=NULL,file_hash=? WHERE message_row_id=1",
            ("a" * 64,),
        )
    replay_paths(new, archive, view, logging.getLogger("test"))
    with closing(sqlite3.connect(new)) as conn:
        p = conn.execute("SELECT file_path FROM message_media WHERE message_row_id=999").fetchone()[
            0
        ]
        assert (view / p).read_bytes() == b"Matching local photograph content"
        assert conn.execute(
            "SELECT file_path FROM message_media WHERE message_row_id=1"
        ).fetchone() == (None,)
    assert reconcile.sha256(db) == receipt["source_db_sha256"]


def test_tampered_recovery_or_invalid_alias(tmp_path, sample):
    from wab_capture.recovered import materialize_recovered, remember_repair

    out = tmp_path / "audit"
    command(out, sample, "--stage")
    receipt = json.loads((out / "reconciliation.json").read_text())
    archive = tmp_path / "archive"
    archive.mkdir()
    remember_repair(archive, out, receipt, out / "msgstore.db")
    next((archive / ".wab-recovered").glob("*")).write_bytes(b"wrong")
    with pytest.raises(ValueError, match="payload changed"):
        materialize_recovered(archive, tmp_path / "input")
    with pytest.raises(ValueError, match="contents changed"):
        remember_repair(archive, out, receipt, out / "msgstore.db")


def test_empty_registry_and_unreferenced_entries(tmp_path, sample):
    import logging

    from wab_capture.recovered import materialize_recovered, remember_repair, replay_paths

    archive = tmp_path / "archive"
    archive.mkdir()
    db, *_ = sample
    view = tmp_path / "view"
    materialize_recovered(archive, view)
    replay_paths(db, archive, view, logging.getLogger("test"))
    assert not view.exists()
    out = tmp_path / "audit"
    command(out, sample, "--stage")
    plan = json.loads((out / "reconciliation.json").read_text())
    plan["files"]["Media/WhatsApp Images/bogus.jpg"] = {"sha256": "a" * 64, "size": 1}
    with pytest.raises(ValueError, match="unreferenced"):
        remember_repair(archive, out, plan, out / "msgstore.db")
