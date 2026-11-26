import hashlib
import json
import sqlite3
import sys
from uuid import UUID

import pytest
from shared.mac_avatars import build_map, main

ACCOUNT = str(UUID(int=19))
LID = "12345@lid"
PHONE = "15550100101@s.whatsapp.net"
PHOTO = b"\xff\xd8\xff" + b"Synthetic-test"


def test_container_map_cli_preserves_unknown_and_binds_only_with_proof(tmp_path, monkeypatch):
    profile = tmp_path / "Media/Profile"
    profile.mkdir(parents=True)
    (profile / "12345@lid.thumb").write_bytes(PHOTO)
    (profile / "12346@lid.thumb").write_bytes(PHOTO)
    (profile / "arbitrary.thumb").write_bytes(PHOTO)
    (profile / "unassigned.thumb").write_bytes(PHOTO)
    (profile / "12347@lid.thumb").write_bytes(PHOTO)
    with sqlite3.connect(tmp_path / "ContactsV2.sqlite") as conn:
        conn.execute("CREATE TABLE ZWAADDRESSBOOKCONTACT(ZLID TEXT, ZWHATSAPPID TEXT)")
        conn.executemany(
            "INSERT INTO ZWAADDRESSBOOKCONTACT VALUES (?,?)",
            [(LID, PHONE), ("12347@lid", PHONE), ("12347@lid", "15550100999@s.whatsapp.net")],
        )
    with sqlite3.connect(tmp_path / "ChatStorage.sqlite") as conn:
        conn.execute("CREATE TABLE ZWAPROFILEPICTUREITEM(ZJID TEXT,ZPATH TEXT)")
        conn.execute(
            "INSERT INTO ZWAPROFILEPICTUREITEM VALUES (?,?)",
            ("111-222@g.us", "Media/Profile/arbitrary.thumb"),
        )
    out = tmp_path / "candidate.json"
    monkeypatch.setattr(
        sys, "argv", ["map", "--container", str(tmp_path), "--account", ACCOUNT, "--out", str(out)]
    )
    main()
    entries = json.loads(out.read_text())["entries"]
    assert {r["sha256"] for r in entries} == {hashlib.sha256(PHOTO).hexdigest()}
    by_file = {r["file"]: r["jid"] for r in entries}
    assert by_file["arbitrary.thumb"] == "111-222@g.us"
    assert by_file["12346@lid.thumb"] is None
    assert by_file["12347@lid.thumb"] is None
    assert by_file["unassigned.thumb"] is None
    # Ambiguous LID also points to PHONE, thus competing file bindings are conservative.
    assert by_file["12345@lid.thumb"] is None
    (profile / "12347@lid.thumb").unlink()
    entries = build_map(profile, ACCOUNT, contacts_database=tmp_path / "ContactsV2.sqlite")[
        "entries"
    ]
    assert {r["file"]: r["jid"] for r in entries}["12345@lid.thumb"] == PHONE


def test_container_refuses_ambiguous_profile_roots_and_clobber(tmp_path, monkeypatch, capsys):
    for sub in ("Media/Profile", "Message/Media/Profile"):
        (tmp_path / sub).mkdir(parents=True)
    out = tmp_path / "map.json"
    out.write_text("prior")
    monkeypatch.setattr(
        sys, "argv", ["map", "--container", str(tmp_path), "--account", ACCOUNT, "--out", str(out)]
    )
    with pytest.raises(SystemExit):
        main()
    assert "exactly one" in capsys.readouterr().err
    (tmp_path / "Message/Media/Profile").rmdir()
    with pytest.raises(SystemExit):
        main()
    assert "File exists" in capsys.readouterr().err
    assert out.read_text() == "prior"


def test_no_contacts_schema_keeps_lid_unassigned(tmp_path):
    (tmp_path / "12345@lid.jpg").write_bytes(PHOTO)
    with sqlite3.connect(tmp_path / "contacts.sqlite") as conn:
        conn.execute("CREATE TABLE other(z int)")
    entries = build_map(tmp_path, ACCOUNT, contacts_database=tmp_path / "contacts.sqlite")[
        "entries"
    ]
    assert entries[0]["jid"] is None
