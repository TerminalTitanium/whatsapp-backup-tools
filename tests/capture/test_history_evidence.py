"""Exercise authenticated, read-only comparison of Android direct-chat history."""

import json
import sqlite3
import tempfile
import zlib
from contextlib import closing

import pytest
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props
from wab_capture import history_evidence
from wab_capture.keys import authenticated_sqlite, verify_key

KEY = "23" * 32
A = "10001@s.whatsapp.net"
B = "10002@lid"
G = "10003@g.us"


def encrypt(db, encrypted, *, compressed=True):
    key = Key15(key=bytes.fromhex(KEY))
    payload = db.read_bytes()
    encrypted.write_bytes(
        Database15(key=key).encrypt(key, Props(), zlib.compress(payload) if compressed else payload)
    )


def make_db(path, rows, *, offset=0):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string, user, server);
            CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id);
            CREATE TABLE message (chat_row_id, from_me, key_id, message_type, text_data);
        """)
        for i, raw in enumerate(dict.fromkeys(row[0] for row in rows), start=offset + 1):
            user, _, server = raw.partition("@")
            db.execute(
                "INSERT INTO jid VALUES(?,?,?,?)", (i, raw if offset else None, user, server)
            )
            db.execute("INSERT INTO chat VALUES(?,?)", (i + 100, i))
            db.executemany(
                "INSERT INTO message VALUES(?,?,?,?,?)",
                (
                    (i + 100, direction, stanza, mtype, "private message content")
                    for jid, direction, stanza, mtype in rows
                    if jid == raw
                ),
            )


def test_exact_outgoing_overlap_and_private_cleanup(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    raw.mkdir()
    ref_dir = tmp_path / "previous"
    ref_dir.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    reference, source = ref_dir / "msgstore.db", tmp_path / "to-encrypt"
    make_db(
        reference,
        [
            (A, 1, "stanza-1", 0),
            (B, 1, "stanza-2", 1),
            (B, 1, "wrong-chat", 0),
            (G, 1, "group-id", 0),
            (A, 1, "service-id", 7),
            (A, 0, "incoming-id", 0),
            (B, 1, "namespace-id", 0),
            (A, 1, None, 0),
        ],
    )
    make_db(
        source,
        [
            (A, 1, "stanza-1", 0),
            (B, 1, "stanza-2", 1),
            (A, 1, "stanza-1", 0),
            (A, 1, "wrong-chat", 0),
            (G, 1, "group-id", 0),
            (A, 1, "service-id", 7),
            (A, 1, "incoming-id", 0),
            ("10002@s.whatsapp.net", 1, "namespace-id", 0),
            (A, 1, "", 0),
            (A, 0, "ignored-incoming", 0),
        ],
        offset=100,
    )
    encrypted = raw / "msgstore.db.crypt15"
    encrypt(source, encrypted)
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (reference, encrypted)}
    result = history_evidence.compare_history(encrypted, KEY, reference)
    assert result == {
        "candidate_outgoing": 9,
        "candidate_unusable": 3,
        "candidate_distinct_direct": 5,
        "candidate_duplicate_rows": 1,
        "reference_outgoing": 7,
        "reference_unusable": 3,
        "reference_distinct_direct": 4,
        "reference_duplicate_rows": 0,
        "matched_messages": 2,
        "matched_chats": 2,
        "assessment": "overlap_observed",
    }
    for secret in (A, B, "stanza-1", "private message content", KEY):
        assert secret not in json.dumps(result)
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
    assert list(ref_dir.iterdir()) == [reference]
    assert list(raw.iterdir()) == [encrypted]
    assert list(scratch.iterdir()) == []


def test_legacy_no_overlap_and_unusable_ids(tmp_path):
    previous = tmp_path / "legacy"
    with closing(sqlite3.connect(previous)) as db, db:
        db.execute("CREATE TABLE messages (key_from_me,key_remote_jid,key_id,status)")
        db.executemany(
            "INSERT INTO messages VALUES(?,?,?,?)",
            [
                (1, A, "no-match", 0),
                (1, A, "stanza", 6),
                (1, "12345", "stanza", 0),
                (1, A, "-1", 0),
                (1, None, "stanza", 0),
            ],
        )
    source = tmp_path / "android"
    make_db(source, [(A, 1, "stanza", 0)])
    encrypted = tmp_path / "backup"
    encrypt(source, encrypted, compressed=False)
    report = history_evidence.compare_history(encrypted, KEY, previous)
    assert report["assessment"] == "indeterminate"
    assert report["matched_chats"] == report["matched_messages"] == 0
    assert report["reference_unusable"] == 4
    assert report["reference_distinct_direct"] == 1
    assert report["candidate_outgoing"] == 1


def test_authentication_and_integrity_before_return_with_cleanup(tmp_path, monkeypatch):
    source, previous = tmp_path / "android", tmp_path / "reference"
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    make_db(source, [(A, 1, "stanza", 0)])
    make_db(previous, [(A, 1, "stanza", 0)])
    encrypted = tmp_path / "encrypted"
    encrypt(source, encrypted)
    with authenticated_sqlite(encrypted, KEY) as private:
        assert private.parent.stat().st_mode & 0o077 == 0
        assert private.read_bytes() == source.read_bytes()
    assert not private.exists()
    with pytest.raises(ValueError, match="Wrong key or corrupt"):
        history_evidence.compare_history(encrypted, "f0" * 32, previous)
    previous.write_bytes(b"SQLite format 3\0" + b"x" * 4000)
    with pytest.raises((ValueError, sqlite3.DatabaseError)):
        history_evidence.compare_history(encrypted, KEY, previous)
    assert list(scratch.iterdir()) == []


def test_live_reference_rejected_while_wal_unchanged(tmp_path):
    source = tmp_path / "android.sqlite"
    make_db(source, [(A, 1, "stanza", 0)])
    encrypted = tmp_path / "encrypted"
    encrypt(source, encrypted)
    with closing(sqlite3.connect(source)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("INSERT INTO message VALUES(101,1,'later',0,'private')")
        db.commit()
        wal = tmp_path / "android.sqlite-wal"
        before = wal.read_bytes()
        with pytest.raises(ValueError, match="journal"):
            history_evidence.compare_history(encrypted, KEY, source)
        assert wal.read_bytes() == before


def test_unusable_evidence_is_indeterminate(tmp_path):
    db = tmp_path / "android"
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute("CREATE TABLE message (from_me)")
        conn.execute("INSERT INTO message VALUES(1)")
    encrypted = tmp_path / "encrypted"
    encrypt(db, encrypted)
    report = history_evidence.compare_history(encrypted, KEY, db)
    assert report["assessment"] == "indeterminate"
    assert report["reference_outgoing"] == report["candidate_unusable"] == 1
    assert report["candidate_distinct_direct"] == 0


@pytest.mark.parametrize(
    ("filename", "fingerprint"),
    [("msgstore.db.crypt15", True), ("msgstore-increment-1.db.crypt15", False)],
)
@pytest.mark.parametrize("payload", [b"", b"\x0f", b"\x01\x02"])
def test_truncated_full_and_increment_report_the_input(tmp_path, filename, fingerprint, payload):
    path = tmp_path / filename
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="Truncated crypt15 backup") as error:
        verify_key(path, KEY, fingerprint=fingerprint)
    assert filename in str(error.value)
