import hashlib
import json
import logging
import sqlite3

import pytest
from wab_archiver.archive_db import stable_group_index
from wab_capture.versions import bind_snapshot, original_path


def test_file_path_reuse_selects_verified_bytes_for_each_message(tmp_path):
    device = tmp_path / "device"
    view = tmp_path / "view"
    archive = tmp_path / "archive"
    archive.mkdir()
    manifest = device / "snapshots" / "test" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    path = "Media/WhatsApp Documents/contract.pdf"
    first = b"first content"
    second = b"second content"
    digests = [hashlib.sha256(b).hexdigest() for b in (first, second, b"other")]
    old = device / "media/WhatsApp Documents/contract.pdf"
    old.parent.mkdir(parents=True)
    old.write_bytes(first)
    newer = device / "media-versions" / digests[1][:2] / digests[1]
    newer.parent.mkdir(parents=True)
    newer.write_bytes(second)
    (view / path).parent.mkdir(parents=True)
    (view / path).write_bytes(newer.read_bytes())
    manifest.write_text(
        json.dumps(
            {
                "media": {
                    path: {
                        "path": newer.relative_to(device).as_posix(),
                        "sha256": digests[1],
                        "size": len(second),
                    }
                }
            }
        )
    )
    database = archive / "native.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE message_media(message_row_id, file_path, file_hash)")
        db.executemany(
            "INSERT INTO message_media VALUES(?,?,?)",
            [(mid, path, fingerprint) for mid, fingerprint in enumerate([*digests, None], 1)],
        )
        db.execute("CREATE TABLE extended_media_data(row_id, file_path, file_hash)")
        db.execute("CREATE TABLE message_media_map(media_row_id,message_row_id)")
        db.execute("INSERT INTO extended_media_data VALUES(77,?,?)", (path, digests[0]))
        db.execute("INSERT INTO message_media_map VALUES(77,11)")
    mapping = bind_snapshot(database, archive, view, manifest, logging.getLogger())
    with sqlite3.connect(database) as db:
        rows = db.execute(
            "SELECT message_id, original_path, effective_path, sha256 FROM "
            "wab_media_bindings ORDER BY message_id"
        ).fetchall()
    assert [r[0] for r in rows] == [1, 2, 3, 4, 11]
    assert all(r[1] == path for r in rows)
    assert [r[3] for r in rows] == [digests[0], digests[1], None, None, digests[0]]
    assert [mapping[r[2]].read_bytes() if mapping[r[2]] else None for r in rows] == [
        first,
        second,
        None,
        None,
        first,
    ]
    assert original_path(rows[1][2]) == path
    assert rows[0][2] != rows[1][2]


def test_traversal_in_native_attachment_aborts(tmp_path):
    manifest = tmp_path / "snapshots" / "a" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"media": {}}')
    db_path = tmp_path / "native.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE message_media(message_row_id, file_path)")
        db.execute("INSERT INTO message_media VALUES(1,'Media/WhatsApp Images/../../local')")
    with pytest.raises(ValueError, match="Unsafe Android media path"):
        bind_snapshot(db_path, tmp_path, tmp_path, manifest, logging.getLogger())


def test_group_jid_survives_rowid_reuse_and_case_insensitive_name_collision(tmp_path):
    groups = {"1": {"folder": "Original", "subject": "Original"}}
    with sqlite3.connect(":memory:") as conn:
        mapped = stable_group_index(
            conn,
            groups,
            {"1": "10@g.us"},
            {"2": "10@g.us", "1": "20@g.us"},
            {"2": "Renamed", "1": "ORIGINAL"},
            tmp_path,
        )
        assert mapped["2"]["folder"] == "Original"
        assert mapped["1"]["folder"] == "ORIGINAL (2)"
        rerun = stable_group_index(
            conn, mapped, {}, {"1": "10@g.us", "2": "20@g.us"}, {"1": "new", "2": "new"}, tmp_path
        )
        assert rerun["1"]["folder"] == "Original"
        assert rerun["2"]["folder"] == "ORIGINAL (2)"
