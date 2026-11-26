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


@pytest.mark.parametrize("reverse", (False, True))
def test_native_lookup_preserves_case_normalization_and_file_directory_aliases(tmp_path, reverse):
    from wab_capture.importer import media_view

    device = tmp_path / "device"
    view = tmp_path / "view"
    archive = tmp_path / "archive"
    archive.mkdir()
    manifest = device / "snapshots" / "test" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    directory = "Media/WhatsApp Images/"
    names = ["IMAGE.jpg", "image.jpg", "É.jpg", "E\u0301.jpg", "foo", "FOO/nested.jpg"]
    if reverse:
        names.reverse()
    entries = {}
    for n, name in enumerate(names):
        payload = bytes([n]) + b"media"
        digest = hashlib.sha256(payload).hexdigest()
        location = device / "media-versions" / digest[:2] / digest
        location.parent.mkdir(parents=True, exist_ok=True)
        location.write_bytes(payload)
        entries[directory + name] = {
            "path": location.relative_to(device).as_posix(),
            "sha256": digest,
            "size": len(payload),
            "native_path_unique": name == "IMAGE.jpg",
        }
    media_view(entries, device, view)
    assert not any(p.is_file() or p.is_symlink() for p in view.rglob("*"))
    manifest.write_text(json.dumps({"media": entries}))
    database = archive / "native.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE message_media(message_row_id, file_path, file_hash)")
        db.executemany(
            "INSERT INTO message_media VALUES(?,?,?)",
            [(mid, path, e["sha256"]) for mid, (path, e) in enumerate(entries.items())],
        )
        db.execute("INSERT INTO message_media VALUES(100,?,NULL)", (directory + "image.jpg",))
        db.execute("INSERT INTO message_media VALUES(101,?,NULL)", (directory + "IMAGE.jpg",))
    bound = bind_snapshot(database, archive, view, manifest, logging.getLogger())
    with sqlite3.connect(database) as db:
        rows = db.execute("SELECT message_id,original_path,effective_path FROM wab_media_bindings")
        for mid, native_path, effective in rows:
            if mid == 100:
                assert bound[effective] is None
            elif mid == 101:
                assert bound[native_path].read_bytes() == bound[effective].read_bytes()
            else:
                payload = bytes([mid]) + b"media"
                assert bound[native_path].read_bytes() == bound[effective].read_bytes() == payload


@pytest.mark.parametrize("marker,visible", [(None, True), (False, False), (True, True)])
def test_native_path_history_precedence_on_original_object(tmp_path, marker, visible):
    device = tmp_path / "device"
    manifest = device / "snapshots/test/manifest.json"
    manifest.parent.mkdir(parents=True)
    location = device / "media/WhatsApp Images/photo.png"
    location.parent.mkdir(parents=True)
    location.write_bytes(b"first")
    native = "Media/WhatsApp Images/photo.png"
    record = {
        "path": location.relative_to(device).as_posix(),
        "sha256": hashlib.sha256(b"first").hexdigest(),
        "size": 5,
    }
    if marker is not None:
        record["native_path_unique"] = marker
    manifest.write_text(json.dumps({"media": {native: record}}))
    database = tmp_path / "working.db"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE message_media(message_row_id, file_path)")
        db.execute("INSERT INTO message_media VALUES(1,?)", (native,))
    mapping = bind_snapshot(database, tmp_path, tmp_path / "view", manifest, logging.getLogger())
    with sqlite3.connect(database) as db:
        (effective,) = db.execute("SELECT file_path FROM message_media").fetchone()
    assert (mapping[effective] is not None) == visible
