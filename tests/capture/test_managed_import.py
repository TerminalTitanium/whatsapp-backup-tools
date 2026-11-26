"""Managed-import invariants exercised with synthetic snapshots and SQLite databases."""

import errno
import hashlib
import json
import os
import sqlite3
import sys
from contextlib import closing
from uuid import UUID

import pytest
from wab_capture import importer, publish

ACCOUNT = str(UUID(int=32))
OTHER = str(UUID(int=33))
STAMP = "2030-01-01T12:00:00+00:00"
HOST = pytest.mark.skipif(sys.platform not in {"linux", "darwin"}, reason="managed import host")


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def file_record(path):
    return {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.fixture
def tree(tmp_path):
    device = tmp_path / "sources" / "phone"
    snap = device / "snapshots" / "test-snapshot"
    (snap / "databases").mkdir(parents=True)
    db = snap / "databases" / "msgstore.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.executescript("""
            CREATE TABLE message (_id,chat_row_id,key_id,from_me);
            INSERT INTO message VALUES(101,3,'example',0);
        """)
    data = {
        "schema_version": 1,
        "account_id": ACCOUNT,
        "device_id": "test-device",
        "captured_at": STAMP,
        "snapshot_id": snap.name,
        "contacts": None,
        "media": {},
        "primary_database": db.name,
        "databases": [{"name": db.name, **file_record(db)}],
    }
    write_json(snap / "manifest.json", data)
    write_json(device / "device.json", {"device_id": data["device_id"]})
    return snap, data, tmp_path / "wab" / ACCOUNT


@pytest.mark.parametrize("name", ["", "../escape", "folder/../file"])
def test_rejects_invalid_source_path(tmp_path, name):
    with pytest.raises(ValueError, match="Invalid relative path"):
        importer.inside(tmp_path, name)


@HOST
def test_staging_rejects_symlinks_and_nonregular_files(tmp_path):
    source = tmp_path / "old"
    source.mkdir()
    (source / "links").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked media"):
        publish.stage_previous(source, tmp_path / "stage", managed=False)
    (source / "links").unlink()
    os.mkfifo(source / "pipe")
    with pytest.raises(ValueError, match="Unsupported archive entry"):
        publish.stage_previous(source, tmp_path / "stage", managed=True)


@pytest.mark.parametrize(
    "bad_name,stored",
    [
        ("Groups/anything", "media/a.jpg"),
        ("Media/../else", "media/a.jpg"),
        ("Media/a.jpg", "snapshots/other/key.txt"),
    ],
)
def test_rejects_invalid_media_paths_before_reading(tree, tmp_path, bad_name, stored):
    snap, _, _ = tree
    with pytest.raises(ValueError, match="snapshot media name|device media store"):
        importer.media_view({bad_name: {"path": stored}}, snap.parent.parent, tmp_path / "view")


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("schema_version", 999, "unsupported snapshot"),
        ("snapshot_id", "unrelated", "unsupported snapshot"),
        ("device_id", "other-device", "wrong device"),
        ("captured_at", "2030-01-01T12:00:00", "capture time"),
    ],
)
@HOST
def test_rejects_misdirected_or_incomplete_snapshot_before_publication(tree, field, value, reason):
    snap, data, archive = tree
    write_json(snap / "manifest.json", {**data, field: value})
    with pytest.raises(ValueError, match=reason):
        importer.import_snapshot(snap)
    assert not archive.exists()


def test_database_inventory_must_match_files(tree):
    snap, data, _ = tree
    data["databases"] *= 2
    with pytest.raises(ValueError, match="repeated database filename"):
        importer.snapshot_material(snap, data)
    data["databases"].pop()
    (snap / "databases" / "unrecorded.db").touch()
    with pytest.raises(ValueError, match="inventory differs"):
        importer.snapshot_material(snap, data)


def test_repair_proof_rejects_wrong_snapshot_digest_and_unverified_supplement(tree, tmp_path):
    snap, data, archive = tree
    db = archive / importer.DATABASE
    db.parent.mkdir(parents=True)
    db.write_bytes(b"current database fingerprint")
    repair = tmp_path / "repair"
    repair.mkdir()
    fields = {
        "schema_version": 1,
        "account_id": ACCOUNT,
        "snapshot_id": snap.name,
        "source_db_sha256": file_record(db)["sha256"],
        "files": {},
    }
    for override, reason in [
        ({"account_id": OTHER}, "different snapshot or account"),
        ({"source_db_sha256": "changed"}, "same source database"),
        ({"files": {"not-media": {}}}, "supplemental media location"),
        ({"derived_db_sha256": "wrong"}, "Derived database checksum"),
    ]:
        (repair / "msgstore.db").touch()
        write_json(repair / "reconciliation.json", {**fields, **override})
        with pytest.raises(ValueError, match=reason):
            importer.repair_inputs(repair, data, archive)
    write_json(repair / "reconciliation.json", fields)
    assert importer.repair_inputs(repair, data, archive) == (db, fields)


def test_failed_atomic_exchange_keeps_prior_tree(tmp_path, monkeypatch):
    stage = tmp_path / "next"
    stage.mkdir()
    target = tmp_path / "current"
    publish.publish(stage, target)
    (target / "marker").write_text("old")
    stage.mkdir()
    monkeypatch.setattr(publish.sys, "platform", "test-unsupported")
    with pytest.raises(OSError) as err:
        publish.publish(stage, target)
    assert err.value.errno == errno.ENOTSUP
    assert (target / "marker").read_text() == "old"
    assert stage.exists()


@HOST
def test_receipts_metadata_guards_and_skipped_imports(tree, monkeypatch):
    import shared.contact_history as history

    snap, data, archive = tree
    with pytest.raises(ValueError, match="first snapshot"):
        importer.import_snapshot(snap, metadata_only=True)
    archive.mkdir()
    with pytest.raises(ValueError, match="Unmanaged target"):
        importer.import_snapshot(snap)
    working = archive / importer.DATABASE
    working.parent.mkdir()
    working.write_bytes((snap / "databases" / "msgstore.db").read_bytes())
    with closing(sqlite3.connect(working)) as native, native:
        native.executescript("""
            CREATE TABLE wab_media_bindings (message_id,original_path,sha256);
            INSERT INTO wab_media_bindings VALUES(101,'Media/a.jpg','observed');
        """)
    importer.record(archive, data, importer.digest(snap / "manifest.json"))
    with closing(sqlite3.connect(archive / importer.LEDGER)) as ledger:
        assert ledger.execute("SELECT row_id,stanza FROM messages").fetchall() == [(101, "example")]
        assert ledger.execute(
            "SELECT message_id,source_sha256 FROM media_observations"
        ).fetchall() == [(101, "observed")]
    seen = []
    monkeypatch.setattr(
        history, "apply_snapshot", lambda s, a, *, account_id: seen.append((s, a, account_id))
    )
    assert importer.import_snapshot(snap)[0] == "Already imported"
    assert importer.import_snapshot(snap, metadata_only=True)[0] == "Updated metadata"
    assert seen == [(snap, archive, ACCOUNT)] * 2
    with pytest.raises(ValueError, match="first full import"):
        importer.import_snapshot(snap, adopt=snap.parent)
    write_json(snap / "manifest.json", {**data, "contacts": "contacts/new"})
    with pytest.raises(ValueError, match="manifest has changed"):
        importer.import_snapshot(snap)


@HOST
def test_failed_worker_then_successful_retry_and_old_snapshot(tree, monkeypatch):
    """Exercise stage cleanup and commit; fake only the upstream CLI, covered in e2e."""
    import subprocess

    import shared.contact_history as history

    snap, data, archive = tree
    (snap / "key.txt").write_text("synthetic")
    failure = True

    def archiver(argv, check):
        assert check and "--stable-paths" in argv and "--snapshot-manifest" in argv
        out = archive.parent / argv[argv.index("--output") + 1]
        native = out / importer.DATABASE
        native.parent.mkdir(parents=True, exist_ok=True)
        native.write_bytes((snap / "databases" / "msgstore.db").read_bytes())
        (out / ".wa_media_archiver.db").touch()
        with closing(sqlite3.connect(native)) as db, db:
            db.execute("CREATE TABLE wab_media_bindings(message_id,original_path,sha256)")
        if failure:
            raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(importer.subprocess, "run", archiver)
    monkeypatch.setattr(history, "apply_snapshot", lambda *args, **kwargs: None)
    with pytest.raises(subprocess.CalledProcessError):
        importer.import_snapshot(snap)
    assert not archive.exists()
    assert not list(archive.parent.glob(".import-*"))
    failure = False
    assert importer.import_snapshot(snap)[0] == "Imported"
    with pytest.raises(ValueError, match="capture order"):
        importer.import_locked(
            snap,
            {**data, "snapshot_id": "old", "captured_at": "2010-01-01T00:00:00+00:00"},
            archive,
        )
    with pytest.raises(ValueError, match="different account"):
        importer.import_locked(snap, {**data, "account_id": OTHER}, archive)
    with pytest.raises(ValueError, match="currently imported"):
        importer.import_locked(snap, {**data, "snapshot_id": "old"}, archive, repair=snap)


@HOST
def test_publication_links_managed_payloads_and_copies_mutable_indexes(tmp_path):
    before = tmp_path / "before"
    payload = before / "Groups" / "example.dat"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"payload")
    (before / ".index").write_bytes(b"original")
    next_dir = tmp_path / "next"
    publish.stage_previous(before, next_dir, managed=True)
    assert (next_dir / "Groups" / "example.dat").samefile(payload)
    (next_dir / ".index").write_bytes(b"updated")
    assert (before / ".index").read_bytes() == b"original"
    publish.publish(next_dir, before)
    assert (before / ".index").read_bytes() == b"updated"
    assert (next_dir / ".index").read_bytes() == b"original"


@HOST
def test_cli_reports_real_metadata_mode_errors(tree, monkeypatch, capsys):
    snap, data, archive = tree
    monkeypatch.setattr(sys, "argv", ["wab-import", str(snap), "--metadata-only"])
    old = os.umask(0o077)
    try:
        with pytest.raises(SystemExit) as exc:
            importer.main()
        assert exc.value.code == 1
        assert "first snapshot" in capsys.readouterr().err
        assert not archive.exists()
    finally:
        os.umask(old)


@HOST
def test_media_view_pins_versions_and_detects_content_change(tree, tmp_path):
    snap, _, _ = tree
    device = snap.parent.parent
    source = device / "media-versions" / "stored"
    source.parent.mkdir()
    source.write_bytes(b"snapshot payload")
    mapping = {"Media/Objects/one": {"path": "media-versions/stored", **file_record(source)}}
    view = tmp_path / "first"
    importer.media_view(mapping, device, view)
    assert (view / "Media/Objects/one").samefile(source)
    source.write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum mismatch"):
        importer.media_view(mapping, device, tmp_path / "second")


def test_unusable_host_and_invalid_location(tmp_path, monkeypatch):
    monkeypatch.setattr(importer.sys, "platform", "win32")
    with pytest.raises(ValueError, match="macOS or Linux"):
        importer.import_snapshot(tmp_path)
    if os.name == "posix":
        monkeypatch.setattr(importer.sys, "platform", "linux")
        with pytest.raises(ValueError, match="under sources"):
            importer.import_snapshot(tmp_path)


def test_unreadable_subtree_aborts_staging(tmp_path, monkeypatch):
    source = tmp_path / "existing"
    source.mkdir()
    bad = source / "Groups"
    bad.mkdir()
    original_scan = os.scandir

    def reject_children(path):
        if path == str(bad) or path == bad:
            raise PermissionError(errno.EACCES, "unreadable", str(path))
        return original_scan(path)

    monkeypatch.setattr(publish.os, "scandir", reject_children)
    with pytest.raises(PermissionError) as exc:
        publish.stage_previous(source, tmp_path / "stage", managed=True)
    assert exc.value.filename == str(bad)
    assert bad.is_dir()
