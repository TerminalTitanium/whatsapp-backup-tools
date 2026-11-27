import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from tests.capture.test_capture import KEY, UUID_A, Phone, get_manifests
from wab_capture import cli
from wab_capture.adb import _roots
from wab_capture.raw import _avatars

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Capture host is macOS or Linux")


def raw(working, monkeypatch, phone, *, accounts=None, keys=None, maps=None):
    monkeypatch.setattr(cli, "AndroidDevice", lambda *_args: phone)
    cli.capture(
        SimpleNamespace(
            root=working,
            device="test-device",
            serial=None,
            phone_root=None,
            account=accounts,
            key_file=keys,
            avatar_map=maps,
        )
    )
    return sorted((working / "sources/test-device/snapshots").glob("*/raw-manifest.json"))


def manifest(path):
    return json.loads(path.read_bytes())


def test_opaque_files_preserved_with_native_names_and_portable_storage(tmp_path, monkeypatch):
    phone = Phone()
    phone.files = {
        "Databases/unknown Name": b"",
        "Databases/unknown name": b"case",
        "Databases/nested/OLD.CRYPT14": b"opaque",
        "Databases/BACKUP/é": b"one",
        "Databases/BACKUP/e\u0301": b"two",
        "Databases/B": b"flat",
        "Databases/b/oth'er\n": b"nested",
    }
    [snap] = raw(tmp_path, monkeypatch, phone)
    rows = manifest(snap)["databases"]
    assert len(rows) == len(phone.files)
    for row in rows:
        data = phone.files["Databases/" + row["relative_path"]]
        assert (snap.parent / row["path"]).read_bytes() == data
        assert row["source_path"] == row["database_dir"] + "/" + row["relative_path"]
        assert row["sha256"] == hashlib.sha256(data).hexdigest()
        assert row["size"] == len(data)
    assert not (snap.parent / "key.txt").exists()


def test_legacy_failure_publishes_before_prompts_and_enter_confirms(tmp_path, monkeypatch):
    phone = Phone()
    key = tmp_path / "key"
    key.write_text("04" * 32)
    device = tmp_path / "sources/test-device"

    def answer(_):
        assert list((device / "snapshots").glob("*/raw-manifest.json"))
        return ""

    monkeypatch.setattr("builtins.input", answer)
    with pytest.raises(ValueError, match="Wrong key"):
        raw(tmp_path, monkeypatch, phone, accounts=[UUID_A], keys=[key])
    assert not get_manifests(tmp_path)
    log = next((device / "logs").glob("*.log")).read_text()
    assert "Raw capture already saved at" in log and "wab-prepare " in log and "--list" in log
    assert "RAW INCOMPLETE" not in log and "04" * 32 not in log
    key.write_text(KEY)
    snap = raw(tmp_path, monkeypatch, phone, accounts=[UUID_A], keys=[key])[-1]
    [prepared] = get_manifests(tmp_path)
    raw_data, prepared_data = manifest(snap), manifest(prepared)
    assert prepared_data["captured_at"] == raw_data["captured_at"]
    assert prepared_data["media"] == raw_data["media_by_root"]["/sdcard/WhatsApp"]
    claim = prepared_data["raw"]
    assert claim["snapshot_id"] == snap.parent.name
    assert claim["manifest_sha256"] == hashlib.sha256(snap.read_bytes()).hexdigest()
    assert all((snap.parent / path).is_file() for path in claim["database_paths"])


def test_pre_and_post_checks_cover_db_media_and_roots(tmp_path, monkeypatch):
    for what in ("database file", "media file", "directory"):
        phone = Phone()
        if what == "directory":
            baseline = phone.discover_dirs()
            answers = iter((baseline, ([], [])))
            phone.discover_dirs = lambda: next(answers)
        else:
            before = phone.all_databases() if what == "database file" else phone.media()
            answers = iter((before, []))
            setattr(
                phone,
                "all_databases" if what == "database file" else "media",
                lambda: next(answers),
            )
        dest = tmp_path / what
        with pytest.raises(ValueError, match="inventory changed"):
            raw(dest, monkeypatch, phone)
        assert not list((dest / "sources/test-device/snapshots").iterdir())


def test_latest_cache_failure_does_not_mask_raw_commit(tmp_path, monkeypatch):
    phone = Phone()
    dest = tmp_path / "sources/test-device"
    outside = tmp_path / "outside"
    outside.mkdir()
    dest.mkdir(parents=True)
    (dest / "contacts").symlink_to(outside, target_is_directory=True)
    [snap] = raw(tmp_path, monkeypatch, phone)
    assert (snap.parent / manifest(snap)["contacts"]).is_file()
    assert not list(outside.iterdir())
    log = next((dest / "logs").glob("*.log")).read_text()
    assert "Latest contact cache unavailable" in log and "RAW INCOMPLETE" not in log


def test_raw_avatar_map_keeps_available_rows_and_unassigns_only_conflicts(tmp_path):
    work = tmp_path / "stage"
    work.mkdir()
    for name in ("a", "b"):
        (tmp_path / name).write_bytes(b"\xff\xd8\xff\xe0" + name.encode())
    path = tmp_path / "map.json"

    def row(jid, image):
        return {"account_id": UUID_A, "jid": jid + "@s.whatsapp.net", "file": image}

    path.write_text(json.dumps([row("1", "a"), row("2", "missing"), row("3", "a"), row("3", "b")]))
    log = []
    rows = _avatars(work, [path], log.append)
    assert {item["jid"] for item in rows} == {"1@s.whatsapp.net", None}
    assert all((work / item["path"]).is_file() for item in rows)
    assert any("row 2" in message for message in log)


def test_explicit_storage_roots_deduplicate_overlaps():
    assert _roots(["/sdcard/a", "/sdcard/a/b", "/sdcard/c", "/sdcard/a/"]) == [
        "/sdcard/a",
        "/sdcard/c",
    ]
