"""Preserve a mixed Android Databases directory, then assign and import it offline."""

import hashlib
import io
import json
import os
import sqlite3
import zipfile
import zlib

import pytest
from tests.e2e.test_android_archive_protocol import (
    ACCOUNT_A,
    ACCOUNT_B,
    FIRST,
    Phone,
    invoke_import,
    run_module,
)
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props

pytestmark = pytest.mark.skipif(os.name != "posix", reason="ADB capture runs on macOS/Linux")

ACTIVE = "msgstore.db.crypt15"
ROTATED = "msgstore-2030-04-12.1.db.crypt15"
DELTA = "msgstore-increment-1.db.crypt15"


def encrypted(payload, key_file):
    key = Key15(key=bytes.fromhex(key_file.read_text()))
    return Database15(key=key).encrypt(key, Props(), zlib.compress(payload))


def group_rename_increment(key_file):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as bundle:
        bundle.writestr("header.json", json.dumps({"format": "protobuf"}))
        bundle.writestr("chat_modified_1.json", json.dumps([{"_id": 1, "subject": "Renamed by A"}]))
    return encrypted(buf.getvalue(), key_file)


def archive_history(phone, account):
    archive = phone.store / "wab" / account
    with sqlite3.connect(archive / "Whatsapp Databases" / "msgstore.db") as conn:
        history = conn.execute("SELECT key_id, text_data FROM message ORDER BY _id").fetchall()
        (subject,) = conn.execute("SELECT subject FROM chat WHERE _id=1").fetchone()
    assert [path.read_bytes() for path in (archive / "Groups").rglob("*.jpg")] == [FIRST]
    return history, subject


def test_mixed_raw_capture_and_offline_account_import(tmp_path):
    phone = Phone(tmp_path)
    legacy = phone.capture(ACCOUNT_A)
    snapshots = legacy.parent
    # Existing schema-v1 archives predate raw-manifest.json and must work on their own.
    for previous_raw in snapshots.glob("*/raw-manifest.json"):
        previous_raw.parent.rename(tmp_path / previous_raw.parent.name)
    invoke_import(legacy, phone)
    assert archive_history(phone, ACCOUNT_A) == ([("k1", "synthetic")], "Project Alpha")
    known_a = legacy / "databases" / ACTIVE
    key_b = tmp_path / "synthetic-key-b"
    key_b.write_text("cd" * 32)
    with sqlite3.connect(phone.db) as db:
        db.execute("UPDATE message SET key_id='from-b', text_data='account B only'")
    known_b = tmp_path / "known-b.crypt15"
    known_b.write_bytes(encrypted(phone.db.read_bytes(), key_b))
    # Opaque .crypt14 bytes must round-trip even when this operator has no key.
    contents = {
        ACTIVE: known_a.read_bytes(),
        ROTATED: known_b.read_bytes(),
        DELTA: group_rename_increment(phone.key),
        "msgstore-2030-04-12.1.db.crypt14": b"opaque rotated base",
        "msgstore-increment-1-2030-04-12.1.db.crypt14": b"opaque first increment",
        "msgstore-increment-2-2030-04-12.1.db.crypt14": b"opaque second increment",
    }
    for name, data in contents.items():
        (phone.phone / "Databases" / name).write_bytes(data)

    run_module(
        "wab_capture",
        ["--root", phone.store, "--device", "android", "--phone-root", phone.phone],
        phone.env,
    )
    [raw_manifest] = snapshots.glob("*/raw-manifest.json")
    raw = raw_manifest.parent
    raw_manifest_bytes = raw_manifest.read_bytes()
    phone.phone.rename(tmp_path / "disconnected-phone")
    (phone.bin / "adb").write_text("#!/bin/sh\nexit 89\n")
    listing = run_module("wab_capture.prepare", [raw, "--list"], phone.env)
    records = json.loads(raw_manifest_bytes)["databases"]
    entries = {item["relative_path"]: item for item in records}
    assert len(records) == len(entries) == 6
    assert set(entries) == set(contents)
    for name, entry in entries.items():
        assert name in listing
        assert entry["size"] == len(contents[name])
        assert entry["sha256"] == hashlib.sha256(contents[name]).hexdigest()

    def prepare(name, account, key_file, known, *extra, success=True):
        before = set(snapshots.glob("*/manifest.json"))
        selection = ["--database", entries[name]["path"]] if name else []
        output = run_module(
            "wab_capture.prepare",
            [
                raw,
                *selection,
                "--account",
                account,
                "--known-backup",
                known,
                "--key-file",
                key_file,
                *extra,
            ],
            phone.env,
            success=success,
        )
        after = set(snapshots.glob("*/manifest.json"))
        if not success:
            assert after == before, output
            return output.casefold()
        [manifest] = after - before
        assert before <= after
        assert json.loads(manifest.read_text())["account_id"] == account
        return manifest.parent

    assert "--known-backup" in prepare(ROTATED, ACCOUNT_B, key_b, known_a, success=False)
    assert "wrong key" in prepare(ROTATED, ACCOUNT_B, phone.key, known_b, success=False)
    assert all((raw / entries[n]["path"]).read_bytes() == data for n, data in contents.items())

    assert archive_history(phone, ACCOUNT_A) == ([("k1", "synthetic")], "Project Alpha")
    # The reference has a different filename. Only its content identifies B's rotated base.
    second = prepare(None, ACCOUNT_B, key_b, known_b)
    first = prepare(ACTIVE, ACCOUNT_A, phone.key, known_a, "--increment", entries[DELTA]["path"])
    invoke_import(second, phone)
    invoke_import(first, phone)
    assert archive_history(phone, ACCOUNT_A) == ([("k1", "synthetic")], "Renamed by A")
    assert archive_history(phone, ACCOUNT_B) == ([("from-b", "account B only")], "Project Alpha")
    assert raw_manifest.read_bytes() == raw_manifest_bytes
    assert all((raw / entries[n]["path"]).read_bytes() == data for n, data in contents.items())
