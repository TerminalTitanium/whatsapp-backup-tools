"""Account selection and idempotent preparation from a completed local device capture."""

import hashlib
import io
import json
import os
import zipfile
import zlib
from uuid import UUID

import pytest
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props
from wab_capture import prepare

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="managed Android workflow requires POSIX"
)
KEY = "cd" * 32
ROOT = "/sdcard/Android/media/com.whatsapp/WhatsApp"
DIR = f"{ROOT}/Databases"
STAMP = "2030-04-12T21:01:00+00:00"
FULL = "msgstore-2030-04-12.1.db.crypt15"
INC1 = "msgstore-increment-1-2030-04-12.1.db.crypt15"


def hashed(payload):
    return hashlib.sha256(payload).hexdigest()


def encrypted(payload, key=KEY):
    return Database15().encrypt(Key15(key=bytes.fromhex(key)), Props(), zlib.compress(payload))


def delta():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("header.json", json.dumps({"format": "protobuf"}))
    return encrypted(buffer.getvalue())


def raw_capture(tmp_path, name="first"):
    device = tmp_path / "sources/phone"
    snap = device / "snapshots" / name
    snap.mkdir(parents=True)
    (device / "device.json").write_text(json.dumps({"device_id": "fake-device"}))
    key = tmp_path / "key"
    key.write_text(KEY)
    relative = "Media/WhatsApp Images/photo.jpg"
    media = {"path": "media/WhatsApp Images/photo.jpg", "sha256": hashed(b"photo"), "size": 5}
    data = {
        "schema_version": 1,
        "kind": "android-device-raw",
        "device_id": "fake-device",
        "snapshot_id": name,
        "captured_at": STAMP,
        "session_id": "session",
        "databases": [],
        "database_dirs": [DIR],
        "media_by_root": {ROOT: {relative: media}},
        "contacts": "contacts/book.txt",
        "contacts_at": STAMP,
        "contact_rows": 1,
        "contacts_sha256": hashed(b"123 Alice"),
        "avatars": [],
    }
    (snap / "contacts").mkdir()
    (snap / data["contacts"]).write_bytes(b"123 Alice")
    return snap, key, data


def add(raw, data, name, payload, *, directory=DIR, overflow=False):
    if directory not in data["database_dirs"]:
        data["database_dirs"].append(directory)
    store = (
        "database-objects/" + hashed(payload)
        if overflow
        else f"databases/{hashed(directory.encode())}/{name}"
    )
    item = {
        "source_path": f"{directory}/{name}",
        "database_dir": directory,
        "relative_path": name,
        "size": len(payload),
        "sha256": hashed(payload),
        "path": store,
    }
    (raw / store).parent.mkdir(parents=True, exist_ok=True)
    (raw / store).write_bytes(payload)
    data["databases"].append(item)
    (raw / "raw-manifest.json").write_text(json.dumps(data))
    return item


def run(raw, capsys, *args, fail=None):
    if fail:
        with pytest.raises(SystemExit) as error:
            prepare.main([str(raw), *map(str, args)])
        assert error.value.code != 0
        message = capsys.readouterr().err
        assert fail in message
        return message
    prepare.main([str(raw), *map(str, args)])
    return capsys.readouterr().out


def test_exact_reference_label_recognition_retries_and_new_captures(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    full = encrypted(b"SQLite format 3\0" + b"synthetic")
    base = add(raw, data, FULL, full)
    add(raw, data, "msgstore.db.crypt14", b"uninterpreted")
    add(raw, data, "msgstore-increment-1.db.crypt14", b"retained legacy increment")
    add(raw, data, "other-file", b"unknown")
    inc = add(raw, data, INC1, delta())
    manifest_bytes = (raw / "raw-manifest.json").read_bytes()
    reference = tmp_path / "known.crypt15"
    reference.write_bytes(full)
    report = run(raw, capsys, "--list")
    assert all(k in report for k in ("full", "increment", "other", base["path"], base["sha256"]))
    assert (
        "full/crypt14 (preserved only)" in report and "increment/crypt14 (preserved only)" in report
    )
    assert not (raw.parents[2] / ".capture.lock").exists()
    assert not (raw.parents[2] / ".account-labels.json").exists()
    out = run(raw, capsys, "--known-backup", reference, "--key-file", key, "--account", "Рабочий")
    account = str(UUID(out.split("Account: ")[1].splitlines()[0]))
    dest = raw.parent / out.split("Prepared snapshot: ")[1].splitlines()[0].split("/")[-1]
    m = json.loads((dest / "manifest.json").read_text())
    assert m["databases"][0]["source_path"] == base["source_path"] and len(m["databases"]) == 1
    assert m["media"] == data["media_by_root"][ROOT]
    assert (dest / m["contacts"]).read_bytes() == b"123 Alice"
    assert (dest / "key.txt").read_text().strip() == KEY
    assert run(raw, capsys, "--database", FULL) == out
    assert "рабочий" in run(raw, capsys, "--list") and account in out
    assert len(list(raw.parent.glob("*/manifest.json"))) == 1
    chain = run(
        raw,
        capsys,
        "--account",
        "Рабочий",
        "--database",
        base["source_path"],
        "--increment",
        inc["path"],
    )
    assert chain != out
    listing = run(raw, capsys, "--list")
    assert account in next(line for line in listing.splitlines() if inc["path"] in line)

    prepared = json.loads(
        next(p for p in raw.parent.glob("*/manifest.json") if p.parent != dest).read_text()
    )
    assert [r["raw_path"] for r in prepared["databases"]] == [base["path"], inc["path"]]
    assert prepared["raw"]["manifest_sha256"] == hashed(manifest_bytes)
    assert (raw / "raw-manifest.json").read_bytes() == manifest_bytes
    foreign = str(UUID(int=12))
    run(raw, capsys, "--account", foreign, "--database", FULL, fail="already belongs")
    again, k2, d2 = raw_capture(tmp_path, "new")
    add(again, d2, FULL, encrypted(b"SQLite format 3\0newer data"))
    next_out = run(again, capsys, "--database", FULL, "--key-file", k2, "--account", "РАБОЧИЙ")
    assert next_out.startswith(f"Account: {account}\n")


def test_reference_ambiguity_and_duplicate_native_records(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    base = encrypted(b"SQLite format 3\0synthetic")
    a = add(raw, data, FULL, base, overflow=True)
    b = add(raw, data, f"old/{FULL}", base, overflow=True)
    ref = tmp_path / "known"
    ref.write_bytes(base)
    run(
        raw,
        capsys,
        "--known-backup",
        ref,
        "--account",
        "phone",
        "--key-file",
        key,
        fail="matched 2 full",
    )
    run(raw, capsys, "--database", a["path"], "--account", "phone", fail="Expected one full")
    run(
        raw,
        capsys,
        "--known-backup",
        ref,
        "--database",
        b["source_path"],
        "--account",
        "phone",
        "--key-file",
        key,
    )
    data["databases"].append(a)
    (raw / "raw-manifest.json").write_text(json.dumps(data))
    run(raw, capsys, "--list", fail="duplicated database")


def test_bad_key_and_invalid_chain_leave_raw_and_registry_alone(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    full = add(raw, data, FULL, encrypted(b"SQLite format 3\0synthetic"))
    cross = add(raw, data, "msgstore-increment-1.db.crypt15", delta())
    gap = add(raw, data, "msgstore-increment-2-2030-04-12.1.db.crypt15", delta())
    wrong = add(raw, data, INC1, encrypted(b"Not a ZIP increment"))
    diffdir = add(raw, data, "other/" + INC1, delta())
    baseargs = ["--database", FULL, "--account", "one", "--key-file", key]
    run(raw, capsys, *baseargs, "--increment", cross["source_path"], fail="different native")
    run(raw, capsys, *baseargs, "--increment", diffdir["source_path"], fail="different native")
    run(raw, capsys, *baseargs, "--increment", gap["source_path"], fail="contiguous sequence")
    msg = run(
        raw,
        capsys,
        *baseargs,
        "--increment",
        wrong["source_path"],
        fail="Could not verify increment",
    )
    assert wrong["source_path"] in msg and "raw capture remains saved" in msg
    key.write_text("fe" * 32)
    msg = run(raw, capsys, *baseargs, fail="Could not verify full")
    assert full["source_path"] in msg and KEY not in msg and key.read_text() not in msg
    assert "msgstore.db.crypt15" not in msg and ".. The raw" not in msg
    assert not list(raw.parent.glob("*/manifest.json"))
    assert not (raw.parents[2] / ".account-labels.json").exists()
    assert not list(raw.parent.parent.glob(".prepare-*"))
    assert (raw / full["path"]).stat().st_size == full["size"]


def test_reencrypted_identical_database_cannot_switch_to_different_label(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    plaintext = b"SQLite format 3\0same payload"
    add(raw, data, FULL, encrypted(plaintext))
    run(raw, capsys, "--database", FULL, "--key-file", key, "--account", "known")
    other, key, data = raw_capture(tmp_path, "later")
    add(other, data, FULL, encrypted(plaintext))
    run(
        other,
        capsys,
        "--database",
        FULL,
        "--key-file",
        key,
        "--account",
        "different",
        fail="another account",
    )
    assert "different" not in (raw.parents[2] / ".account-labels.json").read_text()


def test_reference_disagreement_raw_tamper_and_missing_source_binding(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    base = add(raw, data, FULL, encrypted(b"SQLite format 3\0some"))
    ref = tmp_path / "known"
    ref.write_bytes(b"different bytes")
    args = ["--database", FULL, "--key-file", key, "--account", "name"]
    run(raw, capsys, *args, "--known-backup", ref, fail="differs from --known-backup")
    (raw / base["path"]).write_bytes(b"tampered")
    run(raw, capsys, *args, fail="checksum mismatch")
    data["databases"][0]["path"] = "databases/another-root/" + FULL
    (raw / "raw-manifest.json").write_text(json.dumps(data))
    run(raw, capsys, "--list", fail="Invalid or duplicated")


def test_prepare_preserves_account_scoped_avatar_bytes(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    account = str(UUID(int=1))
    other = str(UUID(int=2))
    image = b"\xff\xd8\xff" + b"x" * 16
    (raw / "avatar.jpg").write_bytes(image)
    data["avatars"] = [
        {
            "account_id": account,
            "jid": "111@s.whatsapp.net",
            "path": "avatar.jpg",
            "sha256": hashed(image),
            "source": "mac",
        },
        {
            "account_id": other,
            "jid": "222@s.whatsapp.net",
            "path": "inexistent",
            "sha256": "0" * 64,
            "source": "mac",
        },
    ]
    add(raw, data, FULL, encrypted(b"SQLite format 3\0some"))
    run(raw, capsys, "--key-file", key, "--database", FULL, "--account", account)
    [manifest] = list(raw.parent.glob("*/manifest.json"))
    [avatar] = json.loads(manifest.read_text())["avatars"]
    assert avatar["jid"] == "111@s.whatsapp.net"
    assert (manifest.parent / avatar["path"]).read_bytes() == image


def test_compare_history_reports_counts_without_writing_raw_or_registry(tmp_path, capsys):
    from tests.capture.test_history_evidence import make_db

    raw, key, data = raw_capture(tmp_path)
    previous = tmp_path / "reference.db"
    make_db(previous, [("101@s.whatsapp.net", 1, "test-outgoing-stanza", 0)])
    base = add(raw, data, FULL, encrypted(previous.read_bytes()))
    before = [(p, p.stat().st_mtime_ns, p.read_bytes()) for p in raw.rglob("*") if p.is_file()]
    result = json.loads(
        run(raw, capsys, "--database", FULL, "--key-file", key, "--compare-history", previous)
    )
    assert result["matched_messages"] == result["matched_chats"] == 1
    assert not (raw.parents[2] / ".capture.lock").exists()
    assert not (raw.parents[2] / ".account-labels.json").exists()
    assert all(
        p.stat().st_mtime_ns == mtime and p.read_bytes() == payload for p, mtime, payload in before
    )
    assert not list(raw.parent.glob("*/manifest.json"))
    key.write_text("01" * 32)
    error = run(
        raw,
        capsys,
        "--database",
        FULL,
        "--key-file",
        key,
        "--compare-history",
        previous,
        fail="Cannot compare full",
    )
    assert base["source_path"] in error


def test_prompt_identifies_selected_file_and_cached_key_failure_explains_recovery(
    tmp_path, capsys, monkeypatch
):
    raw, _, data = raw_capture(tmp_path)
    base = add(raw, data, FULL, encrypted(b"SQLite format 3\0one"))
    monkeypatch.setattr(prepare.sys.stdin, "isatty", lambda: True)
    prompts = []
    monkeypatch.setattr(prepare.getpass, "getpass", lambda prompt: prompts.append(prompt) or KEY)
    run(raw, capsys, "--database", FULL, "--account", "Работа")
    assert len(prompts) == 1 and all(
        bit in prompts[0] for bit in (base["source_path"], "Работа", str(base["size"]))
    )
    other, _, data = raw_capture(tmp_path, "new-key")
    full = add(other, data, FULL, encrypted(b"SQLite format 3\0two", key="ab" * 32))
    message = run(other, capsys, "--database", FULL, "--account", "Работа", fail="--key-file")
    assert full["source_path"] in message
    assert len(prompts) == 1


def test_previously_bound_increment_cannot_be_replayed_on_another_full(tmp_path, capsys):
    raw, key, data = raw_capture(tmp_path)
    add(raw, data, FULL, encrypted(b"SQLite format 3\0one"))
    payload = delta()
    add(raw, data, INC1, payload)
    args = ["--database", FULL, "--key-file", key, "--account", "office", "--increment", INC1]
    run(raw, capsys, *args)
    later, _, data = raw_capture(tmp_path, "new")
    add(later, data, FULL, encrypted(b"SQLite format 3\0two"))
    add(later, data, INC1, payload)
    run(later, capsys, *args, fail="already bound to a different account or full backup")
