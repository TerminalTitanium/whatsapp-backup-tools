import hashlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from wab_capture import adb


def encode(path, data):
    return b"\0".join(
        [path.encode(), str(len(data)).encode(), hashlib.sha256(data).hexdigest().encode(), b""]
    )


def fake_device(monkeypatch, root="/sdcard/WhatsApp"):
    calls = Mock(side_effect=[b"device-serial\n", (root + "\0").encode()])
    monkeypatch.setattr(adb, "_adb", calls)
    device = adb.AndroidDevice()
    assert calls.call_args_list[0].args[0] == ["-d", "get-serialno"]
    assert calls.call_args.args[0][:4] == ["-s", "device-serial", "shell", "-T"]
    return device


def test_device_requires_unambiguous_root_and_device(monkeypatch):
    for roots in (b"", b"/sdcard/WhatsApp\0/sdcard/WhatsApp Business\0"):
        monkeypatch.setattr(adb, "_adb", Mock(side_effect=[b"serial\n", roots]))
        with pytest.raises(ValueError):
            adb.AndroidDevice(serial="serial")
    monkeypatch.setattr(adb, "_adb", Mock(return_value=b"unknown\n"))
    with pytest.raises(RuntimeError):
        adb.AndroidDevice()
    monkeypatch.setattr(adb, "_adb", Mock(return_value=b"other\n"))
    with pytest.raises(RuntimeError):
        adb.AndroidDevice("serial")
    monkeypatch.setattr(adb, "_adb", Mock(return_value=b"serial\n"))
    with pytest.raises(ValueError):
        adb.AndroidDevice("serial", "/data/../escape")


@pytest.mark.skipif(sys.platform != "linux", reason="The device shell requires Android/Linux stat.")
def test_device_shell_script_round_trips_special_paths(monkeypatch, tmp_path):
    root = tmp_path / "WhatsApp's directory"
    (root / "Media").mkdir(parents=True)
    (root / "Databases").mkdir()
    photo = root / "Media" / "a 'photo\n$100.jpeg"
    photo.write_bytes(b"photo")
    full = root / "Databases" / "msgstore.db.crypt15"
    full.write_bytes(b"full db")

    def local_shell(args, timeout):
        if args == ["-d", "get-serialno"]:
            return b"serial\n"
        assert args[:4] == ["-s", "serial", "shell", "-T"]
        return subprocess.check_output(["sh", "-c", args[4]], timeout=timeout)

    monkeypatch.setattr(adb, "_adb", local_shell)
    device = adb.AndroidDevice(root=str(root))
    assert device.root == str(root)
    assert device.media() == [
        adb.RemoteFile(f"Media/{photo.name}", 5, hashlib.sha256(b"photo").hexdigest())
    ]
    assert device.databases() == [
        adb.RemoteFile(f"Databases/{full.name}", 7, hashlib.sha256(b"full db").hexdigest())
    ]


def test_incomplete_duplicate_or_escaping_inventory_rejected():
    good = encode("Media/new", b"hi")
    assert adb._inventory(b"", "Media") == []
    assert adb._inventory(good, "Media")[0].size == 2
    for invalid in (
        b"partial",
        b"partial\0",
        good * 2,
        encode("Media/../escape", b"hi"),
        good.replace(b"\x002\x00", b"\x00-2\x00"),
        encode("other/x", b"file"),
        b"Media/x\x000\x00bad\0",
    ):
        with pytest.raises(ValueError):
            adb._inventory(invalid, "Media")


def test_database_discovery_selects_chain_and_validates_it(monkeypatch):
    device = fake_device(monkeypatch)
    prefix = "Databases/msgstore"
    base = encode(f"{prefix}.db.crypt15", b"full")
    first = encode(f"{prefix}-increment-1.db.crypt15", b"one")
    second = encode(f"{prefix}-increment-2.db.crypt15", b"two")
    old = encode(f"{prefix}-increment-1-2024.12.db.crypt15", b"x")
    legacy = encode(f"{prefix}-increment-1.db.crypt14", b"y")
    monkeypatch.setattr(device, "_shell", Mock(return_value=old + second + legacy + base + first))
    assert [f.path for f in device.databases()] == [
        f"{prefix}.db.crypt15",
        f"{prefix}-increment-1.db.crypt15",
        f"{prefix}-increment-2.db.crypt15",
    ]
    for output in (b"", base + second, base + encode(f"{prefix}.db.crypt14", b"x")):
        monkeypatch.setattr(device, "_shell", Mock(return_value=output))
        with pytest.raises(ValueError):
            device.databases()


def test_contacts_uses_phone_rows_and_preserves_previous_on_error(monkeypatch, tmp_path):
    device = fake_device(monkeypatch)
    out = tmp_path / "contacts" / "wa_contacts.txt"
    data = (
        "Row: 0 display_name=Example, data1=123, mimetype=vnd.android.cursor.item/phone_v2\r\n"
        "Row: 1 display_name=Example, data1=email, mimetype=email\r\n"
    )
    monkeypatch.setattr(device, "_shell", Mock(return_value=data.encode()))
    assert device.contacts(out) == 1
    stored = out.read_text()
    assert "phone_v2" in stored and "mimetype=email" not in stored
    for error, exception in [
        (b"No result found.", ValueError),
        (b"SecurityException", RuntimeError),
    ]:
        monkeypatch.setattr(device, "_shell", Mock(return_value=error))
        with pytest.raises(exception):
            device.contacts(out)
        assert out.read_text() == stored


def test_download_rejects_changes_and_keeps_previous_bytes(monkeypatch, tmp_path):
    device = fake_device(monkeypatch)
    record = adb.RemoteFile("Media/odd file", 7, hashlib.sha256(b"updated").hexdigest())
    out = tmp_path / "local.bin"
    out.write_bytes(b"old")
    for bad in (b"changed", b"truncated"):
        monkeypatch.setattr(adb, "_adb", lambda args, timeout: Path(args[-1]).write_bytes(bad))
        with pytest.raises(ValueError, match="USB transfer"):
            device.pull(record, out)
        assert list(tmp_path.iterdir()) == [out] and out.read_bytes() == b"old"

    def transfer(args, timeout):
        assert args[:4] == ["-s", "device-serial", "pull", "/sdcard/WhatsApp/Media/odd file"]
        Path(args[-1]).write_bytes(b"updated")

    monkeypatch.setattr(adb, "_adb", transfer)
    device.pull(record, out)
    assert out.read_bytes() == b"updated"
    with pytest.raises(ValueError):
        device.pull(adb.RemoteFile("Media/../invalid", 1, "0" * 64), out)


def test_adb_reports_transport_failure(monkeypatch):
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=FileNotFoundError()))
    with pytest.raises(RuntimeError, match="Platform Tools"):
        adb._adb(["version"], 5)
    monkeypatch.setattr(subprocess, "run", Mock(side_effect=subprocess.TimeoutExpired(["adb"], 1)))
    with pytest.raises(RuntimeError, match="timed out"):
        adb._adb(["version"], 5)
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["adb"], 1, b"", b"unauthorized")),
    )
    with pytest.raises(RuntimeError, match="unauthorized"):
        adb._adb(["devices"], 5)
