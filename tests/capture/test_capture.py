import hashlib
import json
import os
import zlib
from types import SimpleNamespace
from uuid import UUID

import pytest
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props
from wab_capture import cli
from wab_capture.adb import RemoteFile
from wab_capture.keys import verify_key
from wab_capture.source import check_account, open_device, previous_snapshots

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="USB snapshot capture runs on macOS and Linux"
)

KEY = "a4" * 32
UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


def crypt(payload, key=KEY):
    return Database15().encrypt(
        Key15(key=bytes.fromhex(key)), Props(), zlib.compress(b"SQLite format 3\0" + payload)
    )


class Phone:
    serial = "test-device"

    def __init__(self):
        self.files = {
            "Media/WhatsApp Images/a.jpg": b"original",
            "Databases/msgstore.db.crypt15": crypt(b"synthetic db"),
            "Databases/msgstore-increment-1.db.crypt15": crypt(b"synthetic incremental"),
        }
        self.pulls = []

    def records(self, prefix):
        return [
            RemoteFile(path, len(data), hashlib.sha256(data).hexdigest())
            for path, data in self.files.items()
            if path.startswith(prefix)
        ]

    def media(self):
        return self.records("Media/")

    def media_stats(self):
        return [RemoteFile(e.path, e.size, None, e.sha256) for e in self.media()]

    def media_digest(self, entry):
        return hashlib.sha256(self.files[entry.path]).hexdigest()

    def discover_dirs(self):
        return (["/sdcard/WhatsApp/Databases"], ["/sdcard/WhatsApp/Media"])

    def at_root(self, root):
        assert root == "/sdcard/WhatsApp"
        return self

    def all_databases(self):
        return self.databases()

    def databases(self):
        return self.records("Databases/")

    def contacts(self, dest):
        dest.write_text("1111,Alice\n")
        return 1

    def pull(self, record, dest):
        self.pulls.append(record.path)
        dest.write_bytes(self.files[record.path])


def run_session(tmp_path, monkeypatch, phone, accounts, inputs=None, cached_key=False):
    key = tmp_path / "operator-key"
    key.write_text(KEY)
    it = iter(inputs or [answer for account in accounts for answer in ("", account)])
    monkeypatch.setattr(cli, "AndroidDevice", lambda *_: phone)
    monkeypatch.setattr("builtins.input", lambda *_: next(it))
    cli.capture(
        SimpleNamespace(
            verify_media=True,
            root=tmp_path,
            device="test-device",
            account=accounts,
            key_file=[] if cached_key else [key] * len(accounts),
            serial=None,
            phone_root=None,
            avatar_map=None,
        )
    )


def get_manifests(tmp):
    return sorted((tmp / "sources/test-device/snapshots").glob("*/manifest.json"))


def read_file(path):
    return json.loads(path.read_text())


def test_complete_capture_repeat_and_key_reuse(tmp_path, monkeypatch):
    phone = Phone()
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    run_session(tmp_path, monkeypatch, phone, [UUID_A], cached_key=True)
    one, two = get_manifests(tmp_path)
    assert read_file(one)["media"] == read_file(two)["media"]
    assert read_file(two)["media_counts"] == {"added": 0, "skipped": 1, "conflicts": 0}
    assert all((path.parent / "key.txt").read_text().strip() == KEY for path in (one, two))
    assert read_file(one)["databases"][0]["name"] == "msgstore.db.crypt15"
    assert len(read_file(one)["databases"]) == 2
    dev = one.parents[2]
    assert (dev / "media/WhatsApp Images/a.jpg").read_bytes() == b"original"
    assert (dev / "contacts/wa_contacts.txt").read_text() == "1111,Alice\n"
    for p in (one, two):
        m = read_file(p)
        assert m["contacts_at"]
        assert (p.parent / m["contacts"]).read_text() == "1111,Alice\n"
        assert (dev / "logs" / (m["session_id"] + ".log")).exists()
        assert "COMPLETE" in (dev / "logs" / (m["session_id"] + ".log")).read_text()
        assert KEY not in p.read_text()
    assert phone.pulls.count("Media/WhatsApp Images/a.jpg") == 1


def test_two_accounts_switched_with_versioned_media(tmp_path, monkeypatch):
    phone = Phone()
    db_b = crypt(b"database B")

    def replies():
        yield ""
        yield UUID_A
        phone.files["Databases/msgstore.db.crypt15"] = db_b
        phone.files["Media/WhatsApp Images/a.jpg"] = b"replacement"
        yield ""
        yield UUID_B

    run_session(tmp_path, monkeypatch, phone, [UUID_A, UUID_B], inputs=replies())
    one, two = get_manifests(tmp_path)
    dev = one.parents[2]
    a, b = [read_file(x) for x in (one, two)]
    assert a["account_id"] == UUID_A and b["account_id"] == UUID_B
    assert a["session_id"] == b["session_id"]
    assert b["media_counts"]["conflicts"] == 1
    path_a, path_b = [m["media"]["Media/WhatsApp Images/a.jpg"]["path"] for m in (a, b)]
    assert (dev / path_a).read_bytes() == b"original"
    assert (dev / path_b).read_bytes() == b"replacement"
    del phone.files["Media/WhatsApp Images/a.jpg"]
    run_session(tmp_path, monkeypatch, phone, [UUID_B])
    assert (dev / path_b).read_bytes() == b"replacement"


def test_stale_second_database_aborts_and_can_retry(tmp_path, monkeypatch):
    phone = Phone()
    with pytest.raises(ValueError, match="Switch accounts"):
        run_session(tmp_path, monkeypatch, phone, [UUID_A, UUID_B])
    [one] = get_manifests(tmp_path)
    assert "INCOMPLETE" in next((one.parents[2] / "logs").iterdir()).read_text()
    phone.files["Databases/msgstore.db.crypt15"] = crypt(b"B")
    run_session(tmp_path, monkeypatch, phone, [UUID_B])
    assert len(get_manifests(tmp_path)) == 2


def test_denied_contacts_preserves_latest(tmp_path, monkeypatch):
    phone = Phone()
    run_session(tmp_path, monkeypatch, phone, [UUID_A])

    def denied(_):
        raise RuntimeError("denied")

    phone.contacts = denied
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    _, snap = get_manifests(tmp_path)
    assert read_file(snap)["contacts"] is None
    assert (snap.parents[2] / "contacts/wa_contacts.txt").read_text() == "1111,Alice\n"


def test_corruption_rotation_path_and_identity(tmp_path, monkeypatch):
    phone = Phone()
    root = tmp_path / "archive"
    root.mkdir()
    phone.files["Databases/msgstore.db.crypt15"] = crypt(b"x", "ff" * 32)
    with pytest.raises(ValueError, match="Wrong key"):
        run_session(root, monkeypatch, phone, [UUID_A])
    phone = Phone()
    init = phone.databases

    def changing():
        rows = init()
        phone.files["Databases/msgstore.db.crypt15"] = crypt(b"new")
        return rows

    phone.databases = changing
    with pytest.raises(ValueError, match="changed"):
        run_session(root, monkeypatch, phone, [UUID_A])
    assert get_manifests(root) == []
    with open_device(root, "test-device", phone.serial) as (dev, _):
        with pytest.raises(ValueError, match="Another capture"):
            with open_device(root, "test-device", phone.serial):
                pass
        assert not previous_snapshots(dev)
    with pytest.raises(ValueError, match="another ADB serial"):
        with open_device(root, "test-device", "other"):
            pass
    with pytest.raises(ValueError, match="device label"):
        with open_device(root, "../bad-path", phone.serial):
            pass
    assert UUID(check_account("new", "hash", []))
    with pytest.raises(ValueError, match="confirmed"):
        run_session(root, monkeypatch, Phone(), [UUID_A], ["", "wrong"])


def test_no_checksum_format_and_bad_mac(tmp_path):
    path = tmp_path / "test.db.crypt15"
    data = crypt(b"test data")
    path.write_bytes(data[:-16])
    verify_key(path, KEY)
    with pytest.raises(ValueError, match="Wrong key"):
        path.write_bytes(data[:-17] + bytes([data[-17] ^ 1]))
        verify_key(path, KEY)
    with pytest.raises(ValueError, match="64 hexadecimal"):
        verify_key(path, "malformed")


def test_device_label_rename_reuses_internal_identifier(tmp_path):
    with open_device(tmp_path, "test-device", "serial") as (device, info):
        old_id = info["device_id"]
    with pytest.raises(ValueError, match="already registered"):
        with open_device(tmp_path, "duplicate", "serial"):
            pass
    device.rename(tmp_path / "sources/new-label")
    with open_device(tmp_path, "new-label", "serial") as (_, new):
        assert new["device_id"] == old_id and new["label"] == "new-label"


def test_missing_historical_candidate_only_when_unambiguous(tmp_path, monkeypatch):
    phone = Phone()
    phone.files["Media/gone.jpg"] = b"only version"
    phone.files["Media/changing.jpg"] = b"first"
    for data in (b"first", b"second"):
        phone.files["Media/changing.jpg"] = data
        run_session(tmp_path, monkeypatch, phone, [UUID_A])
    del phone.files["Media/gone.jpg"], phone.files["Media/changing.jpg"]
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    newest = read_file(get_manifests(tmp_path)[-1])
    assert set(newest["retained_media"]) == {"Media/gone.jpg"}
    assert "Media/gone.jpg" not in newest["media"]


def test_capture_cli_options_and_errors(tmp_path, monkeypatch):
    import sys

    phone = Phone()
    monkeypatch.setattr(cli, "AndroidDevice", lambda *_: phone)
    key = tmp_path / "key"
    key.write_text(KEY)
    argv = [
        "wab-capture",
        "--root",
        str(tmp_path),
        "--device",
        "dev",
        "--account",
        UUID_A,
        "--key-file",
        str(key),
    ]
    answers = iter(["", UUID_A])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    assert (tmp_path / "sources/dev/device.json").is_file()
    for extra, error in ((["--account", UUID_A], "once"), (["--account", UUID_B], "key-file")):
        monkeypatch.setattr(sys, "argv", argv + extra)
        with pytest.raises(SystemExit, match=error):
            cli.main()


def test_reencryption_cannot_attach_same_native_db_to_another_account(tmp_path, monkeypatch):
    phone = Phone()
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    old = phone.files["Databases/msgstore.db.crypt15"]
    phone.files["Databases/msgstore.db.crypt15"] = crypt(b"synthetic db")
    assert old != phone.files["Databases/msgstore.db.crypt15"]
    with pytest.raises(ValueError, match="re-encrypted"):
        run_session(tmp_path, monkeypatch, phone, [UUID_B])
    assert len(get_manifests(tmp_path)) == 1


def test_sqlite_fingerprint_stable_with_raw_and_compressed_payloads(tmp_path):
    plain = b"SQLite format 3\0" + b"synthetic-page" * 200000
    key = Key15(key=bytes.fromhex(KEY))
    path = tmp_path / "msgstore.db.crypt15"
    for payload in (plain, zlib.compress(plain, 1), zlib.compress(plain, 9)):
        path.write_bytes(Database15().encrypt(key, Props(), payload))
        assert verify_key(path, KEY, fingerprint=True) == hashlib.sha256(plain).hexdigest()
    path.write_bytes(Database15().encrypt(key, Props(), zlib.compress(b"not a database")))
    with pytest.raises(ValueError, match="SQLite"):
        verify_key(path, KEY, fingerprint=True)


@pytest.mark.parametrize(
    "first,next_name",
    [
        ("A.jpg", "a.jpg"),
        ("A", "a/nested.jpg"),
        ("A/nested.jpg", "a"),
        ("é.jpg", "e\u0301.jpg"),
        ("P/é.jpg", "p/e\u0301.jpg"),
    ],
)
def test_portable_source_media_collisions_across_captures(tmp_path, monkeypatch, first, next_name):
    phone = Phone()
    phone.files[f"Media/{first}"] = b"initial"
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    del phone.files[f"Media/{first}"]
    phone.files[f"Media/{next_name}"] = b"other bytes"
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    one, two, three = get_manifests(tmp_path)
    dev = one.parents[2]
    original = read_file(one)["media"][f"Media/{first}"]["path"]
    variant = read_file(two)["media"][f"Media/{next_name}"]["path"]
    assert original.startswith("media/")
    assert variant.startswith("media-versions/")
    assert (dev / original).read_bytes() == b"initial"
    assert (dev / variant).read_bytes() == b"other bytes"
    assert read_file(three)["media"][f"Media/{next_name}"]["path"] == variant
    assert read_file(three)["media"][f"Media/{next_name}"]["native_path_unique"] is True
    assert phone.pulls.count(f"Media/{next_name}") == 1
    assert sum(p.is_file() for p in (dev / "media-versions").rglob("*")) == 1


def test_colliding_names_during_initial_capture_keep_both_exact_files(tmp_path, monkeypatch):
    phone = Phone()
    phone.files["Media/photo"] = b"lower"
    phone.files["Media/PHOTO/picture"] = b"upper nested"
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    [snap] = get_manifests(tmp_path)
    mapping = read_file(snap)["media"]
    for name in ("Media/photo", "Media/PHOTO/picture"):
        assert (snap.parents[2] / mapping[name]["path"]).read_bytes() == phone.files[name]
    assert mapping["Media/photo"]["path"].startswith("media-versions/")


def test_layout_collision_followed_by_exact_path_reuse_remembers_all_versions(
    tmp_path, monkeypatch
):
    phone = Phone()
    phone.files["Media/IMG.jpg"] = b"original"
    phone.files["Media/img.jpg"] = b"lower"
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    for data in (b"lower replacement", b"lower"):
        phone.files["Media/img.jpg"] = data
        run_session(tmp_path, monkeypatch, phone, [UUID_A])
    one, two, three = (read_file(f)["media"] for f in get_manifests(tmp_path))
    assert all(record["native_path_unique"] for record in one.values())
    assert two["Media/IMG.jpg"]["native_path_unique"] is True
    assert two["Media/img.jpg"]["native_path_unique"] is False
    assert three["Media/img.jpg"]["native_path_unique"] is False


def test_preexisting_legacy_aliases_preserve_old_files(tmp_path, monkeypatch):
    phone = Phone()
    old = tmp_path / "sources/test-device/media"
    old.mkdir(parents=True)
    (old / "A").write_bytes(b"old A")
    if (old / "a").exists():
        pytest.skip("Simulates an existing store created on a case-sensitive disk.")
    (old / "a").write_bytes(b"old a")
    phone.files.update({"Media/a": b"old a", "Media/A": b"new A"})
    run_session(tmp_path, monkeypatch, phone, [UUID_A])
    [snap] = get_manifests(tmp_path)
    mapping = read_file(snap)["media"]
    assert (old / "A").read_bytes() == b"old A" and (old / "a").read_bytes() == b"old a"
    for name in ("a", "A"):
        record = mapping[f"Media/{name}"]
        assert record["path"].startswith("media-versions/")
        assert (old.parent / record["path"]).read_bytes() == phone.files[f"Media/{name}"]
    assert mapping["Media/a"]["native_path_unique"] is True
    assert mapping["Media/A"]["native_path_unique"] is False
