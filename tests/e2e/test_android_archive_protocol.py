"""Run the fork's CLIs against synthetic crypt15 backups and a local ADB transport."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path
from uuid import UUID

import pytest
from tests.conftest import make_android_db
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.props import Props

pytestmark = pytest.mark.skipif(os.name != "posix", reason="ADB capture runs on macOS/Linux")
ACCOUNT_A = str(UUID(int=100))
ACCOUNT_B = str(UUID(int=200))
CONTACT = "12025550123"
PROJECT = Path(__file__).resolve().parents[2]
MEDIA = "Media/WhatsApp Images"
IMAGE = "team-photo.jpg"
FIRST = b"synthetic-photo-first"
SECOND = b"synthetic-photo-second"

# A desktop-side emulator for adb's documented get-serialno, shell and pull.
# Local paths stand in for a mounted test phone. Shell inventory and hashing
# execute the production Android commands through the platform's sh, except
# on macOS where GNU stat/find are not available. Inventory is modeled there.
ADB = r"""#!/usr/bin/env python3
import hashlib
import os
import pathlib
import shlex
import shutil
import subprocess
import sys

args = sys.argv[1:]
if args[:1] == ['-s']:
    args = args[2:]
elif args[:1] == ['-d']:
    args = args[1:]
mount = os.environ.get("TEST_SDCARD")
if mount:
    args = [a.replace("/sdcard", mount) for a in args]
if env_log := os.environ.get("TEST_ADB_LOG"):
    with open(env_log, "a", encoding="utf-8") as out:
        print(repr(args), file=out)
if args == ['get-serialno']:
    print('TEST-DEVICE')
elif args[:1] == ['pull']:
    if os.environ.get('TEST_FAIL_PULL') == pathlib.Path(args[1]).name:
        sys.exit(1)
    shutil.copyfile(args[1], args[2])
elif args[:2] == ['shell', '-T']:
    cmd = args[2]
    if 'find Databases/' in cmd and os.environ.get('TEST_SWITCH_DB'):
        target = pathlib.Path(os.environ['TEST_SWITCH_DB'])
        counter = target.with_suffix('.count')
        n = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(n))
        if n == 3:  # inventory + final validation for first, then second account
            shutil.copyfile(target, pathlib.Path(shlex.split(cmd)[1]) / 'Databases/msgstore.db.crypt15')
    if mount and cmd.startswith('for path in'):
        data = subprocess.check_output(['/bin/sh', '-c', cmd]).replace(mount.encode(), b'/sdcard')
        sys.stdout.buffer.write(data)
    elif cmd.startswith('sha256sum <'):
        print(hashlib.sha256(pathlib.Path(shlex.split(cmd)[2]).read_bytes()).hexdigest())
    elif cmd.startswith('content query'):
        print(os.environ['TEST_CONTACTS'])
    elif sys.platform == 'darwin' and cmd.startswith('cd '):
        words = shlex.split(cmd)
        root, directory = pathlib.Path(words[1]), words[4]
        if "stat -c" in cmd and "sha256sum" not in cmd:
            files = sorted(f for f in (root / directory).rglob('*') if f.is_file())
            if files:
                buf = sys.stdout.buffer
                buf.write(str(len(files)).encode() + b'\0')
                for f in files:
                    buf.write(f.relative_to(root).as_posix().encode() + b'\0')
                for f in files:
                    st = f.stat()
                    buf.write(f"{st.st_size} {int(st.st_mtime)} {int(st.st_ctime)} {st.st_ino}\n".encode())
                buf.write(b'\0')
            sys.exit(0)
        for f in sorted((root / directory).rglob('*')):
            if f.is_file():
                b = f.read_bytes()
                for value in (f.relative_to(root).as_posix(), str(len(b)), hashlib.sha256(b).hexdigest()):
                    sys.stdout.buffer.write(value.encode() + b'\0')
    else:
        sys.exit(subprocess.run(['/bin/sh', '-c', cmd]).returncode)
else:
    sys.exit('Unexpected adb operation: ' + repr(args))
"""


def run_module(module, args, env, *, stdin="", success=True):
    run = subprocess.run(
        [sys.executable, "-m", module, *map(str, args)],
        cwd=PROJECT,
        env=env,
        input=stdin,
        text=True,
        capture_output=True,
        timeout=45,
    )
    output = run.stdout + run.stderr
    if success:
        assert run.returncode == 0, output
    else:
        assert run.returncode != 0, output
    return output


class Phone:
    def __init__(self, tmp):
        self.store = tmp / "store"
        self.phone = tmp / "phone"
        self.db = tmp / "msgstore.db"
        self.key = tmp / "synthetic-key"
        self.key.write_text("12" * 32)
        (self.phone / "Databases").mkdir(parents=True)
        (self.phone / MEDIA).mkdir(parents=True)
        (self.phone / MEDIA / IMAGE).write_bytes(FIRST)
        self.add_db()
        self.encrypt()
        self.bin = tmp / "bin"
        self.bin.mkdir()
        adb = self.bin / "adb"
        adb.write_text(ADB)
        adb.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.set_contact("Alice")

    def add_db(self):
        conn = make_android_db(self.db)
        with conn:
            conn.execute("ALTER TABLE jid ADD COLUMN server TEXT")
            conn.executemany(
                "INSERT INTO jid VALUES (?,?,?,?)",
                [
                    (1, CONTACT, CONTACT + "@s.whatsapp.net", "s.whatsapp.net"),
                    (2, "100000000001", "100000000001@g.us", "g.us"),
                ],
            )
            conn.execute("INSERT INTO chat VALUES (1,2,'Project Alpha',0,1700000000000,1)")
            conn.execute("INSERT INTO message VALUES (1,1,0,1,1700000000000,'synthetic',1,'k1')")
            conn.execute(
                "INSERT INTO message_media VALUES (1,1,1,?,?,'image/jpeg',NULL)",
                (f"{MEDIA}/{IMAGE}", IMAGE),
            )
        conn.close()

    def encrypt(self):
        key = Key15(key=bytes.fromhex(self.key.read_text()))
        crypt = Database15(key=key)
        payload = crypt.encrypt(key, Props(), zlib.compress(self.db.read_bytes()))
        (self.phone / "Databases" / "msgstore.db.crypt15").write_bytes(payload)

    def set_contact(self, name):
        self.env["TEST_CONTACTS"] = (
            f"Row: 0 display_name={name}, data1=+{CONTACT}, data4=+{CONTACT}, "
            "mimetype=vnd.android.cursor.item/phone_v2"
        )

    def capture(self, account=ACCOUNT_A, *, success=True):
        snaps = self.store / "sources" / "android" / "snapshots"
        before = set(snaps.glob("*/manifest.json"))
        log = run_module(
            "wab_capture",
            [
                "--root",
                self.store,
                "--device",
                "android",
                "--account",
                account,
                "--key-file",
                self.key,
                "--phone-root",
                self.phone,
            ],
            self.env,
            stdin=f"\n{account}\n",
            success=success,
        )
        after = set(snaps.glob("*/manifest.json"))
        if success:
            assert len(after - before) == 1
            return (after - before).pop().parent
        assert before == after, log
        return None


def test_capture_abort_retry_and_account_boundary(tmp_path):
    phone = Phone(tmp_path)
    snap = phone.capture()
    manifest = json.loads((snap / "manifest.json").read_text())
    assert manifest["account_id"] == ACCOUNT_A
    assert manifest["media"][f"{MEDIA}/{IMAGE}"]["sha256"] == hashlib.sha256(FIRST).hexdigest()

    # An unswitched phone must not create the same database under another owner.
    phone.capture(ACCOUNT_B, success=False)
    phone.encrypt()
    # Mimic disconnect on database pull. The first published snapshot must survive.
    phone.env["TEST_FAIL_PULL"] = "msgstore.db.crypt15"
    phone.capture(success=False)
    del phone.env["TEST_FAIL_PULL"]
    (phone.phone / MEDIA / IMAGE).write_bytes(SECOND)
    snap2 = phone.capture()
    m2 = json.loads((snap2 / "manifest.json").read_text())
    first_ref = manifest["media"][f"{MEDIA}/{IMAGE}"]
    second_ref = m2["media"][f"{MEDIA}/{IMAGE}"]
    assert first_ref["path"] != second_ref["path"]
    device = snap.parent.parent
    assert (device / first_ref["path"]).read_bytes() == FIRST
    assert (device / second_ref["path"]).read_bytes() == SECOND
    assert phone.key.read_text() not in "".join(
        p.read_text() for p in (device / "logs").glob("*.log")
    )


def invoke_import(snapshot, phone, *args, success=True):
    return run_module("wab_capture.importer", [snapshot, *args], phone.env, success=success)


def test_adopt_archive_metadata_and_idempotent_import(tmp_path):
    phone = Phone(tmp_path)
    first = phone.capture()
    media_ref = f"{MEDIA}/{IMAGE}"
    legacy = tmp_path / "legacy"
    names = tmp_path / "names.csv"
    names.write_text(f"+{CONTACT},Alice\n")
    run_module(
        "wab_archiver",
        [
            "archive",
            "--msgstore",
            phone.db,
            "--contacts",
            names,
            "--output",
            legacy,
            "--wa-root",
            phone.phone,
            "--preserve-deleted",
        ],
        phone.env,
    )
    old_files = list((legacy / "Groups").rglob("*.jpg"))
    assert len(old_files) == 1
    relative = old_files[0].relative_to(legacy)
    archive = phone.store / "wab" / ACCOUNT_A

    invoke_import(first, phone, "--adopt", legacy)
    assert (archive / relative).read_bytes() == FIRST
    legacy_bytes = old_files[0].read_bytes()
    inode = (archive / relative).stat().st_ino
    assert legacy_bytes == FIRST

    phone.set_contact("Alice Renamed")
    with sqlite3.connect(phone.db) as conn:
        conn.execute("UPDATE chat SET subject='Project Beta' WHERE _id=1")
        conn.execute("INSERT INTO message VALUES (2,1,0,1,1700000050000,'second',1,'k2')")
        conn.execute(
            "INSERT INTO message_media VALUES (2,2,1,?,?,'image/jpeg',NULL)",
            (f"{MEDIA}/new.jpg", "new.jpg"),
        )
    (phone.phone / MEDIA / "new.jpg").write_bytes(SECOND)
    phone.encrypt()
    second = phone.capture()
    invoke_import(second, phone, "--metadata-only")
    assert (archive / relative).stat().st_ino == inode
    assert [path.relative_to(archive) for path in (archive / "Groups").rglob("*.jpg")] == [relative]
    invoke_import(second, phone)
    invoke_import(second, phone)
    assert (archive / relative).stat().st_ino == inode
    photos = list((archive / "Groups").rglob("*.jpg"))
    assert sorted(p.read_bytes() for p in photos) == sorted([FIRST, SECOND])
    # SQLite and the physical file paths remain consistent across staging swaps.
    with sqlite3.connect(archive / ".wa_media_archiver.db") as conn:
        paths = [
            row[0]
            for row in conn.execute(
                "SELECT archive_path FROM archive_copies WHERE original_path=?", (media_ref,)
            )
        ]
    assert paths == [relative.as_posix()]
    assert list((legacy / "Groups").rglob("*.jpg")) == old_files
    assert old_files[0].read_bytes() == legacy_bytes


def test_two_accounts_share_media_but_not_snapshots(tmp_path):
    phone = Phone(tmp_path)
    current = phone.phone / "Databases" / "msgstore.db.crypt15"
    first_bytes = current.read_bytes()
    phone.key.write_text("34" * 32)
    with sqlite3.connect(phone.db) as conn:
        conn.execute("UPDATE message SET key_id='second-account-msg', text_data='separate history'")
    phone.encrypt()
    inactive = tmp_path / "second.crypt15"
    current.rename(inactive)
    current.write_bytes(first_bytes)
    first_key = tmp_path / "first-test-key"
    first_key.write_text("12" * 32)
    phone.env["TEST_SWITCH_DB"] = str(inactive)
    for i in range(30):
        (phone.phone / MEDIA / f"synthetic-{i}.bin").write_bytes(bytes([i]) * 128)
    args = [
        "--root",
        phone.store,
        "--device",
        "android",
        "--phone-root",
        phone.phone,
        "--account",
        ACCOUNT_A,
        "--key-file",
        first_key,
        "--account",
        ACCOUNT_B,
        "--key-file",
        phone.key,
    ]
    run_module("wab_capture", args, phone.env, stdin=f"\n{ACCOUNT_A}\n\n{ACCOUNT_B}\n")
    device = phone.store / "sources" / "android"
    manifests = [
        json.loads(p.read_text()) for p in sorted((device / "snapshots").glob("*/manifest.json"))
    ]
    assert [m["account_id"] for m in manifests] == [ACCOUNT_A, ACCOUNT_B]
    assert len({m["session_id"] for m in manifests}) == 1
    assert len({m["databases"][0]["sha256"] for m in manifests}) == 2
    assert manifests[0]["media"] == manifests[1]["media"]
    assert len(manifests[1]["media"]) == 31
    assert len([p for p in (device / "media").rglob("*") if p.is_file()]) == 31
    assert len(list((device / "logs").glob("*.log"))) == 1


def test_mac_pathless_repair_survives_new_native_snapshot(tmp_path):
    phone = Phone(tmp_path)
    mac = tmp_path / "mac"
    mac.mkdir()
    data = b"synthetic-photo-only-on-mac"
    (mac / "renamed.jpg").write_bytes(data)
    with sqlite3.connect(phone.db) as conn:
        conn.execute("ALTER TABLE message_media ADD COLUMN file_hash BLOB")
        conn.execute(
            "UPDATE message_media SET file_path=NULL, file_hash=?", (hashlib.sha256(data).digest(),)
        )
    phone.encrypt()
    snap = phone.capture()
    invoke_import(snap, phone)
    archive = phone.store / "wab" / ACCOUNT_A
    native = archive / "Whatsapp Databases" / "msgstore.db"
    repair = tmp_path / "repair"
    run_module(
        "wab_capture.reconcile",
        [
            "--db",
            native,
            "--mac-media",
            mac,
            "--account-id",
            ACCOUNT_A,
            "--snapshot-id",
            snap.name,
            "--output",
            repair,
            "--stage",
        ],
        phone.env,
    )
    invoke_import(snap, phone, "--repair", repair)
    with sqlite3.connect(native) as conn:
        resolved_path = conn.execute("SELECT file_path FROM message_media WHERE _id=1").fetchone()[
            0
        ]
    assert resolved_path
    assert any(p.read_bytes() == data for p in (archive / "Groups").rglob("*") if p.is_file())

    # A subsequent Android backup may still lack a path for this same attachment.
    # A repaired working archive must retain its association to the verified bytes.
    phone.encrypt()
    snap2 = phone.capture()
    invoke_import(snap2, phone)
    with sqlite3.connect(native) as conn:
        updated_path = conn.execute("SELECT file_path FROM message_media WHERE _id=1").fetchone()[0]
    assert updated_path == resolved_path


def test_concurrent_import_and_corrupt_snapshot_preserve_existing_archive(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    phone = Phone(tmp_path)
    first = phone.capture()
    with ThreadPoolExecutor(max_workers=3) as workers:
        imports = [workers.submit(invoke_import, first, phone) for _ in range(3)]
        outputs = [job.result() for job in imports]
    assert sum("Already imported:" in output for output in outputs) == 2
    target = phone.store / "wab" / ACCOUNT_A
    original_assets = {
        p.relative_to(target): p.read_bytes() for p in (target / "Groups").rglob("*.jpg")
    }
    assert len(original_assets) == 1

    phone.encrypt()
    second = phone.capture()
    encrypted = second / "databases" / "msgstore.db.crypt15"
    encrypted.write_bytes(encrypted.read_bytes()[:-12])
    assert "checksum" in invoke_import(second, phone, success=False).casefold()
    assert {
        p.relative_to(target): p.read_bytes() for p in (target / "Groups").rglob("*.jpg")
    } == original_assets
    assert not list((phone.store / "wab").glob(".import-*"))


def test_two_device_sources_preserve_case_distinct_media_in_one_account(tmp_path):
    from wab_viewer.main import create_app

    second_tmp = tmp_path / "second-device"
    second_tmp.mkdir()
    other = Phone(second_tmp)
    upper = other.phone / MEDIA / IMAGE.upper()
    if upper.exists():
        pytest.skip("The simulated Android source filesystem folds case in filenames")
    upper.write_bytes(SECOND)
    with sqlite3.connect(other.db) as db:
        db.execute("ALTER TABLE message_media ADD COLUMN file_hash BLOB")
        db.execute("UPDATE message_media SET file_hash=?", (hashlib.sha256(FIRST).digest(),))
        db.execute("INSERT INTO message VALUES (2,1,0,1,1700000050000,'other photo',1,'k2')")
        db.execute(
            "INSERT INTO message_media VALUES (2,2,1,?,?,'image/jpeg',NULL,?)",
            (f"{MEDIA}/{upper.name}", upper.name, hashlib.sha256(SECOND).digest()),
        )
    other.encrypt()

    first_device = Phone(tmp_path)
    first_snapshot = first_device.capture()
    invoke_import(first_snapshot, first_device)
    (other.bin / "adb").write_text(ADB.replace("TEST-DEVICE", "TEST-DEVICE-2"))
    run_module(
        "wab_capture",
        [
            "--root",
            first_device.store,
            "--device",
            "other-android",
            "--account",
            ACCOUNT_A,
            "--key-file",
            other.key,
            "--phone-root",
            other.phone,
        ],
        other.env,
        stdin=f"\n{ACCOUNT_A}\n",
    )
    [manifest_path] = (first_device.store / "sources" / "other-android" / "snapshots").glob(
        "*/manifest.json"
    )
    manifest = json.loads(manifest_path.read_text())
    assert (
        manifest["device_id"]
        != json.loads((first_snapshot / "manifest.json").read_text())["device_id"]
    )
    assert set(manifest["media"]) == {f"{MEDIA}/{IMAGE}", f"{MEDIA}/{upper.name}"}
    invoke_import(manifest_path.parent, other)
    archive = first_device.store / "wab" / ACCOUNT_A
    with sqlite3.connect(archive / "Whatsapp Databases" / "msgstore.db") as db:
        db.execute("ATTACH DATABASE ? AS archive", (str(archive / ".wa_media_archiver.db"),))
        messages = db.execute(
            "SELECT media.message_row_id, copies.archive_path FROM message_media media "
            "JOIN archive.archive_copies copies ON copies.original_path=media.file_path "
            "ORDER BY media.message_row_id"
        ).fetchall()
    assert [mid for mid, _ in messages] == [1, 2]
    client = create_app(archive).test_client()
    for (_, path), expected in zip(messages, [FIRST, SECOND], strict=True):
        response = client.get(f"/media/{path}")
        assert response.status_code == 200
        assert response.data == expected
        response.close()
