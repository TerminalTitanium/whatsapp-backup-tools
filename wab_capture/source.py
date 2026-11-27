"""Create immutable per-account observations beneath a shared device media store."""

import hashlib
import json
import os
import re
import shutil
import tempfile
import unicodedata
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from .keys import verify_key


def utc_now():
    return datetime.now(UTC).isoformat(timespec="microseconds")


def timestamp_id(now):
    return datetime.fromisoformat(now).astimezone(UTC).strftime("%Y-%m-%dT%H%M%S%fZ")


def digest(path):
    with path.open("rb") as infile:
        return hashlib.file_digest(infile, "sha256").hexdigest()


def write_json(path, data):
    with path.open("x", encoding="utf-8") as out:
        json.dump(data, out, ensure_ascii=False, indent=2, allow_nan=False)
        out.write("\n")


@contextmanager
def open_device(root, label, serial):
    import fcntl  # Capture host: macOS or Linux.

    if label in (".", "..") or not re.fullmatch(r"[\w][\w. -]{0,95}", label):
        raise ValueError("Use a device label without path separators, e.g. android-phone.")
    sources = root / "sources"
    sources.mkdir(mode=0o700, parents=True, exist_ok=True)
    device = sources / label
    _ensure_inside(sources, device)
    # Serialize first enrolment as well as captures, so simultaneous commands
    # with different labels cannot assign two UUIDs to the same physical phone.
    with (sources / ".capture.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another capture is active in this sources directory.") from None
        for existing in sources.glob("*/device.json"):
            _ensure_inside(sources, existing)
            if existing.parent != device and json.loads(existing.read_text())["serial"] == serial:
                raise ValueError(
                    f"This ADB device is already registered as {existing.parent.name}."
                )
        device.mkdir(mode=0o700, exist_ok=True)
        info_path = device / "device.json"
        if info_path.exists():
            info = json.loads(info_path.read_text(encoding="utf-8"))
            if info["serial"] != serial:
                raise ValueError("The selected device label belongs to another ADB serial.")
        else:
            info = {"device_id": str(uuid4()), "serial": serial}
        if info.get("label") != label:
            info["label"] = label
            with tempfile.TemporaryDirectory(dir=device) as temporary:
                tmp = Path(temporary) / "device.json"
                write_json(tmp, info)
                os.replace(tmp, info_path)
        for subdir in ("media", "snapshots", "logs"):
            (device / subdir).mkdir(mode=0o700, exist_ok=True)
        yield device, info


def _relative(path, category):
    parts = path.split("/")
    if len(parts) < 2 or parts[0] != category or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"Invalid Android {category} path.")
    return Path(*parts[1:])


def _ensure_inside(base, path):
    if not path.resolve().is_relative_to(base.resolve()) or path.is_symlink():
        raise ValueError(f"Unsafe destination beneath {base.name}.")


class MediaPaths:
    """Reserve one physical spelling and kind per portable path component."""

    def __init__(self, root: Path):
        self.slots = {}
        self.existing_files = set()
        for directory, dirs, files in os.walk(root):
            parent = Path(directory).relative_to(root)
            self.existing_files.update(parent / name for name in files)
            for names, is_directory in ((dirs, True), (files, False)):
                for name in names:
                    path = parent / name
                    key = self.key(path)
                    entry = (path, is_directory and not (root / path).is_symlink())
                    if key in self.slots and self.slots[key] != entry:
                        # A case-sensitive store from an earlier release may contain
                        # both physical spellings. Preserve those old files, but keep
                        # all new observations of this ambiguous path in versions.
                        self.slots[key] = None
                    else:
                        self.slots[key] = entry

    @staticmethod
    def key(path):
        return unicodedata.normalize("NFC", path.as_posix().casefold())

    def reserve(self, relative):
        """Return False if any component would alias another file or directory."""
        wanted = [(p, True) for p in relative.parents if p != Path(".")]
        wanted.append((relative, False))
        for entry in wanted:
            key = self.key(entry[0])
            if key in self.slots and self.slots[key] != entry:
                return False
        for entry in wanted:
            self.slots[self.key(entry[0])] = entry
        return True


def sync_media(usb, device, stage):
    """Keep the first content at each native path; address later versions by hash."""
    media = {}
    counts = {"added": 0, "skipped": 0, "conflicts": 0}
    paths = MediaPaths(device / "media")
    for entry in sorted(usb.media(), key=lambda record: record.path):
        relative = _relative(entry.path, "Media")
        if not re.fullmatch(r"[a-f0-9]{64}", entry.sha256) or entry.path in media:
            raise ValueError("Invalid or repeated media inventory record.")
        original = device / "media" / relative
        usable = paths.reserve(relative)
        original_matches = True
        if usable or relative in paths.existing_files:
            _ensure_inside(device / "media", original)
            if relative in paths.existing_files:
                original_matches = digest(original) == entry.sha256
        target = original
        if not usable or not original_matches:
            counts["conflicts"] += 1
            target = device / "media-versions" / entry.sha256[:2] / entry.sha256
            _ensure_inside(device, target)
        if target.exists():
            if target.stat().st_size != entry.size or (
                target != original and digest(target) != entry.sha256
            ):
                raise ValueError("Previously stored media version failed its checksum.")
            counts["skipped"] += 1
        else:
            temporary = stage / ".pull"
            usb.pull(entry, temporary)
            if temporary.stat().st_size != entry.size or digest(temporary) != entry.sha256:
                raise ValueError("Media transfer changed during capture.")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary.rename(target)
            counts["added"] += 1
        media[entry.path] = {
            "path": target.relative_to(device).as_posix(),
            "size": entry.size,
            "sha256": entry.sha256,
            "native_path_unique": original_matches,
        }
    return media, counts


def previous_snapshots(device):
    snapshots = []
    for manifest in sorted((device / "snapshots").glob("*/manifest.json")):
        item = json.loads(manifest.read_text(encoding="utf-8"))
        db = item["databases"][0]
        snapshots.append(
            (item["account_id"], db["sha256"], db.get("sqlite_sha256"), manifest.parent)
        )
    return snapshots


def merge_media_history(history, account, observed_media):
    """Mark exact-path reuse device-wide and collect absent candidates for this account."""
    candidates = {}
    ambiguous = set()
    for owner, _, _, snapshot in history:
        old = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
        for path, record in old["media"].items():
            current = observed_media.get(path)
            if current:
                if (
                    current["sha256"] != record["sha256"]
                    or record.get("native_path_unique") is False
                ):
                    current["native_path_unique"] = False
                continue
            if owner != account or path in ambiguous:
                continue
            previous = candidates.get(path)
            if previous and previous["sha256"] != record["sha256"]:
                del candidates[path]
                ambiguous.add(path)
            else:
                candidates[path] = {**record, "snapshot_id": old["snapshot_id"]}
    return candidates


def check_account(request, database_hash, history):
    account = str(uuid4()) if request == "new" else str(UUID(request))
    for owner, known_hash, _, _ in history:
        if known_hash == database_hash and owner != account:
            raise ValueError(
                f"The same backup is already bound to {owner}. Switch accounts and "
                "wait for a fresh local backup before continuing."
            )
    return account


def read_key(key_file, account, history, prompt):
    if not key_file:
        key_file = next(
            (snap / "key.txt" for owner, _, _, snap in reversed(history) if owner == account), None
        )
    return key_file.read_text(encoding="ascii").strip() if key_file else prompt(account).strip()


def capture_account(
    usb,
    device,
    info,
    stage,
    request,
    history,
    key_file,
    key_prompt,
    contacts,
    contact_rows,
    contacts_at,
    avatar_map,
    expected_files,
    session_id,
    confirm,
):
    from shared.contact_history import capture_avatars

    primary = expected_files[0]
    account = check_account(request, primary.sha256, history)
    key = read_key(key_file, account, history, key_prompt)
    confirm(account)
    captured = utc_now()
    snapshot_id = timestamp_id(captured) + "_" + account
    database_dir = stage / "databases"
    database_dir.mkdir()
    databases = []
    for entry in expected_files:
        name = _relative(entry.path, "Databases")
        if len(name.parts) != 1 or PurePosixPath(entry.path).suffix != ".crypt15":
            raise ValueError("This capture workflow requires native .crypt15 databases.")
        dest = database_dir / name
        usb.pull(entry, dest)
        if dest.stat().st_size != entry.size or digest(dest) != entry.sha256:
            raise ValueError(f"Database transfer changed: {name}")
        record = {"name": name.name, "size": entry.size, "sha256": entry.sha256}
        sqlite_hash = verify_key(dest, key, fingerprint=entry == primary)
        if entry == primary:
            if any(
                old_hash == sqlite_hash and owner != account for owner, _, old_hash, _ in history
            ):
                raise ValueError(
                    "The same SQLite database was re-encrypted for another archive UUID. Check the active account."
                )
            record["sqlite_sha256"] = sqlite_hash
        databases.append(record)
    (stage / "key.txt").write_text(key + "\n", encoding="ascii")
    contact_file = None
    if contacts is not None:
        contact_file = "contacts/wa_contacts.txt"
        (stage / "contacts").mkdir()
        shutil.copyfile(contacts, stage / contact_file)
    avatars = capture_avatars(stage, avatar_map, account)
    media, counts = sync_media(usb, device, stage)
    if usb.databases() != expected_files:
        raise ValueError("The phone's backup changed during capture. Retry this account.")
    retained = merge_media_history(history, account, media)
    manifest = {
        "schema_version": 1,
        "snapshot_id": snapshot_id,
        "session_id": session_id,
        "device_id": info["device_id"],
        "account_id": account,
        "captured_at": captured,
        "primary_database": databases[0]["name"],
        "databases": databases,
        "media": media,
        "retained_media": retained,
        "contacts": contact_file,
        "contacts_sha256": digest(stage / contact_file) if contact_file else None,
        "contact_rows": contact_rows,
        "contacts_at": contacts_at,
        "avatars": avatars,
        "media_counts": counts,
    }
    write_json(stage / "manifest.json", manifest)
    dest = device / "snapshots" / snapshot_id
    stage.rename(dest)
    history.append((account, primary.sha256, databases[0]["sqlite_sha256"], dest))
    return manifest
