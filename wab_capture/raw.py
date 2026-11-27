"""Preserve every file exposed in Android WhatsApp database trees before interpretation."""

import hashlib
import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from threading import Event, Thread
from time import monotonic

from shared.mac_avatars import capture_avatar, read_avatar_map

from .adb import RemoteFile, active_databases
from .source import (
    MediaPaths,
    _ensure_inside,
    _relative,
    digest,
    sync_media,
    timestamp_id,
    utc_now,
    write_json,
)


def _parent(directory):
    return str(PurePosixPath(directory).parent)


def _db_inventory(usb, directories):
    return {d: usb.at_root(_parent(d)).all_databases() for d in directories}


def _copy_databases(usb, stage, inventory):
    output = []
    for directory, files in inventory.items():
        view = usb.at_root(_parent(directory))
        group_id = hashlib.sha256(directory.encode()).hexdigest()
        root = stage / "databases" / group_id
        root.mkdir(parents=True)
        layout = MediaPaths(root)
        for item in sorted(files, key=lambda f: f.path):
            native = _relative(item.path, "Databases")
            dest = (
                root / native
                if layout.reserve(native)
                else stage / "database-objects" / item.sha256
            )
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                view.pull(item, dest)
            if dest.stat().st_size != item.size or digest(dest) != item.sha256:
                raise ValueError(f"Database changed on transfer: {item.path}")
            output.append(
                {
                    "database_dir": directory,
                    "source_path": (PurePosixPath(directory) / native.as_posix()).as_posix(),
                    "relative_path": native.as_posix(),
                    "path": dest.relative_to(stage).as_posix(),
                    "size": item.size,
                    "sha256": item.sha256,
                }
            )
    return output


def _annotate_paths(device, media_by_root):
    """A path reused for different content cannot identify a hashless message."""
    current = {}
    for media in media_by_root.values():
        for native, record in media.items():
            current.setdefault(native, []).append(record)
    if not current:
        return
    seen = {native: entries[0]["sha256"] for native, entries in current.items()}
    for entries in current.values():
        if any(
            not row["native_path_unique"] or row["sha256"] != entries[0]["sha256"]
            for row in entries
        ):
            for row in entries:
                row["native_path_unique"] = False
    for name in ("raw-manifest.json", "manifest.json"):
        for file in (device / "snapshots").glob("*/" + name):
            old = json.loads(file.read_text(encoding="utf-8"))
            groups = (
                old["media_by_root"].values() if name == "raw-manifest.json" else (old["media"],)
            )
            for group in groups:
                for native, entry in group.items():
                    if native in current and (
                        entry["sha256"] != seen[native] or entry.get("native_path_unique") is False
                    ):
                        for row in current[native]:
                            row["native_path_unique"] = False


def _avatars(stage, maps, log):
    observations = {}
    assignments = {}
    for path in maps or ():
        try:
            root, rows = read_avatar_map(path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log(f"Avatar map unavailable ({type(exc).__name__}): {path}")
            continue
        for index, row in enumerate(rows, 1):
            try:
                account = row["account_id"]
                if not isinstance(account, str) or not account:
                    raise ValueError("Missing account in avatar map")
                entry = capture_avatar(stage, root, row)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                log(f"Avatar skipped in {path}, row {index}: {exc}")
                continue
            jid, sha = entry["jid"], entry["sha256"]
            if jid:
                assignments.setdefault((account, jid), set()).add(sha)
            observations[account, jid, sha] = {**entry, "account_id": account}
    conflicts = {identity for identity, digests in assignments.items() if len(digests) > 1}
    if conflicts:
        log(
            f"Conflicting assignments for {len(conflicts)} avatar identities; images saved unassigned."
        )
    for (account, jid, _), entry in observations.items():
        if (account, jid) in conflicts:
            entry["jid"] = None
    return list(observations.values())


def capture_raw(usb, device, info, session, maps, log, *, verify_media=False):
    done = Event()
    started = monotonic()
    status = "Connecting to phone"

    def report(message):
        nonlocal status
        status = message
        log(message)

    def heartbeat():
        while not done.wait(15):
            log(f"Elapsed {int(monotonic() - started)}s | {status}")

    thread = Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        return _capture_raw(usb, device, info, session, maps, report, verify_media)
    finally:
        done.set()
        thread.join()


def _capture_raw(usb, device, info, session, maps, log, verify_media):
    captured = utc_now()
    snapshot_id = timestamp_id(captured) + "_device"
    dest = device / "snapshots" / snapshot_id
    log("Locating WhatsApp database and media directories on the phone…")
    database_dirs, media_dirs = usb.discover_dirs()
    if not database_dirs and not media_dirs:
        raise ValueError(
            "No WhatsApp Databases or Media directory found in the selected storage roots."
        )
    with tempfile.TemporaryDirectory(prefix=".raw-", dir=device) as temp:
        stage = Path(temp) / "snapshot"
        stage.mkdir()
        log(f"Copying databases from {len(database_dirs)} directories…")
        before = _db_inventory(usb, database_dirs)
        datasets = _copy_databases(usb, stage, before)
        media = {}
        counts = {}
        log(f"Copied {len(datasets)} database files. Media directories: {len(media_dirs)}.")
        inventories = {}
        prior = {}
        if not verify_media:
            needed = {_parent(d) for d in media_dirs}
            for old in sorted((device / "snapshots").glob("*/raw-manifest.json"), reverse=True):
                if not needed:
                    break
                for parent, items in json.loads(old.read_bytes())["media_by_root"].items():
                    if parent in needed:
                        prior[parent] = items
                        needed.remove(parent)
        for directory in media_dirs:
            root = _parent(directory)
            view = usb.at_root(root)
            if verify_media:
                log(f"Reading media checksums on phone: {directory}")
                entries = view.media()
            else:
                log(f"Listing file sizes and timestamps: {directory}")
                entries = view.media_stats()
            inventories[root] = entries
            media[root], counts[root] = sync_media(
                view, device, stage, entries=entries, previous=prior.get(root), log=log
            )
        _annotate_paths(device, media)
        contacts_at = utc_now()
        contacts = "contacts/wa_contacts.txt"
        (stage / "contacts").mkdir()
        try:
            rows = usb.contacts(stage / contacts)
        except (OSError, RuntimeError, ValueError) as exc:
            log(f"Contacts unavailable: {exc}")
            (stage / contacts).unlink(missing_ok=True)
            contacts, rows = None, 0
        avatars = _avatars(stage, maps, log)
        if (database_dirs, media_dirs) != usb.discover_dirs() or before != _db_inventory(
            usb, database_dirs
        ):
            raise ValueError("Android database inventory changed during capture. Retry.")
        for directory in media_dirs:
            root = _parent(directory)
            view = usb.at_root(root)
            log(
                f"Checking {'checksums' if verify_media else 'file sizes and timestamps'} before saving: {directory}"
            )
            after = view.media() if verify_media else view.media_stats()
            if after != inventories[root]:
                raise ValueError("Android media inventory changed during capture. Retry.")
        manifest = {
            "kind": "android-device-raw",
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "session_id": session,
            "device_id": info["device_id"],
            "captured_at": captured,
            "database_dirs": database_dirs,
            "databases": datasets,
            "media_by_root": media,
            "media_counts_by_root": counts,
            "contacts": contacts,
            "contacts_sha256": digest(stage / contacts) if contacts else None,
            "contact_rows": rows,
            "contacts_at": contacts_at,
            "avatars": avatars,
        }
        write_json(stage / "raw-manifest.json", manifest)
        stage.rename(dest)
        log(f"Raw capture already saved at {dest}")
        log(f"List recovered database candidates: wab-prepare {shlex.quote(str(dest))} --list")
        log(
            f"RAW COMPLETE: {len(datasets)} file(s) in {len(database_dirs)} database directories, "
            f"{sum(map(len, media.values()))} media, {rows} contact rows, {len(avatars)} avatar observations."
        )
        for parent, summary in counts.items():
            log(
                f"Media {parent!r}: added={summary['added']} skipped={summary['skipped']} conflicts={summary['conflicts']}"
            )
        totals = {
            k: sum(row[k] for row in counts.values()) for k in ("added", "skipped", "conflicts")
        }
        log(
            f"Shared media total: added={totals['added']} skipped={totals['skipped']} conflicts={totals['conflicts']}"
        )
        from .prepare import kind

        for row in datasets:
            if kind(row) == "full":
                command = shlex.join(["wab-prepare", str(dest), "--database", row["source_path"]])
                log(
                    f"Open account setup for {row['relative_path']!r} ({row['size']} bytes): {command}"
                )
        if not datasets:
            log("No database files were visible in this capture.")
        if contacts:
            latest = device / "contacts"
            try:
                _ensure_inside(device, latest)
                latest.mkdir(exist_ok=True)
                target = latest / "wa_contacts.txt"
                _ensure_inside(device, target)
                tmp = Path(temp) / "contacts.txt"
                shutil.copyfile(dest / contacts, tmp)
                os.replace(tmp, target)
            except (OSError, ValueError) as exc:
                log(f"Latest contact cache unavailable. Snapshot contacts are saved: {exc}")
    return dest, manifest


class CapturedAccountView:
    """Read one unambiguous active backup for compatibility, entirely from the raw snapshot."""

    def __init__(self, snapshot, manifest):
        self.files = {}
        self.series = []
        for directory in manifest["database_dirs"]:
            rows = [row for row in manifest["databases"] if row["database_dir"] == directory]
            records = {
                RemoteFile("Databases/" + r["relative_path"], r["size"], r["sha256"]): snapshot
                / r["path"]
                for r in rows
            }
            if any(
                r.path in {"Databases/msgstore.db.crypt15", "Databases/msgstore.db.crypt14"}
                for r in records
            ):
                chain = active_databases(records)
                self.series.append((directory, chain, rows))
                self.files.update(records)
        if len(self.series) != 1:
            raise ValueError(
                "Multiple or no active database sets. Select the correct raw file with wab-prepare."
            )
        directory, self.chain, rows = self.series[0]
        roots = [r for r in manifest["media_by_root"] if PurePosixPath(directory).is_relative_to(r)]
        nearest = max(roots, key=lambda r: len(PurePosixPath(r).parts)) if roots else None
        indexed = {"Databases/" + row["relative_path"]: row for row in rows}
        selected = [indexed[item.path] for item in self.chain]
        self.observation = {
            "captured_at": manifest["captured_at"],
            "media": manifest["media_by_root"].get(nearest, {}),
            "media_counts": manifest["media_counts_by_root"].get(
                nearest, {"added": 0, "skipped": 0, "conflicts": 0}
            ),
            "raw": {
                "snapshot_id": snapshot.name,
                "manifest_sha256": digest(snapshot / "raw-manifest.json"),
                "database_paths": [row["path"] for row in selected],
                "source_paths": [row["source_path"] for row in selected],
            },
        }

    def databases(self):
        return self.chain

    def pull(self, row, dest):
        shutil.copyfile(self.files[row], dest)
