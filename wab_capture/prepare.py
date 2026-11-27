"""Prepare one account's WAB input from an immutable, offline Android capture."""

import argparse
import getpass
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import sqlite3
import sys
import tempfile
import unicodedata
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

from shared.mac_avatars import capture_avatars, image_extension
from wab_archiver.increment_merger import decrypt_increment_archive
from wab_capture.importer import inside, verified
from wab_capture.keys import verify_key
from wab_capture.source import (
    digest,
    merge_media_history,
    previous_snapshots,
    timestamp_id,
    write_json,
)

FULL = re.compile(r"msgstore(?:-([0-9][0-9.-]*))?\.db\.crypt15")
INC = re.compile(r"msgstore-increment-([1-9][0-9]*)(?:-([0-9][0-9.-]*))?\.db\.crypt15")


def read_raw(raw):
    raw = raw.expanduser().resolve(strict=True)
    device = raw.parent.parent
    if raw.parent.name != "snapshots" or device.parent.name != "sources":
        raise ValueError("Select a raw directory under sources/<device>/snapshots")
    manifest = inside(raw, "raw-manifest.json")
    raw_bytes = manifest.read_bytes()
    data = json.loads(raw_bytes)
    info = json.loads(inside(device, "device.json").read_bytes())
    if (
        data.get("kind") != "android-device-raw"
        or data.get("schema_version") != 1
        or data.get("device_id") != info["device_id"]
        or data.get("snapshot_id") != raw.name
        or datetime.fromisoformat(data["captured_at"]).tzinfo is None
    ):
        raise ValueError("Raw manifest identity, timestamp or version is invalid")
    objects = {}
    sources = set()
    for e in data["databases"]:
        native = PurePosixPath(e["database_dir"])
        rel = PurePosixPath(e["relative_path"])
        storage = e["path"]
        root_id = hashlib.sha256(e["database_dir"].encode()).hexdigest()
        exact = (PurePosixPath("databases") / root_id / rel).as_posix()
        overflow = "database-objects/" + e["sha256"]
        identity = (e["size"], e["sha256"])
        if (
            not native.is_absolute()
            or native.as_posix() not in data["database_dirs"]
            or ".." in native.parts
            or rel.as_posix() != e["relative_path"]
            or rel.is_absolute()
            or not rel.parts
            or ".." in rel.parts
            or (native / rel).as_posix() != e["source_path"]
            or storage not in {exact, overflow}
            or (storage in objects and (storage != overflow or objects[storage] != identity))
            or e["source_path"] in sources
            or not re.fullmatch(r"[a-f0-9]{64}", e["sha256"])
            or not isinstance(e["size"], int)
            or e["size"] < 0
        ):
            raise ValueError("Invalid or duplicated database in raw manifest")
        objects[storage] = identity
        sources.add(e["source_path"])
    return raw, data, hashlib.sha256(raw_bytes).hexdigest()


def kind(entry):
    name = PurePosixPath(entry["relative_path"]).name
    if FULL.fullmatch(name):
        return "full"
    if INC.fullmatch(name):
        return "increment"
    if name.endswith(".crypt14"):
        counterpart = name[:-1] + "5"
        if FULL.fullmatch(counterpart):
            return "full/crypt14 (preserved only)"
        if INC.fullmatch(counterpart):
            return "increment/crypt14 (preserved only)"
    return "other"


def selected(entries, arg, category):
    matches = [e for e in entries if arg in (e["path"], e["relative_path"], e["source_path"])]
    if len(matches) != 1 or kind(matches[0]) != category:
        raise ValueError(f"Expected one {category} crypt15 at {arg!r}; use its path from --list")
    return matches[0]


def choose_base(entries, arg, reference):
    base = selected(entries, arg, "full") if arg else None
    if reference:
        expected = (reference.stat().st_size, digest(reference))
        candidates = [
            e for e in entries if kind(e) == "full" and (e["size"], e["sha256"]) == expected
        ]
        if base and base not in candidates:
            raise ValueError("The selected full backup differs from --known-backup")
        if not base and len(candidates) != 1:
            raise ValueError(
                f"Reference matched {len(candidates)} full backups; select one matching --database path"
            )
        base = base or candidates[0]
    if not base:
        raise ValueError("Select --database or provide an exact --known-backup reference")
    return base


def choose_chain(entries, base, increment_args):
    base_path = PurePosixPath(base["source_path"])
    base_tag = FULL.fullmatch(base_path.name)[1]
    ordered = []
    for name in increment_args:
        entry = selected(entries, name, "increment")
        path = PurePosixPath(entry["source_path"])
        index, tag = INC.fullmatch(path.name).groups()
        if path.parent != base_path.parent or tag != base_tag:
            raise ValueError(
                "The increment belongs to a different native directory or generation tag"
            )
        ordered.append((int(index), entry))
    ordered.sort(key=lambda pair: pair[0])
    if [i for i, _ in ordered] != list(range(1, len(ordered) + 1)):
        raise ValueError("Choose a contiguous sequence of increments from 1 without duplicates")
    return [entry for _, entry in ordered]


def account_for(label, aliases, owners):
    if len(owners) > 1:
        raise ValueError("Conflicting confirmed accounts for the same backup")
    existing = next(iter(owners), None)
    if not label:
        if not existing:
            raise ValueError("Identify this previously unseen database with --account LABEL")
        return str(UUID(existing)), None
    try:
        assigned, alias = str(UUID(label)), None
    except ValueError:
        alias = unicodedata.normalize("NFC", label.strip()).casefold()
        if not alias or len(alias) > 100 or any(ord(c) < 32 for c in alias):
            raise ValueError("Invalid account label")
        assigned = aliases.get(alias) or existing or str(uuid4())
    if existing and assigned != existing:
        raise ValueError(f"Confirmed database already belongs to account {existing}")
    return str(UUID(assigned)), alias


def authenticated_increment(path, key, stage):
    verify_key(path, key)
    zip_path = stage / ".increment-check.zip"
    try:
        decrypt_increment_archive(str(path), key, str(zip_path), logging.getLogger(__name__))
        with zipfile.ZipFile(zip_path) as content:
            if "header.json" not in content.namelist():
                raise ValueError("Increment ZIP does not contain header.json")
            if not isinstance(json.loads(content.read("header.json")), dict):
                raise ValueError("Invalid increment header")
            if content.testzip() is not None:
                raise ValueError("Corrupt increment ZIP")
    finally:
        zip_path.unlink(missing_ok=True)


def copy_raw_avatars(raw, raw_data, account, stage):
    result = []
    for row in raw_data.get("avatars", []):
        if row.get("account_id") != account:
            continue
        source = inside(raw, row["path"])
        with source.open("rb") as f:
            ext = image_extension(f.read(12))
        if not ext or digest(source) != row["sha256"]:
            raise ValueError("Raw Mac avatar checksum or format mismatch")
        dest = f"avatars/{row['sha256']}.{ext}"
        (stage / "avatars").mkdir(exist_ok=True)
        shutil.copyfile(source, stage / dest)
        result.append({"jid": row["jid"], "path": dest, "sha256": row["sha256"], "source": "mac"})
    return result


def select_media(raw_data, base):
    directory = PurePosixPath(base["database_dir"])
    roots = [
        PurePosixPath(root) for root in raw_data["media_by_root"] if directory.is_relative_to(root)
    ]
    if not roots:
        return {}
    return raw_data["media_by_root"][max(roots, key=lambda p: len(p.parts)).as_posix()]


def prepare_locked(raw, data, fingerprint, args):
    device, sources = raw.parent.parent, raw.parents[2]
    alias_file = sources / ".account-labels.json"
    aliases = (
        json.loads(inside(sources, alias_file.name).read_bytes()) if alias_file.exists() else {}
    )
    local_history = previous_snapshots(device)
    history = list(local_history)
    for other in sorted(sources.glob("*/device.json")):
        if other.parent != device:
            history.extend(previous_snapshots(other.parent))
    owners_by_hash = {}
    for owner, encrypted, _, _ in history:
        owners_by_hash.setdefault(encrypted, set()).add(owner)

    if args.list:
        for owner, _, _, directory in history:
            previous = json.loads(inside(directory, "manifest.json").read_bytes())
            for increment in previous["databases"][1:]:
                owners_by_hash.setdefault(increment["sha256"], set()).add(owner)
        for entry in data["databases"]:
            owners = owners_by_hash.get(entry["sha256"], set())
            known = sorted(
                set(owners) | {alias for alias, owner in aliases.items() if owner in owners}
            )
            print(
                f"{kind(entry):9} {entry['size']:12d}  {entry['sha256']}  {entry['path']}  "
                f"[{', '.join(known) or 'unassigned'}]  {entry['source_path']}"
            )
        return None
    base = choose_base(data["databases"], args.database, args.known_backup)
    increments = choose_chain(data["databases"], base, args.increment)
    owners = owners_by_hash.get(base["sha256"], set())
    if args.compare_history:
        account, alias = (next(iter(owners)) if len(owners) == 1 else None), None
    else:
        account, alias = account_for(args.account, aliases, owners)
    known_key = None
    if args.key_file:
        key = args.key_file.read_text(encoding="ascii").strip()
    else:
        known_key = next(
            (
                p / "key.txt"
                for owner, _, _, p in sorted(history, key=lambda r: r[3].name, reverse=True)
                if owner == account and (p / "key.txt").is_file()
            ),
            None,
        )
        if known_key:
            key = known_key.read_text(encoding="ascii").strip()
        elif sys.stdin.isatty():
            target = next((name for name, uid in aliases.items() if uid == account), account)
            key = getpass.getpass(
                f"Full backup {base['source_path']} ({base['size']} bytes), "
                f"account {args.account or target or 'unassigned'}. Enter its 64-character crypt15 key: "
            ).strip()
        else:
            raise ValueError("No saved key for this account; supply --key-file PATH")

    key_hint = ". Retry with --key-file /path/to/the-matching-key.txt" if known_key else ""
    if args.compare_history:
        from wab_capture.history_evidence import compare_history

        try:
            encrypted = verified(raw, base["path"], base)
            result = compare_history(encrypted, key, args.compare_history)
        except (ValueError, OSError, sqlite3.Error) as exc:
            raise ValueError(
                f"Cannot compare full {base['source_path']}: {str(exc).rstrip('.')}{key_hint}"
            ) from exc
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return None

    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=device) as tmp:
        stage = Path(tmp) / "snapshot"
        db_dir = stage / "databases"
        db_dir.mkdir(parents=True)
        records = []
        for n, entry in enumerate([base, *increments]):
            name = "msgstore.db.crypt15" if not n else f"msgstore-increment-{n}.db.crypt15"
            # Authenticate under the native filename so diagnostics identify the
            # actual Android input. Normalize names only for the WAB replay step.
            checked = Path(tmp) / PurePosixPath(entry["source_path"]).name
            record = {k: entry[k] for k in ("size", "sha256", "source_path")}
            record.update(name=name, raw_path=entry["path"])
            try:
                shutil.copyfile(inside(raw, entry["path"]), checked)
                if checked.stat().st_size != entry["size"] or digest(checked) != entry["sha256"]:
                    raise ValueError("Raw database checksum mismatch")
                if not n:
                    record["sqlite_sha256"] = verify_key(checked, key, fingerprint=True)
                    sqlite_owners = {
                        o for o, _, sql_hash, _ in history if sql_hash == record["sqlite_sha256"]
                    }
                    if sqlite_owners - {account}:
                        raise ValueError(
                            "The authenticated SQLite database already belongs to another account"
                        )
                else:
                    authenticated_increment(checked, key, stage)
                checked.rename(db_dir / name)
            except (ValueError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
                raise ValueError(
                    f"Could not verify {kind(entry)} {entry['source_path']}: {str(exc).rstrip('.')}{key_hint}"
                ) from exc
            records.append(record)

        if increments:
            selected_hashes = {r["sha256"] for r in increments}
            for owner, encrypted, plain, prior in history:
                if owner == account and (
                    encrypted == base["sha256"] or plain == records[0]["sqlite_sha256"]
                ):
                    continue
                previous = json.loads(inside(prior, "manifest.json").read_bytes())
                for member in previous["databases"][1:]:
                    if member["sha256"] in selected_hashes:
                        raise ValueError(
                            f"Selected increment {member['sha256']} was already bound to a different account or full backup"
                        )

        contact = data["contacts"]
        if contact:
            source = inside(raw, contact)
            contact = "contacts/wa_contacts.txt"
            (stage / "contacts").mkdir()
            shutil.copyfile(source, stage / contact)
            if digest(stage / contact) != data["contacts_sha256"]:
                raise ValueError("Raw contacts checksum mismatch")
        avatars = copy_raw_avatars(raw, data, account, stage)
        avatars += capture_avatars(stage, args.avatar_map, account)
        unique_avatars = {}
        for item in avatars:
            jid, sha = item["jid"], item["sha256"]
            aid = jid or sha
            if aid in unique_avatars and unique_avatars[aid]["sha256"] != sha:
                raise ValueError("Conflicting Mac avatar observations for this contact")
            unique_avatars[aid] = item
        avatars = [unique_avatars[k] for k in sorted(unique_avatars)]
        claim = {
            "snapshot_id": raw.name,
            "manifest_sha256": fingerprint,
            "database_paths": [e["path"] for e in (base, *increments)],
            "source_paths": [e["source_path"] for e in (base, *increments)],
        }
        identity = json.dumps([claim, account, avatars], sort_keys=True).encode()
        sid = f"{timestamp_id(data['captured_at'])}_{account}_{hashlib.sha256(identity).hexdigest()[:16]}"
        dest = device / "snapshots" / sid
        media = select_media(data, base)
        retained = merge_media_history(local_history, account, media)
        manifest = {
            "schema_version": 1,
            "snapshot_id": sid,
            "session_id": data["session_id"],
            "device_id": data["device_id"],
            "account_id": account,
            "captured_at": data["captured_at"],
            "raw": claim,
            "databases": records,
            "primary_database": records[0]["name"],
            "media": media,
            "retained_media": retained,
            "contacts": contact,
            "contacts_sha256": data["contacts_sha256"],
            "contacts_at": data["contacts_at"],
            "contact_rows": data["contact_rows"],
            "avatars": avatars,
            "media_counts": {"observed": len(media)},
        }
        (stage / "key.txt").write_text(key + "\n", encoding="ascii")
        write_json(stage / "manifest.json", manifest)
        if dest.exists():
            old = json.loads(inside(dest, "manifest.json").read_bytes())
            if (
                old.get("raw") != claim
                or old["account_id"] != account
                or old["avatars"] != avatars
                or old["databases"] != records
            ):
                raise ValueError("Existing prepared snapshot has conflicting provenance")
        if alias and alias not in aliases:
            label_update = Path(tmp) / "labels.json"
            write_json(label_update, {**aliases, alias: account})
            os.replace(label_update, alias_file)
        if not dest.exists():
            stage.rename(dest)
        return account, dest


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument(
        "--list", action="store_true", help="Show captured database candidates and confirmed owners"
    )
    parser.add_argument("--account", help="Human account label or an existing WAB account UUID")
    parser.add_argument("--database", help="Selected full crypt15 path as shown in --list")
    parser.add_argument(
        "--known-backup",
        type=Path,
        help="Select or verify the identical encrypted full backup by size and SHA-256",
    )
    parser.add_argument(
        "--increment",
        action="append",
        default=[],
        help="Explicit corresponding crypt15 increment (repeat in sequence)",
    )
    parser.add_argument(
        "--compare-history",
        type=Path,
        metavar="PREVIOUS_SQLITE",
        help="Compare outgoing chat history locally without preparing or assigning a snapshot",
    )
    parser.add_argument("--avatar-map", type=Path)
    parser.add_argument(
        "--key-file", type=Path, help="Text file containing the 64 hexadecimal crypt15 key digits"
    )
    args = parser.parse_args(argv)
    if args.list and any(
        [
            args.account,
            args.database,
            args.known_backup,
            args.increment,
            args.avatar_map,
            args.key_file,
            args.compare_history,
        ]
    ):
        parser.error("Use --list by itself, then select a backup to prepare")
    if args.compare_history and (args.account or args.increment or args.avatar_map):
        parser.error(
            "--compare-history cannot be combined with --account, --increment or --avatar-map"
        )
    try:
        if sys.platform not in ("linux", "darwin"):
            raise ValueError("Managed Android preparation requires macOS or Linux")
        import fcntl

        raw, data, fingerprint = read_raw(args.raw)
        if args.list or args.compare_history:
            prepare_locked(raw, data, fingerprint, args)
            return
        with (raw.parents[2] / ".capture.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            output = prepare_locked(raw, data, fingerprint, args)
        if output:
            account, path = output
            print(
                f"Account: {account}\nPrepared snapshot: {path}\nwab-import {shlex.quote(str(path))}"
            )
    except (OSError, ValueError, KeyError, sqlite3.Error, zipfile.BadZipFile) as error:
        parser.exit(
            1, f"Preparation failed: {str(error).rstrip('.')}. The raw capture remains saved.\n"
        )


if __name__ == "__main__":
    main()
