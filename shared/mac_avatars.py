"""Build an account-scoped local avatar map from a copy of WhatsApp Mac profile media."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from contextlib import closing
from pathlib import Path
from urllib.parse import unquote
from uuid import UUID

JID = re.compile(r"(?:[0-9]+@(?:s\.whatsapp\.net|lid)|[0-9]+(?:-[0-9]+)?@g\.us)\Z")
FILENAME_JID = re.compile(
    r"^([0-9]+(?:-[0-9]+)?@(?:s\.whatsapp\.net|lid|g\.us))(?:[-_]\d+)?(?:\.(?:jpg|jpeg|png|webp|thumb))*$",
    re.I,
)


def image_extension(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return ""


def _read_lid_owners(path: Path | None) -> dict[str, set[str]]:
    """Resolve Mac-local LIDs only through explicit co-occurrence in the Mac address book."""
    owners = defaultdict(set)
    if path:
        uri = path.resolve(strict=True).as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            cols = {r[1].upper() for r in db.execute("PRAGMA table_info(ZWAADDRESSBOOKCONTACT)")}
            if {"ZLID", "ZWHATSAPPID"} <= cols:
                for lid, phone in db.execute("SELECT ZLID, ZWHATSAPPID FROM ZWAADDRESSBOOKCONTACT"):
                    if isinstance(lid, str) and re.fullmatch(r"[0-9]+@lid", lid):
                        if isinstance(phone, str) and re.fullmatch(
                            r"[0-9]+@s\.whatsapp\.net", phone
                        ):
                            owners[lid].add(phone)
    return owners


def _container_inputs(container: Path) -> tuple[Path, Path | None, Path | None]:
    root = container.expanduser().resolve(strict=True)
    dirs = [d for d in (root / "Media/Profile", root / "Message/Media/Profile") if d.is_dir()]
    if len(dirs) != 1:
        raise ValueError("Expected exactly one Mac profile directory; use --profile-dir.")
    chat = root / "ChatStorage.sqlite"
    contacts = root / "ContactsV2.sqlite"
    return dirs[0], chat if chat.is_file() else None, contacts if contacts.is_file() else None


def build_map(
    directory: Path,
    account_id: str,
    database: Path | None = None,
    contacts_database: Path | None = None,
) -> dict:
    """Only assign unambiguous profile images using explicit file or database JIDs."""
    account_id = str(UUID(account_id))
    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("Expected a Mac profile image directory")
    files = {}
    digests = {}
    assignments = defaultdict(set)
    by_name = defaultdict(list)
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            if not image_extension(stream.read(12)):
                continue
            stream.seek(0)
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        rel = path.relative_to(directory).as_posix()
        digests[rel] = digest
        files[rel] = None
        by_name[path.name].append(rel)
        match = FILENAME_JID.fullmatch(unquote(path.name))
        if match:
            assignments[rel].add(match[1].lower())

    if database:
        uri = database.resolve(strict=True).as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            columns = {r[1].upper() for r in db.execute("PRAGMA table_info(ZWAPROFILEPICTUREITEM)")}
            if {"ZJID", "ZPATH"} <= columns:
                for jid, raw in db.execute("SELECT ZJID, ZPATH FROM ZWAPROFILEPICTUREITEM"):
                    if (
                        not isinstance(raw, str)
                        or not isinstance(jid, str)
                        or not JID.fullmatch(jid)
                    ):
                        continue
                    rel = unquote(raw).rsplit("Media/Profile/", 1)[-1].removeprefix("./")
                    matches = by_name.get(Path(rel).name, [])
                    if rel in files:
                        matches = [rel]
                    elif "/" in rel:
                        matches = []
                    if len(matches) == 1:
                        assignments[matches[0]].add(jid)

    # A numeric @lid in the Mac cache is not proof of the same Android identity.
    # Keep unresolved and conflicting observations, but never label them as a phone.
    lid_owners = _read_lid_owners(contacts_database)
    for rel, candidates in assignments.items():
        assignments[rel] = {
            owner
            for candidate in candidates
            for owner in (
                lid_owners.get(candidate, {candidate})
                if candidate.endswith("@lid")
                else {candidate}
            )
        }
    owner_counts = defaultdict(set)
    for rel, candidates in assignments.items():
        for jid in candidates:
            owner_counts[jid].add(rel)
    for rel, candidates in assignments.items():
        if len(candidates) == 1:
            jid = next(iter(candidates))
            if not jid.endswith("@lid") and len(owner_counts[jid]) == 1:
                files[rel] = jid
    return {
        "root": str(directory),
        "entries": [
            {"account_id": account_id, "jid": jid, "file": rel, "sha256": digests[rel]}
            for rel, jid in files.items()
        ],
    }


def capture_avatars(snapshot_dir: Path, map_path: Path | None, account_id: str) -> list[dict]:
    """Copy account-matched avatar evidence into a snapshot under a digest-derived path."""
    if not map_path:
        return []
    map_path = Path(map_path).resolve(strict=True)
    spec = json.loads(map_path.read_text(encoding="utf-8"))
    root = map_path.parent
    if isinstance(spec, dict):
        root = (root / spec["root"]).resolve(strict=True)
        spec = spec["entries"]
    if not isinstance(spec, list):
        raise ValueError("Avatar map must contain an entries list")
    entries = []
    assigned = {}
    for row in spec:
        if row["account_id"] != account_id:
            continue
        jid = row["jid"]
        if jid is not None and (not isinstance(jid, str) or not JID.fullmatch(jid)):
            raise ValueError("Invalid WhatsApp JID in avatar map")
        path = (root / row["file"]).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError("Avatar path outside map root")
        data = path.read_bytes()
        ext = image_extension(data)
        if not ext:
            raise ValueError("Unsupported avatar format (expected JPEG, PNG, or WebP)")
        digest = hashlib.sha256(data).hexdigest()
        if row.get("sha256", digest) != digest:
            raise ValueError("Avatar bytes changed since the Mac map was generated")
        if jid and assigned.setdefault(jid, digest) != digest:
            raise ValueError("Conflicting avatar assignment for the same account and JID")
        rel = f"avatars/{digest}.{ext}"
        destination = snapshot_dir / rel
        destination.parent.mkdir(exist_ok=True)
        if not destination.exists():
            destination.write_bytes(data)
        entries.append({"jid": jid, "path": rel, "sha256": digest, "source": "mac"})
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    locations = parser.add_mutually_exclusive_group()
    locations.add_argument(
        "--profile-dir", type=Path, help="An extracted Mac profile-image directory"
    )
    locations.add_argument(
        "--container", type=Path, help="An extracted or local Mac WhatsApp group container"
    )
    parser.add_argument(
        "--contacts-database", type=Path, help="Mac ContactsV2.sqlite for explicit LID mappings"
    )
    parser.add_argument(
        "--account", required=True, help="Archive UUID of the account linked to this Mac"
    )
    parser.add_argument("--database", type=Path, help="Mac ChatStorage.sqlite (read-only)")
    parser.add_argument("--out", type=Path, required=True, help="New private JSON map")
    args = parser.parse_args()
    directory, db, contacts = args.profile_dir, args.database, args.contacts_database
    try:
        if directory is None:
            container = (
                args.container
                or Path.home() / "Library/Group Containers/group.net.whatsapp.WhatsApp.shared"
            )
            directory, auto_db, auto_contacts = _container_inputs(container)
            db, contacts = db or auto_db, contacts or auto_contacts
        result = build_map(directory, args.account, db, contacts)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"{exc}\n")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    entries = result["entries"]
    print(f"{len(entries)} images, {sum(e['jid'] is not None for e in entries)} assigned")


if __name__ == "__main__":
    main()
