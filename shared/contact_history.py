"""Apply one Android snapshot's names and local profile images without scanning media."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from shared.db import build_contact_folder_name
from shared.mac_avatars import JID, capture_avatars, image_extension

__all__ = ["apply_snapshot", "capture_avatars", "meaningful_name"]


def meaningful_name(value: str | None) -> str:
    """Suppress archive-generated placeholders, numeric labels and masked phone hints."""
    value = (value or "").strip()
    if (
        not value
        or value.casefold() in {"unknown", "unknown contact", "null", "none"}
        or re.fullmatch(r"unknown(?: contact)?\s*\([+\d -]+\)", value, re.I)
        or re.fullmatch(r"[\d()\s.+∙•*-]+", value)
    ):
        return ""
    return value


def _inside(directory: Path, rel: str) -> Path:
    if Path(rel).is_absolute():
        raise ValueError("Snapshot path must be relative")
    path = (directory / rel).resolve(strict=True)
    if not path.is_relative_to(directory) or not path.is_file():
        raise ValueError("Invalid path in snapshot")
    return path


def _observation_stamp(timestamp: str) -> str:
    stamp = datetime.fromisoformat(timestamp)
    if stamp.tzinfo is None:
        raise ValueError("Snapshot observation time requires a timezone")
    return stamp.astimezone(UTC).isoformat(timespec="microseconds")


def apply_snapshot(snapshot_dir: Path, archive_dir: Path, *, account_id: str) -> dict:
    """Merge immutable observations ordered by capture time. Commit the entire import atomically."""
    from wab_archiver.android_handler import load_contacts

    snapshot_dir = Path(snapshot_dir).resolve(strict=True)
    manifest = json.loads(_inside(snapshot_dir, "manifest.json").read_text(encoding="utf-8"))
    account = str(UUID(account_id))
    if account != manifest["account_id"]:
        raise ValueError("Snapshot belongs to a different account")
    stamp = _observation_stamp(manifest["captured_at"])
    book_stamp = _observation_stamp(manifest.get("contacts_at") or manifest["captured_at"])
    snap_id = manifest["snapshot_id"]
    contacts = {}
    if manifest.get("contacts"):
        book = _inside(snapshot_dir, manifest["contacts"])
        if (
            manifest.get("contacts_sha256")
            and hashlib.sha256(book.read_bytes()).hexdigest() != manifest["contacts_sha256"]
        ):
            raise ValueError("Snapshot contacts checksum mismatch")
        contacts = load_contacts(str(book), logging.getLogger(__name__))
    arch_db = Path(archive_dir).resolve(strict=True) / ".wa_media_archiver.db"
    uri = arch_db.as_uri() + "?mode=rw"
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS identity_owner (singleton INTEGER PRIMARY KEY CHECK(singleton=1), account TEXT NOT NULL)"
        )
        conn.execute("INSERT OR IGNORE INTO identity_owner VALUES (1, ?)", (account,))
        if (
            conn.execute("SELECT account FROM identity_owner WHERE singleton=1").fetchone()[0]
            != account
        ):
            raise ValueError("Archive belongs to a different account")
        conn.execute("""CREATE TABLE IF NOT EXISTS contact_observations (
            number TEXT NOT NULL, stamp TEXT NOT NULL, snapshot TEXT NOT NULL, name TEXT NOT NULL,
            PRIMARY KEY(number,stamp,snapshot))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS avatar_blobs (
            sha256 TEXT PRIMARY KEY, mime TEXT NOT NULL, data BLOB NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS avatar_observations (
            jid TEXT NOT NULL, stamp TEXT NOT NULL, snapshot TEXT NOT NULL, sha256 TEXT NOT NULL,
            PRIMARY KEY(jid,stamp,snapshot))""")
        # Seed known names from unmanaged archives once, at a date before all observed snapshots.
        existing = conn.execute("SELECT number,display_name FROM contacts").fetchall()
        conn.executemany(
            """INSERT INTO contact_observations SELECT ?, '', '', ?
             WHERE NOT EXISTS (SELECT 1 FROM contact_observations WHERE number=?)""",
            (
                (number, name, number)
                for number, label in existing
                if (name := meaningful_name(label))
            ),
        )
        names = [
            (num, book_stamp, snap_id, name)
            for num, raw in contacts.items()
            if (name := meaningful_name(raw))
        ]
        conn.executemany("INSERT OR IGNORE INTO contact_observations VALUES (?,?,?,?)", names)
        # Replay latest display metadata even after an older archiver run wrote its own index.
        latest = conn.execute("""SELECT number,name FROM (
            SELECT number,name,ROW_NUMBER() OVER(PARTITION BY number ORDER BY stamp DESC,snapshot DESC) AS n
            FROM contact_observations) WHERE n=1""").fetchall()
        conn.executemany(
            """INSERT INTO contacts(number,folder,display_name) VALUES (?,?,?)
               ON CONFLICT(number) DO UPDATE SET display_name=excluded.display_name""",
            ((number, build_contact_folder_name(name, number), name) for number, name in latest),
        )

        assigned = 0
        for entry in manifest.get("avatars", []):
            jid = entry["jid"]
            if jid is None:
                continue  # The snapshot retains this unassigned asset.
            if not isinstance(jid, str) or not JID.fullmatch(jid):
                raise ValueError("Invalid avatar JID")
            data = _inside(snapshot_dir, entry["path"]).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            ext = image_extension(data)
            if not ext or digest != entry["sha256"]:
                raise ValueError("Avatar digest or format mismatch")
            mime = "image/jpeg" if ext == "jpg" else f"image/{ext}"
            conn.execute("INSERT OR IGNORE INTO avatar_blobs VALUES(?,?,?)", (digest, mime, data))
            conn.execute(
                "INSERT OR IGNORE INTO avatar_observations VALUES(?,?,?,?)",
                (jid, stamp, snap_id, digest),
            )
            assigned += 1
    return {"names_observed": len(names), "avatars_observed": assigned}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument(
        "--archive", type=Path, required=True, help="Existing WAB archive (stop its viewer first)"
    )
    parser.add_argument(
        "--account", required=True, help="Confirm the existing archive's account UUID"
    )
    args = parser.parse_args()
    try:
        if (args.archive / ".wab-imports.sqlite").exists():
            raise ValueError("Use wab-import --metadata-only for a managed archive.")
        result = apply_snapshot(args.snapshot, args.archive, account_id=args.account)
    except (ValueError, OSError, sqlite3.Error, KeyError) as exc:
        parser.exit(1, f"Metadata refresh failed: {exc}\n")
    print(
        f"Observed {result['names_observed']} contact numbers and {result['avatars_observed']} profile images"
    )


if __name__ == "__main__":
    main()
