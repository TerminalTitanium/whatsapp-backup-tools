"""Import a committed Android snapshot into its account's local WAB archive."""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from datetime import datetime
from pathlib import Path
from uuid import UUID

from .publish import publish, stage_previous
from .source import digest

LEDGER = ".wab-imports.sqlite"
DATABASE = Path("Whatsapp Databases/msgstore.db")


def inside(root, name):
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"Invalid relative path: {name!r}")
    result = (root / relative).resolve(strict=True)
    if not result.is_relative_to(root.resolve()) or not result.is_file():
        raise ValueError(f"File outside source: {name!r}")
    return result


def verified(root, name, entry):
    path = inside(root, name)
    if path.stat().st_size != entry["size"] or digest(path) != entry["sha256"]:
        raise ValueError(f"Snapshot checksum mismatch: {name!r}")
    return path


def media_view(mapping, device, view):
    """Verify all captured objects. Reserve the temporary tree for recovered files.

    Android path spellings are exact manifest keys. Exposing them as native
    symlinks would collapse case and Unicode variants on common macOS volumes.
    """
    (view / "Media" / "WhatsApp Images").mkdir(parents=True)
    for name, item in mapping.items():
        parts = name.split("/")
        if len(parts) < 2 or parts[0] != "Media" or any(p in {"", ".", ".."} for p in parts):
            raise ValueError(f"Invalid snapshot media name: {name!r}")
        if Path(item["path"]).parts[:1] not in {("media",), ("media-versions",)}:
            raise ValueError("Snapshot media must reside in a device media store.")
        verified(device, item["path"], item)


def snapshot_material(snap, manifest):
    expected = {}
    for item in manifest["databases"]:
        name = item["name"]
        if name != Path(name).name or name in expected:
            raise ValueError("Invalid or repeated database filename.")
        expected[name] = verified(snap / "databases", name, item)
    if set((snap / "databases").iterdir()) != set(expected.values()):
        raise ValueError("Snapshot database inventory differs from manifest.")
    return expected[manifest["primary_database"]]


def receipt(archive, snapshot_id):
    if not (archive / LEDGER).is_file():
        return None, None
    with closing(sqlite3.connect((archive / LEDGER).as_uri() + "?mode=ro", uri=True)) as conn:
        found = conn.execute(
            "SELECT manifest_hash FROM imports WHERE snapshot=?", (snapshot_id,)
        ).fetchone()
        latest = conn.execute(
            "SELECT snapshot, observed, account FROM imports ORDER BY observed DESC, rowid DESC LIMIT 1"
        ).fetchone()
    return found[0] if found else None, latest


def record(archive, data, fingerprint):
    with closing(sqlite3.connect(archive / LEDGER)) as conn, conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS imports(snapshot TEXT PRIMARY KEY, device TEXT, account TEXT, observed REAL, manifest_hash TEXT)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages(snapshot TEXT, row_id INTEGER, chat_row_id INTEGER, stanza TEXT, from_me INTEGER, PRIMARY KEY(snapshot,row_id)) WITHOUT ROWID"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS media_observations(snapshot TEXT, message_id INTEGER, original_path TEXT, source_sha256 TEXT)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS media_snapshot ON media_observations(snapshot,message_id)"
        )
        sid = data["snapshot_id"]
        conn.execute(
            "INSERT INTO imports VALUES(?,?,?,?,?)",
            (
                sid,
                data["device_id"],
                data["account_id"],
                datetime.fromisoformat(data["captured_at"]).timestamp(),
                fingerprint,
            ),
        )
        conn.execute("ATTACH DATABASE ? AS native", (str(archive / DATABASE),))
        conn.execute(
            "INSERT INTO messages SELECT ?,_id,chat_row_id,key_id,from_me FROM native.message",
            (sid,),
        )

        _record_media(conn, sid)


def _record_media(conn, snapshot_id):
    # Keep native source paths even when WAB uses a version-specific path to show the attachment.
    conn.execute("DELETE FROM media_observations WHERE snapshot=?", (snapshot_id,))
    conn.execute(
        "INSERT INTO media_observations SELECT ?,message_id,original_path,sha256 "
        "FROM native.wab_media_bindings",
        (snapshot_id,),
    )


def repair_inputs(repair, data, archive):
    plan = json.loads(inside(repair, "reconciliation.json").read_text())
    if plan["schema_version"] != 1 or any(
        plan[k] != data[k] for k in ("account_id", "snapshot_id")
    ):
        raise ValueError("Repair belongs to a different snapshot or account.")
    source = archive / DATABASE
    if digest(source) != plan["source_db_sha256"]:
        raise ValueError("Repair plan requires the same source database as its audit.")
    for name, item in plan["files"].items():
        if not name.startswith("Media/"):
            raise ValueError("Invalid supplemental media location.")
        verified(repair / "supplement", name, item)
    if plan.get("derived_db_sha256"):
        source = inside(repair, "msgstore.db")
        if digest(source) != plan["derived_db_sha256"]:
            raise ValueError("Derived database checksum mismatch.")
    return source, plan


def archive_run(database, key, contacts, work, view, settings, manifest):
    settings.touch()
    cmd = [
        sys.executable,
        "-m",
        "wab_archiver",
        "archive",
        "--config",
        str(settings),
        "--output",
        str(work),
        "--msgstore",
        str(database),
        "--preserve-deleted",
        "--stable-paths",
        "--snapshot-manifest",
        str(manifest),
        "--wa-root",
        str(view),
    ]
    if key:
        cmd += ["--e2e-key", str(key)]
    if contacts:
        cmd += ["--contacts", str(contacts)]
    # Keep managed imports independent from interactive WAB config files.
    subprocess.run(cmd, check=True)


def import_locked(snap, data, archive, *, adopt=None, metadata_only=False, repair=None):
    from shared.contact_history import apply_snapshot

    fingerprint = digest(snap / "manifest.json")
    sid = data["snapshot_id"]
    account = data["account_id"]
    seen, latest = receipt(archive, sid)
    if seen and seen != fingerprint:
        raise ValueError("Previously imported snapshot manifest has changed.")
    if latest and latest[2] != account:
        raise ValueError("Target archive belongs to a different account.")
    if archive.is_symlink() or (archive.exists() and not latest):
        raise ValueError("Unmanaged target directory. Use --adopt with a separate source archive.")
    if adopt and (latest or metadata_only or repair):
        raise ValueError("Adoption is available only on the first full import.")
    if metadata_only:
        if not latest:
            raise ValueError("Import the account's first snapshot before applying metadata.")
        apply_snapshot(snap, archive, account_id=account)
        return "Updated metadata"
    if seen and not repair:
        apply_snapshot(snap, archive, account_id=account)
        return "Already imported"
    if repair and (not seen or latest[0] != sid):
        raise ValueError("Repair requires the currently imported snapshot.")
    if latest and datetime.fromisoformat(data["captured_at"]).timestamp() < latest[1]:
        raise ValueError(
            "Import full snapshots in capture order; use --metadata-only for older metadata."
        )
    prior = archive if latest else adopt
    if prior and (
        not (prior / DATABASE).is_file() or not (prior / ".wa_media_archiver.db").is_file()
    ):
        raise ValueError("Expected an existing Android WAB archive.")
    if adopt and (archive.parent.is_relative_to(adopt) or (adopt / LEDGER).exists()):
        raise ValueError("Choose an independent unmanaged archive for adoption.")
    database = snapshot_material(snap, data)
    key = inside(snap, "key.txt") if database.suffix == ".crypt15" else None
    contacts = inside(snap, data["contacts"]) if data["contacts"] else None
    device = snap.parent.parent
    repair_hash = digest(inside(repair, "reconciliation.json")) if repair else None
    if (
        repair
        and (archive / ".wab-last-repair").is_file()
        and (archive / ".wab-last-repair").read_text() == repair_hash
    ):
        return "Repair already imported"
    with tempfile.TemporaryDirectory(prefix=".import-", dir=archive.parent) as temporary:
        tmp = Path(temporary)
        work = tmp / "archive"
        work.mkdir(mode=0o700)
        if prior:
            stage_previous(prior, work, managed=bool(latest))
        if adopt:
            apply_snapshot(snap, work, account_id=account)
        view = tmp / "input"
        media_view(data["media"], device, view)
        if repair:
            database, plan = repair_inputs(repair, data, archive)
            key = None
            from .recovered import remember_repair

            remember_repair(work, repair, plan, database)
        from .recovered import materialize_recovered

        materialize_recovered(work, view)
        for report in (
            "missing_media_report.csv",
            "duplicate_media_report.csv",
            "source_conflicts_report.csv",
        ):
            (work / report).unlink(missing_ok=True)
        archive_run(
            database, key, contacts, work, view, tmp / "config.toml", snap / "manifest.json"
        )
        apply_snapshot(snap, work, account_id=account)
        if not seen:
            record(work, data, fingerprint)
        if repair:
            with closing(sqlite3.connect(work / LEDGER)) as conn, conn:
                conn.execute("ATTACH DATABASE ? AS native", (str(work / DATABASE),))
                _record_media(conn, sid)
            (work / ".wab-last-repair").write_text(repair_hash)
        publish(work, archive)
    return "Imported"


def import_snapshot(snapshot, *, adopt=None, metadata_only=False, repair=None):
    if sys.platform not in ("linux", "darwin"):
        raise ValueError("Managed Android imports require macOS or Linux.")
    import fcntl

    snap = Path(snapshot).resolve(strict=True)
    if snap.parent.name != "snapshots" or snap.parent.parent.parent.name != "sources":
        raise ValueError("Select a snapshot under sources/<device>/snapshots/.")
    data = json.loads(inside(snap, "manifest.json").read_text(encoding="utf-8"))
    if data["schema_version"] != 1 or snap.name != data["snapshot_id"]:
        raise ValueError("Incomplete or unsupported snapshot.")
    device = json.loads((snap.parent.parent / "device.json").read_text())
    if device["device_id"] != data["device_id"]:
        raise ValueError("Snapshot is under the wrong device directory.")
    account = str(UUID(data["account_id"]))
    if account != data["account_id"] or datetime.fromisoformat(data["captured_at"]).tzinfo is None:
        raise ValueError("Invalid account or capture time.")
    archives = snap.parents[3] / "wab"
    archives.mkdir(mode=0o700, exist_ok=True)
    archive = archives / account
    with (archives / f".{account}.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = import_locked(
            snap,
            data,
            archive,
            adopt=Path(adopt).resolve() if adopt else None,
            metadata_only=metadata_only,
            repair=Path(repair).resolve() if repair else None,
        )
    return result, archive


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--adopt",
        type=Path,
        help="Seed a new archive from a closed, operator-confirmed legacy Android archive of this account (copied once).",
    )
    mode.add_argument(
        "--metadata-only",
        action="store_true",
        help="Apply names and avatar history without traversing the media library.",
    )
    mode.add_argument(
        "--repair",
        type=Path,
        help="Apply a verified Mac reconciliation bundle to this account's current snapshot.",
    )
    args = parser.parse_args()
    try:
        result, path = import_snapshot(**vars(args))
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Import stopped: {exc}\n")
    print(f"{result}: {path}")


if __name__ == "__main__":
    main()
