"""Match missing Android attachments to local Mac bytes by their plaintext SHA-256."""

import argparse
import base64
import csv
import hashlib
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import stat
import unicodedata
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class Attachment:
    table: str
    pk: int
    message: int
    path: str
    sha: str
    mime: str


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stored_hash(value):
    """Android schemas use base64 text, hex text or binary digest bytes."""
    if isinstance(value, bytes):
        if len(value) == 32:
            return value.hex()
        value = value.decode("ascii", errors="replace")
    if not isinstance(value, str):
        return ""
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()
    try:
        digest = base64.b64decode(value, validate=True)
    except ValueError:
        return ""
    return digest.hex() if len(digest) == 32 else ""


def attachments(db):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    # Fixed table names. Old schemas may omit the unencrypted content hash or MIME type.
    specs = [("message_media", "m.message_row_id", "")]
    if {"message_media_map", "extended_media_data"} <= tables:
        specs.append(
            (
                "extended_media_data",
                "link.message_row_id",
                "JOIN message_media_map link ON link.media_row_id=m.row_id",
            )
        )
    for table, mid, join in specs:
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        digest = "m.file_hash" if "file_hash" in cols else "NULL"
        mime = "m.mime_type" if "mime_type" in cols else "NULL"
        rows = db.execute(
            f"SELECT m.rowid, {mid}, m.file_path, {digest}, {mime} "
            f"FROM {table} m {join} ORDER BY m.rowid, {mid}"
        )
        for pk, message, path, value, mime_type in rows:
            if message is not None:
                yield Attachment(
                    table, pk, message, path or "", stored_hash(value), mime_type or ""
                )


def read_missing(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not {"message_id", "file_path"} <= set(reader.fieldnames or []):
            raise ValueError("Expected WAB missing_media_report.csv with message_id and file_path")
        return {(int(r["message_id"]), r["file_path"]) for r in reader}


def safe_relative(path):
    parts = path.split("/")
    return (
        len(parts) > 1
        and parts[0] == "Media"
        and "\\" not in path
        and "\x00" not in path
        and all(part not in ("", ".", "..") for part in parts)
    )


def canonical_path(path):
    # Default Mac volumes compare Unicode normalizations and case insensitively.
    return unicodedata.normalize("NFC", path).casefold()


def previous_files(path, valid_hashes, roots):
    if path is None:
        return
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if not {"archive_input_path", "sha256"} <= set(reader.fieldnames or []):
            raise ValueError("Previous map needs sha256 and archive_input_path columns")
        for row in reader:
            if stored_hash(row["sha256"]) not in valid_hashes or not row["archive_input_path"]:
                continue
            candidate = (path.parent / row["archive_input_path"]).resolve()
            if any(candidate.is_relative_to(root) for root in roots) and candidate.is_file():
                yield candidate


def raise_walk_error(error):
    raise error


def mac_files(roots):
    for root in roots:
        for parent, dirs, files in os.walk(root, onerror=raise_walk_error):
            dirs.sort()
            for name in sorted(files):
                candidate = Path(parent) / name
                if stat.S_ISREG(candidate.lstat().st_mode):
                    yield candidate


def match_files(wanted, roots, previous):
    found = {}
    if wanted:
        for source in (previous_files(previous, wanted, roots), mac_files(roots)):
            for path in source:
                digest = sha256(path)
                if digest in wanted:
                    found.setdefault(digest, path)
                if len(found) == len(wanted):
                    return found
    return found


def target_path(item):
    if item.path:
        return item.path
    ext = mimetypes.guess_extension(item.mime.split(";")[0]) or ".bin"
    return f"Media/WhatsApp Recovered/{item.sha}{ext}"


def check_standalone(db):
    if not db.is_file():
        raise ValueError(f"Database is missing: {db}")
    # Hash receipts must cover every committed page. A cold snapshot or cleanly
    # closed database is required; never checkpoint or modify the user's source.
    for suffix in ("-wal", "-journal"):
        sidecar = Path(f"{db}{suffix}")
        if sidecar.is_file() and sidecar.stat().st_size:
            raise ValueError("Database has a live journal. Close WAB and use a standalone copy.")


def run(args):
    db_path = args.db.resolve()
    check_standalone(db_path)
    fingerprint = sha256(db_path)
    roots = sorted({path.resolve(strict=True) for path in args.mac_media})
    if not all(root.is_dir() for root in roots):
        raise ValueError("Each --mac-media must be a directory")
    missing = read_missing(args.missing) if args.missing is not None else set()
    with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        selected = []
        used_paths = defaultdict(set)
        pending = set(missing)
        for item in attachments(db):
            if item.path:
                used_paths[canonical_path(item.path)].add((item.path, item.sha))
            key = (item.message, item.path)
            if key in missing or not item.path:
                selected.append(item)
                pending.discard(key)

        matched = match_files({item.sha for item in selected if item.sha}, roots, args.previous_map)
        # A generated path must not shadow any existing native path with different bytes.
        for item in selected:
            if not item.path and item.sha in matched:
                new = target_path(item)
                used_paths[canonical_path(new)].add((new, item.sha))

        out = args.output
        out.mkdir(mode=0o700, parents=False, exist_ok=False)
        try:
            counts = write_output(args, db, fingerprint, selected, matched, pending, used_paths)
            check_standalone(db_path)
            if sha256(db_path) != fingerprint:
                raise ValueError(
                    "Source DB changed during the audit. Retry from a stable snapshot."
                )
        except BaseException:
            shutil.rmtree(out)
            raise
    return counts


def write_output(args, db, fingerprint, selected, matched, pending, used_paths):
    out = args.output
    files = {}
    updates = {}
    counts = {"with_path": 0, "without_path": 0, "unresolved": 0}
    supplement = out / "supplement"
    if args.stage:
        (supplement / "Media").mkdir(parents=True)
    with (out / "media-map.tsv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(
            (
                "account_id",
                "snapshot_id",
                "message_id",
                "source_table",
                "source_rowid",
                "original_path",
                "import_path",
                "sha256",
                "mac_file",
                "status",
                "evidence",
            )
        )
        for item in selected:
            dest = target_path(item)
            candidate = matched.get(item.sha)
            status = "with_path" if item.path else "without_path"
            reason = ""
            if not item.sha:
                reason = "no valid Android plaintext SHA-256"
            elif not candidate:
                reason = "no candidate with matching SHA-256"
            elif not safe_relative(dest):
                reason = "unsafe WAB source path"
            elif len(used_paths[canonical_path(dest)]) != 1:
                reason = "conflicting source paths or content"
            if reason:
                status = "unresolved"
            elif args.stage:
                if dest not in files:
                    output = supplement / PurePosixPath(dest)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with candidate.open("rb") as src, output.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
                    if sha256(output) != item.sha:
                        raise ValueError("Source file changed while staging")
                    files[dest] = {"size": output.stat().st_size, "sha256": item.sha}
                if not item.path:
                    updates[item.table, item.pk] = dest
            counts[status] += 1
            writer.writerow(
                (
                    args.account_id,
                    args.snapshot_id,
                    item.message,
                    item.table,
                    item.pk,
                    item.path,
                    dest if status != "unresolved" else "",
                    item.sha,
                    str(candidate) if candidate else "",
                    status,
                    reason or "Android plaintext SHA-256 matches file bytes",
                )
            )

        # WAB may report generated output names for null paths. Those rows are
        # already covered by direct enumeration when this message has no path.
        pathless = {item.message for item in selected if not item.path}
        for mid, path in sorted(pending):
            if mid in pathless and not safe_relative(path):
                continue
            writer.writerow(
                (
                    args.account_id,
                    args.snapshot_id,
                    mid,
                    "",
                    "",
                    path,
                    "",
                    "",
                    "",
                    "unresolved",
                    "report row has no matching database attachment",
                )
            )
            counts["unresolved"] += 1
    receipt = {
        "schema_version": 1,
        "account_id": args.account_id,
        "snapshot_id": args.snapshot_id,
        "source_db_sha256": fingerprint,
        "derived_db_sha256": None,
        "files": files,
        "counts": counts,
    }
    if args.stage:
        if updates:
            derived = out / "msgstore.db"
            with closing(sqlite3.connect(derived)) as repaired:
                db.backup(repaired)
                with repaired:
                    for (table, pk), value in updates.items():
                        repaired.execute(
                            f"UPDATE {table} SET file_path=? WHERE rowid=? "
                            "AND COALESCE(file_path,'')=''",
                            (value, pk),
                        )
            receipt["derived_db_sha256"] = sha256(derived)
        (out / "reconciliation.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", type=Path, required=True, help="Standalone decrypted Android database"
    )
    parser.add_argument(
        "--missing",
        type=Path,
        help="Matching missing-media CSV. Omit to audit only rows without a path.",
    )
    parser.add_argument(
        "--mac-media",
        type=Path,
        required=True,
        action="append",
        help="Directory of candidate media (repeatable)",
    )
    parser.add_argument(
        "--previous-map",
        type=Path,
        help="Prior attachment-map.tsv (hints only; files are rehashed)",
    )
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--output", type=Path, required=True, help="New, private result directory")
    parser.add_argument(
        "--stage", action="store_true", help="Prepare verified files for a repair import"
    )
    args = parser.parse_args(argv)
    try:
        counts = run(args)
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"Audit failed: {exc}\n")
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
