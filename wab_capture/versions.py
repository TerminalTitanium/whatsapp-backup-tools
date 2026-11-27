"""Bind Android media rows to verified file versions in the working viewer database."""

import json
import re
import sqlite3
from collections import defaultdict
from contextlib import closing
from functools import cache
from pathlib import Path

from .reconcile import attachments, safe_relative, sha256
from .recovered import replay_paths

VERSION_DIR = ".wab-versions"


def original_path(path):
    """Reverse a managed source alias when looking up the legacy archive filename."""
    dirs = path.split("/")
    if len(dirs) >= 5 and dirs[-3] == VERSION_DIR and re.fullmatch(r"[0-9a-f]{64}", dirs[-2]):
        return "/".join([*dirs[:-3], dirs[-1]])
    return path


def capture_path(path):
    """Normalize Android paths also recognized by the legacy viewer."""
    normalized = path.replace("\\", "/")
    normalized = normalized.removeprefix("WhatsApp/")
    if (
        normalized.startswith("/")
        or "\x00" in normalized
        or any(p in {".", ".."} for p in normalized.split("/"))
    ):
        raise ValueError(f"Unsafe Android media path: {path!r}")
    return normalized if safe_relative(normalized) else ""


def version_path(path, fingerprint):
    parent, _, name = path.rpartition("/")
    return f"{parent}/{VERSION_DIR}/{fingerprint}/{name}"


def bind_snapshot(database, archive, view, manifest, logger):
    """Project source versions into a disposable, decrypted copy of the Android database.

    The upstream viewer joins by file_path. Giving each version a distinct lookup
    key preserves that contract without modifying the phone database or media.
    """
    device = manifest.resolve().parents[2]
    data = json.loads(manifest.read_text(encoding="utf-8"))
    current = data["media"]
    retained = data.get("retained_media", {})
    known_hashes = defaultdict(set)
    ledger = archive / ".wab-imports.sqlite"
    if ledger.is_file():
        with closing(sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True)) as history:
            for path, fingerprint in history.execute(
                "SELECT DISTINCT original_path,source_sha256 FROM media_observations "
                "WHERE source_sha256 IS NOT NULL"
            ):
                known_hashes[path].add(fingerprint)

    @cache
    def observed_hash(path):
        return sha256(path) if path.is_file() else None

    def stored_file(relative):
        value = Path(relative)
        if value.parts[:1] not in {("media",), ("media-versions",)} or ".." in value.parts:
            raise ValueError("Invalid managed media path")
        target = (device / value).resolve()
        if not target.is_relative_to(device):
            raise ValueError("Media store entry escapes its device directory")
        return target

    @cache
    def choose(native, supplied, expected):
        # Recovery may supply a hash-qualified alias for an originally pathless row.
        if not supplied:
            return "", None, None
        supplied_path = capture_path(supplied)
        native_path = capture_path(native)
        if not supplied_path:
            # Android also records non-media internal objects. Preserve their
            # native reference without reading any host filesystem path.
            return supplied, None, None
        reference = native_path or supplied_path
        current_entry = current.get(reference)
        if current_entry:
            candidate = stored_file(current_entry["path"])
            actual = observed_hash(candidate)
            if (
                actual != current_entry["sha256"]
                or candidate.stat().st_size != current_entry["size"]
            ):
                raise ValueError(f"Snapshot media object failed its checksum: {reference!r}")
            # Older manifests retain their original-path proof. A new capture's
            # explicit false flag records known reuse, even after reverting bytes.
            unique = current_entry.get(
                "native_path_unique",
                current_entry["path"] == Path("media", *reference.split("/")[1:]).as_posix(),
            )
            if candidate.stat().st_size and (
                expected == actual
                or (not expected and unique is True and not (known_hashes[native] - {actual}))
            ):
                return version_path(reference, actual), candidate, actual
        # The private temporary tree contains only content-addressed Mac repairs.
        if expected:
            candidate = view / supplied_path
            if observed_hash(candidate) == expected and candidate.stat().st_size:
                return version_path(reference, expected), candidate, expected
        if expected and native_path:
            # A reused name can have two different bytes in the same snapshot.
            # A native plaintext hash permits reading either retained version.
            prior = retained.get(native_path)
            candidates = []
            if prior and prior["sha256"] == expected:
                candidates.append(stored_file(prior["path"]))
            candidates.extend(
                (
                    stored_file(Path("media", *native_path.split("/")[1:])),
                    stored_file(Path("media-versions", expected[:2], expected)),
                )
            )
            for old in candidates:
                if observed_hash(old) == expected and old.stat().st_size:
                    return version_path(reference, expected), old, expected
        # An adopted archive can still index unrelated bytes at the native name.
        # Leave a distinct unpopulated viewer key for unresolved attachments.
        return version_path(reference, "unavailable"), None, None

    with closing(sqlite3.connect(database)) as db, db:
        before = {}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='wab_media_bindings'").fetchone():
            before = {
                (table, pk, mid): native
                for table, pk, mid, native in db.execute(
                    "SELECT table_name,media_rowid,message_id,original_path FROM wab_media_bindings"
                )
            }
        initial = {
            (a.table, a.pk, a.message): before.get((a.table, a.pk, a.message), a.path)
            for a in attachments(db)
        }

        replay_paths(database, archive, view, logger)
        # Without a retry, a repair may start from the derived viewer database
        # and refer to this same version-specific key.
        db.execute("DROP TABLE IF EXISTS wab_media_bindings")
        db.execute("""CREATE TABLE wab_media_bindings(
            table_name TEXT, media_rowid INTEGER, message_id INTEGER, original_path TEXT,
            effective_path TEXT, sha256 TEXT, PRIMARY KEY(table_name,media_rowid,message_id)
        ) WITHOUT ROWID""")
        resolved = {}
        updates = {}
        for a in attachments(db):
            key = (a.table, a.pk, a.message)
            native = initial[key]
            supplied = a.path
            if key in before and native and a.path:
                local = capture_path(a.path)
                if not local or not (view / local).is_file():
                    supplied = native
            effective, source, fingerprint = choose(native, supplied, a.sha)
            if effective:
                resolved.setdefault(effective, source)
            if effective != a.path:
                updates[a.table, a.pk] = effective
            db.execute(
                "INSERT INTO wab_media_bindings VALUES(?,?,?,?,?,?)",
                (*key, native, effective, fingerprint),
            )
        for (table, pk), effective in updates.items():
            db.execute(f"UPDATE {table} SET file_path=? WHERE rowid=?", (effective or None, pk))
    # Cover other upstream source lookups (e.g. a thumbnail) that are not media rows.
    for path, entry in current.items():
        resolved.setdefault(path, stored_file(entry["path"]))
    return resolved
