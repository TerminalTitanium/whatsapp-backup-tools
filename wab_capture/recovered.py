"""Keep content-verified Mac repairs available to later Android imports."""

import logging
import re
import shutil
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from .reconcile import attachments, safe_relative, sha256, target_path

REGISTRY = ".wab-recovery.sqlite"
PAYLOADS = ".wab-recovered"


def remember_repair(archive: Path, repair: Path, plan: dict, db_path: Path) -> None:
    """Persist observations and payloads in the transactional publication tree."""
    observed = set()
    payloads = archive / PAYLOADS
    payloads.mkdir(mode=0o700, exist_ok=True)
    with (
        closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as native,
        closing(sqlite3.connect(archive / REGISTRY)) as journal,
        journal,
    ):
        journal.execute("""CREATE TABLE IF NOT EXISTS repairs(
            account TEXT, snapshot TEXT, db_sha256 TEXT, message INTEGER, source_table TEXT,
            source_rowid INTEGER, import_path TEXT, sha256 TEXT, canonical TEXT,
            PRIMARY KEY(account,snapshot,db_sha256,message,source_table,source_rowid))""")
        for item in attachments(native):
            entry = plan["files"].get(item.path)
            if not entry:
                continue
            if item.sha != entry["sha256"] or not re.fullmatch(r"[a-f0-9]{64}", item.sha):
                raise ValueError("Staged media digest disagrees with Android attachment")
            if not safe_relative(item.path):
                raise ValueError("Invalid supplemental media path")
            digest = item.sha
            target = payloads / digest
            if item.path not in observed:
                if not target.exists():
                    shutil.copyfile(repair / "supplement" / item.path, target)
                if sha256(target) != digest:
                    raise ValueError("Recovered media contents changed")
                observed.add(item.path)
            # Preserve extension from the typed Android record for pathless observations.
            canonical = target_path(replace(item, path=""))
            journal.execute(
                "INSERT OR IGNORE INTO repairs VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    plan["account_id"],
                    plan["snapshot_id"],
                    plan["source_db_sha256"],
                    item.message,
                    item.table,
                    item.pk,
                    item.path,
                    digest,
                    canonical,
                ),
            )
    if observed != set(plan["files"]):
        raise ValueError("Repair contains an unreferenced supplemental path")


def materialize_recovered(archive: Path, view: Path) -> None:
    """Provide hash-qualified media aliases in the disposable Android source view."""
    journal_path = archive / REGISTRY
    if not journal_path.is_file():
        return
    with closing(
        sqlite3.connect(journal_path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as journal:
        for digest, canonical in journal.execute("SELECT DISTINCT sha256,canonical FROM repairs"):
            if not re.fullmatch(r"[a-f0-9]{64}", digest) or not safe_relative(canonical):
                raise ValueError("Invalid saved recovery alias")
            alias = view / canonical
            payload = archive / PAYLOADS / digest
            if sha256(payload) != digest:
                raise ValueError("Stored verified recovery payload changed")
            if alias.is_file():
                # The real capture's bytes win. replay_paths only uses exact hashes.
                continue
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to(payload.resolve())


def replay_paths(database: Path, archive: Path, view: Path, logger: logging.Logger) -> None:
    """Fill working-DB paths with verified aliases; snapshot sources are immutable."""
    registry = archive / REGISTRY
    if not registry.is_file():
        return
    with (
        closing(sqlite3.connect(registry.resolve().as_uri() + "?mode=ro", uri=True)) as journal,
        closing(sqlite3.connect(database)) as native,
        native,
    ):
        aliases = dict(
            journal.execute(
                "SELECT sha256,MIN(canonical) FROM repairs GROUP BY sha256 ORDER BY sha256"
            )
        )
        if not aliases:
            return
        decisions = {}
        checks = {}
        for item in attachments(native):
            alias = aliases.get(item.sha)
            if alias is None or not safe_relative(alias):
                continue
            if item.path and not safe_relative(item.path):
                continue
            if item.path:
                current = view / item.path
                if current not in checks:
                    checks[current] = sha256(current) if current.is_file() else None
                if checks[current] == item.sha:
                    continue
            fallback = view / alias
            if fallback not in checks:
                checks[fallback] = sha256(fallback) if fallback.is_file() else None
            if checks[fallback] == item.sha:
                decisions[item.table, item.pk] = alias
        for (table, pk), path in decisions.items():
            native.execute(f"UPDATE {table} SET file_path=? WHERE rowid=?", (path, pk))
        if decisions:
            logger.info("Reused verified Mac recovery for %d attachment(s).", len(decisions))
