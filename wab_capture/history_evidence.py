"""Compare outgoing direct-chat stanza IDs offline without assigning an account."""

from __future__ import annotations

import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

from wab_capture.keys import authenticated_sqlite
from wab_capture.reconcile import check_standalone

_DIRECT_JID = re.compile(r"[0-9]+@(?:s\.whatsapp\.net|lid)")


def _direct_jid(raw, user, server):
    """Require an exact native address in a direct-chat namespace."""
    if raw:
        return raw if isinstance(raw, str) and _DIRECT_JID.fullmatch(raw) else None
    address = f"{user}@{server}"
    return address if _DIRECT_JID.fullmatch(address) else None


def _stat_signature(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _copy_reference(source, target):
    # Never open the operator's reference in SQLite, where journaling may create sidecars.
    check_standalone(source)
    before = _stat_signature(source)
    with source.open("rb") as inp, target.open("xb") as out:
        shutil.copyfileobj(inp, out, 1024 * 1024)
    check_standalone(source)
    if _stat_signature(source) != before:
        raise ValueError("The reference database changed while it was being read.")


def _outgoing_rows(db):
    def columns(table):
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}

    message = columns("message")
    if message:
        if "from_me" not in message:
            raise ValueError("Unsupported Android message table: missing outgoing direction.")
        chat, jid = columns("chat"), columns("jid")
        joins = ""
        address = "NULL"
        if "chat_row_id" in message and {"_id", "jid_row_id"} <= chat and "_id" in jid:
            raw = "j.raw_string" if "raw_string" in jid else "NULL"
            user = "j.user" if "user" in jid else "NULL"
            server = "j.server" if "server" in jid else "NULL"
            address = f"direct_jid({raw}, {user}, {server})"
            joins = "LEFT JOIN chat c ON c._id=m.chat_row_id LEFT JOIN jid j ON j._id=c.jid_row_id"
        stanza = "m.key_id" if "key_id" in message else "NULL"
        service = "m.message_type IS 7" if "message_type" in message else "0"
        return db.execute(
            f"SELECT {address}, {stanza}, {service} FROM message m {joins} WHERE m.from_me=1"
        )

    legacy = columns("messages")
    if "key_from_me" not in legacy:
        raise ValueError("Unsupported database: expected Android WhatsApp message history.")
    address = "direct_jid(key_remote_jid, NULL, NULL)" if "key_remote_jid" in legacy else "NULL"
    stanza = "key_id" if "key_id" in legacy else "NULL"
    service = "status IS 6" if "status" in legacy else "0"
    return db.execute(f"SELECT {address}, {stanza}, {service} FROM messages WHERE key_from_me=1")


def _index(path, index, table):
    uri = path.as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        if db.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",):
            raise ValueError("SQLite integrity check failed.")
        db.create_function("direct_jid", 3, _direct_jid, deterministic=True)
        counts = {"outgoing": 0, "unusable": 0}

        def evidence():
            for jid, stanza, is_service in _outgoing_rows(db):
                counts["outgoing"] += 1
                if (
                    is_service
                    or not jid
                    or not isinstance(stanza, str)
                    or not stanza.strip()
                    or stanza in {"-1", "0"}
                ):
                    counts["unusable"] += 1
                    continue
                yield jid, stanza

        index.execute(
            f"CREATE TABLE {table} (jid TEXT, stanza TEXT, PRIMARY KEY (jid, stanza)) WITHOUT ROWID"
        )
        index.executemany(f"INSERT OR IGNORE INTO {table} VALUES (?,?)", evidence())
        counts["distinct_direct"] = index.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        counts["duplicate_rows"] = (
            counts["outgoing"] - counts["unusable"] - counts["distinct_direct"]
        )
        return counts


def compare_history(encrypted: Path, key_hex: str, previous_sqlite: Path) -> dict:
    """Count exact shared (direct JID, outgoing stanza ID) pairs, never print content or IDs.

    Counts are a lower bound. A history gap, a changed JID namespace or missing usable
    identifiers can all produce zero overlap. Local row IDs play no part in the comparison.
    """
    reference = Path(previous_sqlite).resolve(strict=True)
    check_standalone(reference)
    with authenticated_sqlite(Path(encrypted), key_hex) as candidate:
        previous = candidate.parent / "reference.sqlite"
        _copy_reference(reference, previous)
        with closing(sqlite3.connect(candidate.parent / "pairs.sqlite")) as index:
            report = {}
            for table, path in (("candidate", candidate), ("reference", previous)):
                for key, count in _index(path, index, table).items():
                    report[f"{table}_{key}"] = count
            messages, chats = index.execute(
                """SELECT COUNT(*),COUNT(DISTINCT candidate.jid)
                   FROM candidate JOIN reference USING(jid,stanza)"""
            ).fetchone()
            report.update(
                matched_messages=messages,
                matched_chats=chats,
                assessment="overlap_observed" if messages else "indeterminate",
            )
            return report
