"""Viewer joins an Android attachment to its verified bytes across name reuse."""

import hashlib
import os
import sqlite3

import pytest
from tests.e2e.test_android_archive_protocol import (
    ACCOUNT_A,
    FIRST,
    IMAGE,
    MEDIA,
    SECOND,
    Phone,
    invoke_import,
)
from wab_viewer.main import create_app

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="managed Android capture runs on macOS/Linux"
)


def test_two_messages_with_reused_native_path_keep_distinct_viewer_files(tmp_path):
    phone = Phone(tmp_path)
    path = f"{MEDIA}/{IMAGE}"
    with sqlite3.connect(phone.db) as db:
        db.execute("ALTER TABLE message_media ADD COLUMN file_hash BLOB")
        db.execute("UPDATE message_media SET file_hash=?", (hashlib.sha256(FIRST).digest(),))
    phone.encrypt()
    first = phone.capture()
    invoke_import(first, phone)
    with sqlite3.connect(phone.db) as db:
        db.execute("INSERT INTO message VALUES (2,1,0,1,1700000050000,'new photo',1,'k2')")
        db.execute(
            "INSERT INTO message_media VALUES (2,2,1,?,?,'image/jpeg',NULL,?)",
            (path, IMAGE, hashlib.sha256(SECOND).digest()),
        )
    (phone.phone / path).write_bytes(SECOND)
    phone.encrypt()
    second = phone.capture()
    invoke_import(second, phone)
    archive = phone.store / "wab" / ACCOUNT_A
    with sqlite3.connect(archive / "Whatsapp Databases/msgstore.db") as db:
        db.execute("ATTACH DATABASE ? AS archive", (str(archive / ".wa_media_archiver.db"),))
        copies = db.execute(
            "SELECT mm.message_row_id, ac.archive_path FROM message_media mm "
            "JOIN archive.archive_copies ac ON ac.original_path = mm.file_path "
            "ORDER BY mm.message_row_id"
        ).fetchall()
    client = create_app(archive).test_client()
    assert [mid for mid, _ in copies] == [1, 2]
    for (_, copy), expected in zip(copies, [FIRST, SECOND], strict=True):
        result = client.get("/media/" + copy)
        assert result.status_code == 200 and result.data == expected
        result.close()
