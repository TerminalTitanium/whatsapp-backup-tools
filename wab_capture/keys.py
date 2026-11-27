"""Authenticate a local .crypt15 backup without persisting any decrypted bytes."""

import hashlib
import zlib
from pathlib import Path

from Cryptodome.Cipher import AES
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.key15 import Key15


def _plaintext_chunks(path: Path, key_hex: str):
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32 or len(key_hex) != 64:
            raise ValueError
    except ValueError:
        raise ValueError("A crypt15 key must contain 64 hexadecimal characters.") from None

    with path.open("rb") as stream:
        db = DatabaseFactory.from_file(stream)
        if not isinstance(db, Database15):
            raise ValueError("Capture requires a crypt15 backup with an E2E key.")
        cipher = AES.new(Key15(key=key).get(), AES.MODE_GCM, nonce=db.get_iv())
        # DatabaseFactory positioned the stream after the header and seeded the
        # WhatsApp footer checksum. The payload ends with TAG[, MD5].
        remaining = path.stat().st_size - stream.tell() - 32
        if remaining < 0:
            raise ValueError("Truncated crypt15 backup.")
        while remaining:
            data = stream.read(min(remaining, 1024 * 1024))
            if not data:
                raise ValueError("Truncated crypt15 backup.")
            db.file_hash.update(data)
            yield cipher.decrypt(data)
            remaining -= len(data)
        before_end, last = stream.read(16), stream.read(16)
        db.file_hash.update(before_end)
        if db.file_hash.digest() == last:
            tag = before_end
        else:
            yield cipher.decrypt(before_end)
            tag = last
        try:
            cipher.verify(tag)
        except ValueError:
            raise ValueError(f"Wrong key or corrupt backup: {path.name}") from None


def verify_key(path: Path, key_hex: str, *, fingerprint=False):
    """Exhaust the iterator to verify GCM; only publish a digest after verification."""
    hasher = hashlib.sha256()
    header = bytearray()
    unpack = None
    first = True
    for chunk in _plaintext_chunks(path, key_hex):
        if not fingerprint:
            continue
        if first:
            # Whole Android backups are either SQLite or zlib-compressed SQLite.
            if not chunk.startswith(b"S"):
                unpack = zlib.decompressobj()
            first = False
        pending = chunk
        while pending:
            try:
                block = unpack.decompress(pending, 1024 * 1024) if unpack else pending
            except zlib.error:
                raise ValueError(f"Wrong key or corrupt backup: {path.name}") from None
            if len(header) < 16:
                header.extend(block[: 16 - len(header)])
            hasher.update(block)
            pending = unpack.unconsumed_tail if unpack else b""
    if fingerprint:
        if header != b"SQLite format 3\x00" or (unpack and not unpack.eof):
            raise ValueError("The full backup does not contain a complete SQLite database payload.")
        return hasher.hexdigest()
    return None
