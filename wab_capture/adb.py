"""Read a WhatsApp backup from a single Android device using ADB shell v2."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import tempfile
from copy import copy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from wab_archiver.increment_merger import filter_active_increments

_STORAGE = "/sdcard"
_ROOTS = (
    f"{_STORAGE}/Android/media/com.whatsapp/WhatsApp",
    f"{_STORAGE}/WhatsApp",
    f"{_STORAGE}/Android/media/com.whatsapp.w4b/WhatsApp Business",
    f"{_STORAGE}/WhatsApp Business",
)
_PACKAGE_ROOTS = (
    f"{_STORAGE}/Android/media/com.whatsapp",
    f"{_STORAGE}/Android/media/com.whatsapp.w4b",
    *_ROOTS,
)
_FULL = re.compile(r"Databases/msgstore\.db\.(crypt1[45])")
_INCREMENT = re.compile(r"Databases/msgstore-increment-(\d+)[^/]*\.(crypt1[45])")
_DIGEST = re.compile(r"[a-f0-9]{64}")

# One remote shell request per inventory. Read names as arguments to find's
# -exec action, never as shell syntax. The NUL framing also preserves newlines.
_HASH_FILES = r"""
for f do
    size=$(stat -c %s "$f") && sum=$(sha256sum < "$f") || {
        printf 'incomplete file record\000'
        exit 1
    }
    printf '%s\000%s\000%s\000' "$f" "$size" "${sum%% *}"
done
"""


@dataclass(frozen=True)
class RemoteFile:
    """A relative Android path together with its observed contents."""

    path: str
    size: int
    sha256: str | None
    stamp: str | None = None


def _adb(args: list[str], timeout: int) -> bytes:
    try:
        result = subprocess.run(["adb", *args], capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError("Install Android SDK Platform Tools (adb).") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("ADB timed out. Check the USB connection and retry.") from exc
    if result.returncode:
        reason = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            f"ADB failed ({result.returncode}): {reason or 'check device connection'}"
        )
    return result.stdout


def _relative(path: str) -> bool:
    return all(part not in ("", ".", "..") for part in path.split("/")) and "\0" not in path


def _inventory(raw: bytes, directory: str) -> list[RemoteFile]:
    fields = raw.split(b"\0")
    if fields.pop() or len(fields) % 3:
        raise ValueError(f"Incomplete Android inventory for {directory}.")
    files: list[RemoteFile] = []
    seen = set()
    for i in range(0, len(fields), 3):
        path, size, digest = (x.decode("utf-8") for x in fields[i : i + 3])
        if (
            not _relative(path)
            or not path.startswith(directory + "/")
            or path in seen
            or not size.isascii()
            or not size.isdecimal()
            or not _DIGEST.fullmatch(digest)
        ):
            raise ValueError(f"Invalid or duplicate Android file in {directory} inventory.")
        files.append(RemoteFile(path, int(size), digest))
        seen.add(path)
    return sorted(files, key=lambda f: f.path)


def _roots(paths):
    roots = set()
    for path in paths:
        if not path.startswith("/") or ".." in PurePosixPath(path).parts or "\0" in path:
            raise ValueError("Android root must be an absolute directory.")
        roots.add(PurePosixPath(path))
    return [str(p) for p in sorted(roots) if roots.isdisjoint(p.parents)]


def active_databases(records):
    by_path = {f.path: f for f in records}
    full = [f for f in records if _FULL.fullmatch(f.path)]
    if len(full) != 1 or not full[0].size:
        raise ValueError("Expected exactly one nonempty active full WhatsApp database.")
    suffix = PurePosixPath(full[0].path).suffix
    incs = [f.path for f in records if _INCREMENT.fullmatch(f.path) and f.path.endswith(suffix)]
    active = filter_active_increments(incs, full[0].path)
    for index, name in enumerate(active, start=1):
        match = _INCREMENT.fullmatch(name)
        if match is None or int(match[1]) != index or not by_path[name].size:
            raise ValueError("Incomplete Android incremental backup sequence. Retry after backup.")
    return [full[0], *(by_path[name] for name in active)]


class AndroidDevice:
    """Pin all reads in this session to a single authorized ADB serial and root."""

    def __init__(self, serial=None, root=None, raw=False):
        selector = ["-s", serial] if serial else ["-d"]
        self.serial = _adb([*selector, "get-serialno"], 30).decode().strip()
        if not self.serial or self.serial in {"unknown", "offline"}:
            raise RuntimeError(
                "Connect and authorize exactly one USB device or specify its serial."
            )
        if serial and self.serial != serial:
            raise RuntimeError("ADB returned a different serial than requested.")
        roots = _roots(
            ([root] if isinstance(root, str) else root) or (_PACKAGE_ROOTS if raw else _ROOTS)
        )
        self.search_roots = roots
        if raw:
            return
        command = (
            f"for dir in {shlex.join(roots)}; do "
            'if [ -f "$dir/Databases/msgstore.db.crypt15" ] || '
            '[ -f "$dir/Databases/msgstore.db.crypt14" ]; then '
            r"""printf '%s\000' "$dir"; fi; done"""
        )
        available = self._shell(command, 30).decode().split("\0")
        found = [path for path in available if path]
        if len(found) != 1 or found[0] not in roots:
            if found:
                raise ValueError(
                    f"Multiple WhatsApp roots. Select one explicitly: {', '.join(found)}"
                )
            raise ValueError("No full WhatsApp backup found. Back up the active account first.")
        self.root = found[0]

    def discover_dirs(self):
        """Discover storage directories while pruning media and known database trees."""
        # Probe standard Android layouts directly, including shared-storage aliases.
        # Recursive discovery still covers manufacturer and secondary account layouts.
        parents = set(self.search_roots) | {
            root
            for root in _ROOTS
            if any(PurePosixPath(root).is_relative_to(p) for p in self.search_roots)
        }
        direct = [
            str(PurePosixPath(parent) / name)
            for parent in sorted(parents)
            if PurePosixPath(parent).name not in {"Databases", "Media"}
            for name in ("Databases", "Media")
        ]
        command = (
            f"for path in {shlex.join(direct)}; do "
            r"""if [ -d "$path" ]; then printf '%s\000' "$path"; fi; done; """
            f"for dir in {shlex.join(self.search_roots)}; do "
            'case "${dir##*/}" in Databases|Media) '
            r"""(cd "$dir") || exit 1; printf '%s\000' "$dir"; continue;; esac; """
            'if [ -d "$dir" ]; then find "$dir" -type d '
            r"\( -name Databases -o -name Media \) -print0 -prune || exit 1; fi; done"
        )
        raw = self._shell(command, 300).split(b"\0")
        if raw.pop():
            raise ValueError("Incomplete Android directory inventory.")
        found = set()
        for field in raw:
            name = field.decode("utf-8")
            path = PurePosixPath(name)
            if (
                str(path) != name
                or ".." in path.parts
                or path.name not in {"Media", "Databases"}
                or not any(path.is_relative_to(r) for r in self.search_roots)
            ):
                raise ValueError("Invalid Android storage directory.")
            found.add(path)
        return tuple(
            sorted(str(p) for p in found if p.name == kind) for kind in ("Databases", "Media")
        )

    def at_root(self, parent):
        view = copy(self)
        view.root = parent
        return view

    def _shell(self, command: str, timeout: int) -> bytes:
        # A non-PTY shell preserves NUL framing and reports remote command failure.
        return _adb(["-s", self.serial, "shell", "-T", command], timeout)

    def _scan(self, directory: str, predicates: str) -> list[RemoteFile]:
        script = (
            f"cd {shlex.quote(self.root)} && find {directory}/ {predicates} "
            f"-type f -exec sh -c {shlex.quote(_HASH_FILES)} sh {{}} +"
        )
        return _inventory(self._shell(script, 6 * 3600), directory)

    def media(self) -> list[RemoteFile]:
        return self._scan("Media", "")

    def media_stats(self):
        """Batch stat calls on the device. Filenames are NUL framed separately."""
        batch = (
            r"""printf '%s\000' "$#" "$@"; stat -c '%s %Y %Z %i' "$@" || exit 1; printf '\000'"""
        )
        cmd = f"cd {shlex.quote(self.root)} && find Media/ -type f -exec sh -c {shlex.quote(batch)} sh {{}} +"
        fields = iter(self._shell(cmd, 3600).split(b"\0"))
        result = {}
        try:
            for count in fields:
                if not count:
                    if next(fields, None) is not None:
                        raise ValueError("Invalid Android media inventory")
                    break
                n = int(count)
                if n < 1:
                    raise ValueError("Invalid Android media batch")
                names = [next(fields).decode() for _ in range(n)]
                lines = next(fields).decode("ascii").splitlines()
                for name, line in zip(names, lines, strict=True):
                    numbers = line.split()
                    if (
                        not name.startswith("Media/")
                        or not _relative(name)
                        or name in result
                        or len(numbers) != 4
                        or not all(re.fullmatch(r"-?[0-9]+", v) for v in numbers)
                        or int(numbers[0]) < 0
                    ):
                        raise ValueError("Invalid Android media stat record")
                    result[name] = RemoteFile(name, int(numbers[0]), None, " ".join(numbers[1:]))
            else:
                raise ValueError("Truncated Android media inventory")
        except StopIteration as exc:
            raise ValueError("Truncated Android media inventory") from exc
        return sorted(result.values(), key=lambda row: row.path)

    def media_digest(self, entry):
        path = shlex.quote(f"{self.root}/{entry.path}")
        result = self._shell(f"sha256sum < {path}", 3600).decode().split()
        if not result or not _DIGEST.fullmatch(result[0]):
            raise ValueError("Invalid Android checksum")
        return result[0]

    def all_databases(self) -> list[RemoteFile]:
        return self._scan("Databases", "")

    def databases(self) -> list[RemoteFile]:
        records = self._scan(
            "Databases",
            r"-maxdepth 1 \( -name 'msgstore.db.crypt1[45]' -o -name 'msgstore-increment-*.crypt1[45]' \)",
        )
        return active_databases(records)

    def contacts(self, destination: Path) -> int:
        """Write a complete, nonempty phone/WhatsApp contact export or leave the target untouched."""
        data = self._shell(
            "content query --uri content://com.android.contacts/data "
            "--projection display_name:data1:data4:mimetype",
            120,
        ).decode("utf-8")
        if "SecurityException" in data or "Permission Denial" in data:
            raise RuntimeError("Android denied access to contacts.")
        rows = [
            line
            for line in data.splitlines()
            if line.startswith("Row: ")
            and (
                "mimetype=vnd.android.cursor.item/phone_v2" in line
                or "vnd.com.whatsapp" in line
                or "@s.whatsapp.net" in line
            )
        ]
        if not rows:
            raise ValueError("Android returned no phone contacts.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(dir=destination.parent, delete=False)
        temp = Path(tmp.name)
        try:
            with tmp:
                tmp.write(("\n".join(rows) + "\n").encode("utf-8"))
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)
        return len(rows)

    def pull(self, file: RemoteFile, destination: Path) -> None:
        """Publish the file only after confirming it matches the device inventory."""
        if not _relative(file.path) or file.path.split("/", 1)[0] not in {"Media", "Databases"}:
            raise ValueError("Invalid Android source path.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as tmp:
            temp = Path(tmp.name)
        try:
            _adb(["-s", self.serial, "pull", f"{self.root}/{file.path}", str(temp)], 3600)
            if temp.stat().st_size != file.size:
                raise ValueError(f"Size changed during USB transfer: {file.path}")
            if file.sha256 is not None:
                with temp.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest != file.sha256:
                    raise ValueError(f"Contents changed during USB transfer: {file.path}")
            temp.chmod(0o600)
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)
