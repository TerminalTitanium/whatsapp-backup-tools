"""Publish a complete working archive on one filesystem (macOS and Linux)."""

import ctypes
import errno
import os
import shutil
import sys
from pathlib import Path


def stage_previous(source: Path, stage: Path, managed: bool) -> None:
    """Copy mutable indices; link write-once payloads on managed reruns."""

    def fail_on_unreadable(error: OSError):
        raise error

    for directory, dirs, names in os.walk(source, onerror=fail_on_unreadable):
        relative = Path(directory).relative_to(source)
        dest = stage / relative
        dest.mkdir(mode=0o700, exist_ok=True)
        for name in dirs + names:
            if (Path(directory) / name).is_symlink():
                raise ValueError(
                    "Managed archives require local files; export symlinked media first."
                )
        payloads = relative.parts and relative.parts[0] in {"Contacts", "Groups", ".wab-recovered"}
        for name in names:
            src = Path(directory) / name
            if not src.is_file():
                raise ValueError(f"Unsupported archive entry: {src}")
            if managed and payloads:
                os.link(src, dest / name)
            else:
                shutil.copy2(src, dest / name)


def publish(stage: Path, target: Path) -> None:
    """Atomically install a directory; on replacement the old tree ends up at stage."""
    if not target.exists():
        stage.rename(target)
        return
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise OSError(errno.ENOTSUP, "Atomic directory exchange requires macOS or Linux.")
    libc = ctypes.CDLL(None, use_errno=True)
    src, dst = os.fsencode(stage), os.fsencode(target)
    if sys.platform == "darwin":
        result = libc.renamex_np(src, dst, 2)  # RENAME_SWAP
    elif hasattr(libc, "renameat2"):
        result = libc.renameat2(-100, src, -100, dst, 2)  # AT_FDCWD, RENAME_EXCHANGE
    else:
        raise OSError(errno.ENOTSUP, "Atomic directory exchange requires renameat2 on Linux.")
    if result:
        code = ctypes.get_errno()
        raise OSError(code, f"Could not exchange archive directories: {os.strerror(code)}")
