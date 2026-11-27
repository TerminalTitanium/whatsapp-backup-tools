"""Capture Android WhatsApp source files over USB. Account preparation is optional."""

import argparse
import getpass
import os
import shlex
import sys
import tempfile
from pathlib import Path
from uuid import UUID

from .adb import AndroidDevice
from .raw import CapturedAccountView, capture_raw
from .source import (
    capture_account,
    open_device,
    previous_snapshots,
    timestamp_id,
    utc_now,
    write_json,
)


def _confirm_account(account):
    reply = input(f"Use account {account}? Press Enter to accept or type its UUID: ").strip()
    if reply and reply.lower() != account:
        raise ValueError("Account was not confirmed.")


def _compatibility(usb, device, info, args, work, session, log, first):
    ids = [str(UUID(a)) for a in args.account if a != "new"]
    if len(ids) != len(set(ids)):
        raise ValueError("Each existing account can only be requested once in a session.")
    if args.key_file and len(args.key_file) != len(args.account):
        raise ValueError("Supply a --key-file for each --account, in order, or omit them all.")
    if args.avatar_map and len(args.avatar_map) not in {1, len(args.account)}:
        raise ValueError("Supply one shared --avatar-map or one for each account in order.")
    history = previous_snapshots(device)
    for account in dict.fromkeys(owner for owner, _, _, _ in history):
        print(f"Previously prepared account: {account}")
    completed = []
    try:
        for i, request in enumerate(args.account):
            if i == 0:
                snapshot, raw = first
                input("The current phone state is saved. Press Enter to prepare this snapshot. ")
            else:
                input(
                    f"Account {i + 1}/{len(args.account)}: switch accounts, finish the local "
                    "WhatsApp backup, then press Enter to capture it. "
                )
                snapshot, raw = capture_raw(usb, device, info, session, args.avatar_map, log)
            view = CapturedAccountView(snapshot, raw)
            files = view.databases()
            if not files[0].path.endswith(".crypt15"):
                raise ValueError("Legacy account preparation requires a full crypt15 E2E backup.")
            log(f"Active full backup: {files[0].size} bytes, SHA-256 {files[0].sha256}")
            stage = work / f"account-{i}"
            stage.mkdir()
            avatar_map = None
            if raw["avatars"]:
                avatar_map = work / f"avatars-{i}.json"
                entries = [{**row, "file": row["path"]} for row in raw["avatars"]]
                write_json(avatar_map, {"root": str(snapshot.resolve()), "entries": entries})
            manifest = capture_account(
                view,
                device,
                info,
                stage,
                request,
                history,
                args.key_file[i] if args.key_file else None,
                lambda account: getpass.getpass(f"64-character backup key for {account}: "),
                snapshot / raw["contacts"] if raw["contacts"] else None,
                raw["contact_rows"],
                raw["contacts_at"],
                avatar_map,
                files,
                session,
                _confirm_account,
                raw_observation=view.observation,
            )
            completed.append(manifest["account_id"])
            log(f"Committed snapshot {manifest['snapshot_id']}")
    finally:
        log(f"Prepared {len(completed)}/{len(args.account)} account(s): {', '.join(completed)}")


def capture(args):
    usb = AndroidDevice(args.serial, args.phone_root, True)
    with open_device(args.root, args.device, usb.serial) as (device, info):
        session = timestamp_id(utc_now())
        log_path = device / "logs" / f"{session}.log"
        print(f"Session log: {log_path}")
        with log_path.open("x", encoding="utf-8", buffering=1) as logfile:

            def log(message):
                logfile.write(f"{utc_now()} {message}\n")
                print(message, flush=True)

            log(f"Device {info['device_id']} ({args.device})")
            try:
                first = capture_raw(usb, device, info, session, args.avatar_map, log)
            except (Exception, KeyboardInterrupt) as exc:
                log(f"RAW INCOMPLETE: {exc or type(exc).__name__}")
                raise
            if args.account:
                try:
                    with tempfile.TemporaryDirectory(
                        prefix=f".partial-{session}-", dir=device
                    ) as tmp:
                        _compatibility(usb, device, info, args, Path(tmp), session, log, first)
                except (Exception, KeyboardInterrupt) as exc:
                    log(f"ACCOUNT PREPARATION INCOMPLETE: {exc or type(exc).__name__}")
                    log(
                        "The raw snapshots listed above are complete. Resume offline with wab-prepare."
                    )
                    raise
            elif args.key_file:
                log(
                    f"Supply keys during offline preparation: wab-prepare {shlex.quote(str(first[0]))} --list"
                )
            log("COMPLETE")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--root", required=True, type=Path, help="Local archive root containing sources/"
    )
    p.add_argument(
        "--device", required=True, help="Persistent, operator-chosen device folder label"
    )
    p.add_argument(
        "--account",
        action="append",
        metavar="UUID|new",
        help="Optional compatibility mode: prepare an account after saving each raw capture.",
    )
    p.add_argument(
        "--key-file",
        action="append",
        type=Path,
        help="Local single-line crypt15 key. Repeat in account order, or enter interactively.",
    )
    p.add_argument("--serial", help="Select a specific ADB device")
    p.add_argument(
        "--phone-root",
        action="append",
        help="Scan this Android storage directory recursively (repeatable)",
    )
    p.add_argument(
        "--avatar-map",
        action="append",
        type=Path,
        help="Mac avatar observation map for known accounts",
    )
    args = p.parse_args()
    previous = os.umask(0o077)
    try:
        capture(args)
    except (ValueError, OSError, RuntimeError, EOFError, KeyboardInterrupt) as exc:
        sys.exit(f"Capture stopped: {exc or type(exc).__name__}")
    finally:
        os.umask(previous)
