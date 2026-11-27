"""Capture Android backups for one or more explicitly selected WhatsApp accounts."""

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from pathlib import Path
from uuid import UUID

from .adb import AndroidDevice
from .source import capture_account, open_device, previous_snapshots, timestamp_id, utc_now


def _confirm_account(account):
    if (
        input(f"Confirm the active WhatsApp account by typing its archive UUID {account}: ").strip()
        != account
    ):
        raise ValueError("Account was not confirmed.")


def _session(usb, device, info, args, work, session, log):
    completed = []
    try:
        history = previous_snapshots(device)
        for account in dict.fromkeys(owner for owner, _, _, _ in history):
            print(f"Previously captured account: {account}")
        contacts = work / "wa_contacts.txt"
        contacts_at = utc_now()
        try:
            rows = usb.contacts(contacts)
            log(f"Contacts: {rows} source rows, observed {contacts_at}")
        except (OSError, RuntimeError, ValueError) as exc:
            contacts, rows = None, 0
            log(f"Contacts unavailable: {exc}")
        for i, request in enumerate(args.account):
            input(
                f"Account {i + 1}/{len(args.account)} ({request}): switch to the account in "
                "WhatsApp, finish its backup and press Enter. "
            )
            files = usb.databases()
            if not files:
                raise ValueError("No active full backup on the device.")
            if not files[0].path.endswith(".crypt15"):
                raise ValueError("USB snapshot capture requires a full crypt15 E2E backup.")
            log(f"Active full backup: {files[0].size} bytes, SHA-256 {files[0].sha256}")
            stage = work / f"account-{i}"
            stage.mkdir()
            manifest = capture_account(
                usb,
                device,
                info,
                stage,
                request,
                history,
                args.key_file[i] if args.key_file else None,
                lambda account: getpass.getpass(f"64-character backup key for {account}: "),
                contacts,
                rows,
                contacts_at,
                args.avatar_map[min(i, len(args.avatar_map) - 1)] if args.avatar_map else None,
                files,
                session,
                _confirm_account,
            )
            completed.append(manifest["account_id"])
            log(f"Committed snapshot {manifest['snapshot_id']}")
            for db in manifest["databases"]:
                log(f"  {db['name']}: {db['size']} bytes, SHA-256 {db['sha256']}")
            log(
                f"  Media: {manifest['media_counts']}; avatars: {len(manifest['avatars'])}; contact rows: {rows}"
            )
            if contacts:
                latest = device / "contacts"
                latest.mkdir(exist_ok=True)
                tmp = work / "latest.txt"
                shutil.copyfile(contacts, tmp)
                os.replace(tmp, latest / "wa_contacts.txt")
    finally:
        log(f"Completed {len(completed)}/{len(args.account)} account(s): {', '.join(completed)}")


def capture(args):
    if not args.account:
        raise ValueError("Specify --account new or an existing archive UUID.")
    ids = [str(UUID(a)) for a in args.account if a != "new"]
    if len(ids) != len(set(ids)):
        raise ValueError("Each existing account can only be requested once in a session.")
    if args.key_file and len(args.key_file) != len(args.account):
        raise ValueError("Supply a --key-file for each --account, in order, or omit them all.")
    if args.avatar_map and len(args.avatar_map) not in {1, len(args.account)}:
        raise ValueError("Supply one shared --avatar-map or one for each account in order.")
    usb = AndroidDevice(args.serial, args.phone_root)
    with open_device(args.root, args.device, usb.serial) as (device, info):
        session = timestamp_id(utc_now())
        log_path = device / "logs" / f"{session}.log"
        print(f"Session log: {log_path}")
        with log_path.open("x", encoding="utf-8", buffering=1) as logfile:

            def log(message):
                logfile.write(f"{utc_now()} {message}\n")
                print(message, flush=True)

            log(f"Device {info['device_id']} ({args.device}); requested accounts {args.account}")
            try:
                with tempfile.TemporaryDirectory(prefix=f".partial-{session}-", dir=device) as temp:
                    _session(usb, device, info, args, Path(temp), session, log)
            except (Exception, KeyboardInterrupt) as exc:
                log(f"INCOMPLETE: {exc or type(exc).__name__}")
                raise
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
        required=True,
        metavar="UUID|new",
        help="Repeat for each active account to capture in order.",
    )
    p.add_argument(
        "--key-file",
        action="append",
        type=Path,
        help="Local single-line crypt15 key. Repeat in account order, or enter interactively.",
    )
    p.add_argument("--serial", help="Select a specific ADB device")
    p.add_argument(
        "--phone-root", help="Android WhatsApp directory containing Media/ and Databases/"
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
