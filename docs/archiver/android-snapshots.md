# Android USB snapshots (fork)

The capture host is macOS or Linux with Python 3.11+, Android SDK Platform Tools
(`adb`) and the fork installed in the active Python environment. Use Android's
USB debugging authorization on a trusted computer. This workflow reads a
completed local WhatsApp **crypt15** backup using its 64-hex-character E2E key.
It does not initiate a WhatsApp backup or switch the active WhatsApp account.

## First capture

Choose a private local root with capacity for the shared media and encrypted
snapshot databases. Use one stable label per physical phone. To capture two
accounts from that device, create a current in-app backup for the first account
and run:

```sh
wab-capture --root "$HOME/WhatsApp-Archive" --device android-phone \
  --account new --account new
```

For each account, the command asks you to select it on the device, wait until
its in-app backup finishes, and press Enter. It prints the size and SHA-256
of the full database it actually found. Enter the E2E key at the hidden prompt
and confirm the displayed archive UUID. Between the two prompts, switch
accounts on the phone and complete the second backup. Keep the UUIDs from the
session log for future captures. You can also supply your own UUIDs to associate
existing accounts or prepare the avatar map before the first capture.

The manifest records the full database’s SHA-256 over its authenticated SQLite
bytes as well as the encrypted file hash. If the phone still exposes a full
database previously captured for another
account, capture stops before publishing that snapshot. A valid key proves that
the backup authenticated; the operator confirms the active account.
For a busy ADB environment pass `--serial SERIAL`. With multiple accessible
WhatsApp directories, set `--phone-root /sdcard/Android/media/com.whatsapp/WhatsApp`
for the relevant application. Capture checks the serial against the device
registration. To rename the label, rename the whole device folder while capture
is stopped, then use its new name. The internal device UUID stays the same.

## Next month

Run the same command with the assigned UUIDs, in the desired capture order.
Capture reuses each account's locally saved key. Following a key rotation,
supply `--key-file /private/path/to/key.txt` once per requested account in
matching order; the file contains the account's single hexadecimal key.
Do not provide keys on the command line. The local snapshot deliberately contains
`key.txt`: anyone who can read the snapshot can decrypt it.

The phone is inventoried by content hash. Unchanged media need no new transfer.
Data can still be read by both devices to verify identity, so a verification
pass over a large media collection takes time. The capture process reads the
address book once per session; each committed snapshot records its observation
time. A denied or empty contacts query is recorded as unavailable and the
previous local address book remains available.

## On disk

- `sources/<device>/media/` holds the first content observed at each Android
  media path. Distinct bytes found later at that path go into `media-versions/`.
  Versions referred to by previous snapshots remain available.
- `snapshots/<UTC>_<account-uuid>/` contains the full encrypted database and
  its active ordered increments under `databases/`, the authenticated `key.txt`,
  available contact and avatar observations and `manifest.json`. The manifest maps
  observed Android `Media/…` paths to exact device-relative objects, sizes and
  SHA-256. Its separate `retained_media` map of candidates (keyed by Android
  path) records missing files with one historically observed version for this
  account. A candidate still needs a verified match to the message.
- `contacts/wa_contacts.txt` is the device's latest successfully collected
  address book. The independently saved contact observation is inside the snapshot.
- `logs/<UTC>.log` is one session receipt with account IDs, database hashes,
  counts, completion status and errors. An interrupted run leaves the completed
  snapshots intact. After a forced termination a hidden partial work directory
  may remain outside `snapshots/`. It cannot be imported as a completed capture.
  Resume by retrying the incomplete account; already saved media are checked
  and reused.
- Use `--avatar-map FILE` to include available Mac images. The UTF-8 JSON file
  is an array of objects with an explicitly confirmed `account_id`, native
  `jid`, and local image `file` (relative to that JSON file). An unassigned
  image for a known account can use a null `jid`. Supply one shared map or repeat
  the option once per account, in capture order.

Importing a committed snapshot into the selected account's WAB archive is a
separate operation. The USB capture never renames a WAB contact folder.
