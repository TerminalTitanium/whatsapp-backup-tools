# Android USB dumps and account snapshots

## Capture from a phone

On macOS or Linux, connect an unlocked Android device and authorize USB debugging for this computer. Use the same device label each time.

```sh
wab-capture --root "$HOME/WhatsApp-Archive" --device android-phone-note9
```

Capture makes a dated device dump under `sources/<device>/snapshots/<UTC>_device/`. It inventories accessible WhatsApp database and media directories, including nested account layouts inside the standard and Business packages. Default search roots are `/sdcard/Android/media/com.whatsapp`, `/sdcard/Android/media/com.whatsapp.w4b`, `/sdcard/WhatsApp` and `/sdcard/WhatsApp Business`. It records every regular file recursively inside the discovered `Databases` directories, regardless of its name, suffix, or encryption format. This is a dump of the WhatsApp files exposed to ADB on shared storage. Private app storage and chats that have not been backed up are outside that scope. Use `--serial SERIAL` to select a connected phone or repeat `--phone-root ANDROID_DIRECTORY` to select specific roots.

The final `RAW COMPLETE` line reports the capture counts. The raw manifest records the original Android paths, sizes, SHA-256 digests and storage locations. The dump retains separate observations for files with identical bytes under different paths. A matching digest can prove that two copies contain the same encrypted data. Only independent evidence can connect that data to a particular account.

Media are stored once per device in `sources/<device>/media/`. If the phone reuses a path for different bytes, `media-versions/` preserves the alternative. This also covers Android names that collide on a case-insensitive Mac volume. Normal capture lists file metadata. It reuses an observed local file when the remote path, size, timestamps and inode and the local file metadata still match. New files are hashed on the computer. Older captures without a metadata record and changed files with existing local copies can require an individual checksum. Repeat the command with `--verify-media` for a full content check, including changes that preserve metadata. A deleted phone file remains in the local store. The contact export is saved when available. See `sources/<device>/logs/` for the session log.

## Select an account's database after capture

Capture prints the full dump path and a ready-to-run `wab-prepare … --list` command at completion. The phone may be disconnected.

```sh
wab-prepare "$RAW" --list
wab-prepare "$RAW" --database "$DATABASE" --account personal
```

Set `DATABASE` to the original Android path in the final column of a `full` row. `unassigned` indicates that no confirmed owner is registered for those bytes. The operator assigns the human-readable account label; reuse it on later dumps. An existing archive's UUID can also be supplied. Use `--known-backup FILE` to compare captured entries against the exact encrypted backup file previously identified for the account. A unique matching full database can be selected using that option alone. With more than one match, supply an explicit `--database` and keep `--known-backup` to verify the choice. Phone slot, directory number, file size and successful key verification alone do not establish account ownership.

For a different encrypted file, `wab-prepare "$RAW" --database "$DATABASE" --compare-history "$PREVIOUS_DB" --key-file "$KEY_FILE"` compares outgoing messages with those in a known, decrypted `msgstore.db`. It counts matches in the same direct chats. This comparison makes no account assignment. An empty result leaves ownership open.

Preparation authenticates a full crypt15 database with its 64-character hexadecimal key and saves that key beside the prepared account database. Use the hidden prompt, or pass `--key-file FILE` with one key. Supply any confirmed crypt15 increments explicitly, in chain order, using repeated `--increment` arguments. Use contiguous sequence numbers starting at 1 from the same original directory and filename generation as the selected base. The operator confirms they belong together. Raw capture retains crypt14 and other files even when preparation cannot use them.

The command prints the permanent account UUID and the path to a separate account snapshot. Add `--avatar-map FILE` during preparation to include account-matched Mac avatars. To prepare another account from the same device dump, select its full database and account label. If WhatsApp only exposes its database after an account switch, capture another dump after its in-app backup finishes. The previous observations remain available.

## Import an account snapshot

```sh
wab-import "$SNAPSHOT"
wab-viewer "$ARCHIVE"
```

`SNAPSHOT` is the path printed by preparation. `ARCHIVE` is the path reported by import, under `wab/<account-uuid>/`. Close the account's viewer before a full import, use completed snapshots in capture order and keep both `sources/` and `wab/` when moving the collection. The raw device capture can be revisited to prepare another database later. [Mac operator guide](../android-archive-quickstart.md)
