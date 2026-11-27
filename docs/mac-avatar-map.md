# Add local Mac avatars to Android snapshots

Run this command with the Python interpreter from the WAB environment. Use the archive UUID of the account whose WhatsApp data is open on this Mac. `wab-prepare` prints the UUID after preparing a database for an account label. Supply one map per linked account. On multi-account installations use an account-specific copy whose ownership you can confirm.

```sh
python -m shared.mac_avatars --account "$ACCOUNT_UUID" --out avatar-map.json
```

The default location is `~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared`. The command reads profile images from `Media/Profile` or `Message/Media/Profile`, along with available `ChatStorage.sqlite` and `ContactsV2.sqlite` metadata. To scan a copy instead, add `--container /path/to/copied-container`. A copied SQLite database must include committed WAL contents if it was captured while WhatsApp was active. With another layout, set `--profile-dir` and optionally `--database` (ChatStorage) and `--contacts-database` (ContactsV2) explicitly.

The JSON map lists candidate image files, their digests, and any confirmed JIDs. A filename containing a full contact or group JID, or a matching profile-picture row in ChatStorage, can supply a binding. Bare digits alone do not identify an owner. A Mac LID requires an explicit phone-JID mapping in the Mac address book for automatic Android attribution. An unsupported or ambiguous identity remains unassigned. A missing Mac cache entry is not a request to remove an older avatar.

Review ambiguous entries locally. When independent evidence confirms the identity, set the entry's `jid` to the exact contact or group JID associated with that account. Add `--avatar-map avatar-map.json` when preparing an account snapshot with `wab-prepare`. This also works with a raw USB dump collected before the map existed. The snapshot retains the actual image bytes. Create a new map for each observation; map creation refuses to overwrite an existing file. Device databases, maps, snapshots, and profile pictures belong outside the Git repository.
