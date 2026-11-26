# Recover Android attachments from files saved on a Mac

Start with the standalone, decrypted Android database for one account and its matching WAB missing-media report. Close active writers before using the database. The command opens it read-only and rejects a live journal. Use the account ID and snapshot ID recorded by capture. Candidate roots can be local Mac media folders or previously extracted media. Each input remains local.

```sh
python -m wab_capture.reconcile \
  --account-id "$ACCOUNT_ID" --snapshot-id "$SNAPSHOT_ID" \
  --db "$ARCHIVE/Whatsapp Databases/msgstore.db" \
  --missing "$ARCHIVE/missing_media_report.csv" \
  --mac-media "$MAC_MEDIA" \
  --output "$WORK/audit"
```

Choose a new output directory inside an existing parent. The audit creates a private directory containing `media-map.tsv`. It prints three counts of attachment **records**:

| Count | Meaning |
|---|---|
| `with_path` | The Mac bytes match the source attachment hash and Android provides a usable relative path. |
| `without_path` | The bytes match, and the source database had an empty or null attachment path. |
| `unresolved` | Evidence is insufficient, the matching file is missing, the source path is ambiguous or unsafe, or the report and database disagree. The TSV records the reason. |

The input CSV only identifies candidate records. The database provides the plaintext SHA-256 and the actual Android path. The audit also checks pathless rows in the database because some Android queries omit them from the missing report. Omit `--missing` to check pathless rows alone. Each TSV entry identifies the account, snapshot, table, row, message, candidate path and matching evidence. A raw row ID is local to its database.

Pass `--mac-media` multiple times for separate roots. `--previous-map /path/to/attachment-map.tsv` tries candidate files from a previous reconciliation first. Legacy map entries can name absolute paths or paths relative to the map; only files inside the supplied media roots are eligible. Every positive match compares the freshly computed SHA-256 of candidate bytes to the current source database's content hash. Identical filenames, timestamps, prior message row IDs and encrypted file hashes cannot establish that match. Modified or recompressed previews usually remain unresolved.

## Prepare verified repairs

Repeat the audit with a **new** output directory and `--stage`. It writes the TSV plus:

- `supplement/Media/…` containing verified payloads in WAB's expected layout.
- `msgstore.db` when a confirmed attachment has no source path. This is a derived copy with explicit paths assigned to matched attachment rows. The original database remains available to reproduce the repair.
- `reconciliation.json` identifying the account, snapshot, original database SHA-256, optional derived database SHA-256 and every supplemental path's content hash and size.

For a managed WAB archive, stop the viewer and apply the staged bundle to the **current imported snapshot** of that account:

```sh
wab-import "$SNAPSHOT" --repair "$WORK/staged"
```

The importer checks the bundle's account, snapshot, original database fingerprint, payload sizes and hashes before publishing the change. Applying the same bundle again is safe. A successful repair keeps the verified payloads and their provenance in the local archive. Later snapshots can reuse that evidence for a pathless attachment with the same plaintext SHA-256 even when its row ID changes. An unrelated file cannot claim that association using a filename or row ID alone.

Keep the receipt with its files to reproduce the repair. For a separate manual test archive, ordinary `wab-archiver archive` accepts the original media root and the supplemental root as two `--wa-root` arguments. Pass the derived database via `--msgstore` when present. Use the same local contact export and preservation settings as the source archive. Independently verify that the recovered media opens from the intended message.
