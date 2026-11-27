[← Back to Main Readme](../README.md)

# Prerequisites & Installation

Everything you need to get started with **WhatsApp Backup Tools (`whatsapp-backup-tools`)**.

---

## 1. System Requirements

- **Python**: Version 3.11 or later is required (Python 3.12 recommended).
- **Supported Operating Systems**: Windows 10/11, macOS (12+), and modern Linux distributions.
- **Local Storage**: Adequate free disk space for your media and extracted databases. All processing is 100% local—no data leaves your machine.

---

## 2. Installation

Follow the [fork installation steps](../README.md#step-1-install-the-tool) to select the checkout for this version. In its root directory, install with `python -m pip install .` (on Windows you can use `py -m pip install .`).

The installed commands are:

- **`wab-archiver`** reads Android and iPhone backups and organizes their media.
- **`wab-viewer`** opens the local archive viewer.
- **`wab-capture`** copies the databases, media and available contact data visible on an Android device to a dated local dump over USB. It runs on macOS or Linux.
- **`wab-prepare`** lists dumped databases and prepares a selected full crypt15 backup for a named account.
- **`wab-import`** imports prepared account snapshots into a working archive for each account on macOS or Linux.

If you have a wheel built from the fork, you can install it with `python -m pip install /path/to/file.whl`. For offline installation, keep the required dependency wheels alongside it and add `--no-index --find-links /path/to/wheels`. The [upstream project on PyPI](https://pypi.org/project/whatsapp-backup-tools/) and its [GitHub releases](https://github.com/auanasgheps/whatsapp-backup-tools/releases) provide the original distribution.

All required core packages (`flask`, `wa-crypt-tools`, `iphone-backup-decrypt`, `cryptography`) are automatically installed.

### Manual Execution (without pip)

From the same checkout, you can run the tools directly using Python:

```bash
python -m wab_archiver --help
python -m wab_viewer --help
```

When using manual execution, you must manually install required packages (`pip install flask wa-crypt-tools iphone-backup-decrypt cryptography`).

---

## 3. Platform-Specific Prerequisites

- **Android Users**:
  - To collect a raw device dump, connect an authorized USB device. To prepare a full crypt15 database for import, supply its 64-character hexadecimal end-to-end backup key.
  - **ADB (Android Debug Bridge)**: Required if using USB extraction (`wab-capture`, `--from-adb` or `--pull-media`).
  - No root is required.
  - Follow the [device dump and account preparation guide](android-archive-quickstart.md) or the [original Android archiver guide](archiver/setup-android.md).

- **iOS Users**:
  - In-app WhatsApp E2E backup must be **disabled** before making a device backup.
  - **Apple Devices App / iTunes / Finder**: Required to create a local computer backup of your device (`--ios-backup`).
  - Review the [iOS Setup Guide](archiver/setup-ios.md).

---

## 4. Third-Party Libraries & Dependencies

WhatsApp Backup Tools uses the following open-source dependencies (installed automatically via `pip` or bundled locally):

| Library | Type | Purpose | Component |
| :--- | :--- | :--- | :--- |
| [`flask`](https://palletsprojects.com/p/flask/) | Python Package | Local WebUI server (`127.0.0.1:5000`) | `wab-viewer` |
| [`wa-crypt-tools`](https://github.com/eladnava/wa-crypt-tools) | Python Package | Android `crypt12/14/15` backup decryption | `wab-archiver` |
| [`iphone-backup-decrypt`](https://github.com/johanley/iphone-backup-decrypt) | Python Package | iOS backup parsing and decryption | `wab-archiver` |
| [`cryptography`](https://cryptography.io/) | Python Package | Low-level cryptographic primitives | Archiver decryption pipelines |
| [`Pico CSS`](https://picocss.com/) | CSS (Bundled) | Semantic, zero-CDN dark/light styling | `wab-viewer` |

*(Optional)* For contributors running tests or linting (`pip install -e ".[test,lint]"`): `pytest`, `pytest-cov`, `ruff`, and `tzdata`.

---

## Next Step

👉 Proceed to the **[Archiver Guide](archiver/index.md)** to prepare your media archive.
