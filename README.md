# Hash Verification Tool

A small, dependency-light Python tool for generating and verifying
cryptographic hashes of individual files or whole folder trees.
Ships with a **command-line interface**, a **Tkinter GUI** and
pre-built **single-file Windows executables** — designed for integrity
checks, backup validation, basic forensic workflows and as a clean
reference project for portfolio / learning purposes.

> **Status:** v1.1.0 — stable. CLI + GUI, live progress reporting,
> bilingual UI (Türkçe / English), 23 passing unit tests.

---

## What's new in v1.1.0

- **Live progress reporting** during folder hashing and verification
  (determinate progress bar in the GUI, per-file debug log in the CLI).
- **GUI language toggle** under *Settings → Language* — switch between
  Türkçe and English without restarting. Preference is persisted next
  to the executable.
- **Windows installers**: `dist/HashTool.exe` (CLI) and
  `dist/HashToolGUI.exe` (GUI) — no Python install required to run.
- New `ProgressEvent` callback hook on the core API so any future
  front-end can show progress too.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

---

## Features

- Hash a single file or recursively hash every file under a folder
- Algorithms: **MD5**, **SHA-1**, **SHA-256** (default: `sha256`), **SHA-512**
- Saves a structured **JSON manifest** with relative path, hash,
  algorithm, size and last-modified time per file
- Re-verifies a folder against an existing manifest and classifies
  every file as **unchanged / modified / new / missing / error**
- Exports the verification report as **JSON** or **CSV**
- Streams files in 64 KiB chunks so multi-GB files do not exhaust RAM
- Live progress reporting via a typed `ProgressEvent` callback (GUI
  progress bar, CLI `-v` debug lines, or your own consumer)
- Bilingual GUI (Türkçe / English) with on-the-fly language switch
- Robust error handling: missing files, permission errors, broken
  manifests and I/O failures are reported, not crashed on
- Optional ANSI colour output (degrades gracefully if `colorama` is
  not installed or stdout is not a TTY)
- Lightweight logging to `logs/hash_tool.log`

---

## Project Layout

```
Hash Verification Tool/
├── main.py                  # CLI entry point (argparse)
├── gui_main.py              # GUI entry point (thin wrapper)
├── core/
│   ├── __init__.py
│   ├── hash_utils.py        # Streamed hashing + ProgressEvent + count_files
│   ├── manifest_manager.py  # Manifest dataclass + JSON I/O
│   ├── verifier.py          # Compare live folder vs manifest
│   └── reporter.py          # Console / JSON / CSV reporting
├── gui/
│   ├── __init__.py
│   ├── app.py               # Tkinter app (threaded worker + queue)
│   └── i18n.py              # Translation dictionary (TR / EN)
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Logging helper (GUI-safe)
│   └── settings.py          # JSON-backed settings store
├── tests/
│   ├── test_hash_utils.py
│   ├── test_manifest_manager.py
│   └── test_verifier.py
├── demo.py                  # End-to-end demo scenario
├── build_exe.bat            # Build dist/HashTool.exe (CLI)
├── build_gui_exe.bat        # Build dist/HashToolGUI.exe (GUI)
├── requirements.txt
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Installation

Requires **Python 3.10+** (uses PEP 604 `|` type unions and modern
typing). Tested on Windows 11.

```powershell
# 1. Clone or download the project, then:
cd "Hash Verification Tool"

# 2. (Recommended) create a virtualenv
python -m venv .venv
.venv\Scripts\activate

# 3. Install runtime dependencies (just colorama)
pip install -r requirements.txt
```

That's it — everything else (Tkinter, hashlib, json, csv) is in the
standard library.

### Don't want to install Python?

Pre-built single-file Windows executables are published on the
**[GitHub Releases](../../releases)** page of this repository
(not committed into the repo itself — binary files belong in Releases).

| File                   | Purpose | Approx. size |
|------------------------|---------|--------------|
| `HashTool.exe`         | CLI     | ~8 MB        |
| `HashToolGUI.exe`      | GUI     | ~12 MB       |

Both are single-file PyInstaller builds — no installer, no registry
changes. Delete the file to uninstall.

---

## Usage — GUI

```powershell
python gui_main.py
# or double-click dist\HashToolGUI.exe
```

The GUI has three tabs that mirror the CLI:

1. **Hash** — pick a file or folder, choose an algorithm, save a
   manifest. A determinate progress bar + status line
   (`Hashing [42/500]  path/to/file`) shows live progress on big folders.
2. **Verify** — pick a folder and a manifest, see every file classified
   by status with colour coding (green = unchanged, orange = modified,
   blue = new, red = missing, grey = error).
3. **Report** — convert a saved JSON report to CSV or vice versa.

Switch the UI language on the fly from **Settings → Language** (Türkçe
or English). The choice is saved to `hashtool_settings.json` next to
the script / exe and restored on the next launch.

---

## Usage — CLI

The CLI exposes three subcommands: `hash`, `verify`, `report`.

```powershell
python main.py --help
python main.py hash --help
python main.py verify --help
python main.py report --help
```

### 1. Hash a single file

```powershell
python main.py hash --file "C:\example\file.txt"
python main.py hash --file "C:\example\file.txt" --algo sha1
python main.py hash --file "C:\example\file.txt" --output single.json
```

When `--output` is omitted you get a one-liner on stdout
(`<algo>  <digest>  <path>`). With `--output` you get a manifest JSON
that contains the same metadata as a folder scan.

### 2. Hash an entire folder

```powershell
python main.py hash --folder "C:\example_folder" --algo sha256 --output manifest.json
python main.py -v hash --folder "C:\example_folder" --output manifest.json
```

The folder is walked recursively and each file is added to the
manifest. Files that cannot be read (permission, missing during scan,
etc.) are skipped with a warning rather than aborting the run. Pass
`-v` for per-file debug lines (live progress in the terminal).

### 3. Verify a folder against a manifest

```powershell
python main.py verify --folder "C:\example_folder" --manifest manifest.json
python main.py verify --folder "C:\example_folder" --manifest manifest.json --show-details
python main.py verify --folder "C:\example_folder" --manifest manifest.json --report report.json
python main.py verify --folder "C:\example_folder" --manifest manifest.json --report report.csv
```

Exit codes are CI-friendly:
- `0` — folder matches the manifest
- `1` — differences detected (modified / new / missing / errors)
- `2` — bad arguments
- `3` — unrecoverable failure (manifest broken, folder missing, …)

### 4. Convert a saved JSON report to CSV (or vice versa)

```powershell
python main.py report --input report.json --format csv
python main.py report --input report.json --format csv --output report.csv
```

### 5. Quick end-to-end demo

```powershell
python demo.py
```

`demo.py` builds a small folder under `demo_data/`, hashes it,
deliberately tampers with it, then re-verifies — so you can see all
five status categories light up in one run.

---

## Manifest Format

Manifests are plain JSON, easy to diff in version control:

```json
{
  "metadata": {
    "schema_version": "1.0",
    "tool_version": "1.1.0",
    "created_at": "2026-04-20T12:34:56+00:00",
    "algorithm": "sha256",
    "root_path": "C:/example_folder",
    "file_count": 3
  },
  "entries": {
    "docs/readme.txt": {
      "hash": "9f86d081...",
      "algorithm": "sha256",
      "size": 1024,
      "mtime": 1714478096.512
    }
  }
}
```

Paths are always stored with forward slashes so the same manifest can
be verified on Windows and POSIX systems.

---

## Progress callback (for embedders)

Both `build_manifest_for_folder` and `Verifier.verify` accept an
optional `on_progress` callback so a host application can render a
progress bar:

```python
from core.hash_utils import ProgressEvent, count_files
from core.manifest_manager import build_manifest_for_folder

root = "C:/example_folder"
total = count_files(root)

def on_progress(ev: ProgressEvent) -> None:
    print(f"[{ev.done}/{ev.total}] {ev.percent:5.1f}%  {ev.path}")

manifest = build_manifest_for_folder(root, algorithm="sha256",
                                     on_progress=on_progress)
```

`ProgressEvent` carries `done`, `total`, `path` and a computed `percent`
property. The callback fires after every file (success *or* error) so
the numerator and denominator always stay consistent.

---

## Why SHA-256 by default?

- **Collision-resistant in practice.** No public collisions exist for
  SHA-256, while MD5 has been broken since 2004 and SHA-1 since 2017
  (Google's SHAttered).
- **Standardised.** SHA-256 is part of NIST's SHA-2 family and is the
  baseline integrity primitive used by TLS certificates, Bitcoin,
  Linux package managers, Git's modern object format and most
  forensic tools.
- **Fast enough.** On modern CPUs the bottleneck is disk I/O, not
  hashing.

### When *might* you still want MD5 / SHA-1?

Only for **non-security-critical** parity checks — comparing a backup
to its source on a trusted system, deduplicating files, etc. Both are
considered cryptographically broken and **must not** be used to prove
that a file was not tampered with by an adversary.

The tool keeps MD5 and SHA-1 available so you can validate downloads
that still publish those legacy checksums, but the default is
deliberately the safe choice.

---

## Building the executables yourself

```powershell
# CLI
build_exe.bat           # produces dist\HashTool.exe

# GUI (no console window)
build_gui_exe.bat       # produces dist\HashToolGUI.exe
```

Both scripts install PyInstaller on first run if it is missing and
clean up previous build artefacts before each build.

---

## Running the tests

```powershell
python -m unittest discover -s tests -v
```

The test suite is pure standard library — no extra dependencies
needed. 23 tests covering hashing, manifest round-trip, verifier
classification, `count_files`, `ProgressEvent.percent` and the
progress-callback behaviour on both folder hashing and verification.

---

## Roadmap (post-v1.1 ideas)

- Parallel hashing for huge folders (process pool)
- Glob-based include / exclude rules (`--exclude "*.tmp"`)
- HMAC mode for keyed integrity verification
- Signed manifests (Ed25519) for tamper-evident reports
- Watch mode (`--watch`) using `watchdog`
- Drag-and-drop support in the GUI
- macOS / Linux GUI builds (the code is already platform-agnostic;
  only the build scripts are Windows-specific)

---

## License

Released under the [MIT License](LICENSE). No warranty — verify before
relying on it for anything safety-critical.
