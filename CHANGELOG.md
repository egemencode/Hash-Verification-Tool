# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and this project
follows [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-04-20

### Added
- **Live progress reporting** during folder hashing and verification.
  - GUI: determinate progress bar + status line (`Hashing [42/500]  path/to/file`).
  - CLI: debug-level log line per file when run with `-v`.
  - New `core.hash_utils.ProgressEvent` dataclass and `count_files()` helper.
- **GUI language toggle** under *Settings → Language* (Türkçe / English).
  - Live UI rebuild — no app restart needed.
  - Preference persisted to `hashtool_settings.json` next to the executable.
- `gui/i18n.py` — translation dictionary with English fallback.
- `utils/settings.py` — tiny JSON-based settings store.
- `LICENSE` (MIT) and `CHANGELOG.md` files.

### Changed
- `build_manifest_for_folder` and `Verifier.verify` now accept
  `on_progress: Callable[[ProgressEvent], None]`. The callback fires
  after every file (success or error), so the denominator/numerator
  are always consistent for UI bars.
- GUI worker thread now emits typed messages via a queue, letting the
  Tk event loop render progress without blocking.
- `utils/logger.py` guards against `sys.stderr is None` so the
  `--noconsole` GUI build no longer crashes on the first log call.

### Tests
- 23 unit tests (up from 18): new coverage for `count_files`,
  `ProgressEvent.percent`, and progress-callback behaviour in both
  `build_manifest_for_folder` and `Verifier.verify`.

## [1.0.0] — 2026-04-20

### Added
- Initial MVP release.
- CLI (`main.py`) with three subcommands:
  - `hash`   — compute digest of a file or every file under a folder,
    saving a JSON manifest.
  - `verify` — re-scan a folder and classify entries as
    `unchanged / modified / new / missing / error`.
  - `report` — convert a JSON report to CSV (or vice versa).
- Algorithms: MD5, SHA-1, SHA-256 (default).
- 64 KiB chunked file reads so multi-GB files do not exhaust RAM.
- JSON manifest schema with algorithm, size, mtime per entry.
- Verification reports in console, JSON or CSV.
- Tkinter GUI (`gui_main.py`) with three tabs mirroring the CLI.
- End-to-end demo script (`demo.py`).
- 18 unit tests covering hashing, manifest round-trip and verifier logic.
- Windows build scripts producing single-file executables:
  - `build_exe.bat`       → `dist/HashTool.exe` (CLI, ~8 MB)
  - `build_gui_exe.bat`   → `dist/HashToolGUI.exe` (GUI, ~12 MB)
