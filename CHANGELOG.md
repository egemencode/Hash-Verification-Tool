# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

A security and correctness revision. Several changes are deliberately
**breaking**: where backwards compatibility and a truthful verdict conflicted,
the verdict won.

### Added
- **Signed manifests, end to end.** `keygen`, `sign` and `--sign-key` make the
  Ed25519 trust path reachable from the CLI for the first time; `verify
  --trusted-key` accepts a `.pub` file or raw hex. Private keys are encrypted
  with DPAPI on Windows (`--portable` opts out, loudly).
  The tool refuses to sign with a key stored inside the scanned folder or next
  to the manifest, refuses to overwrite an existing key, and refuses to sign an
  incomplete scan. Key placement is judged on the normalised path, so an
  extended-length (`\\?\`) spelling names the same location and cannot slip a
  private key into the folder its own signed manifest describes.
  `--trusted-key` pointed at a private key file derives the public half from
  the key material rather than reading the file's `public_key` field, which is
  not covered by the DPAPI blob and could otherwise be edited on its own to
  nominate an attacker's key as the operator's trusted one.
  `sign --force` replaces a signature but first requires the existing one to
  verify: a signature that no longer checks out means the content changed after
  it was signed, and re-signing would put the operator's key behind that
  change. `keygen` removes anything it brought into existence if either half
  fails to write, so a failed run cannot leave a private key — in `--portable`
  mode, a plaintext one — lying around unreported.
- `inspect` — describe a manifest's schema, coverage and signature state
  without scanning. Unlike `verify` it also explains a *broken* signature
  instead of refusing to speak about it.
- `--follow-symlinks` on `hash` and `verify`. Off by default; targets that
  resolve outside the scanned root are still skipped. Real directories are
  always walked, and a directory *link* is followed only when its target has
  not been traversed yet — so a link can neither hide the directory it points
  at nor, in a web of mutually-linked directories, make the walk grow with the
  number of links. A directory is walked once as itself plus once per followed
  link aimed at it or an ancestor, so the worst case is bounded by the depth of
  the tree rather than by how the links are wired.
- `--allow-insecure-algorithm`, required to build an MD5/SHA-1 manifest.
- `--write-partial`, `--allow-unsigned`, `--trusted-key`.
- `core/scan_policy.py` — one decision table shared by the CLI and the GUI, so
  the graphical path can no longer be the permissive one.
- Exit codes `4` (manifest invalid), `5` (untrusted reference), `6`
  (incomplete scan), `7` (cancelled).
- `ScanState` and a `cancel` predicate for `build_manifest_for_folder` and
  `Verifier.verify`.
- **A Cancel button for the Advanced tabs, in the status bar.** One worker slot
  serves Hash, Verify and Report, so one control stops whichever is running.
  The token is polled once per file, and a cancelled run reports a distinct
  terminal state instead of arriving as a completed one — otherwise the
  completion handler described a deliberate cancel as a scan that failed and
  told the user to investigate.
- **A Cancel button on the Trust Check screen.** The cancellation machinery was
  already there — a session carries a token, the pipeline polls it at every
  stage boundary — but nothing the user could press fired it, so a scan of the
  wrong file could only be stopped by closing the window. The button is enabled
  exactly while a scan runs. Because cancellation is cooperative it shows
  "İptal ediliyor…" and waits for the worker to reach its next stage rather
  than claiming the scan is already over, and the end-state card now gives
  cancel-specific advice instead of telling someone who chose to stop that they
  should fix a problem.

### Changed
- **Risk decisions are a monotonic table, not a score.** Any VirusTotal
  detection is at least MEDIUM, a hash mismatch is HIGH, and positive signals
  (a valid signature, a matching fingerprint) carry zero weight — they can no
  longer cancel out a detection.
- **Signature verification happens inside the normal load→verify flow and
  fails closed.** An unsigned or self-signed manifest no longer exits `0`.
- MD5/SHA-1 comparisons report `collision_prone_algorithm`, never
  `trusted_match`, and print a caveat next to the result.
- **ProgressEvent contract**: the denominator comes from the same file list the
  loop iterates (previously a second, independent walk, so a file created in
  between pushed `done` past `total`), and exactly one terminal event is always
  emitted — including for an empty folder.
- MD5/SHA-1/SHA-256 are computed in one pass, with the metadata snapshot taken
  from the same file descriptor as the bytes.
- User data moved to `%LOCALAPPDATA%\HashTool\`; all writes are atomic and a
  corrupt store is quarantined rather than emptied.
- The VirusTotal API key is stored with DPAPI; legacy plaintext copies are
  migrated and scrubbed.

### Fixed
- A Tk geometry-manager conflict prevented the app from opening at all.
- Folder scans followed junctions, so a link could pull files from anywhere on
  the disk into the manifest.
- `hash --file X --output X` overwrote the file it was asked to fingerprint.
- The single-file `--output` path read the file twice, so the printed digest
  and the stored one could describe different bytes.
- An incomplete scan wrote a manifest to the expected path, where everything it
  missed would verify as "unchanged" forever.
- A superseded or cancelled GUI scan could render its verdict under a different
  file; three scheduled-callback leaks produced Tcl errors on teardown.
- Closing the window during a folder hash abandoned the worker thread. That
  thread is what writes the manifest — it calls `save()` itself — so walking
  away from a scan still produced a reference file on disk. The window now
  cancels the worker and waits for it, bounded.
- Drag-and-drop decoded paths as UTF-8 with `errors="replace"`, turning
  filenames NTFS accepts (unpaired surrogates) into paths that do not exist.
  The drop hook now asks the library for `DragQueryFileW`, so a path arrives as
  text and no code-page round trip happens at all. When a library build hands
  back bytes anyway they are read as the active code page first and only then
  as UTF-8 — some ANSI sequences are also well-formed UTF-8 and name a
  *different* file that exists, so the order decides which file the drop means.
  Decoding can no longer raise either: the exception unwound into the ctypes
  callback, skipping `DragFinish`, and the drop did nothing at all.
- Spreadsheet formulas in CSV reports are neutralised.
- The Authenticode check resolves `powershell.exe` through the Win32 API only —
  no PATH fallback, no `-ExecutionPolicy Bypass`.

### Tests
- 37 → 530, no skips. Verified on a cp1254 console with `PYTHONUTF8` and
  `PYTHONIOENCODING` unset, and under explicit UTF-8.
- `tools/verify_fix_coverage.py` reverts each fix in a scratch copy and requires
  the test that claims to cover it to fail, so a test that asserts nothing is
  caught rather than counted.

## [1.2.0] — 2026-04-20

### Added
- **Trust Check** — the main GUI surface is now a single-file "Güven
  Kontrolü" screen that hashes a file, queries VirusTotal by SHA-256 (the file
  is never uploaded), checks the Windows Authenticode signature, compares
  against a local fingerprint store and presents a plain-Turkish risk summary.
- The original Hash / Verify / Report tools moved under a "Gelişmiş" tab.
- New core modules: `file_info`, `vt_client`, `signature_checker`,
  `local_verify`, `risk_engine`, `smart_summary`, `history_manager`,
  `trust_report`, `trust_pipeline`.
- New GUI views: `trust_check_view`, `history_view`, `settings_view`.

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
