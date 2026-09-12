# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and this project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing here changes the product. It changes what the test suite is able to
claim, which turned out to be less than it looked.

### CI, and what it found immediately
- `.github/workflows/gate.yml` runs the gate on a GitHub Windows runner,
  started by hand rather than by a push: a gate is several full suite runs by
  definition and private-repository Windows minutes bill at twice the
  wall-clock. It describes the machine before judging anything, and on failure
  uploads whatever temp directories the suite left behind.
- Its first run turned **620 green tests here into 13 failures and a skip
  there**, on identical product code. Ten of the thirteen were one pattern:
  test hooks comparing a path by its *string*.

### Paths are not their spelling
- Six sites wrote `str(self_path) == str(target)` to recognise a file. The
  product normalises deliberately — `ScanController.select` stores
  `Path(p).resolve()`, the scanner resolves its root before walking — so on a
  machine whose temp directory is reachable by an 8.3 short name the hooks
  never matched. Eight tests describing an *incomplete* scan were measuring a
  complete one; the TOCTOU test that swaps a file mid-read never swapped it.
- `tests/support.py` gained `same_path()` (identity via `os.path.samefile`:
  volume and file index, which no spelling can change) and `deny_reads_of()`
  (a read denial that **raises if it never fired**, so a fixture that quietly
  stops working cannot keep reporting success). All six sites converted. No
  product code touched.
- Found while fixing that, and not by CI, which reported it as a pass:
  `assertNotEqual(selected_path, str(a))` succeeds on a spelling difference
  even when the selection really is `a`. The negative form is the one that
  rots silently.
- `tools/run_suite_gate.py --odd-temp` hands the suite a second spelling of
  `TEMP`, reproducing the runner's condition on any machine. Measured both
  ways: the pre-fix files fail exactly the ten tests CI reported; the fixed
  ones pass. This class of defect no longer needs a second machine to find.

### Skips are machine-specific, and so was the zero-skip rule
- The drag-and-drop ANSI test skipped on the runner claiming "no ANSI code
  page". The runner has one — cp1252 — it just has no `ş` or `ı`. It now picks
  a name the machine's code page can spell whose bytes are still invalid
  UTF-8, and fails rather than skips if no candidate fits.
- The suite holds 68 skip sites. None fire here, which is why the gate reports
  "0 skipped"; the claim was always "this suite does not skip **on this
  machine**". Recorded as item 13 in `docs/P1-BACKLOG.md` rather than fixed
  wholesale.

### Verified on the runner
- The second CI run turned 13 failures into **3**, and the skip is gone: 627
  tests ran there, none skipped. The ten path-identity fixes hold on the
  machine that found them.
- Backlog item 7 has its evidence at last. This desktop cannot create a file
  symlink (`WinError 1314`, Developer Mode absent from the registry, measured
  again), so the containment test had only ever exercised its directory-junction
  branch here. The runner can, and the test passed there — the rule that a link
  cannot pull content in from outside the scanned root is now checked for real
  file symlinks, not only for junctions.

### Fixed: the tool was discarding its own diagnosis
- `signature_checker` kept only the *first line* of a failing PowerShell's
  stderr. PowerShell spreads an error over several lines and puts the useful
  half after the first, so the message a user saw stopped mid-sentence. This is
  how it reached CI:

      PowerShell hatası: Get-AuthenticodeSignature : The
      'Get-AuthenticodeSignature' command was found in the module

  The clause naming why the module could not be loaded — the only part that
  identified the machine's problem — was thrown away by us, not by the log.
  `_error_summary()` now joins the explanatory lines, stops at PowerShell's
  console furniture (`At line:`, `+`, `CategoryInfo`) and bounds the result, so
  the message stays one readable line and says what happened.

### Still open
- Signature checking does not work at all on the runner: PowerShell cannot load
  `Microsoft.PowerShell.Security`. The tool fails closed — it reports ERROR, not
  "unsigned" and not "valid" — so no verdict is wrong, but the feature is
  absent there. Two causes were proposed and **both were measured and refuted**:
  execution policy (`Restricted` still works here) and `PSModulePath` (emptying
  it or pointing it elsewhere still works). The deliberate decision to run
  without `-ExecutionPolicy Bypass` was left standing rather than reverted on a
  guess. Item 14; the next CI run will carry the full message.
- The three tests are left failing there on purpose. Loosening them to pass
  would hide a real environmental limitation.

## [2.1.0] — 2026-09-12

The application became one screen. Everything a first-time user needs is now in
a single window — drop a file, read the verdict — and everything technical
moved out of the way without being removed.

### Changed
- **The four tabs collapsed to one screen.** Trust Check fills the window;
  History, Settings and the power-user Hash/Verify/Report tools moved to a
  Tools menu that opens each in its own window, hidden until asked for. No
  feature was removed — every one is a click away.
- **The main screen hides what a beginner does not need.** The SHA-256
  fingerprint, the save/export buttons and the per-check detail tabs now sit
  behind one "İleri" toggle. The first screen is: pick a file, read the verdict.
- **A modern Windows 11 look.** Widget styling now comes from the Sun Valley
  theme (`sv-ttk`) — rounded buttons, a real accent action, proper dark/light
  surfaces — while the app keeps the text, risk and badge colours it measured
  for contrast. `sv-ttk` is optional; the app falls back to its own styling if
  it is missing, and the GUI build bundles it with `--collect-data sv_ttk`.
- `ScanController`'s state enum was renamed `ScanState` → `ControllerState` so
  it no longer shadows the scan-progress `ScanState` in `core.hash_utils`. Enum
  values are unchanged, so nothing serialised moves.

### Fixed
- **Logs are written where they persist.** The log file moved from an
  exe-adjacent `logs/` dir — which in a PyInstaller onefile build is a temporary
  `_MEI` directory that vanishes on exit — to the per-user data dir the settings
  already use (`%LOCALAPPDATA%\HashTool\logs`), with a source-adjacent fallback.

## [2.0.0] — 2026-08-20

A security and correctness revision. Several changes are deliberately
**breaking**: where backwards compatibility and a truthful verdict conflicted,
the verdict won.

The major number moves because of that, not because the release is large. A
script that ran `verify` against an unsigned manifest and checked for exit `0`
stops working here — the exit code is `5` now, and that is a change to the
contract, not a bug fix. Calling it 1.3.0 would have been the quiet choice and
the wrong one.

Built and checked as an executable, which is new: `tools/verify_exe_smoke.py`
runs twelve behaviours through `dist\HashTool.exe` and through the source
side by side, and opens `dist\HashToolGUI.exe` to read the version out of its
own title bar. The build that shipped before this one answered `--version`
with the same string as this one while lacking `keygen`, `sign`, `inspect`,
the MD5 refusal and the unsigned-manifest refusal entirely — so the harness
now requires an executable to report the version its source tree declares.

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
- **Signing from the Hash tab.** Every manifest the GUI produced was unsigned,
  and an unsigned manifest proves nothing on its own: whoever can change the
  files can change the reference too. The signing key goes through the same
  decision table the CLI uses, so a key stored inside the scanned folder or
  beside the manifest is refused here as well — the table existed, the
  graphical path simply had not been consulting it. The key is resolved before
  hashing starts (an unreadable key costs nothing and is reported, rather than
  discovered after the scan and quietly turned into an unsigned manifest the
  user believes is signed), the signature is applied before the file is written
  and only for a complete scan, and the result names the matching `.pub` so the
  recipient can actually check it.
- **A trusted-key field on the Verify tab.** `SignatureState.TRUSTED` — the only
  state in which a match says "these files are what the holder of that key
  published" — needs a trusted public key, and the GUI passed none, so its badge
  could never read better than "signed, but the source is not verified". The
  screen said as much and told the user to go and use the CLI. It takes the same
  inputs `--trusted-key` does: a `.pub` file, a private key file (the public
  half is derived, never read from the file's own field), or raw hex. The key is
  checked when the manifest is loaded rather than after the scan, so an
  untrustworthy reference does not cost a full hash of the tree first, and a key
  file that cannot be read is reported instead of falling back to an untrusted
  comparison whose screen looks like a successful one.
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
- **The default screens now speak the language the menu offers.** Choosing
  English translated the menu, the tab captions and the Advanced tabs, and left
  everything under them in Turkish: Trust Check, History and Settings contained
  no lookups at all between the three of them. The menu therefore described a
  language the application did not have, which is the same defect as the
  warning that once told users to press a "Remove key" button that did not
  exist. All three screens are translated, including the strings they compute
  rather than lay out — the risk badge, the signature and local-record
  verdicts, the VirusTotal columns and every dialog. The privacy sentence is
  the one statement that now exists in two places, and a test holds the Turkish
  copy identical to the one `core/trust_pipeline.py` states.

- **The verdict itself now reads in the chosen language.** Translating the
  screens left the sentence the tool exists to produce — the headline above the
  risk badge, the bullets under it, the advice line and the evidence rows —
  composed in Turkish by `core/risk_engine.py` and `core/smart_summary.py`. An
  English user got an English interface and a Turkish judgement.

  The core still does not translate. It returns a `core.phrases.Phrase`: which
  sentence is true, plus the values that belong in it. The words are chosen by
  the presentation layer, which is the one that already knows the language.
  That keeps the split the codebase was built around — `gui/trust_presenter.py`
  exists so the wording and the decision rules can be tested apart, and the
  risk engine is a decision table rather than a score.

  Exported reports follow: JSON and HTML are written in the language the user
  was working in, down to the document's `lang` attribute, and every finding
  carries both spellings — the words a person reads and the key a program can
  match on, because a translated sentence is not a stable identifier.

- **Everything the application chooses to say is now translated.** The policy
  notices that refuse or qualify a hash request, the prompts asked before a
  fingerprint replaces the stored one, what the local record says about a
  file, the progress line during a scan, and the "this file changed while it
  was being scanned" finding.

  The boundary is deliberate and stated: text the application *chose* is
  translated; text that relays what the operating system, the filesystem or a
  remote API reported is not. A diagnostic naming a `PermissionError` loses
  what makes it useful if it is rephrased, and several are raised from the
  signing and key paths where editing for wording alone is a poor trade.

  These render themselves at the point of use rather than returning an
  unrendered phrase like the verdict does, because they are consumed in the
  same breath they are produced and `main.py` prints them to stderr with no
  presenter to hand them to. `PolicyNotice.message` stayed the plain string
  every existing caller already read, so the CLI and the Hash tab needed no
  changes at all.

  The translation table moved from `gui/i18n.py` to `core/i18n.py` for this:
  `core/scan_policy.py` holds the rules both front ends obey, and a core
  module importing `gui` to reach `t()` would invert the dependency that file
  exists to avoid. `gui/i18n.py` re-exports, so every view import is unchanged,
  and the CLI never selects a language — its output is byte-identical to
  before.

### Changed
- **The window follows the system theme.** There is a second palette now, and
  it is a second set of decisions rather than an inversion: almost none of the
  light colours survive on a dark ground. Which surface is the difficult one
  flips too — dark text struggles on the darker surface, light text on the
  lighter one — so each palette is measured against its own hardest ground
  rather than against a fixed colour, in both directions, by the contrast
  tests.

  The accent was the sharp edge. The light accent carries white text at
  5.38:1; the dark accent carries white at **2.01:1**, which is unreadable,
  and black at 10.47:1. So the foreground the accent pairs with is part of the
  palette rather than a literal, and the test checks each accent against its
  own. A test written against `"#ffffff"` would have passed the light theme
  and shipped an illegible primary button in the other one.

  Widgets ttk styling cannot reach are painted explicitly: the log areas are
  plain `ScrolledText`, which is a Text in a Frame with a Scrollbar and keeps
  the Windows defaults whatever the theme says. On light that was invisible —
  the defaults happened to match. The menu *bar* stays light: on Windows it is
  drawn by the OS and ignores what Tk is told, which is a limitation named
  here rather than papered over.
- **The window is built on `clam` instead of `vista`.** `vista` is what Tk
  reaches for on Windows and it draws Windows 7-era chrome: cramped tabs,
  buttons with no real padding, and a primary action distinguishable from the
  rest only by bold text. The look is now built rather than inherited — flat
  surfaces, one spacing step, a tab that shows which one is selected, and the
  accent spent on exactly one control per screen. `gui/theme.py` owns both the
  palette and the chrome, so a colour and the ground it must be legible against
  cannot be edited in different files. If `clam` is missing the earlier chain
  still applies: a visual preference is not worth failing to open over.
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
- **The summary box drew black text on whatever ground the theme gave it.**
  It took its background from the palette and its foreground from Tk's
  default. On the light theme that was invisible luck; on the dark one it is
  black on charcoal, in the box that holds the reason for the risk verdict.
  Nothing had ever compared a widget's two ends to each other, so the palette
  could be spotless and every ground known while this sat in the middle of the
  main screen. There is now a check that walks every widget in both themes and
  requires its text to be readable against its own background.
- **Part of the verdict was hidden at the smallest window size.** The summary
  bullets sat in a box four lines tall, and Tk does not report the lines that
  do not fit — it stops drawing them, with nothing on screen to say so. At the
  880-pixel minimum the window allows, the longest summary lost one line in
  Turkish and two in English. What went missing was not decoration: the
  bullets are the evidence for the risk level above them, so the screen showed
  a verdict while withholding part of the reason for it. The box now grows to
  what the sentences need and re-measures when the window is resized. Found by
  measuring the rendered card rather than by reading the code — the suite, the
  gate and the coverage harness all passed while it was there, because none of
  them makes the window small and looks.
- **A finished Hash / Verify / Report run could be discarded silently.** The
  poll drained the worker's queue and then asked whether the thread was still
  alive. The worker queues its terminal message and *then* returns, so a drain
  that came up empty a moment earlier says nothing about whether one arrived
  since — and in that window the run was treated as having nothing to report.
  The status line read "Hazır.", the tab stayed empty, and because finishing
  also drops the reference to the worker the message was gone for good. A hash
  run in that window wrote its manifest and said nothing; a failed run was
  reported as a normal finish, which is the worse half. The poll now looks
  once more after finding the thread gone. Trust Check never had this: its
  poll asks the controller whether the scan is still current rather than
  asking the thread whether it is still alive.
- **"Test Key" could report a verdict about a key you had already replaced.**
  Paste a key, press Test, notice it is wrong, paste the right one, press Test
  again: two lookups are in flight and whichever finishes last writes the
  screen. The older one usually does — it started earlier — so the screen
  settles on "the key was rejected" about a key that is no longer in the
  field. Settings ran its lookup on a bare thread with no notion of which
  request was current, and handed the answer back with a cross-thread
  `after()` that Tkinter refuses unless the main loop happens to be running
  and that raises outright on a destroyed window. Background work now goes
  through `core/task_runner.py`: identity, a cancel token, a bounded join, and
  delivery through a queue drained on the thread that owns the widgets. A
  superseded answer is refused on arrival, which is the only guarantee
  available — cancelling cannot interrupt a request already in flight.
  The Advanced tabs and Trust Check keep their own machinery for now; folding
  all three into the runner is a separate piece of work.
- **The drop-zone sentence lost its last word.** The label wrapped at a fixed
  820 pixels while its column was narrower than that, and the failure mode of a
  `wraplength` guess that is too generous is not "wraps late" — the text is
  laid out as one long line and the container cuts it at its edge, with nothing
  to say so. 86 pixels were missing in Turkish and 8 in English. It now wraps
  at the width the layout actually gives it, which also survives a resize. The
  English screen is what exposed this, but the language it hurt most was the
  original one.
- **Colours the interface drew text in were illegible.** Measured against white
  the neutral badge was 2.68:1 — the "Taranıyor…" state, on screen during every
  scan — with the medium-risk orange at 3.08:1 and the modified-file orange at
  3.79:1, where WCAG AA asks 4.5:1 for body text. A risk indicator nobody can
  read is worse than none: it occupies the place the warning was meant to be.
  White turned out to be the wrong yardstick: ttk paints most of the window
  with `SystemButtonFace` (`#f0f0f0`), and every ratio measured against white
  is an upper bound on what is actually on screen. Against the real surface the
  repaired orange was still 4.39:1 and the low-risk green sat exactly on 4.50.
  The palette is now derived against the darker of the two real grounds, so it
  holds on both, and the surfaces are read back from the live ttk style by a
  test rather than assumed.
- Colours and fonts were literals in four view modules — eleven colours in
  twenty-eight places, the risk palette written out twice — so the two copies
  could drift apart with nothing to notice, and "fix the contrast" had no
  single place to happen. They now come from `gui/theme.py`, and the contrast
  of every colour a screen renders is recomputed from the WCAG formula by
  `tests/test_gui_theme_contrast.py`.
  Consolidating them moved a colour that was already legible: hint text went
  from `#666666` to `#616161`, because it and the "unknown" grey differed by
  five units and no eye separates those. Font sizes are unchanged.
- The exported HTML report carried a third copy of the risk palette, so
  repairing the on-screen colours made the same verdict render in two different
  shades depending on whether you read it in the window or in the report saved
  from that window. It cannot import the GUI theme without inverting the
  layering, so a test keeps the two in step instead — and while there, the
  report's own `.sev-warn` (3.08:1) and de-emphasised `.weight` (3.54:1) were
  brought up to AA as well.
- `tools/verify_fix_coverage.py` counted a revert as proven whenever the test
  run exited non-zero — which `unittest` also does for a test it cannot find.
  A renamed or misfiled test therefore left an entry green while protecting
  nothing, and one had: the verify-side terminal-event test lived in the wrong
  class, so its entry had never once run the test it named. The harness now
  requires the named test to pass against unmodified code before the revert is
  applied.
- **Settings could silently undo a language you had already switched to.** The
  value lived in three places and the menu switch updated two of them, so the
  Settings tab was rebuilt holding the previous language; the next save — even
  one made to change something else entirely — wrote it back and switched the
  UI to it.
- **A stored VirusTotal key that could not be decrypted could not be removed.**
  An ordinary save preserves such a token on purpose, because treating
  "undecryptable" as "absent" once destroyed a user's only copy; but the
  escape hatch had no control in the UI, and the warning the application
  raised named a button that did not exist. Settings now offers "Anahtarı
  Kaldır", behind a confirmation that defaults to no.
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
- 37 → 632, no skips. Verified on a cp1254 console with `PYTHONUTF8` and
  `PYTHONIOENCODING` unset, and under explicit UTF-8.
- `tools/verify_fix_coverage.py` reverts each fix in a scratch copy and requires
  the test that claims to cover it to fail, so a test that asserts nothing is
  caught rather than counted. 87 of 87.
- `tools/verify_exe_smoke.py` is new: twelve behaviours run through the packaged
  EXE and through the source side by side, each carrying an absolute expectation
  as well, because two builds can agree by being equally broken. `--gui` opens
  the windowed build, finds its window through Win32 and reads the version out
  of the title bar. `--teeth` points the same scenarios at a build known to
  predate the work and requires it to fail — a smoke test that cannot tell a
  three-month-old executable from today's would pass forever without looking at
  anything.
- The gate quotes a crashed round from the *top* of the fatal-error dump rather
  than the bottom. The bottom is unittest's own runner machinery and is
  identical for every crash; the frame naming the test is at the top. Found by
  needing it: a round died with `0xC0000409` and the excerpt was ten lines of
  `unittest/suite.py`. Held by `tests/test_gate_reporting.py`.
- The three tools no longer reconfigure stdout at import time. A module that
  rewrites the process's stdout just by being imported makes whatever imports
  it order-dependent, and this suite has spent enough rounds on encoding
  defects to care which encoding it is running under.
- **Every test temp directory now goes through `DiagnosticTempDir`.** Thirty-six
  files already did; seventeen used `tempfile.TemporaryDirectory` directly and
  were exposed to a failure the helper exists to absorb — a directory Windows
  refuses to remove while it is verifiably empty, because `unlink` only marks a
  file for deletion and the entry survives until the last handle closes. One of
  those seventeen produced a red round during this release's testing; the
  directory it left behind was inspected, was empty, and deleted without
  complaint minutes later.
  The conversion deliberately makes leaks *more* visible: these directories are
  named `hvt-test-*`, which the gate's leak check looks for, while plain `tmp*`
  ones were invisible to it.
- Fixed in the harness while doing that: `DiagnosticTempDir.__enter__` returned
  the object where `tempfile.TemporaryDirectory` returns a string, so
  `with ... as d:` bound something `os.environ` will not accept — despite the
  class documenting itself as a drop-in. Held by three new tests.

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
