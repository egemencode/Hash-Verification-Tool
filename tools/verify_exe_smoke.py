"""
Run the packaged EXE through the behaviours the suite only checks in source.

The unit suite imports ``main`` and calls it in-process. That proves the *code*
is right and says nothing about the artefact a user actually double-clicks:
whether an optional dependency made it into the bundle, whether the frozen
executable's own Windows manifest opts into long paths, whether a Win32 call
still works with no interpreter directory to sit next to. Every one of those
can break while all 610 tests stay green, because none of them exist until
PyInstaller runs.

So this is not part of the suite. Putting it there would force a skip whenever
``dist/`` is absent — a fresh clone, another machine, CI — and a skip is
exactly the shape of report the gate exists to refuse. It runs after a build,
explicitly, and says what it measured.

The core of it is differential: each scenario runs twice, once through
``main.py`` under the venv interpreter and once through the EXE, and the two
have to agree. That is deliberately not the whole test. Two builds can agree
by being equally broken, so every scenario also carries an absolute
expectation — this exit code, this digest, this many manifest entries — that
holds no matter what the other build did. Agreement without an anchor is just
a mirror.

``--teeth <old.exe>`` points the same scenarios at a build known to predate
the work and *requires* it to fail. A smoke test that cannot tell a
three-month-old executable from today's would pass forever without looking at
anything, which is the failure mode this repository keeps finding in its own
tests. If the legacy build passes everything, this reports NO-TEETH and exits
non-zero — the harness accusing itself.

Usage:
    python tools/verify_exe_smoke.py
    python tools/verify_exe_smoke.py --exe dist\\HashTool.exe
    python tools/verify_exe_smoke.py --teeth dist\\eski-2026-05-24\\HashTool.exe
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


REPO = Path(__file__).resolve().parent.parent
PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
DEFAULT_EXE = REPO / "dist" / "HashTool.exe"

# Mirrored from main.py on purpose. If someone renumbers an exit code there,
# this file has to be edited too — which is the point. These numbers are the
# tool's contract with whatever script calls it, and a contract that silently
# follows the implementation is not a contract.
EXIT_OK = 0
EXIT_DIFFERENCES = 1
EXIT_USAGE = 2
EXIT_FAILURE = 3
EXIT_UNTRUSTED_REFERENCE = 5

# Windows will not delete a tree through a path past MAX_PATH without this.
EXTENDED = "\\\\?\\"


@dataclass
class Run:
    code: int
    out: str
    err: str

    @property
    def text(self) -> str:
        return self.out + self.err


@dataclass
class Outcome:
    """What a scenario saw.

    ``facts`` is compared across builds; ``problems`` are absolute
    expectations that failed and stand on their own.
    """

    facts: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


class Build:
    """One way of invoking the tool: the source tree, or a packaged EXE."""

    def __init__(self, name: str, argv_prefix: list[str]) -> None:
        self.name = name
        self.argv_prefix = argv_prefix

    def __call__(self, *args: str, cwd: Path | None = None) -> Run:
        env = dict(os.environ)
        # The gate meets the machine's real code page rather than a UTF-8 one
        # inherited from whoever opened the shell; so does this. An encoding
        # defect that only shows up outside a UTF-8 console is still a defect.
        env.pop("PYTHONUTF8", None)
        env.pop("PYTHONIOENCODING", None)
        proc = subprocess.run(
            self.argv_prefix + list(args),
            capture_output=True,
            cwd=str(cwd or REPO),
            env=env,
        )
        # UTF-8 because main.py reconfigures its streams to it explicitly,
        # rather than because the console happens to be in that code page —
        # that reconfiguration is the behaviour, and the Turkish scenario
        # below fails if a build ever stops doing it.
        return Run(
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )


def _no_crash(run: Run, where: str, problems: list[str]) -> None:
    for marker in (
        "Traceback (most recent call last)",
        "UnicodeEncodeError",
        "ModuleNotFoundError",
        "Failed to execute script",
    ):
        if marker in run.text:
            problems.append(f"{where}: output carries {marker}")


def _expect(run: Run, code: int, where: str, problems: list[str]) -> None:
    if run.code != code:
        tail = run.text.strip().splitlines()
        detail = f" — {tail[-1][:160]}" if tail else " — no output"
        problems.append(f"{where}: exit {run.code}, expected {code}{detail}")
    _no_crash(run, where, problems)


def _declared_version() -> str | None:
    """The version the working tree claims, read rather than imported.

    Read, because this harness has to be able to judge an executable even when
    the tree it sits in will not import — and because the file is the thing
    the build was made from.
    """
    text = (REPO / "core" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else None


def _normalised_manifest(path: Path) -> dict:
    """A manifest minus the parts that cannot match across two separate runs."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    meta = dict(doc.get("metadata", {}))
    for volatile in ("created_at", "root_path"):
        meta.pop(volatile, None)
    entries = {
        name: {k: v for k, v in entry.items() if k != "mtime"}
        for name, entry in doc.get("entries", {}).items()
    }
    return {"metadata": meta, "entries": entries}


# ---------------------------------------------------------------------------
# Scenarios. Each gets an empty workspace and the build under test.
# ---------------------------------------------------------------------------


def s_version(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    result = run("--version")
    _expect(result, EXIT_OK, "version", out.problems)
    match = re.search(r"hash-tool (\d+\.\d+\.\d+)", result.text)
    if not match:
        out.problems.append(
            f"version: no version string in {result.text.strip()[:80]!r}"
        )
        return out
    out.facts["version"] = match.group(1)
    # The one check that catches a build nobody rebuilt. Two executables three
    # months apart, with a different set of subcommands and different security
    # behaviour, both answered "1.2.0" — so a version that merely exists says
    # nothing. It has to be *this tree's* version.
    declared = _declared_version()
    if declared and match.group(1) != declared:
        out.problems.append(
            f"version: reports {match.group(1)}, the tree declares {declared} — "
            "this executable was built from different source"
        )
    return out


def s_single_file_digest(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    target = ws / "tek.txt"
    body = b"integrity is a claim about a moment"
    target.write_bytes(body)
    result = run("hash", "--file", str(target))
    _expect(result, EXIT_OK, "single-file", out.problems)
    found = re.search(r"\b([0-9a-f]{64})\b", result.text)
    expected = hashlib.sha256(body).hexdigest()
    if not found:
        out.problems.append("single-file: no sha256 digest printed")
    elif found.group(1) != expected:
        out.problems.append(f"single-file: digest {found.group(1)} != {expected}")
    else:
        out.facts["digest"] = found.group(1)
    return out


def _folder_fixture(ws: Path) -> Path:
    data = ws / "veri"
    (data / "alt").mkdir(parents=True)
    (data / "bir.txt").write_bytes(b"first")
    (data / "alt" / "iki.bin").write_bytes(bytes(range(256)))
    return data


def s_folder_roundtrip(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    result = run("hash", "--folder", str(data), "--output", str(manifest))
    _expect(result, EXIT_OK, "roundtrip/hash", out.problems)
    if not manifest.exists():
        out.problems.append("roundtrip: no manifest written")
        return out
    doc = _normalised_manifest(manifest)
    if len(doc["entries"]) != 2:
        out.problems.append(f"roundtrip: {len(doc['entries'])} entries, expected 2")
    out.facts["manifest"] = doc
    verified = run(
        "verify", "--folder", str(data), "--manifest", str(manifest),
        "--allow-unsigned",
    )
    _expect(verified, EXIT_OK, "roundtrip/verify", out.problems)
    return out


def s_tamper_detected(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    run("hash", "--folder", str(data), "--output", str(manifest))
    (data / "bir.txt").write_bytes(b"second")
    verified = run(
        "verify", "--folder", str(data), "--manifest", str(manifest),
        "--allow-unsigned",
    )
    _expect(verified, EXIT_DIFFERENCES, "tamper", out.problems)
    out.facts["exit"] = verified.code
    return out


def s_missing_detected(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    run("hash", "--folder", str(data), "--output", str(manifest))
    (data / "alt" / "iki.bin").unlink()
    verified = run(
        "verify", "--folder", str(data), "--manifest", str(manifest),
        "--allow-unsigned",
    )
    _expect(verified, EXIT_DIFFERENCES, "missing", out.problems)
    out.facts["exit"] = verified.code
    return out


def s_insecure_algorithm_refused(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    data = _folder_fixture(ws)
    result = run(
        "hash", "--folder", str(data), "--algo", "md5",
        "--output", str(ws / "m.json"),
    )
    _expect(result, EXIT_USAGE, "insecure-algo", out.problems)
    if (ws / "m.json").exists():
        out.problems.append("insecure-algo: a manifest was written anyway")
    out.facts["exit"] = result.code
    return out


def s_unsigned_reference_refused(ws: Path, run: Build) -> Outcome:
    """An unverifiable reference has to stop the run, not report a match.

    Without ``--allow-unsigned`` that is exit 5.
    """
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    run("hash", "--folder", str(data), "--output", str(manifest))
    verified = run("verify", "--folder", str(data), "--manifest", str(manifest))
    _expect(verified, EXIT_UNTRUSTED_REFERENCE, "unsigned-reference", out.problems)
    out.facts["exit"] = verified.code
    return out


def s_signed_roundtrip(ws: Path, run: Build) -> Outcome:
    """Ed25519 signing needs ``cryptography`` inside the bundle, and the key
    store reaches for DPAPI. Neither exists until the EXE is built."""
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    # Deliberately not beside the manifest: the tool refuses that, and the
    # scenario below is the one that pins the refusal.
    key = ws / "anahtarlar" / "anahtar.key"
    key.parent.mkdir()
    run("hash", "--folder", str(data), "--output", str(manifest))
    generated = run("keygen", "--out", str(key))
    _expect(generated, EXIT_OK, "signed/keygen", out.problems)
    if not key.exists():
        out.problems.append("signed: no private key written")
        return out
    signed = run("sign", "--manifest", str(manifest), "--key", str(key))
    _expect(signed, EXIT_OK, "signed/sign", out.problems)
    public = Path(str(key) + ".pub")
    if not public.exists():
        out.problems.append("signed: no public key written")
        return out
    verified = run(
        "verify", "--folder", str(data), "--manifest", str(manifest),
        "--trusted-key", str(public),
    )
    _expect(verified, EXIT_OK, "signed/verify", out.problems)
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    mode = doc.get("metadata", {}).get("integrity_mode")
    out.facts["integrity_mode"] = mode
    if mode == "none":
        out.problems.append("signed: manifest still reports integrity_mode=none")
    return out


def s_key_beside_manifest_refused(ws: Path, run: Build) -> Outcome:
    """A private key sitting next to the manifest it signs is a published key.

    This scenario exists because the harness tripped over the guard by
    accident: the first draft put the key in the workspace root and the tool
    refused, identically in both builds. A guard found that way is worth
    holding on to — it is the difference between a signature that means
    something and one anybody can forge.
    """
    out = Outcome()
    data = _folder_fixture(ws)
    manifest = ws / "m.json"
    key = ws / "anahtar.key"  # same folder as the manifest, on purpose
    run("hash", "--folder", str(data), "--output", str(manifest))
    generated = run("keygen", "--out", str(key))
    _expect(generated, EXIT_OK, "key-beside/keygen", out.problems)
    signed = run("sign", "--manifest", str(manifest), "--key", str(key))
    if signed.code == EXIT_OK:
        out.problems.append(
            "key-beside: signed with the private key stored next to the "
            "manifest — anyone holding that pair can forge one"
        )
    _no_crash(signed, "key-beside/sign", out.problems)
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    out.facts["exit"] = signed.code
    out.facts["integrity_mode"] = doc.get("metadata", {}).get("integrity_mode")
    return out


def s_long_path(ws: Path, run: Build) -> Outcome:
    """Past MAX_PATH.

    A frozen executable carries its own Windows application manifest, and
    long-path support is declared *there* — it is not inherited from the
    machine's registry setting the way a plain ``python.exe`` run inherits it.
    """
    out = Outcome()
    deep = ws / "derin"
    deep.mkdir()
    segment = "u" * 40
    while len(str(deep)) < 300:
        deep = deep / segment
    try:
        deep.mkdir(parents=True)
    except OSError:
        deep = Path(EXTENDED + str(deep))
        deep.mkdir(parents=True)
    target = deep / "derin.txt"
    target.write_text("derinlik", encoding="utf-8")
    if len(str(target)) <= 260:
        out.problems.append("long-path: the fixture path is not past MAX_PATH")

    manifest = ws / "m.json"
    result = run("hash", "--folder", str(ws / "derin"), "--output", str(manifest))
    _expect(result, EXIT_OK, "long-path/hash", out.problems)
    if not manifest.exists():
        out.problems.append("long-path: no manifest written")
        return out
    doc = _normalised_manifest(manifest)
    # The sharp end. A scan that walks nothing and reports success exits 0
    # with an empty manifest, which is why the entry count is the assertion
    # and the exit code is not.
    if len(doc["entries"]) != 1:
        out.problems.append(
            f"long-path: {len(doc['entries'])} entries, expected 1 — "
            "the deep file was never hashed"
        )
    out.facts["entries"] = sorted(doc["entries"])
    verified = run(
        "verify", "--folder", str(ws / "derin"), "--manifest", str(manifest),
        "--allow-unsigned",
    )
    _expect(verified, EXIT_OK, "long-path/verify", out.problems)
    return out


def s_turkish_paths(ws: Path, run: Build) -> Outcome:
    """Names the console code page cannot spell.

    The bundle has its own idea of stdout, so this is not the same test as the
    in-process one. The file is tampered with on purpose: ``--show-details``
    only prints a name when there is a difference to report, and printing the
    name is the whole point — a manifest can hold the characters perfectly
    while the program that reports them dies on the way to the console.
    """
    out = Outcome()
    name = "ölçüm-şğüıöç.txt"
    data = ws / "Türkçe Klasör"
    data.mkdir()
    (data / name).write_text("gövde", encoding="utf-8")
    manifest = ws / "m.json"
    result = run("hash", "--folder", str(data), "--output", str(manifest))
    _expect(result, EXIT_OK, "turkish/hash", out.problems)
    if not manifest.exists():
        out.problems.append("turkish: no manifest written")
        return out
    doc = _normalised_manifest(manifest)
    if len(doc["entries"]) != 1:
        out.problems.append(f"turkish: {len(doc['entries'])} entries, expected 1")
    out.facts["entries"] = sorted(doc["entries"])

    (data / name).write_text("değişti", encoding="utf-8")
    verified = run(
        "verify", "--folder", str(data), "--manifest", str(manifest),
        "--allow-unsigned", "--show-details",
    )
    _expect(verified, EXIT_DIFFERENCES, "turkish/verify", out.problems)
    if name not in verified.text:
        out.problems.append(
            f"turkish: {name!r} never reached stdout intact — the details "
            "listing is where a code-page defect shows up"
        )
    out.facts["name_reported"] = name in verified.text
    return out


def s_absent_folder(ws: Path, run: Build) -> Outcome:
    out = Outcome()
    result = run(
        "hash", "--folder", str(ws / "yok"), "--output", str(ws / "m.json")
    )
    _expect(result, EXIT_FAILURE, "absent-folder", out.problems)
    out.facts["exit"] = result.code
    return out


SCENARIOS: list[tuple[str, Callable[[Path, Build], Outcome]]] = [
    ("version", s_version),
    ("single-file-digest", s_single_file_digest),
    ("folder-roundtrip", s_folder_roundtrip),
    ("tamper-detected", s_tamper_detected),
    ("missing-detected", s_missing_detected),
    ("insecure-algorithm-refused", s_insecure_algorithm_refused),
    ("unsigned-reference-refused", s_unsigned_reference_refused),
    ("signed-roundtrip", s_signed_roundtrip),
    ("key-beside-manifest-refused", s_key_beside_manifest_refused),
    ("long-path", s_long_path),
    ("turkish-paths", s_turkish_paths),
    ("absent-folder", s_absent_folder),
]


# ---------------------------------------------------------------------------
# The GUI build. Nothing above reaches it: HashToolGUI.exe is built from a
# different entry point, with a different hidden-import list, and it is the
# one a user actually double-clicks.
# ---------------------------------------------------------------------------

# "Hash Doğrulama Aracı  —  v1.2.0", spelled so the dashes and the Turkish
# characters do not have to survive a round trip through anything.
WINDOW_TITLE = re.compile(r"Hash Doğrulama Aracı\s+—\s+v(\d+\.\d+\.\d+)")


def _visible_windows() -> dict[int, str]:
    """Every visible top-level window, keyed by handle, read from Win32.

    Not ``Process.MainWindowTitle``: a one-file PyInstaller build runs the
    real program in a *child* of the process you started, so the parent has
    no window and asking it reports nothing — which looks exactly like a GUI
    that failed to open.

    Keyed by handle rather than by title, because two copies of this program
    have the *same* title. An earlier draft diffed sets of title strings, and
    a single leftover instance from a previous run made every later window
    invisible to it: the string was already in the "before" set, so nothing
    new ever appeared and a working GUI was reported as never opening.
    """
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    windows: dict[int, str] = {}

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def collect(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length:
                buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buffer, length + 1)
                windows[int(hwnd)] = buffer.value
        return True

    user32.EnumWindows(collect, 0)
    return windows


def _close_window(hwnd: int) -> None:
    import ctypes

    ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE


def _gui_launch(name: str, argv: list[str], timeout: float = 30.0) -> Outcome:
    import time

    out = Outcome()
    before = set(_visible_windows())
    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    proc = subprocess.Popen(argv, cwd=str(REPO), env=env)

    hwnd = None
    title = ""
    appeared: dict[int, str] = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.25)
        appeared = {h: t for h, t in _visible_windows().items() if h not in before}
        hwnd = next((h for h, t in appeared.items() if WINDOW_TITLE.search(t)), None)
        if hwnd is not None:
            title = appeared[hwnd]
            break
        if proc.poll() is not None and not appeared:
            break

    if hwnd is None:
        out.problems.append(
            f"{name}: no window titled like the app appeared within "
            f"{timeout:.0f}s (exit={proc.poll()}, "
            f"new windows={sorted(appeared.values())})"
        )
    else:
        shown = WINDOW_TITLE.search(title).group(1)
        out.facts["version"] = shown
        declared = _declared_version()
        if declared and shown != declared:
            out.problems.append(
                f"{name}: the title bar says v{shown}, the tree declares "
                f"{declared} — this window is not this source"
            )
        _close_window(hwnd)

    # Two separate obligations, reported separately: the window has to go
    # away, and the process has to end. A one-file build reaches the second
    # through its bootloader parent, so they do not happen at the same moment.
    import ctypes

    window_gone = hwnd is None
    for _ in range(40):
        if hwnd is not None and not ctypes.windll.user32.IsWindow(hwnd):
            window_gone = True
        if window_gone and proc.poll() is not None:
            break
        time.sleep(0.25)
    if hwnd is not None and not window_gone:
        out.problems.append(f"{name}: the window ignored WM_CLOSE")
    if proc.poll() is None:
        # /T because the one-file bootloader is the parent of the process
        # that owns the window. Killing the parent alone strands the child,
        # which is how this run left an orphan on the desktop the first time.
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True
        )
        if hwnd is not None:
            out.problems.append(
                f"{name}: process still running after its window closed"
            )
    return out


def _report_gui(exe: Path) -> int:
    pythonw = REPO / ".venv" / "Scripts" / "pythonw.exe"
    source = _gui_launch("source", [str(pythonw), str(REPO / "gui_main.py")])
    packaged = _gui_launch("exe", [str(exe)])

    problems = source.problems + packaged.problems
    differs = source.facts != packaged.facts
    for name, outcome in (("source", source), ("exe", packaged)):
        shown = outcome.facts.get("version", "—")
        print(f"  {name:7} pencere sürümü: {shown}")
    print()
    for problem in problems:
        print(f"  {problem}")
    if differs:
        print(f"  source and EXE disagree: {source.facts} vs {packaged.facts}")
    if problems or differs:
        print("\nGUI EXE sınaması başarısız.")
        return 1
    print("GUI EXE açıldı, penceresini gösterdi ve kapandı — kaynakla aynı sürüm.")
    return 0


def _run_all(build: Build, root: Path) -> dict[str, Outcome]:
    results: dict[str, Outcome] = {}
    for name, scenario in SCENARIOS:
        workspace = root / f"{build.name}-{name}"
        workspace.mkdir(parents=True)
        try:
            results[name] = scenario(workspace, build)
        except Exception as exc:  # a scenario that cannot run is a failure
            results[name] = Outcome(problems=[f"{name}: harness raised {exc!r}"])
    return results


def _report_teeth(exe: dict[str, Outcome]) -> int:
    caught = [name for name, outcome in exe.items() if outcome.problems]
    for name in caught:
        print(f"  yakalandı  {name}")
        for problem in exe[name].problems:
            print(f"             {problem}")
    print()
    if not caught:
        print(
            "NO-TEETH: the legacy build passed every scenario, so this harness "
            "cannot tell it from a current one."
        )
        return 1
    print(f"TEETH: {len(caught)}/{len(SCENARIOS)} senaryo eski yapıyı reddetti.")
    return 0


def _report_differential(src: dict[str, Outcome], exe: dict[str, Outcome]) -> int:
    failures = 0
    for name, _ in SCENARIOS:
        problems = src[name].problems + exe[name].problems
        differs = src[name].facts != exe[name].facts
        if not problems and not differs:
            print(f"  ok    {name}")
            continue
        failures += 1
        print(f"  FAIL  {name}")
        for problem in problems:
            print(f"        {problem}")
        if differs:
            print("        source and EXE disagree:")
            for key in sorted(set(src[name].facts) | set(exe[name].facts)):
                left, right = src[name].facts.get(key), exe[name].facts.get(key)
                if left != right:
                    print(f"          {key}: source={left!r} exe={right!r}")
    print()
    if failures:
        print(f"{failures}/{len(SCENARIOS)} senaryo başarısız.")
        return 1
    print(
        f"{len(SCENARIOS)}/{len(SCENARIOS)} senaryo geçti — EXE kaynakla aynı "
        "davranıyor ve beklentileri tek başına da karşılıyor."
    )
    return 0


def main() -> int:
    # Not at import time: these are ordinary modules as well as
    # scripts, and a module that rewrites the process's stdout just by
    # being imported makes whatever imports it order-dependent.
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exe", type=Path, default=DEFAULT_EXE,
        help="the packaged executable under test",
    )
    parser.add_argument(
        "--teeth", type=Path,
        help="an EXE known to predate the work; it has to fail",
    )
    parser.add_argument(
        "--gui", type=Path, nargs="?", const=REPO / "dist" / "HashToolGUI.exe",
        help="check the windowed build instead: open it, find its window, "
             "read the version out of the title, close it",
    )
    args = parser.parse_args()

    if not PYTHON.exists():
        print(f"venv interpreter not found: {PYTHON}")
        return 2
    if args.gui is not None:
        if not args.gui.exists():
            print(f"executable not found: {args.gui}")
            return 2
        print(f"GUI EXE: {args.gui}\n")
        return _report_gui(args.gui)
    target = args.teeth or args.exe
    if not target.exists():
        print(f"executable not found: {target}")
        return 2

    root = Path(tempfile.mkdtemp(prefix="hvt-exesmoke-"))
    source = Build("source", [str(PYTHON), str(REPO / "main.py")])
    packaged = Build("exe", [str(target)])

    try:
        print(f"kaynak : {PYTHON.name} main.py")
        print(f"EXE    : {target}")
        print(f"senaryo: {len(SCENARIOS)}\n")

        source_results = _run_all(source, root)
        exe_results = _run_all(packaged, root)

        if args.teeth:
            return _report_teeth(exe_results)
        return _report_differential(source_results, exe_results)
    finally:
        # Only this run's own root, and loudly if it will not go. Silently
        # ignoring a cleanup error is how a leaked temp directory becomes
        # somebody else's intermittent failure.
        try:
            shutil.rmtree(EXTENDED + str(root))
        except OSError as exc:
            print(f"UYARI: geçici dizin silinemedi: {root} ({exc})")


if __name__ == "__main__":
    raise SystemExit(main())
