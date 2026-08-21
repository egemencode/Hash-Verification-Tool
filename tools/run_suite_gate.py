"""
Run the full suite N times and require every round to be clean.

A single green run does not clear this branch. Three of the defects found here
were intermittent by nature — a scheduled Tk callback firing after teardown, a
temp directory surviving cleanup — and each showed up in roughly one run in
five. Repetition is the only thing that distinguishes "fixed" from "did not
happen to fire this time".

A round passes only when all of these hold:

  * the suite exits 0;
  * it actually ran a full suite — ``unittest`` exits 0 for a run in which
    every test skipped, so "no failures" and "the behaviour was checked" are
    not the same statement. The round asserts a floor on the number of tests
    and that the count did not move between rounds;
  * nothing skipped. A skip is how this suite reports "the scenario could not
    be set up here", which is precisely the case a green tick must not cover;
  * stderr carries none of the teardown noise patterns (a Tk callback that
    raises is reported on stderr and does *not* fail the run, so exit 0 alone
    would hide it);
  * no new ``hvt*`` directory is left in the system temp directory.

The default mode runs with ``PYTHONUTF8`` and ``PYTHONIOENCODING`` removed from
the child environment, so the suite meets the active code page (cp1254 on this
machine) rather than a UTF-8 one inherited from whoever started the shell. That
is the configuration real users get, and it is where the encoding defects were.
``--utf8`` runs the same gate under an explicitly UTF-8 child instead.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
TEMP_ROOT = Path(tempfile.gettempdir())
TEMP_GLOB = "hvt*"

# Tk reports a callback exception on stderr and carries on, so these never
# reach the exit code. They are the signature of a scheduled callback outliving
# the widget it targets.
NOISE = (
    "Exception in Tkinter callback",
    "TclError",
    "invalid command name",
    "bgerror",
)

# unittest writes its summary to stderr, not stdout.
RAN_RE = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
SKIPPED_RE = re.compile(r"\bskipped=(\d+)")

# When the interpreter dies rather than failing a test, Python prints a stack
# dump and the informative end of it is the *top*: the frame nearest the crash
# names the test. The tail is unittest's own runner machinery, identical for
# every crash there has ever been.
FATAL = ("Windows fatal exception", "Fatal Python error", "Current thread 0x")


def failure_excerpt(err: str, limit: int = 14) -> str:
    """The part of a failed round's stderr worth printing.

    Normally that is the last few lines — the assertion and its traceback.
    For a crash it is the opposite end, so this looks for the dump header
    first and reads forward from there.
    """
    lines = err.strip().splitlines()
    for marker in FATAL:
        for index, line in enumerate(lines):
            if marker in line:
                excerpt = lines[index:index + limit]
                return "\n      ".join(excerpt)
    return "\n      ".join(lines[-limit:])


def child_env(utf8: bool, odd_temp: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    if utf8:
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
    if odd_temp:
        # Hand the suite a temp directory spelled a second way. Windows is
        # case-insensitive, so this names the same directory — which is the
        # entire point: any test that compares a path by its *string* rather
        # than by which file it is now sees two spellings and breaks.
        #
        # This is not a hypothetical mode. A GitHub runner's TEMP is an 8.3
        # short path, the product resolves paths before it opens them, and ten
        # tests that had been green here for months turned out never to have
        # set up the scenario they described. Uppercasing reproduces that in
        # one line, on any machine, without a runner.
        for name in ("TEMP", "TMP"):
            value = env.get(name)
            if value:
                env[name] = value.upper()
    return env


def temp_dirs() -> set[str]:
    return {p.name for p in TEMP_ROOT.glob(TEMP_GLOB) if p.is_dir()}


def child_encoding(env: dict[str, str]) -> str:
    proc = subprocess.run(
        [str(PYTHON), "-c", "import sys; print(sys.stdout.encoding)"],
        cwd=str(REPO), capture_output=True, env=env, timeout=120,
    )
    return proc.stdout.decode("ascii", "replace").strip()


def one_round(env: dict[str, str], min_tests: int) -> tuple[bool, list[str], int]:
    before = temp_dirs()
    try:
        proc = subprocess.run(
            [str(PYTHON), "-m", "unittest", "discover", "-s", "tests", "-t", "."],
            cwd=str(REPO), capture_output=True, env=env, timeout=1800,
        )
    except subprocess.TimeoutExpired:
        # A hung round is a failed round, not a crashed harness: the remaining
        # rounds still carry information about whether this reproduces.
        return False, ["the suite did not finish within 1800s"], -1
    err = proc.stderr.decode("utf-8", "replace")

    problems: list[str] = []
    if proc.returncode != 0:
        problems.append(f"exit {proc.returncode}\n      {failure_excerpt(err)}")

    # Exit 0 says "nothing failed", not "the behaviour was checked". A suite in
    # which everything skipped also exits 0.
    match = RAN_RE.search(err)
    ran = int(match.group(1)) if match else -1
    if ran < 0:
        problems.append("could not find unittest's 'Ran N tests' summary")
    elif ran < min_tests:
        problems.append(f"only {ran} tests ran, expected at least {min_tests}")

    skipped = sum(int(n) for n in SKIPPED_RE.findall(err))
    if skipped:
        problems.append(f"{skipped} test(s) skipped — this suite must not skip")

    for pattern in NOISE:
        if pattern in err:
            line = next(
                (ln.strip() for ln in err.splitlines() if pattern in ln), pattern
            )
            problems.append(f"teardown noise {pattern!r}: {line[:160]}")

    # Only directories that are still there once the child has exited count.
    # A temp root can outlive its files for a moment on Windows; one that has
    # since gone was not leaked.
    leaked = sorted(
        name for name in temp_dirs() - before if (TEMP_ROOT / name).exists()
    )
    if leaked:
        problems.append(f"temp directories left behind: {leaked}")

    return not problems, problems, ran


def main() -> int:
    # Not at import time: these are ordinary modules as well as
    # scripts, and a module that rewrites the process's stdout just by
    # being imported makes whatever imports it order-dependent.
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument(
        "--min-tests", type=int, default=500,
        help="Fail a round that ran fewer tests than this (default 500).",
    )
    parser.add_argument(
        "--utf8", action="store_true",
        help="Run the child under explicit UTF-8 instead of the code page.",
    )
    parser.add_argument(
        "--odd-temp", action="store_true",
        help="Spell TEMP a second way, so a test that compares paths as "
             "strings rather than by identity breaks here instead of on "
             "somebody else's machine.",
    )
    args = parser.parse_args()

    env = child_env(args.utf8, args.odd_temp)
    encoding = child_encoding(env)
    mode = "explicit UTF-8" if args.utf8 else "active code page"
    if args.odd_temp:
        mode += f"   temp: {env.get('TEMP', '(unset)')}"
    print(f"mode: {mode}   child stdout encoding: {encoding}")
    if not args.utf8 and encoding.lower().replace("-", "") == "utf8":
        print(
            "  !! the child is already UTF-8, so this run does NOT exercise the "
            "code page and cannot stand in for the cp1254 gate"
        )
        return 1

    failures: list[tuple[int, list[str]]] = []
    counts: list[int] = []
    for index in range(1, args.rounds + 1):
        ok, problems, ran = one_round(env, args.min_tests)
        if ran > 0:
            counts.append(ran)
        if ok:
            print(f"  ok round {index}/{args.rounds}  ({ran} tests, 0 skipped)")
        else:
            failures.append((index, problems))
            print(f"  !! round {index}/{args.rounds} FAILED")
            for problem in problems:
                print(f"      {problem}")
        sys.stdout.flush()

    # A count that moves between rounds means collection itself is not
    # deterministic, so no single round's result describes the suite.
    if len(set(counts)) > 1:
        failures.append((0, [f"test count varied across rounds: {sorted(set(counts))}"]))
        print(f"  !! test count varied across rounds: {sorted(set(counts))}")

    print()
    passed = args.rounds - len([f for f in failures if f[0]])
    print(f"{passed} / {args.rounds} clean rounds ({mode})")
    for index, problems in failures:
        label = f"round {index}" if index else "across rounds"
        for problem in problems:
            print(f"  FAILED [{label}] {problem}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
