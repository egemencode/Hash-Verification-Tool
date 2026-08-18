"""
Path handling contract (§3.4): Unicode names, long paths and reparse points.

Filenames are attacker- and user-controlled data. A name the tool cannot
round-trip is not a cosmetic problem: the digest gets attributed to a path
that does not exist, and the next verify reports the real file as "missing"
and the mangled one as "new".

Covered here:
* emoji / Turkish / RTL-override / combining-sequence / zero-byte names survive
  a hash -> verify round trip, in-process and through a cp1254 console;
* paths beyond the classic 260-character limit;
* the ``--follow-symlinks`` switch exists, defaults to off, and cannot be used
  to pull content from outside the scanned root.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import main as cli
from tests.support import DiagnosticTempDir
from tests.test_folder_scan_integrity import _make_junction

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# One entry per awkward class of filename. Invisible or ambiguous codepoints
# are written as escapes so the source states exactly what is under test.
TURKISH_NAME = "düz türkçe Iışığı.txt"
EMOJI_NAME = "emoji \U0001f510\U0001f9ea.txt"
RTL_NAME = "fake‮gnp.exe.txt"        # RTL override: a real spoofing trick
NFD_NAME = "é combining.txt"        # "e" + U+0301 COMBINING ACUTE
NFC_NAME = "é precomposed.txt"       # U+00E9: same grapheme, other bytes
QUOTE_NAME = "boşluk  ve 'tırnak'.txt"
ZERO_BYTE_NAME = "zero-byte.bin"

AWKWARD_NAMES = [
    TURKISH_NAME,
    EMOJI_NAME,
    RTL_NAME,
    NFD_NAME,
    NFC_NAME,
    QUOTE_NAME,
    ZERO_BYTE_NAME,
]


def run_cli(args: list[str]) -> tuple[int, str, str]:
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


class AwkwardFilenameTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.created: list[str] = []
        for name in AWKWARD_NAMES:
            target = self.data / name
            payload = b"" if name == ZERO_BYTE_NAME else name.encode("utf-8")
            target.write_bytes(payload)
            self.created.append(name)
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_every_name_is_recorded_verbatim(self) -> None:
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        recorded = set(doc["entries"])
        for name in self.created:
            self.assertIn(
                name, recorded,
                f"{name!r} was not recorded under its real name; "
                f"manifest holds {sorted(recorded)!r}",
            )

    def test_round_trip_verifies_clean(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        code, out, err = run_cli(
            ["verify", "--folder", str(self.data),
             "--manifest", str(self.manifest), "--allow-unsigned"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)

    def test_nfc_and_nfd_names_stay_distinct(self) -> None:
        # Normalising filenames would collapse two different files into one
        # manifest entry, hiding a change in whichever lost the race.
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertIn(NFD_NAME, doc["entries"])
        self.assertIn(NFC_NAME, doc["entries"])

    def test_zero_byte_file_is_hashed_not_skipped(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        entry = doc["entries"][ZERO_BYTE_NAME]
        self.assertEqual(entry["size"], 0)
        # SHA-256 of the empty string.
        self.assertEqual(
            entry["hash"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


class LegacyConsoleTests(unittest.TestCase):
    """The same names, through a child process with no UTF-8 environment."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "veri"
        self.data.mkdir()
        (self.data / EMOJI_NAME).write_text("içerik", encoding="utf-8")
        (self.data / RTL_NAME).write_bytes(b"rtl")
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        # The point of the test: no hidden encoding help.
        env.pop("PYTHONUTF8", None)
        env.pop("PYTHONIOENCODING", None)
        return subprocess.run(
            [sys.executable, "main.py", *args],
            cwd=str(_PROJECT_ROOT), capture_output=True, env=env, timeout=180,
        )

    def test_emoji_and_rtl_names_do_not_crash_the_cli(self) -> None:
        proc = self._run(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)]
        )
        self.assertEqual(
            proc.returncode, 0,
            f"stdout={proc.stdout.decode('utf-8', 'replace')}\n"
            f"stderr={proc.stderr.decode('utf-8', 'replace')}",
        )
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertIn(EMOJI_NAME, doc["entries"])

        proc = self._run(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--allow-unsigned", "--show-details"]
        )
        self.assertEqual(
            proc.returncode, 0, proc.stderr.decode("utf-8", "replace")
        )


class LongPathTests(unittest.TestCase):
    """Paths past the classic MAX_PATH limit must still be scannable."""

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.manifest = self.root / "m.json"
        self.mode = "plain"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_deep_tree(self) -> Path:
        """
        Create a directory whose absolute path exceeds 260 characters.

        Windows only accepts plain long paths when LongPathsEnabled is set;
        otherwise the extended ``\\\\?\\`` prefix is required. Both are real
        deployments, so we use whichever the machine supports and record which
        one ran — the tool has to cope either way.
        """
        segment = "u" * 40
        deep = self.root / "deep"
        deep.mkdir()
        while len(str(deep)) < 300:
            deep = deep / segment
        try:
            deep.mkdir(parents=True)
            return deep
        except OSError:
            self.mode = "extended"
            extended = Path("\\\\?\\" + str(deep))
            extended.mkdir(parents=True)
            return extended

    def test_hash_and_verify_a_file_beyond_max_path(self) -> None:
        deep = self._build_deep_tree()
        target = deep / "derin.txt"
        target.write_text("derinlik", encoding="utf-8")
        self.assertGreater(len(str(target)), 260, "the test path is not long enough")

        code, out, err = run_cli(
            ["hash", "--folder", str(self.root / "deep"),
             "--output", str(self.manifest)]
        )
        self.assertEqual(code, cli.EXIT_OK, f"[{self.mode}] {out}\n{err}")
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["entries"]), 1, doc["entries"])

        code, out, err = run_cli(
            ["verify", "--folder", str(self.root / "deep"),
             "--manifest", str(self.manifest), "--allow-unsigned"]
        )
        self.assertEqual(code, cli.EXIT_OK, f"[{self.mode}] {out}\n{err}")


class FollowSymlinksSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "inside.txt").write_text("inside", encoding="utf-8")
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("secret", encoding="utf-8")
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _entries(self) -> set[str]:
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        return set(doc["entries"])

    def test_default_run_does_not_follow_a_junction(self) -> None:
        if not _make_junction(self.data / "link", self.outside):
            self.skipTest("cannot create a junction on this system")
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        self.assertEqual(self._entries(), {"inside.txt"})

    def test_follow_symlinks_changes_what_hash_records(self) -> None:
        # `real/deep.txt` is inside an ordinary directory and is hashed either
        # way, so asserting on it says nothing about the flag. The only path
        # that appears when — and only when — the junction is followed is
        # `link/deep.txt`. Assert both directions, or dropping the flag from
        # the CLI call becomes an invisible no-op.
        inner = self.data / "real"
        inner.mkdir()
        (inner / "deep.txt").write_text("deep", encoding="utf-8")
        if not _make_junction(self.data / "link", inner):
            self.skipTest("cannot create a junction on this system")

        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        self.assertNotIn(
            "link/deep.txt", self._entries(),
            "the junction was followed without being asked",
        )

        self.manifest.unlink()
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--follow-symlinks"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        entries = self._entries()
        self.assertIn(
            "link/deep.txt", entries,
            f"--follow-symlinks was accepted but ignored: {sorted(entries)}",
        )
        self.assertIn("real/deep.txt", entries)

    def test_follow_symlinks_still_refuses_to_leave_the_root(self) -> None:
        if not _make_junction(self.data / "link", self.outside):
            self.skipTest("cannot create a junction on this system")
        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--follow-symlinks"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        self.assertNotIn(
            "link/secret.txt", self._entries(),
            "--follow-symlinks pulled a file from outside the scanned root",
        )

    def test_verify_honours_the_same_switch(self) -> None:
        # A fixture with no link at all cannot tell whether verify passes the
        # flag through. Build the manifest *with* the flag, then verify: only a
        # verify that also follows the junction sees `link/deep.txt`; one that
        # ignores the flag reports it missing and exits 1.
        inner = self.data / "real"
        inner.mkdir()
        (inner / "deep.txt").write_text("deep", encoding="utf-8")
        if not _make_junction(self.data / "link", inner):
            self.skipTest("cannot create a junction on this system")

        code, out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--follow-symlinks"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        self.assertIn("link/deep.txt", self._entries())

        code, out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--allow-unsigned", "--follow-symlinks"]
        )
        self.assertEqual(
            code, cli.EXIT_OK,
            f"verify did not follow the junction the manifest was built with:"
            f"\n{out}\n{err}",
        )

        # And without the flag the same manifest must NOT verify clean — which
        # is what proves the assertion above depended on the flag.
        code, _out, _err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--allow-unsigned"]
        )
        self.assertEqual(code, cli.EXIT_DIFFERENCES)


if __name__ == "__main__":
    unittest.main()
