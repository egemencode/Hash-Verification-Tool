"""
The CLI's output encoding contract: always UTF-8, whatever the console
code page is.

Without this, the same command produces different bytes on a Turkish Windows
(cp1254) than on a UTF-8 machine, Turkish characters in a path can raise
UnicodeEncodeError, and any test that decodes the output as UTF-8 silently
depends on a hidden environment variable.

Each case runs the real CLI in a child process with the encoding environment
set explicitly — never inherited.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(args, env_overrides: dict[str, str | None]):
    env = dict(os.environ)
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        [sys.executable, "main.py", *args],
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        env=env,
        timeout=120,
    )


# The two environments the contract must hold in.
_LEGACY_CONSOLE = {"PYTHONUTF8": None, "PYTHONIOENCODING": None}
_EXPLICIT_UTF8 = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}


class OutputIsAlwaysUtf8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "veri"
        self.data.mkdir()
        # A Turkish filename: the characters that break under cp1254 handling.
        (self.data / "çalışma günü.txt").write_text("içerik", encoding="utf-8")
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _hash(self, env):
        return _run(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest)], env
        )

    def test_hash_succeeds_in_legacy_console_environment(self) -> None:
        proc = self._hash(_LEGACY_CONSOLE)
        self.assertEqual(
            proc.returncode, 0,
            proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace"),
        )

    def test_hash_succeeds_in_explicit_utf8_environment(self) -> None:
        proc = self._hash(_EXPLICIT_UTF8)
        self.assertEqual(proc.returncode, 0)

    def test_output_decodes_as_utf8_in_both_environments(self) -> None:
        for name, env in (("legacy", _LEGACY_CONSOLE), ("utf8", _EXPLICIT_UTF8)):
            with self.subTest(environment=name):
                self._hash(env)
                proc = _run(
                    ["verify", "--folder", str(self.data),
                     "--manifest", str(self.manifest), "--allow-unsigned"],
                    env,
                )
                combined = proc.stdout + proc.stderr
                # Must decode strictly as UTF-8 — no replacement characters.
                text = combined.decode("utf-8")
                self.assertNotIn("�", text)

    def test_turkish_message_bytes_are_identical_across_environments(self) -> None:
        self._hash(_LEGACY_CONSOLE)
        a = _run(["verify", "--folder", str(self.data),
                  "--manifest", str(self.manifest)], _LEGACY_CONSOLE)
        b = _run(["verify", "--folder", str(self.data),
                  "--manifest", str(self.manifest)], _EXPLICIT_UTF8)
        # Same command, same bytes — the console code page must not leak in.
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.returncode, b.returncode)

    def test_turkish_text_survives_the_round_trip(self) -> None:
        self._hash(_LEGACY_CONSOLE)
        proc = _run(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest)],
            _LEGACY_CONSOLE,
        )
        text = (proc.stdout + proc.stderr).decode("utf-8")
        # The unsigned-reference warning contains Turkish diacritics.
        self.assertIn("imzasız", text)


if __name__ == "__main__":
    unittest.main()
