"""
A manifest produced from the GUI must be signable, under the same rules.

`keygen` / `sign` / `--sign-key` were CLI-only, so every manifest the graphical
path produced was unsigned — and an unsigned manifest proves nothing on its
own: whoever can change the files can change the reference too. The previous
round gave the Verify tab a trusted-key field, which closed the *reading* half.
This is the writing half.

The rules that make a signature worth anything are already in
``core/scan_policy.py`` and already enforced for the CLI. What matters here is
that the graphical path consults the same table rather than growing a second,
more permissive one — the exact failure that table was created to end.

Signing is verified end to end: the manifest the GUI writes is handed to the
real CLI `verify --trusted-key`, which is the only check that proves the
artefact is genuinely usable rather than merely carrying a signature block.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

import main as cli
from core import manifest_signing

from tests.support import DiagnosticTempDir

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"


def run_cli(args: list[str]) -> int:
    from contextlib import redirect_stderr, redirect_stdout
    from io import StringIO

    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        return cli.main(args)


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
@unittest.skipUnless(
    manifest_signing.is_available(),
    "signing needs the optional 'cryptography' backend",
)
class HashTabSigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        (self.data / "b.txt").write_text("beta", encoding="utf-8")

        self.keydir = self.root / "keys"
        self.keydir.mkdir()
        self.key = self.keydir / "signing.key"
        self.pub = self.key.with_suffix(".key.pub")
        self.assertEqual(run_cli(["keygen", "--out", str(self.key)]), cli.EXIT_OK)

        self.outdir = self.root / "baseline"
        self.outdir.mkdir()
        self.manifest = self.outdir / "m.json"

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.tab = self.app.hash_tab

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _run_hash(self, sign_key: str = "", *, target=None, output=None, mode="folder"):
        """Drive a hash run to completion. Returns (blocked_messages, ran)."""
        blocked: list[tuple] = []
        self.tab.mode_var.set(mode)
        self.tab.target_var.set(str(target if target is not None else self.data))
        self.tab.output_var.set(str(output if output is not None else self.manifest))
        self.tab.sign_key_var.set(sign_key)
        with mock.patch("gui.app.messagebox.showerror",
                        lambda *a, **k: blocked.append(a)), \
             mock.patch("gui.app.messagebox.showwarning",
                        lambda *a, **k: blocked.append(a)), \
             mock.patch("gui.app.messagebox.askyesno", return_value=True):
            self.tab._on_run()                                   # noqa: SLF001
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                self.app.update()
                self.app.update_idletasks()
                if getattr(self.app, "_worker", None) is None:
                    break
        return blocked

    # ------------------------------------------------------------------
    def test_a_manifest_signed_from_the_gui_verifies_against_the_public_key(self) -> None:
        self._run_hash(str(self.key))

        self.assertTrue(self.manifest.exists(), "no manifest was written")
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertIn(
            "signature", doc,
            "the GUI wrote an unsigned manifest even though a key was given",
        )
        # The only check that matters: the real verifier accepts it.
        self.assertEqual(
            run_cli([
                "verify", "--folder", str(self.data),
                "--manifest", str(self.manifest), "--trusted-key", str(self.pub),
            ]),
            cli.EXIT_OK,
            "the signature the GUI produced does not verify",
        )

    def test_without_a_key_the_manifest_stays_unsigned(self) -> None:
        self._run_hash("")

        self.assertTrue(self.manifest.exists())
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertNotIn("signature", doc)

    def test_a_key_inside_the_scanned_folder_is_refused(self) -> None:
        # Anyone who receives the folder receives the key and can forge
        # manifests, so this must be refused here exactly as the CLI refuses it.
        inside = self.data / "leaked.key"
        self.assertEqual(run_cli(["keygen", "--out", str(inside)]), cli.EXIT_OK)

        blocked = self._run_hash(str(inside))

        self.assertTrue(blocked, "the GUI accepted a key stored inside the scan")
        self.assertFalse(
            self.manifest.exists(),
            "a refused request still produced a manifest",
        )

    def test_a_key_beside_the_manifest_is_refused(self) -> None:
        beside = self.outdir / "beside.key"
        self.assertEqual(run_cli(["keygen", "--out", str(beside)]), cli.EXIT_OK)

        blocked = self._run_hash(str(beside))

        self.assertTrue(
            blocked, "the GUI accepted a private key shipped next to what it signs"
        )
        self.assertFalse(self.manifest.exists())

    def test_a_signing_key_is_refused_for_a_single_file(self) -> None:
        # A signature attests to a folder inventory. Accepting a key here and
        # then quietly writing an unsigned single-file manifest would leave the
        # user believing they had signed something.
        blocked = self._run_hash(
            str(self.key), target=self.data / "a.txt", mode="file"
        )

        self.assertTrue(blocked, "a signing key was accepted for a single file")
        self.assertFalse(
            self.manifest.exists(),
            "a refused request still wrote a manifest",
        )

    def test_an_unusable_key_is_reported_and_nothing_is_written(self) -> None:
        junk = self.root / "not-a-key.txt"
        junk.write_text("this is not a key", encoding="utf-8")

        blocked = self._run_hash(str(junk))

        self.assertTrue(blocked, "an unusable signing key was accepted silently")
        self.assertFalse(
            self.manifest.exists(),
            "a manifest was written for a run whose key could not be read",
        )


if __name__ == "__main__":
    unittest.main()
