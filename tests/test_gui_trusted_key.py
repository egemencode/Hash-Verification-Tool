"""
The trusted-verification path must be reachable from the GUI.

`SignatureState.TRUSTED` — the only state in which a match actually says
"these files are what the person holding that key published" — requires a
trusted public key to be supplied. The CLI takes one via `--trusted-key`. The
Verify tab passed none, to either `Manifest.load` or `Verifier`, so the badge
it rendered could never read better than "signed, but the source is not
verified", no matter what the user had on disk.

The screen even said so, and told the user to go and use the CLI instead. That
is the asymmetry `core/scan_policy.py` was written to remove in a previous
round, still present here: the expert surface can establish provenance and the
default one cannot.

These tests build a real signed manifest through the CLI — the artefact a user
would actually have — and then drive the GUI against it.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import main as cli
from core import manifest_signing

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
class VerifyTabTrustedKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._env = mock.patch.dict(
            os.environ, {"LOCALAPPDATA": str(self.root / "profile")}
        )
        self._env.start()

        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        (self.data / "b.txt").write_text("beta", encoding="utf-8")

        # The key lives outside the folder being hashed, as the tool requires.
        self.keydir = self.root / "keys"
        self.keydir.mkdir()
        self.key = self.keydir / "signing.key"
        self.pub = self.key.with_suffix(".key.pub")
        self.manifest = self.root / "m.json"

        self.assertEqual(run_cli(["keygen", "--out", str(self.key)]), cli.EXIT_OK)
        self.assertEqual(
            run_cli([
                "hash", "--folder", str(self.data),
                "--output", str(self.manifest), "--sign-key", str(self.key),
            ]),
            cli.EXIT_OK,
        )

        from gui.app import HashToolApp

        self.app = HashToolApp()
        self.app.update_idletasks()
        self.tab = self.app.verify_tab

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        finally:
            self._env.stop()
            self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _run_verify(self, trusted_key: str = "") -> str:
        """Drive a verification to completion and return what is on screen."""
        self.tab.folder_var.set(str(self.data))
        self.tab.manifest_var.set(str(self.manifest))
        self.tab.trusted_key_var.set(trusted_key)
        with mock.patch("gui.app.messagebox.showerror"), \
             mock.patch("gui.app.messagebox.showwarning"):
            self.tab._on_run()                                  # noqa: SLF001
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                self.app.update()
                self.app.update_idletasks()
                if getattr(self.app, "_worker", None) is None:
                    break
            else:
                raise AssertionError("the verification never finished")
        return self.tab.summary.get("1.0", "end")

    # ------------------------------------------------------------------
    def test_a_trusted_key_establishes_the_manifest_provenance(self) -> None:
        shown = self._run_verify(str(self.pub))

        self.assertIn(
            "Güvenilen anahtarla doğrulandı", shown,
            "supplying the trusted key did not establish the manifest's origin",
        )
        # The screen must stop sending the user elsewhere once the default
        # interface can do the job.
        self.assertNotIn(
            "verify --trusted-key", shown,
            "the GUI still tells the user to go and use the CLI for this",
        )

    def test_without_a_key_the_result_is_not_claimed_as_trusted(self) -> None:
        shown = self._run_verify("")

        self.assertNotIn(
            "Güvenilen anahtarla doğrulandı", shown,
            "a manifest verified against no trusted key was reported as trusted",
        )

    def test_the_wrong_key_stops_the_run_as_a_tampering_signal(self) -> None:
        # A signature that does not verify against the key the operator trusts
        # is the same event the CLI answers with EXIT_UNTRUSTED_REFERENCE: it
        # must stop the comparison, not quietly downgrade to an untrusted one
        # whose screen looks like an ordinary result.
        other = self.keydir / "other.key"
        self.assertEqual(run_cli(["keygen", "--out", str(other)]), cli.EXIT_OK)

        shown = self._run_verify(str(other.with_suffix(".key.pub")))

        self.assertNotIn(
            "Güvenilen anahtarla doğrulandı", shown,
            "a manifest signed by a different key was reported as trusted",
        )
        self.assertIn(
            "doğrulama durduruldu", shown,
            f"the run did not stop on an unverifiable signature: {shown!r}",
        )

    def test_an_untrustworthy_manifest_is_rejected_before_the_folder_is_scanned(
        self,
    ) -> None:
        # The signature is checked against the trusted key when the manifest is
        # loaded, not after the scan. Otherwise someone pointing the tool at a
        # large tree waits through a full hash of it only to be told the
        # reference was never worth comparing against — and the machine does
        # all that work on the say-so of a file we already knew we distrust.
        import gui.app as app_mod

        other = self.keydir / "other.key"
        self.assertEqual(run_cli(["keygen", "--out", str(other)]), cli.EXIT_OK)

        scanned: list[str] = []
        real = app_mod.Verifier

        class RecordingVerifier(real):  # type: ignore[valid-type,misc]
            def verify(self, folder, *args, **kwargs):
                scanned.append(str(folder))
                return super().verify(folder, *args, **kwargs)

        with mock.patch.object(app_mod, "Verifier", RecordingVerifier):
            self._run_verify(str(other.with_suffix(".key.pub")))

        self.assertEqual(
            scanned, [],
            "the folder was scanned before the manifest was found untrustworthy",
        )

    def test_an_unreadable_key_is_reported_and_nothing_is_claimed(self) -> None:
        # A typo in the path, or a file that is not a key at all: the run must
        # say so rather than quietly falling back to an untrusted comparison
        # that looks the same as a successful one.
        junk = self.root / "not-a-key.txt"
        junk.write_text("this is not a key", encoding="utf-8")

        errors: list[tuple] = []
        self.tab.folder_var.set(str(self.data))
        self.tab.manifest_var.set(str(self.manifest))
        self.tab.trusted_key_var.set(str(junk))
        with mock.patch("gui.app.messagebox.showerror",
                        lambda *a, **k: errors.append(a)):
            self.tab._on_run()                                  # noqa: SLF001
            self.app.update()
            self.app.update_idletasks()

        self.assertTrue(errors, "an unusable trusted key was accepted silently")
        self.assertNotIn(
            "Güvenilen anahtarla doğrulandı",
            self.tab.summary.get("1.0", "end"),
        )


if __name__ == "__main__":
    unittest.main()
