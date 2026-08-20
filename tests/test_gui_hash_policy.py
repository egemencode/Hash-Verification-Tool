"""
The Hash tab must apply the same rules the CLI does, against real Tk widgets.

The CLI refuses to build an MD5 manifest without an explicit opt-in and
refuses to write a manifest over the file it describes. The GUI reaches the
same core functions with none of those checks, so the safer interface is the
one for experts and the default one silently does the dangerous thing.

Each case drives the real ``HashTab`` and asserts on what ends up on disk.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk

    _probe = tk.Tk()
    _probe.destroy()
    TK_AVAILABLE = True
    TK_SKIP = ""
except Exception as exc:  # pragma: no cover
    TK_AVAILABLE = False
    TK_SKIP = f"Tk unavailable: {exc}"

import core.hash_utils as hash_utils

from tests.support import DiagnosticTempDir


@unittest.skipUnless(TK_AVAILABLE, TK_SKIP or "Tk unavailable")
class HashTabPolicyTests(unittest.TestCase):
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
        self.manifest = self.root / "m.json"

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
    def _pump(self, rounds: int = 120) -> None:
        for _ in range(rounds):
            self.app.update()
            self.app.update_idletasks()

    def _configure(self, *, mode: str, target: Path, output: Path | None,
                   algo: str = "sha256") -> None:
        self.tab.mode_var.set(mode)
        self.tab.target_var.set(str(target))
        self.tab.output_var.set(str(output) if output else "")
        self.tab.algo_var.set(algo)

    def _run_and_wait(self) -> None:
        self.tab._on_run()          # noqa: SLF001
        self._pump()

    # ---- MD5 needs a conscious decision -------------------------------
    def test_md5_manifest_asks_before_running(self) -> None:
        self._configure(mode="folder", target=self.data,
                        output=self.manifest, algo="md5")
        asked: list[str] = []

        def refuse(title, body, **kwargs):
            asked.append(f"{title} {body}")
            return False

        with mock.patch("gui.app.messagebox.askyesno", refuse):
            self._run_and_wait()

        self.assertTrue(asked, "an MD5 manifest was built with no confirmation")
        self.assertFalse(
            self.manifest.exists(),
            "the manifest was written even though the user said no",
        )
        combined = " ".join(asked).lower()
        self.assertIn("md5", combined)

    def test_md5_manifest_proceeds_when_confirmed(self) -> None:
        self._configure(mode="folder", target=self.data,
                        output=self.manifest, algo="md5")
        with mock.patch("gui.app.messagebox.askyesno", lambda *a, **k: True):
            self._run_and_wait()
        self.assertTrue(self.manifest.exists(), "confirming MD5 did not build it")
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(doc["metadata"]["algorithm"], "md5")

    def test_sha256_does_not_ask(self) -> None:
        self._configure(mode="folder", target=self.data, output=self.manifest)
        asked: list[str] = []

        def spy(title, body, **kwargs):
            asked.append(title)
            return True

        with mock.patch("gui.app.messagebox.askyesno", spy):
            self._run_and_wait()
        self.assertEqual(asked, [], "the safe default asked a needless question")
        self.assertTrue(self.manifest.exists())

    # ---- the manifest must not eat its own subject --------------------
    def test_single_file_output_over_the_input_is_refused(self) -> None:
        target = self.root / "important.bin"
        target.write_bytes(b"the only copy")
        self._configure(mode="file", target=target, output=target)

        errors: list[str] = []
        with mock.patch("gui.app.messagebox.showerror",
                        lambda title, body, **k: errors.append(f"{title} {body}")):
            self._run_and_wait()

        self.assertEqual(
            target.read_bytes(), b"the only copy",
            "the GUI overwrote the file it was asked to fingerprint",
        )
        self.assertTrue(errors, "the user was not told why nothing happened")

    def test_single_file_with_output_reads_the_file_once(self) -> None:
        target = self.root / "payload.bin"
        target.write_bytes(b"payload bytes")
        self._configure(mode="file", target=target, output=self.manifest)

        real = hash_utils._guarded_hash_stream
        reads: list[str] = []

        def counting(path, algos, chunk_size):
            reads.append(str(Path(path).resolve()))
            return real(path, algos, chunk_size)

        hash_utils._guarded_hash_stream = counting
        try:
            self._run_and_wait()
        finally:
            hash_utils._guarded_hash_stream = real

        self.assertTrue(self.manifest.exists(), "no manifest was produced")
        mine = [r for r in reads if r == str(target.resolve())]
        self.assertEqual(
            len(mine), 1, f"the file was read {len(mine)} times for one manifest"
        )

    def test_a_target_with_no_default_manifest_name_reports_an_error(self) -> None:
        # Deriving the default output path moved from the worker thread (where
        # _Worker wrapped every exception into an error dialog) onto the Tk
        # main thread, where nothing catches it. A drive root or a bare UNC
        # share has no filename to build "manifest.json" beside, so the button
        # raises into Tk's callback handler: the user sees it do nothing at
        # all — no dialog, no log line, no clue.
        for target in ("C:\\", "\\\\nohost-does-not-exist\\share"):
            with self.subTest(target=target):
                self._configure(mode="folder", target=Path(target), output=None)
                shown: list[str] = []
                with mock.patch(
                    "gui.app.messagebox.showerror",
                    lambda title, body, **k: shown.append(f"{title} {body}"),
                ):
                    try:
                        self.tab._on_run()   # noqa: SLF001
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"the Hash button raised on the Tk thread: {exc!r}")
                    self._pump(20)
                self.assertTrue(
                    shown, "the button did nothing and said nothing"
                )

    # ---- writing into the scanned folder ------------------------------
    def test_manifest_inside_the_scanned_folder_is_called_out(self) -> None:
        inside = self.data / "manifest.json"
        self._configure(mode="folder", target=self.data, output=inside)
        self._run_and_wait()

        self.assertTrue(inside.exists())
        shown = self.tab.output_area.get("1.0", "end").lower()
        self.assertIn(
            "manifest.json", shown,
            "nothing said the manifest was written inside the scanned folder",
        )
        self.assertTrue(
            "hariç" in shown or "excluded" in shown,
            f"no note that it was excluded from its own inventory:\n{shown}",
        )


if __name__ == "__main__":
    unittest.main()
