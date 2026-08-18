"""
Drag-and-drop must hand back the path the OS actually gave us.

windnd delivers dropped paths as bytes in the filesystem encoding. Decoding
them as UTF-8 with ``errors="replace"`` is lossy: any byte sequence that is
not valid UTF-8 turns into U+FFFD, and the result names a file that does not
exist. NTFS accepts unpaired surrogates in filenames, and Python encodes those
with ``surrogatepass`` — so this is not a theoretical case, it is a file you
can create and then fail to open.

``os.fsdecode`` is the inverse of ``os.fsencode`` by construction, so the
decoded string round-trips back to the real file.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from gui.views.trust_check_view import decode_dropped_path
from tests.support import DiagnosticTempDir


class DecodeDroppedPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _drop(self, path: str) -> str:
        """What the library hands us for *path*."""
        return decode_dropped_path(os.fsencode(path))

    def test_ascii_path_round_trips(self) -> None:
        target = self.root / "plain.txt"
        target.write_text("x", encoding="utf-8")
        self.assertEqual(self._drop(str(target)), str(target))

    def test_turkish_path_round_trips(self) -> None:
        target = self.root / "çalışma günü ışığı.txt"
        target.write_text("x", encoding="utf-8")
        decoded = self._drop(str(target))
        self.assertEqual(decoded, str(target))
        self.assertTrue(os.path.exists(decoded))

    def test_emoji_path_round_trips(self) -> None:
        target = self.root / "rapor \U0001f510.txt"
        target.write_text("x", encoding="utf-8")
        self.assertTrue(os.path.exists(self._drop(str(target))))

    def test_unpaired_surrogate_name_still_names_a_real_file(self) -> None:
        # NTFS allows this; a lossy decode turns it into a path that is not
        # there, and the user is told their file does not exist.
        target = self.root / "lone\udcff.txt"
        try:
            with open(target, "wb") as handle:
                handle.write(b"x")
        except OSError as exc:  # pragma: no cover - other filesystems
            self.skipTest(f"filesystem rejects the name: {exc}")

        decoded = self._drop(str(target))
        self.assertTrue(
            os.path.exists(decoded),
            f"the dropped path no longer names a real file: {decoded!r}",
        )
        self.assertEqual(decoded, str(target))
        os.unlink(target)

    def test_already_decoded_input_passes_through(self) -> None:
        # Some windnd builds hand back str; both shapes must work.
        target = self.root / "plain.txt"
        target.write_text("x", encoding="utf-8")
        self.assertEqual(decode_dropped_path(str(target)), str(target))

    def test_ansi_bytes_from_the_drop_library_still_name_the_file(self) -> None:
        # windnd calls the ANSI DragQueryFile unless asked for unicode, so the
        # bytes that arrive are in the active code page — cp1254 on a Turkish
        # Windows — not UTF-8. Decoding them as UTF-8 does not merely mangle
        # the name, it raises, and the exception unwinds into a ctypes callback
        # where nothing catches it: the drop silently does nothing at all.
        target = self.root / "şarkı çalışma.txt"
        target.write_text("x", encoding="utf-8")
        try:
            ansi = str(target).encode("mbcs")
        except UnicodeEncodeError:  # pragma: no cover - non-Windows
            self.skipTest("no ANSI code page on this platform")

        decoded = decode_dropped_path(ansi)
        self.assertTrue(
            os.path.exists(decoded),
            f"an ANSI-encoded drop did not name a real file: {decoded!r}",
        )
        self.assertEqual(decoded, str(target))

    def test_an_ansi_name_that_is_also_valid_utf8_resolves_to_the_dropped_file(
        self,
    ) -> None:
        # Some ANSI byte sequences are *also* well-formed UTF-8, and the two
        # readings name different files that can sit side by side in the same
        # folder. cp1254 "Ã§" is the pair C3 A7, which UTF-8 reads as "ç". Both
        # decodings then name a file that exists, so "first one that exists"
        # no longer disambiguates — the decoder order alone decides. The bytes
        # came from the ANSI API, so the code page reading is the true one;
        # trying os.fsdecode first hands the caller a file the user never
        # dropped, and the tool reports a verdict for the wrong file.
        dropped = self.root / "Ã§.txt"
        try:
            raw = str(dropped).encode("mbcs")
        except UnicodeEncodeError:  # pragma: no cover - non-Windows
            self.skipTest("the active code page cannot represent this name")
        try:
            utf8_view = raw.decode("utf-8")
        except UnicodeDecodeError:  # pragma: no cover - other code page
            self.skipTest("these ANSI bytes are not also valid UTF-8 here")
        if utf8_view == str(dropped):  # pragma: no cover - other code page
            self.skipTest("the code page and UTF-8 agree; no ambiguity to test")

        decoy = Path(utf8_view)
        dropped.write_text("dropped", encoding="utf-8")
        decoy.write_text("decoy", encoding="utf-8")

        decoded = decode_dropped_path(raw)
        self.assertEqual(
            decoded,
            str(dropped),
            "the ANSI bytes were read as UTF-8, so the drop resolved to "
            f"{decoded!r} instead of the file the user dropped",
        )

    def test_a_name_the_code_page_cannot_represent_never_raises(self) -> None:
        # Emoji have no cp1254 representation, so the ANSI API cannot deliver
        # this name at all. Whatever arrives, decoding must degrade to a
        # visible "no such file" — never an exception in the drop callback.
        raw = "C:\\yok\\\U0001f510.txt".encode("utf-8")
        decoded = decode_dropped_path(raw)
        self.assertIsInstance(decoded, str)

    def test_the_view_asks_the_library_for_unicode(self) -> None:
        # The real fix is upstream of decoding: request DragQueryFileW so the
        # library hands back str and no code-page round trip happens.
        import gui.views.trust_check_view as view_mod

        self.assertTrue(
            view_mod.DROP_HOOK_KWARGS.get("force_unicode"),
            "the drop hook still uses the ANSI path, which cannot represent "
            "every filename NTFS accepts",
        )


if __name__ == "__main__":
    unittest.main()
