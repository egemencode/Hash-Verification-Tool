"""
P0.1 — the atomic writer's contract, stated as behaviour.

Contract: after ``write_json_atomic`` / ``write_text_atomic`` returns *or
raises*, the destination directory contains **exactly** the destination file
(when the write succeeded) or its previous content (when it failed), and
never a temporary file.

These tests deliberately do NOT clean up leftovers themselves: a leaked temp
file must surface as a failure, not be quietly swept away.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import DiagnosticTempDir
from core.atomic_io import AtomicWriteError, write_json_atomic, write_text_atomic


class _Dir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.target = self.root / "history.json"

    def tearDown(self) -> None:
        # Report leftovers as a failure *before* cleanup removes the evidence.
        leftovers = sorted(p.name for p in self.root.iterdir() if p != self.target)
        self._tmp.cleanup()
        if leftovers:
            self.fail(f"temporary files leaked into the target directory: {leftovers}")

    def entries(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir())


class SuccessPathTests(_Dir):
    def test_only_destination_remains(self) -> None:
        write_json_atomic(self.target, {"a": 1})
        self.assertEqual(self.entries(), ["history.json"])

    def test_repeated_writes_leave_nothing_behind(self) -> None:
        for i in range(50):
            write_json_atomic(self.target, {"i": i})
        self.assertEqual(self.entries(), ["history.json"])


class FailurePathTests(_Dir):
    """Every failing stage must leave the directory exactly as it was."""

    def _preexisting(self) -> None:
        write_json_atomic(self.target, {"original": True})

    def test_encode_failure_leaves_no_temp(self) -> None:
        self._preexisting()
        # A payload that cannot be encoded to the target codec.
        with self.assertRaises(Exception):
            write_text_atomic(self.target, "ünicode", encoding="ascii")
        self.assertEqual(self.entries(), ["history.json"])
        self.assertTrue(json.loads(self.target.read_text(encoding="utf-8"))["original"])

    def test_write_failure_leaves_no_temp(self) -> None:
        self._preexisting()
        with mock.patch("core.atomic_io.os.write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write_json_atomic(self.target, {"new": True})
        self.assertEqual(self.entries(), ["history.json"])

    def test_fsync_failure_leaves_no_temp(self) -> None:
        self._preexisting()
        with mock.patch("core.atomic_io.os.fsync", side_effect=OSError("no fsync")):
            with self.assertRaises(OSError):
                write_json_atomic(self.target, {"new": True})
        self.assertEqual(self.entries(), ["history.json"])

    def test_close_failure_leaves_no_temp(self) -> None:
        self._preexisting()
        real_close = os.close
        state = {"tripped": False}

        def failing_close(fd):
            if not state["tripped"]:
                state["tripped"] = True
                real_close(fd)          # still release the descriptor
                raise OSError("close failed")
            return real_close(fd)

        with mock.patch("core.atomic_io.os.close", failing_close):
            with self.assertRaises(OSError):
                write_json_atomic(self.target, {"new": True})
        self.assertEqual(self.entries(), ["history.json"])

    def test_replace_failure_leaves_no_temp(self) -> None:
        self._preexisting()
        with mock.patch("core.atomic_io.os.replace", side_effect=OSError("locked")):
            with self.assertRaises(OSError):
                write_json_atomic(self.target, {"new": True})
        self.assertEqual(self.entries(), ["history.json"])
        self.assertTrue(json.loads(self.target.read_text(encoding="utf-8"))["original"])

    def test_serialisation_failure_leaves_no_temp(self) -> None:
        self._preexisting()

        class NotSerialisable:
            pass

        with self.assertRaises(TypeError):
            write_json_atomic(self.target, {"bad": NotSerialisable()})
        self.assertEqual(self.entries(), ["history.json"])


class ShortWriteTests(_Dir):
    """os.write() returning 0 must fail loudly, not spin forever."""

    def test_zero_length_write_raises_instead_of_looping(self) -> None:
        with mock.patch("core.atomic_io.os.write", return_value=0):
            with self.assertRaises(AtomicWriteError):
                write_json_atomic(self.target, {"payload": "x" * 100})
        self.assertEqual(self.entries(), [])

    def test_partial_writes_are_completed(self) -> None:
        real_write = os.write

        def dribble(fd, data):
            # Write one byte at a time: the loop must still finish correctly.
            return real_write(fd, data[:1])

        with mock.patch("core.atomic_io.os.write", dribble):
            write_json_atomic(self.target, {"value": "abcdefghij"})
        self.assertEqual(
            json.loads(self.target.read_text(encoding="utf-8"))["value"], "abcdefghij"
        )
        self.assertEqual(self.entries(), ["history.json"])


class UnlinkFailureTests(_Dir):
    """If the temp file cannot be removed, say so — do not swallow it."""

    def test_unremovable_temp_is_reported(self) -> None:
        real_unlink = os.unlink
        stuck: dict[str, str] = {}

        def refuse(path, *a, **kw):
            stuck["path"] = str(path)
            raise PermissionError("held by another process")

        with mock.patch("core.atomic_io.os.replace", side_effect=OSError("locked")), \
             mock.patch("core.atomic_io.os.unlink", refuse):
            with self.assertRaises(OSError) as ctx:
                write_json_atomic(self.target, {"new": True})
        # The raised error must mention that a temp file was left behind.
        self.assertIn("temp", str(ctx.exception).lower())
        # Clean the evidence up manually so tearDown's assertion is meaningful
        # for *unexpected* leaks only.
        real_unlink(stuck["path"])


if __name__ == "__main__":
    unittest.main()
