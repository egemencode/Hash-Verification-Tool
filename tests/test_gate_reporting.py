"""
What the release gate prints when a round fails.

The gate quotes an excerpt of the child's stderr, and for a normal failure the
right excerpt is the end: the assertion and the traceback under it. A round
that *crashes* is the opposite. Python prints a fatal-error dump whose last
lines are unittest's own runner machinery — identical for every crash there
has ever been — while the frame that names the failing test sits at the top.

This is not hypothetical. A packaging-round gate hit exit 3221226505
(0xC0000409) twice in twenty-two rounds, and the quoted excerpt was ten lines
of ``unittest/suite.py`` and ``runpy`` both times. The dump had the answer in
it; the reporting threw that half away.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))

from run_suite_gate import failure_excerpt  # noqa: E402


FATAL_DUMP = """\
Windows fatal exception: code 0xc0000409

Current thread 0x00001b4c (most recent call first):
  File "C:\\proje\\tests\\test_gui_worker_race.py", line 88 in tearDown
  File "C:\\Python312\\Lib\\unittest\\case.py", line 634 in run
  File "C:\\Python312\\Lib\\unittest\\suite.py", line 122 in run
  File "C:\\Python312\\Lib\\unittest\\main.py", line 281 in runTests
  File "<frozen runpy>", line 198 in _run_module_as_main

Extension modules: _cffi_backend (total: 1)
"""

ASSERTION_FAILURE = """\
test_one (tests.test_thing.ThingTests) ... ok
test_two (tests.test_thing.ThingTests) ... FAIL

======================================================================
FAIL: test_two (tests.test_thing.ThingTests)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "tests/test_thing.py", line 12, in test_two
    self.assertEqual(1, 2)
AssertionError: 1 != 2
"""


class FailureExcerptTests(unittest.TestCase):
    def test_a_crash_is_quoted_from_the_dump_header(self) -> None:
        excerpt = failure_excerpt(FATAL_DUMP, limit=4)
        self.assertIn("Windows fatal exception", excerpt)
        self.assertIn("Current thread", excerpt)

    def test_a_crash_excerpt_reaches_the_test_that_was_running(self) -> None:
        """The whole point: the excerpt has to name a test, not the runner."""
        excerpt = failure_excerpt(FATAL_DUMP, limit=5)
        self.assertIn("test_gui_worker_race.py", excerpt)
        self.assertNotIn("_run_module_as_main", excerpt)

    def test_an_ordinary_failure_is_still_quoted_from_the_end(self) -> None:
        excerpt = failure_excerpt(ASSERTION_FAILURE, limit=3)
        self.assertIn("AssertionError: 1 != 2", excerpt)
        self.assertNotIn("test_one", excerpt)

    def test_the_limit_bounds_the_excerpt(self) -> None:
        lines = failure_excerpt(FATAL_DUMP, limit=3).splitlines()
        self.assertEqual(len(lines), 3, lines)

    def test_a_dump_shorter_than_the_limit_is_not_padded(self) -> None:
        excerpt = failure_excerpt("Fatal Python error: Aborted", limit=10)
        self.assertEqual(excerpt, "Fatal Python error: Aborted")

    def test_output_with_no_dump_and_no_traceback_still_returns_something(self) -> None:
        self.assertEqual(failure_excerpt("only one line", limit=5), "only one line")


class ImportSideEffectTests(unittest.TestCase):
    """Importing a tool must not rewrite this process's stdout.

    All three tools reconfigure stdout to UTF-8, which is right for a script
    printing Turkish to a cp1254 console and wrong to do at import time: a
    module that changes global state just by being imported makes every suite
    that imports it order-dependent. This suite has spent enough rounds on
    encoding defects to care which encoding it is actually running under.
    """

    def test_importing_the_gate_leaves_stdout_alone(self) -> None:
        before = sys.stdout.encoding
        import importlib

        import run_suite_gate

        importlib.reload(run_suite_gate)
        self.assertEqual(sys.stdout.encoding, before)


if __name__ == "__main__":
    unittest.main()
