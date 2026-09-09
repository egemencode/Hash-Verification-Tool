"""The log file lives with the per-user data, not next to a frozen exe."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from utils import logger as logmod
from utils.settings import base_dir


class LogsDirTests(unittest.TestCase):
    def test_logs_live_under_the_per_user_base_dir(self):
        # Must match where settings stores everything else. A PyInstaller
        # onefile build's __file__ is a temporary _MEI directory that vanishes
        # on exit, so a source-adjacent logs/ dir would lose every log there.
        self.assertEqual(logmod._logs_dir(), base_dir() / "logs")

    def test_logs_dir_falls_back_instead_of_raising(self):
        # Logging is best-effort: if the per-user base cannot be resolved,
        # _logs_dir must return the fallback, never propagate the error into
        # get_logger().
        with mock.patch("utils.settings.base_dir", side_effect=OSError("boom")):
            self.assertEqual(logmod._logs_dir(), logmod._fallback_logs_dir())


if __name__ == "__main__":
    unittest.main()
