"""CSV formula-injection neutralisation tests (P1.5)."""

from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir
from core.reporter import report_to_csv
from core.verifier import ErrorEntry, ModifiedEntry, VerificationResult


def _result_with_hostile_cells() -> VerificationResult:
    r = VerificationResult(folder="C:/x", algorithm="sha256")
    # A path that Excel would treat as a formula.
    r.new.append("=HYPERLINK(\"http://evil\")")
    r.missing.append("+SUM(A1:A9)")
    r.errors.append(ErrorEntry(path="@cmd", error="-2+3"))
    r.modified.append(
        ModifiedEntry(path="normal.txt", old_hash="a", new_hash="b", old_size=1, new_size=2)
    )
    return r


def _read_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.reader(fh))


class CsvInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = DiagnosticTempDir()
        self.out = Path(self.tmp.name) / "r.csv"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_dangerous_cells_are_prefixed_by_default(self) -> None:
        report_to_csv(_result_with_hostile_cells(), self.out)
        flat = [cell for row in _read_rows(self.out) for cell in row]
        # Every hostile cell must now start with a single quote.
        self.assertIn("'=HYPERLINK(\"http://evil\")", flat)
        self.assertIn("'+SUM(A1:A9)", flat)
        self.assertIn("'@cmd", flat)
        self.assertIn("'-2+3", flat)

    def test_normal_cells_untouched(self) -> None:
        report_to_csv(_result_with_hostile_cells(), self.out)
        flat = [cell for row in _read_rows(self.out) for cell in row]
        self.assertIn("normal.txt", flat)

    def test_raw_mode_keeps_values(self) -> None:
        report_to_csv(_result_with_hostile_cells(), self.out, sanitize=False)
        flat = [cell for row in _read_rows(self.out) for cell in row]
        self.assertIn("=HYPERLINK(\"http://evil\")", flat)
        self.assertNotIn("'=HYPERLINK(\"http://evil\")", flat)


if __name__ == "__main__":
    unittest.main()
