"""
End-to-end demo for the Hash Verification Tool.

Creates a throwaway folder, hashes it, deliberately tampers with the
contents (modifies a file, deletes one, adds a new one) and re-verifies
so that every status category is exercised in a single run.

Run from the project root:

    python demo.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.manifest_manager import build_manifest_for_folder
from core.reporter import report_to_console, report_to_csv, report_to_json
from core.verifier import Verifier

_PROJECT_ROOT = Path(__file__).resolve().parent
# Keep the scanned folder and the manifest/report files separate so the
# manifest itself is not picked up as a 'new' file during verification.
DEMO_ROOT = _PROJECT_ROOT / "demo_data" / "files"
_OUTPUT_DIR = _PROJECT_ROOT / "demo_data"
MANIFEST_PATH = _OUTPUT_DIR / "manifest.json"
REPORT_JSON = _OUTPUT_DIR / "report.json"
REPORT_CSV = _OUTPUT_DIR / "report.csv"


def _build_initial_layout(root: Path) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    (root / "readme.txt").write_text(
        "Hash Verification Tool demo — original content.\n", encoding="utf-8"
    )
    (root / "config.ini").write_text(
        "[settings]\nlevel=info\n", encoding="utf-8"
    )

    docs = root / "docs"
    docs.mkdir()
    (docs / "notes.md").write_text("# Notes\nfirst draft\n", encoding="utf-8")

    binary = root / "blob.bin"
    binary.write_bytes(b"\x00\x01\x02\x03" * 256)


def _tamper_with_layout(root: Path) -> None:
    # Modify
    (root / "readme.txt").write_text(
        "Hash Verification Tool demo — TAMPERED content.\n", encoding="utf-8"
    )
    # Delete
    (root / "config.ini").unlink()
    # Add
    (root / "new_file.log").write_text("freshly added\n", encoding="utf-8")
    # And leave docs/notes.md + blob.bin alone so we get 'unchanged' too.


def main() -> int:
    print(">>> Step 1: building a small demo folder under demo_data/")
    _build_initial_layout(DEMO_ROOT)

    print(">>> Step 2: hashing the folder and saving the manifest")
    build = build_manifest_for_folder(DEMO_ROOT, algorithm="sha256")
    manifest = build.manifest
    manifest.save(MANIFEST_PATH)
    status = "complete" if build.complete else f"PARTIAL ({len(build.skipped)} skipped)"
    print(f"    manifest -> {MANIFEST_PATH}  ({len(manifest.entries)} files, {status})")

    print(">>> Step 3: tampering with the folder (modify + delete + add)")
    _tamper_with_layout(DEMO_ROOT)

    print(">>> Step 4: re-verifying against the original manifest")
    result = Verifier(manifest).verify(DEMO_ROOT)
    report_to_console(result, verbose=True)

    print(">>> Step 5: writing JSON + CSV reports")
    report_to_json(result, REPORT_JSON)
    report_to_csv(result, REPORT_CSV)
    print(f"    json report -> {REPORT_JSON}")
    print(f"    csv  report -> {REPORT_CSV}")

    return 0 if result.is_clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
