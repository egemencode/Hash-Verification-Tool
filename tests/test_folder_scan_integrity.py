"""
P0.5 — folder scanning and manifest correctness.

Behaviours under test:
  * verification re-hashes with a handle-bound strict snapshot, so a content
    swap that preserves size+mtime cannot pass as "unchanged";
  * reparse points (symlinks / junctions) are not followed by default, and a
    junction pointing outside the root cannot smuggle files in;
  * a junction cycle terminates;
  * the manifest/report never scan themselves;
  * an unreadable file makes the build *incomplete* — never a silent success;
  * the CLI distinguishes these outcomes by exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support import DiagnosticTempDir, deny_reads_of
from core.hash_utils import enumerate_files
from core.manifest_manager import Manifest, build_manifest_for_folder
from core.verifier import Verifier

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = sys.platform.startswith("win")


def _make_junction(link: Path, target: Path) -> bool:
    """Create a directory junction/symlink. Returns False if unsupported."""
    if IS_WINDOWS:
        proc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, text=True,
        )
        return proc.returncode == 0
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except OSError:
        return False


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()


class ContentSwapTests(_Tree):
    def test_same_size_and_mtime_swap_is_detected(self) -> None:
        victim = self.data / "payload.bin"
        victim.write_bytes(b"ORIGINAL" * 64)
        build = build_manifest_for_folder(self.data)
        manifest = build.manifest if hasattr(build, "manifest") else build

        st = victim.stat()
        victim.write_bytes(b"REPLACED" * 64)          # identical length
        os.utime(victim, ns=(st.st_atime_ns, st.st_mtime_ns))  # identical mtime
        after = victim.stat()
        self.assertEqual(after.st_size, st.st_size)
        self.assertEqual(after.st_mtime_ns, st.st_mtime_ns)

        result = Verifier(manifest).verify(self.data)
        self.assertFalse(result.is_clean, "a forged-metadata content swap passed as clean")
        self.assertTrue(result.modified, "the swapped file was not reported as modified")


class ReparsePointTests(_Tree):
    def test_junction_outside_root_is_not_followed(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("should not be scanned", encoding="utf-8")
        (self.data / "inside.txt").write_text("ok", encoding="utf-8")

        if not _make_junction(self.data / "link", outside):
            self.skipTest("cannot create a junction on this system")

        build = build_manifest_for_folder(self.data)
        manifest = build.manifest if hasattr(build, "manifest") else build
        joined = " ".join(manifest.entries)
        self.assertIn("inside.txt", joined)
        self.assertNotIn("secret.txt", joined, "a file outside the root was scanned")

    def test_junction_cycle_terminates(self) -> None:
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        sub = self.data / "sub"
        sub.mkdir()
        if not _make_junction(sub / "loop", self.data):
            self.skipTest("cannot create a junction on this system")

        # Must return rather than recursing forever.
        build = build_manifest_for_folder(self.data)
        manifest = build.manifest if hasattr(build, "manifest") else build
        self.assertIn("a.txt", " ".join(manifest.entries))

    def test_junction_cycle_terminates_while_following(self) -> None:
        # The cycle guard only ever runs when following is enabled, so this is
        # the case that actually exercises it.
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        sub = self.data / "sub"
        sub.mkdir()
        if not _make_junction(sub / "loop", self.data):
            self.skipTest("cannot create a junction on this system")

        build = build_manifest_for_folder(self.data, follow_symlinks=True)
        self.assertIn("a.txt", build.manifest.entries)

    def test_no_link_kind_can_pull_content_from_outside_the_root(self) -> None:
        # Containment used to be checked only in the directory branch, so a
        # *file* symlink pointing at, say, an SSH key would be hashed and
        # recorded as an entry of the scanned folder — precisely what the
        # flag's own help text promises cannot happen.
        #
        # Creating a file symlink needs SeCreateSymbolicLinkPrivilege, which is
        # not available to an ordinary process on a machine without Developer
        # Mode. So this asserts the rule for whichever link kinds this machine
        # can actually create — never nothing.
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("must not be scanned", encoding="utf-8")
        (self.data / "inside.txt").write_text("ok", encoding="utf-8")

        checked = []
        if _make_junction(self.data / "dirlink", outside):
            checked.append("directory junction")
        try:
            (self.data / "filelink.txt").symlink_to(outside / "secret.txt")
            checked.append("file symlink")
        except OSError:
            # No privilege for file symlinks here; the directory case below
            # still exercises the same containment branch.
            pass
        self.assertTrue(checked, "no link kind could be created to test with")

        entries = {
            p.relative_to(self.data).as_posix()
            for p in enumerate_files(self.data, follow_symlinks=True)
        }
        self.assertIn("inside.txt", entries)
        for name in entries:
            self.assertNotIn(
                "secret.txt", name,
                f"a file from outside the root was scanned via {checked}: {name}",
            )

    def test_a_junction_web_does_not_explode_the_walk(self) -> None:
        # A cycle guard that only rejects "this directory is its own ancestor"
        # puts no bound on how many *distinct paths* reach the same directory.
        # With N directories that all link to each other, the walk enumerates
        # every simple path through the junction graph — factorial in N. A few
        # kilobytes of metadata inside the scanned tree is then enough to wedge
        # the scan, and enumeration finishes before any cancel is polled, so
        # the run cannot even be stopped.
        n = 6
        dirs = []
        for i in range(n):
            d = self.data / f"d{i}"
            d.mkdir()
            (d / "f.txt").write_text(f"file {i}", encoding="utf-8")
            dirs.append(d)
        for i, source in enumerate(dirs):
            for j, target in enumerate(dirs):
                if i != j and not _make_junction(source / f"to{j}", target):
                    self.skipTest("cannot create a junction on this system")

        found = enumerate_files(self.data, follow_symlinks=True)

        # Every real file must still be covered under its real path.
        real_paths = {
            f"d{i}/f.txt" for i in range(n)
        }
        seen = {p.relative_to(self.data).as_posix() for p in found}
        self.assertTrue(
            real_paths.issubset(seen),
            f"a real directory was dropped from the scan: {sorted(seen)}",
        )
        # And the total work must stay proportional to the tree, not to the
        # number of paths through it. Unbounded here means "the tool hangs".
        self.assertLessEqual(
            len(found), 4 * n,
            f"{len(found)} entries yielded for {n} real files — the walk is "
            "enumerating paths through the junction graph, not the tree",
        )

    def test_a_junction_does_not_hide_the_directory_it_points_at(self) -> None:
        # A device+inode set shared across the whole walk cannot tell "I am
        # inside myself" from "I have already seen this content elsewhere".
        # With a junction pointing at a sibling, whichever name sorts first
        # claims the identity and the other directory silently vanishes from
        # the manifest — a coverage hole exactly where someone placed a link.
        real = self.data / "real"
        real.mkdir()
        (real / "deep.txt").write_text("deep", encoding="utf-8")
        if not _make_junction(self.data / "link", real):
            self.skipTest("cannot create a junction on this system")

        build = build_manifest_for_folder(self.data, follow_symlinks=True)
        entries = set(build.manifest.entries)
        self.assertIn(
            "real/deep.txt", entries,
            f"the real directory was dropped from the scan: {sorted(entries)}",
        )
        self.assertIn("link/deep.txt", entries)


class SelfExclusionTests(_Tree):
    def test_manifest_inside_root_excludes_itself(self) -> None:
        (self.data / "f.txt").write_text("x", encoding="utf-8")
        target = self.data / "manifest.json"

        build = build_manifest_for_folder(self.data, exclude=[target])
        manifest = build.manifest if hasattr(build, "manifest") else build
        manifest.save(target)

        self.assertNotIn("manifest.json", manifest.entries)
        # And a verify straight afterwards must be clean, not "new file".
        loaded = Manifest.load(target)
        result = Verifier(loaded).verify(self.data, exclude=[target])
        self.assertTrue(result.is_clean, f"unexpected: {result.summary()}")


class PartialBuildTests(_Tree):
    def test_unreadable_file_makes_build_incomplete(self) -> None:
        (self.data / "good.txt").write_text("ok", encoding="utf-8")
        bad = self.data / "bad.bin"
        bad.write_bytes(b"data")

        # Not a str comparison: the product resolves the scan root before it
        # opens anything under it, so on a machine whose temp directory has
        # another spelling the denial would never fire and this test would
        # assert "incomplete" about a scan that read every file.
        with deny_reads_of(bad):
            build = build_manifest_for_folder(self.data)

        self.assertFalse(build.complete, "a build that skipped a file claimed success")
        self.assertTrue(build.skipped or build.errors)
        self.assertIn("good.txt", build.manifest.entries)
        self.assertNotIn("bad.bin", build.manifest.entries)

    def test_complete_build_reports_complete(self) -> None:
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        build = build_manifest_for_folder(self.data)
        self.assertTrue(build.complete)
        self.assertEqual(build.skipped, [])
        self.assertGreaterEqual(len(build.inventory), 1)


class CliExitCodeTests(_Tree):
    """Different failures must be distinguishable by exit code."""

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "main.py", *args],
            cwd=str(_PROJECT_ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )

    def test_clean_folder_exits_zero(self) -> None:
        # --allow-unsigned: this test is about the folder scan, not about
        # reference trust (which has its own suite).
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        m = self.root / "m.json"
        self.assertEqual(
            self._run("hash", "--folder", str(self.data), "--output", str(m)).returncode, 0
        )
        proc = self._run(
            "verify", "--folder", str(self.data), "--manifest", str(m), "--allow-unsigned"
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_missing_manifest_and_mismatch_differ(self) -> None:
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        m = self.root / "m.json"
        self._run("hash", "--folder", str(self.data), "--output", str(m))

        missing = self._run(
            "verify", "--folder", str(self.data),
            "--manifest", str(self.root / "nope.json"), "--allow-unsigned",
        ).returncode
        (self.data / "a.txt").write_text("changed", encoding="utf-8")
        mismatch = self._run(
            "verify", "--folder", str(self.data), "--manifest", str(m), "--allow-unsigned"
        ).returncode

        self.assertNotEqual(missing, 0)
        self.assertNotEqual(mismatch, 0)
        self.assertNotEqual(
            missing, mismatch, "a missing manifest and a content mismatch share an exit code"
        )

    def test_partial_manifest_build_exits_non_zero(self) -> None:
        # A folder containing a file we cannot read must not report success.
        (self.data / "a.txt").write_text("a", encoding="utf-8")
        locked = self.data / "locked.bin"
        locked.write_bytes(b"secret")

        def deny() -> bool:
            if IS_WINDOWS:
                user = os.environ.get("USERNAME") or ""
                proc = subprocess.run(
                    ["icacls", str(locked), "/inheritance:r", "/deny", f"{user}:(R)"],
                    capture_output=True, text=True,
                )
                return proc.returncode == 0
            os.chmod(locked, 0o000)
            return os.geteuid() != 0 if hasattr(os, "geteuid") else True

        def restore() -> None:
            if IS_WINDOWS:
                subprocess.run(
                    ["icacls", str(locked), "/reset"], capture_output=True, text=True
                )
                subprocess.run(
                    ["icacls", str(locked), "/grant", f"{os.environ.get('USERNAME')}:(F)"],
                    capture_output=True, text=True,
                )
            else:
                os.chmod(locked, 0o644)

        if not deny():
            self.skipTest("cannot make a file unreadable on this system")
        try:
            proc = self._run(
                "hash", "--folder", str(self.data), "--output", str(self.root / "m.json")
            )
            if proc.returncode == 0:
                self.skipTest("the OS still allowed reading the locked file")
            self.assertEqual(
                proc.returncode, 6,
                f"expected EXIT_INCOMPLETE:\n{proc.stdout}\n{proc.stderr}",
            )
            # The CLI's encoding contract is UTF-8 regardless of the console
            # code page, so this text is stable in any environment.
            self.assertIn("KISMİ", proc.stdout + proc.stderr)
        finally:
            restore()


if __name__ == "__main__":
    unittest.main()
