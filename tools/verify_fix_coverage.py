"""
Prove every fix is actually held by a test.

For each fix: copy the tree to a scratch directory, revert exactly that fix,
run the test that claims to cover it, and require the test to FAIL. A test that
still passes against the reverted code is not protecting anything — which is
how the previous round shipped four vacuous assertions.

The real tree is never modified.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

REPO = Path(__file__).resolve().parent.parent
PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
SKIP_DIRS = {".venv", ".git", "dist", "build", "demo_data", "__pycache__",
             "logs", "data", ".pytest_cache", "docs"}

# (label, relative file, text to find, replacement, test to run)
REVERTS = [
    ("bounded junction walk", "core/hash_utils.py",
     """                identity = _file_identity(path)
                if is_link:
                    if identity is None or identity in traversed:
                        continue
                if identity is not None:
                    traversed.add(identity)
                yield from _walk(path)""",
     """                identity = _file_identity(path)
                if identity is not None and identity in traversed:
                    continue
                if identity is not None:
                    traversed.add(identity)
                yield from _walk(path)""",
     "tests.test_folder_scan_integrity.ReparsePointTests"
     ".test_a_junction_does_not_hide_the_directory_it_points_at"),

    ("bounded junction walk (explosion)", "core/hash_utils.py",
     "                if is_link:\n"
     "                    if identity is None or identity in traversed:\n"
     "                        continue\n",
     "                if False:\n"
     "                    if identity is None or identity in traversed:\n"
     "                        continue\n",
     "tests.test_folder_scan_integrity.ReparsePointTests"
     ".test_a_junction_web_does_not_explode_the_walk"),

    ("link containment (any kind)", "core/hash_utils.py",
     "            if is_link and not _contained(path):\n"
     "                continue  # the target escapes the root: never smuggle it in\n",
     "            if False:\n"
     "                continue\n",
     "tests.test_folder_scan_integrity.ReparsePointTests"
     ".test_no_link_kind_can_pull_content_from_outside_the_root"),

    ("md5 excluded from trusted_match", "core/verifier.py",
     "            and not self.collision_prone_algorithm\n",
     "\n",
     "tests.test_cli_scan_contract.InsecureAlgorithmTests"
     ".test_collision_prone_algorithm_never_yields_trusted_match"),

    ("hash honours --follow-symlinks", "main.py",
     "            follow_symlinks=follow_symlinks,\n",
     "            follow_symlinks=False,\n",
     "tests.test_unicode_paths.FollowSymlinksSwitchTests"
     ".test_follow_symlinks_changes_what_hash_records"),

    ("verify honours --follow-symlinks", "main.py",
     '            follow_symlinks=bool(getattr(args, "follow_symlinks", False)),\n',
     "            follow_symlinks=False,\n",
     "tests.test_unicode_paths.FollowSymlinksSwitchTests"
     ".test_verify_honours_the_same_switch"),

    ("single enumeration (build)", "core/manifest_manager.py",
     "        paths = enumerate_files(root, **walk_kwargs)\n"
     "        before = inventory_for_paths(root, paths)\n"
     "        total = len(paths)\n",
     "        before = snapshot_inventory(root, **walk_kwargs)\n"
     "        total = len(before)\n"
     "        paths = iter_files(root, **walk_kwargs)\n",
     "tests.test_progress_contract.BuildProgressTests"
     ".test_done_never_exceeds_total_when_a_file_appears_mid_scan"),

    ("single enumeration (verify)", "core/verifier.py",
     "        paths = enumerate_files(root, **walk_kwargs)\n"
     "        before_inventory = inventory_for_paths(root, paths)\n"
     "        total = len(paths)\n",
     "        before_inventory = snapshot_inventory(root, **walk_kwargs)\n"
     "        total = count_files(root, **walk_kwargs)\n"
     "        paths = iter_files(root, **walk_kwargs)\n",
     "tests.test_progress_contract.VerifyProgressTests"
     ".test_done_never_exceeds_total_when_a_file_appears_mid_verify"),

    ("cancelled build never saved", "core/manifest_manager.py",
     "        if self.cancelled:\n",
     "        if False:\n",
     "tests.test_progress_contract.BuildProgressTests"
     ".test_cancelled_build_refuses_to_write_a_manifest"),

    ("terminal event on failure (build)", "core/manifest_manager.py",
     "        _announce(ScanState.FAILED)\n        raise\n",
     "        raise\n",
     "tests.test_progress_contract.BuildProgressTests"
     ".test_a_scan_that_raises_still_reports_a_terminal_event"),

    ("terminal event on failure (verify)", "core/verifier.py",
     "            _announce(ScanState.FAILED)\n            raise\n",
     "            raise\n",
     "tests.test_progress_contract.VerifyProgressTests"
     ".test_a_verify_that_raises_still_reports_a_terminal_event"),

    ("public key derived from private half", "core/key_files.py",
     "            return load_private_key(candidate).public_hex\n",
     "            pass\n",
     "tests.test_cli_signing_wizard.SigningLifecycleTests"
     ".test_a_tampered_public_key_field_cannot_pass_as_trusted"),

    ("extended-length path normalisation", "core/scan_policy.py",
     "    text = str(absolute)\n",
     "    return absolute\n    text = str(absolute)\n",
     "tests.test_cli_signing_wizard.SigningLifecycleTests"
     ".test_extended_length_path_does_not_bypass_the_key_placement_block"),

    ("sign checks the manifest's root", "main.py",
     "    if manifest.root_path and is_inside(args.key, manifest.root_path):\n",
     "    if False:\n",
     "tests.test_cli_signing_wizard.SigningLifecycleTests"
     ".test_sign_refuses_a_key_inside_the_folder_the_manifest_describes"),

    ("sign --force checks the old signature", "main.py",
     "            manifest.check_integrity(None)\n",
     "            pass\n",
     "tests.test_cli_signing_wizard.SigningLifecycleTests"
     ".test_sign_force_will_not_re_bless_a_broken_signature"),

    ("keygen tracks the file from creation", "core/key_files.py",
     "    if created is not None:\n        created.append(path)\n",
     "    pass\n",
     "tests.test_cli_signing_wizard.SigningLifecycleTests"
     ".test_a_write_that_fails_after_the_file_exists_leaves_no_key"),

    # The original defect: fsdecode alone, with nothing catching its exception.
    ("drop path decoding never raises", "gui/views/trust_check_view.py",
     "    candidates: list[str] = []\n",
     "    return os.fsdecode(raw)\n    candidates: list[str] = []\n",
     "tests.test_drop_path_decoding.DecodeDroppedPathTests"
     ".test_ansi_bytes_from_the_drop_library_still_name_the_file"),

    # And the ordering itself: mbcs must be tried before fsdecode, or an
    # ANSI path that also decodes as valid UTF-8 resolves to the wrong file.
    ("drop path decoding prefers the code page", "gui/views/trust_check_view.py",
     '    for decoder in (lambda b: b.decode("mbcs"), os.fsdecode):\n',
     '    for decoder in (os.fsdecode, lambda b: b.decode("mbcs")):\n',
     "tests.test_drop_path_decoding.DecodeDroppedPathTests"
     ".test_an_ansi_name_that_is_also_valid_utf8_resolves_to_the_dropped_file"),

    ("drop hook asks for unicode", "gui/views/trust_check_view.py",
     'DROP_HOOK_KWARGS: dict[str, object] = {"force_unicode": True}',
     'DROP_HOOK_KWARGS: dict[str, object] = {}',
     "tests.test_drop_path_decoding.DecodeDroppedPathTests"
     ".test_the_view_asks_the_library_for_unicode"),

    # The button can be present, enabled and wired to nothing: reverting only
    # the call that fires the token leaves a control that looks alive.
    ("cancel button actually cancels", "gui/views/trust_check_view.py",
     "        self._controller.cancel()\n"
     "        self.cancel_button.state([\"disabled\"])\n",
     "        self.cancel_button.state([\"disabled\"])\n",
     "tests.test_gui_cancel_button.CancelButtonTests"
     ".test_pressing_cancel_stops_a_running_scan"),

    # The controller discards a result that lands after the cancel, so no
    # terminal branch fires and the screen would claim to still be scanning.
    ("cancelled scan always reaches an end state", "gui/views/trust_check_view.py",
     "            and self._controller.state is ScanState.CANCELLED\n",
     "            and False\n",
     "tests.test_gui_cancel_button.CancelButtonTests"
     ".test_a_scan_that_finishes_just_after_cancel_still_ends_the_screen"),

    ("cancel button is enabled only while busy", "gui/views/trust_check_view.py",
     "        self.cancel_button.state([\"!disabled\"] if busy else [\"disabled\"])\n",
     "        self.cancel_button.state([\"disabled\"])\n",
     "tests.test_gui_cancel_button.CancelButtonTests"
     ".test_cancel_is_only_usable_while_a_scan_is_running"),

    # The worker is what calls build.save(), so abandoning it on close left a
    # manifest behind for a scan the user walked away from.
    ("closing the window stops the background worker", "gui/app.py",
     "        self._shutdown_background_worker()\n",
     "        pass\n",
     "tests.test_gui_advanced_cancel.AdvancedTabCancelTests"
     ".test_closing_the_window_does_not_leave_a_manifest_behind"),

    ("folder hash honours the cancel token", "gui/app.py",
     "                exclude=[saved_to], cancel=cancel,\n",
     "                exclude=[saved_to],\n",
     "tests.test_gui_advanced_cancel.AdvancedTabCancelTests"
     ".test_pressing_cancel_stops_a_folder_hash"),

    # Without a distinct terminal message a cancelled run reaches _on_done,
    # which reports an incomplete build as a failure the user must fix.
    ("cancelled work is not delivered as done", "gui/app.py",
     "            if self._cancel.is_set():\n"
     "                self._queue.put(_Message(\"cancelled\", None))\n"
     "            else:\n"
     "                self._queue.put(_Message(\"done\", result))\n",
     "            self._queue.put(_Message(\"done\", result))\n",
     "tests.test_gui_advanced_cancel.AdvancedTabCancelTests"
     ".test_cancelling_is_not_reported_as_a_failed_scan"),

    ("status-bar cancel starts disabled", "gui/app.py",
     "        self.cancel_button.state([\"disabled\"])\n        self._statusbar = bar\n",
     "        self._statusbar = bar\n",
     "tests.test_gui_advanced_cancel.AdvancedTabCancelTests"
     ".test_cancel_is_idle_when_nothing_is_running"),

    # Three holders of the language; updating two of them is what let the
    # Settings tab write the stale one back.
    ("language switch updates the typed settings", "gui/app.py",
     "        self._app_settings.language = lang\n",
     "        pass\n",
     "tests.test_gui_settings_state.LanguageStateTests"
     ".test_saving_settings_keeps_the_language_chosen_from_the_menu"),

    # An ordinary save preserves an undecryptable token on purpose, so without
    # this call there is no path at all that removes it.
    ("settings can remove the stored key", "gui/views/settings_view.py",
     "        self._settings.clear_api_key()\n",
     "        pass\n",
     "tests.test_gui_settings_state.UnreadableKeyRemovalTests"
     ".test_an_undecryptable_key_can_be_removed"),

    ("key removal asks first", "gui/views/settings_view.py",
     "        if not messagebox.askyesno(\n",
     "        if False:\n",
     "tests.test_gui_settings_state.UnreadableKeyRemovalTests"
     ".test_removal_is_abandoned_when_the_user_declines"),

    ("GUI reports an underivable output path", "gui/app.py",
     "        except (ValueError, OSError) as exc:\n",
     "        except ZeroDivisionError as exc:\n",
     "tests.test_gui_hash_policy.HashTabPolicyTests"
     ".test_a_target_with_no_default_manifest_name_reports_an_error"),

    ("GUI asks before building an MD5 manifest", "gui/app.py",
     "        for notice in confirmations(notices):\n",
     "        for notice in []:\n",
     "tests.test_gui_hash_policy.HashTabPolicyTests"
     ".test_md5_manifest_asks_before_running"),

    ("GUI blocks output over input", "gui/app.py",
     "        blocking = first_blocking(notices)\n",
     "        blocking = None\n",
     "tests.test_gui_hash_policy.HashTabPolicyTests"
     ".test_single_file_output_over_the_input_is_refused"),

    ("single read for a single-file manifest", "main.py",
     "                args.file, algorithm=algo, ensure_stable=bool(args.output)\n",
     "                args.file, algorithm=algo, ensure_stable=False\n",
     None),  # placeholder, replaced below
]

# The single-read fix is a structural change, not a one-line flag; revert it by
# restoring the second read.
REVERTS[-1] = (
    "single read for a single-file manifest", "main.py",
    "                manifest = manifest_from_hashed_file(\n"
    "                    args.file, algo, digest, snapshot\n"
    "                )\n",
    "                manifest = build_manifest_for_file(args.file, algo)\n",
    "tests.test_cli_scan_contract.SingleFileOutputTests"
    ".test_single_file_manifest_reads_the_file_once",
)


def copy_tree(dest: Path) -> None:
    for item in REPO.iterdir():
        if item.name in SKIP_DIRS:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(
                item, target,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        else:
            shutil.copy2(item, target)


def run_test(cwd: Path, dotted: str) -> tuple[int, str]:
    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)
    env.pop("PYTHONIOENCODING", None)
    proc = subprocess.run(
        [str(PYTHON), "-m", "unittest", dotted],
        cwd=str(cwd), capture_output=True, env=env, timeout=900,
    )
    return proc.returncode, proc.stderr.decode("utf-8", "replace")


def main() -> int:
    results = []
    for label, rel, find, replace, dotted in REVERTS:
        scratch = Path(tempfile.mkdtemp(prefix="teeth-"))
        try:
            copy_tree(scratch)
            path = scratch / rel
            text = path.read_text(encoding="utf-8")
            if find not in text:
                results.append((label, "ANCHOR-MISSING", ""))
                print(f"  !! {label}: revert anchor not found in {rel}")
                continue
            path.write_text(text.replace(find, replace, 1), encoding="utf-8")

            code, err = run_test(scratch, dotted)
            if code == 0:
                results.append((label, "NO-TEETH", err[-400:]))
                print(f"  !! {label}: test STILL PASSES against reverted code")
            else:
                first = next(
                    (ln for ln in err.splitlines()
                     if ln.startswith(("FAIL:", "ERROR:"))), "?"
                )
                results.append((label, "ok", first))
                print(f"  ok {label}  -> {first[:90]}")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    print()
    bad = [r for r in results if r[1] != "ok"]
    print(f"{len(results) - len(bad)} / {len(results)} fixes are held by a test")
    for label, status, detail in bad:
        print(f"  FAILED CHECK [{status}] {label}")
        if detail:
            print("   ", detail.replace("\n", "\n    ")[:600])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
