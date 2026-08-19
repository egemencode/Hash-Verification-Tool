"""
What the application chooses to say must read in the chosen language.

§7 translated the verdict. This covers the rest of what the application says
on its own account: the policy notices that refuse or qualify a hash request,
the baseline prompts, the local-record results, the progress line during a
scan, and the message when a file changes underneath one.

The boundary, and why it is where it is
---------------------------------------
Translated: text the application *chose* to say. Not translated: text that
relays what the operating system, the filesystem or a remote API reported —
"the settings file could not be read (PermissionError)", "DPAPI is not
available on this platform". Those are diagnostics. They name conditions the
application did not author and cannot rephrase without losing the detail that
makes them useful, and several of them are raised from the signing and key
paths, where a rewrite for wording alone is a bad trade.

That line is a decision, not an accident. It is recorded in
`docs/P1-BACKLOG.md`; there is deliberately no test that greps the source for
Turkish letters, because this project's rule is that a test asserts behaviour
rather than searching for words in code. What guards the boundary instead is
`test_every_policy_code_has_a_sentence` below: it drives the policy through
every configuration that produces a notice and requires each one to come back
as words rather than as its own key, so a notice added without a translation
fails rather than quietly showing `policy.something_new`.

Rendering: notices and immediate messages render themselves
-----------------------------------------------------------
Unlike the verdict, these do not outlive the moment they are shown, and both
front ends need plain text — `main.py` prints notices to stderr and has no
presenter to hand them to. So they resolve at the point of use through the
active language, and `PolicyNotice.message` stays the plain string every
existing caller already reads.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class PolicyNoticeLanguageTests(unittest.TestCase):
    """The refusals and warnings that decide whether a scan may proceed."""

    def tearDown(self) -> None:
        from core.i18n import set_language

        set_language("tr")

    def _notices(self, language: str, **kwargs) -> list[str]:
        from core.i18n import set_language
        from core.scan_policy import evaluate_hash_request

        set_language(language)
        return [n.message for n in evaluate_hash_request(**kwargs)]

    def test_a_refusal_reads_in_the_chosen_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a.bin"
            target.write_bytes(b"x")
            kwargs = dict(mode="file", target=str(target), output=str(target))
            turkish = self._notices("tr", **kwargs)
            english = self._notices("en", **kwargs)

        self.assertTrue(turkish, "the policy raised no notice to compare")
        self.assertEqual(len(turkish), len(english))
        for tr_text, en_text in zip(turkish, english):
            with self.subTest(notice=tr_text[:40]):
                self.assertNotEqual(tr_text, en_text)

    def test_an_insecure_algorithm_warning_keeps_its_values(self) -> None:
        """
        The warning names the algorithm and the safe alternatives. Those are
        values, not words: a translation that dropped them would still read
        like a sentence.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "data"
            target.mkdir()
            kwargs = dict(
                mode="folder", target=str(target),
                output=str(Path(tmp) / "m.json"),
                algorithm="md5", allow_insecure_algorithm=True,
            )
            turkish = " ".join(self._notices("tr", **kwargs))
            english = " ".join(self._notices("en", **kwargs))

        for text in (turkish, english):
            self.assertIn("md5", text.lower())
            self.assertIn("sha256", text.lower())
        self.assertNotEqual(turkish, english)


    def test_every_policy_code_has_a_sentence(self) -> None:
        """
        Drive the policy through every configuration that raises a notice and
        require each to come back as words.

        ``t()`` falls back to the key when a translation is missing, so a
        notice added without one does not raise — it puts
        ``policy.something_new`` in a dialog. This is the guard for that, and
        it is why the notice's ``code`` and its translation key are the same
        string: the two cannot be renamed apart without this failing.
        """
        from core.i18n import set_language
        from core.scan_policy import evaluate_hash_request

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "data"
            folder.mkdir()
            single = root / "a.bin"
            single.write_bytes(b"x")
            key_inside = folder / "signing.key"
            key_inside.write_bytes(b"k")
            manifest = root / "m.json"
            key_beside = root / "beside.key"
            key_beside.write_bytes(b"k")
            inside_manifest = folder / "m.json"

            configurations = [
                dict(mode="file", target=str(single), output=str(single)),
                dict(mode="folder", target=str(folder), output=str(manifest),
                     sign_key=str(key_inside)),
                dict(mode="folder", target=str(folder), output=str(manifest),
                     sign_key=str(key_beside)),
                dict(mode="folder", target=str(folder), output=str(manifest),
                     algorithm="md5"),
                dict(mode="folder", target=str(folder),
                     output=str(inside_manifest)),
            ]

            seen: dict[str, str] = {}
            for language in ("tr", "en"):
                set_language(language)
                for config in configurations:
                    for notice in evaluate_hash_request(**config):
                        seen.setdefault(f"{language}:{notice.code}", notice.message)

        codes = {entry.split(":", 1)[1] for entry in seen}
        self.assertGreaterEqual(
            len(codes), 5,
            f"the configurations did not reach every notice: {sorted(codes)}",
        )
        for entry, message in sorted(seen.items()):
            with self.subTest(notice=entry):
                code = entry.split(":", 1)[1]
                self.assertNotEqual(
                    message, f"policy.{code}",
                    "this notice has no sentence; t() fell back to the key",
                )
                self.assertIn(" ", message, f"not a sentence: {message!r}")


class BaselinePromptLanguageTests(unittest.TestCase):
    """The questions asked before a fingerprint replaces the stored one."""

    def tearDown(self) -> None:
        from core.i18n import set_language

        set_language("tr")

    def test_every_prompt_reads_in_the_chosen_language(self) -> None:
        from core.baseline import BaselineDecision, decision_prompt
        from core.i18n import set_language

        for decision in BaselineDecision:
            with self.subTest(decision=decision.value):
                set_language("tr")
                turkish = decision_prompt(decision)
                set_language("en")
                english = decision_prompt(decision)
                self.assertTrue(turkish)
                self.assertNotEqual(turkish, english)


class LocalRecordLanguageTests(unittest.TestCase):
    """What the local fingerprint store says about a file it has seen."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        from core.i18n import set_language

        try:
            set_language("tr")
        finally:
            self._tmp.cleanup()

    def _messages(self, language: str) -> list[str]:
        from core.i18n import set_language
        from core.local_verify import LocalVerifyStore

        set_language(language)
        store = LocalVerifyStore(
            store_path=str(Path(self._tmp.name) / f"store-{language}.json")
        )
        said = [store.compare("C:/x/a.bin", "a" * 64).message]
        said.append(store.remember("C:/x/a.bin", "a" * 64, 10).message)
        said.append(store.compare("C:/x/a.bin", "a" * 64).message)
        said.append(store.compare("C:/x/a.bin", "b" * 64).message)
        return said

    def test_every_outcome_reads_in_the_chosen_language(self) -> None:
        turkish = self._messages("tr")
        english = self._messages("en")
        self.assertEqual(len(turkish), 4)
        for tr_text, en_text in zip(turkish, english):
            with self.subTest(message=tr_text[:40]):
                self.assertTrue(tr_text, "the store said nothing")
                self.assertNotEqual(tr_text, en_text)


class ScanProgressLanguageTests(unittest.TestCase):
    """The line the status bar shows while a scan is running."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.target = Path(self._tmp.name) / "sample.bin"
        self.target.write_bytes(b"hello" * 100)

    def tearDown(self) -> None:
        from core.i18n import set_language

        try:
            set_language("tr")
        finally:
            self._tmp.cleanup()

    def _steps(self, language: str) -> list[str]:
        from unittest import mock

        from core.i18n import set_language
        from core.trust_pipeline import run_trust_check

        set_language(language)
        steps: list[str] = []
        client = mock.Mock()
        client.has_key = False
        run_trust_check(
            str(self.target),
            vt_client=client,
            local_store=None,
            check_signature_flag=False,
            query_virustotal=False,
            on_progress=steps.append,
        )
        return steps

    def test_every_progress_step_reads_in_the_chosen_language(self) -> None:
        turkish = self._steps("tr")
        english = self._steps("en")
        self.assertGreaterEqual(len(turkish), 3, "the scan reported almost nothing")
        self.assertEqual(len(turkish), len(english))
        for tr_step, en_step in zip(turkish, english):
            with self.subTest(step=tr_step):
                self.assertNotEqual(tr_step, en_step)


class FileChangedLanguageTests(unittest.TestCase):
    """
    The one error in this tier that is a finding, not a relayed diagnostic.

    "The file changed while it was being scanned" is something this tool
    detected and decided to say. It is also the most security-relevant thing
    it can say mid-scan, so it belongs in the user's language.
    """

    def tearDown(self) -> None:
        from core.i18n import set_language

        set_language("tr")

    def _message(self, language: str) -> str:
        from core.i18n import set_language
        from core.trust_pipeline import FileChangedDuringScanError, file_changed_error

        set_language(language)
        error = file_changed_error("content", r"C:\tmp\a.bin")
        self.assertIsInstance(error, FileChangedDuringScanError)
        return str(error)

    def test_it_reads_in_the_chosen_language_and_names_the_file(self) -> None:
        turkish = self._message("tr")
        english = self._message("en")
        self.assertNotEqual(turkish, english)
        for text in (turkish, english):
            self.assertIn("a.bin", text, "the message does not say which file")


if __name__ == "__main__":
    unittest.main()
