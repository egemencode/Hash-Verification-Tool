"""
The signing surface must be reachable from the CLI.

`verify --trusted-key` and the TRUSTED signature state exist in the core, but
until a user can actually *produce* a signed manifest, the only outcomes the
shipped tool can reach are "unsigned" and "accepted under --allow-unsigned".
The trusted path is dead code from the user's point of view.

These tests drive the whole lifecycle the way a user would: create a key,
sign a manifest with it, verify against the public key, and confirm that a
tampered manifest is rejected. They also pin the two mistakes that make
signing pointless — publishing the private key alongside the manifest, and
silently overwriting an existing key.
"""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import main as cli
from core import manifest_signing
from tests.support import DiagnosticTempDir


def run_cli(args: list[str]) -> tuple[int, str, str]:
    """Invoke the real CLI entry point and capture its streams."""
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(
    manifest_signing.is_available(),
    "signing needs the optional 'cryptography' backend",
)
class SigningLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        (self.data / "b.txt").write_text("beta", encoding="utf-8")
        # The key lives outside the folder being hashed, as it must.
        self.keydir = self.root / "keys"
        self.keydir.mkdir()
        self.key = self.keydir / "signing.key"
        self.manifest = self.root / "m.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    def test_keygen_writes_key_and_prints_public_hex(self) -> None:
        code, out, _err = run_cli(["keygen", "--out", str(self.key)])
        self.assertEqual(code, cli.EXIT_OK, out)
        self.assertTrue(self.key.exists(), "no key file was written")

        pub = cli.load_public_key(str(self.key.with_suffix(".key.pub")))
        # The public key must be printed so it can be distributed out of band.
        self.assertIn(pub, out.replace("\n", ""))
        self.assertEqual(len(bytes.fromhex(pub)), 32)

    def test_private_key_material_never_reaches_stdout(self) -> None:
        code, out, err = run_cli(["keygen", "--out", str(self.key)])
        self.assertEqual(code, cli.EXIT_OK)
        private_hex = cli.load_private_key(str(self.key))
        self.assertNotIn(private_hex, out)
        self.assertNotIn(private_hex, err)

    def test_a_failed_keygen_leaves_nothing_behind(self) -> None:
        # The two halves are written one after the other. If the second write
        # fails, a private key survives with no public key beside it — and
        # every later `keygen` at that path refuses, because "the file already
        # exists". The user is then stuck with a key they cannot use or
        # replace without knowing to delete it by hand.
        from core import key_files

        real_write = key_files._write_restricted
        calls = {"n": 0}

        def fail_on_second(path, text):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_write(path, text)

        key_files._write_restricted = fail_on_second
        try:
            code, _out, err = run_cli(["keygen", "--out", str(self.key)])
        finally:
            key_files._write_restricted = real_write

        self.assertNotEqual(code, cli.EXIT_OK, err)
        self.assertFalse(
            self.key.exists(),
            "a private key survived a failed keygen and now blocks retrying",
        )
        self.assertFalse(self.key.with_suffix(".key.pub").exists())

        # And the obvious recovery — just run it again — must work.
        code, _out, err = run_cli(["keygen", "--out", str(self.key)])
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertTrue(self.key.exists())

    def test_a_write_that_fails_after_the_file_exists_leaves_no_key(self) -> None:
        # The file is created by os.open before anything is written to it, so a
        # failure in write/fsync (a flaky volume, ENOSPC, a network redirector)
        # leaves a file the cleanup never learns about. In --portable mode that
        # file holds the full plaintext private key, while the CLI reports that
        # nothing was written — so the user never thinks to shred it — and every
        # later keygen at that path refuses because "the file already exists".
        import os as os_mod

        from core import key_files

        real_fsync = os_mod.fsync
        state = {"fired": False}

        def fail_once(fd):
            if not state["fired"]:
                state["fired"] = True
                raise OSError(5, "Input/output error")
            return real_fsync(fd)

        os_mod.fsync = fail_once
        try:
            code, out, err = run_cli(
                ["keygen", "--out", str(self.key), "--portable"]
            )
        finally:
            os_mod.fsync = real_fsync

        self.assertNotEqual(code, cli.EXIT_OK, out)
        leftover = ""
        if self.key.exists():
            leftover = self.key.read_text(encoding="utf-8", errors="replace")
        self.assertFalse(
            self.key.exists(),
            "the CLI reported that no key was written, but left one on disk "
            f"({len(leftover)} bytes) — and it blocks every retry:\n{err}",
        )
        # Recovery must work without the user knowing to delete anything.
        code, _out, err = run_cli(["keygen", "--out", str(self.key)])
        self.assertEqual(code, cli.EXIT_OK, err)

    def test_keygen_refuses_to_overwrite_an_existing_key(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        original = self.key.read_bytes()

        code, _out, err = run_cli(["keygen", "--out", str(self.key)])
        self.assertEqual(code, cli.EXIT_USAGE, err)
        self.assertEqual(
            self.key.read_bytes(),
            original,
            "an existing signing key was overwritten — every manifest signed "
            "with it becomes unverifiable, and that cannot be undone",
        )

    # ------------------------------------------------------------------
    def test_signed_manifest_verifies_against_the_trusted_key(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        pubfile = str(self.key.with_suffix(".key.pub"))

        code, out, err = run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--sign-key", str(self.key)]
        )
        self.assertEqual(code, cli.EXIT_OK, err or out)

        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(doc["metadata"]["integrity_mode"], "ed25519")
        self.assertIn("signature", doc)

        # No --allow-unsigned: this must pass on trust alone.
        code, out, err = run_cli(
            ["verify", "--folder", str(self.data),
             "--manifest", str(self.manifest), "--trusted-key", pubfile]
        )
        self.assertEqual(code, cli.EXIT_OK, err or out)

    def test_tampering_with_a_signed_manifest_is_rejected(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        pubfile = str(self.key.with_suffix(".key.pub"))
        run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--sign-key", str(self.key)]
        )

        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        entry = next(iter(doc["entries"].values()))
        entry["hash"] = "0" * len(entry["hash"])
        self.manifest.write_text(json.dumps(doc), encoding="utf-8")

        code, _out, err = run_cli(
            ["verify", "--folder", str(self.data),
             "--manifest", str(self.manifest), "--trusted-key", pubfile]
        )
        self.assertEqual(code, cli.EXIT_UNTRUSTED_REFERENCE, err)

    def test_verifying_against_a_different_key_is_not_trusted(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        other = self.keydir / "other.key"
        run_cli(["keygen", "--out", str(other)])

        run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--sign-key", str(self.key)]
        )
        code, _out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--trusted-key", str(other.with_suffix(".key.pub"))]
        )
        self.assertEqual(code, cli.EXIT_UNTRUSTED_REFERENCE, err)

    def test_sign_command_signs_an_existing_unsigned_manifest(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        before = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertNotIn("signature", before)

        run_cli(["keygen", "--out", str(self.key)])
        code, out, err = run_cli(
            ["sign", "--manifest", str(self.manifest), "--key", str(self.key)]
        )
        self.assertEqual(code, cli.EXIT_OK, err or out)

        after = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(after["entries"], before["entries"], "signing altered the data")
        code, _out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--trusted-key", str(self.key.with_suffix(".key.pub"))]
        )
        self.assertEqual(code, cli.EXIT_OK, err)

    # ------------------------------------------------------------------
    def test_signing_key_inside_the_scanned_folder_is_refused(self) -> None:
        # Publishing the private key next to the manifest it signs defeats the
        # whole scheme: anyone who receives the folder can forge manifests.
        inside = self.data / "signing.key"
        run_cli(["keygen", "--out", str(inside)])

        code, _out, err = run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--sign-key", str(inside)]
        )
        self.assertEqual(code, cli.EXIT_USAGE, err)
        self.assertFalse(
            self.manifest.exists(),
            "a manifest was signed with a key stored inside the folder it describes",
        )

    def test_a_tampered_public_key_field_cannot_pass_as_trusted(self) -> None:
        # --trusted-key accepts a private key file, and that file carries both
        # halves. Reading the public half verbatim throws away the only free
        # cross-check available: an attacker who edits one JSON field — without
        # ever touching the DPAPI-protected private blob — gets their own key
        # used as "the operator's trusted key", and a manifest they signed
        # verifies as TRUSTED.
        run_cli(["keygen", "--out", str(self.key)])
        attacker = self.keydir / "attacker.key"
        run_cli(["keygen", "--out", str(attacker)])
        attacker_pub = json.loads(
            attacker.with_suffix(".key.pub").read_text(encoding="utf-8")
        )["public_key"]

        doc = json.loads(self.key.read_text(encoding="utf-8"))
        doc["public_key"] = attacker_pub
        self.key.write_text(json.dumps(doc), encoding="utf-8")

        # The attacker signs with their own key.
        run_cli(["hash", "--folder", str(self.data),
                 "--output", str(self.manifest), "--sign-key", str(attacker)])

        code, out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--trusted-key", str(self.key)]
        )
        self.assertNotEqual(
            code, cli.EXIT_OK,
            "a manifest signed with the attacker's key verified as trusted "
            f"against the operator's own (tampered) key file:\n{out}\n{err}",
        )

    def test_extended_length_path_does_not_bypass_the_key_placement_block(self) -> None:
        # \\?\ is the ordinary remedy for long paths, so a script that uses it
        # is not exotic. Path.resolve() keeps the prefix on one operand and not
        # the other, so the containment comparison silently answers "no" and
        # both placement blocks are skipped — the private key ends up published
        # inside the very folder its signature attests to.
        inside = self.data / "signing.key"
        run_cli(["keygen", "--out", str(inside)])

        code, _out, err = run_cli(
            ["hash", "--folder", str(self.data), "--output", str(self.manifest),
             "--sign-key", "\\\\?\\" + str(inside)]
        )
        self.assertEqual(code, cli.EXIT_USAGE, err)
        self.assertFalse(
            self.manifest.exists(),
            "a manifest was signed with a key stored inside the folder it "
            "describes, reached through an extended-length path",
        )

    def test_signing_key_next_to_the_manifest_is_refused(self) -> None:
        beside = self.root / "signing.key"
        run_cli(["keygen", "--out", str(beside)])

        code, _out, err = run_cli(
            ["hash", "--folder", str(self.data),
             "--output", str(self.manifest), "--sign-key", str(beside)]
        )
        self.assertEqual(code, cli.EXIT_USAGE, err)

    def test_sign_refuses_a_key_inside_the_folder_the_manifest_describes(self) -> None:
        # `hash --sign-key` refuses this, so the obvious workaround is to build
        # the manifest unsigned and sign it afterwards. If `sign` does not
        # apply the same rule, the guard is decoration: the published folder
        # still ships the private key that signs manifests for it.
        keydir = self.data / "keys"
        keydir.mkdir()
        inside = keydir / "signing.key"
        run_cli(["keygen", "--out", str(inside)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])

        code, _out, err = run_cli(
            ["sign", "--manifest", str(self.manifest), "--key", str(inside)]
        )
        self.assertEqual(code, cli.EXIT_USAGE, err)
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertNotIn("signature", doc, "the manifest was signed anyway")

    def test_sign_force_will_not_re_bless_a_broken_signature(self) -> None:
        # The operator's habit of re-signing must not become the step that
        # launders tampering: a signature that no longer verifies means the
        # content changed after it was signed, and replacing it puts the
        # operator's real key behind the attacker's edit.
        run_cli(["keygen", "--out", str(self.key)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--sign-key", str(self.key)])

        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        entry = next(iter(doc["entries"].values()))
        tampered = "0" * len(entry["hash"])
        entry["hash"] = tampered
        self.manifest.write_text(json.dumps(doc), encoding="utf-8")

        code, out, err = run_cli(
            ["sign", "--manifest", str(self.manifest), "--key", str(self.key),
             "--force"]
        )
        self.assertNotEqual(code, cli.EXIT_OK, out + err)
        self.assertTrue(
            "imza" in (out + err).lower(),
            f"nothing said the existing signature was broken:\n{out}\n{err}",
        )

        # And the tampered content must not now carry a valid signature.
        code, out, _err = run_cli(
            ["inspect", "--manifest", str(self.manifest),
             "--trusted-key", str(self.key.with_suffix(".key.pub"))]
        )
        self.assertNotEqual(
            code, cli.EXIT_OK,
            f"tampered content ended up trusted:\n{out}",
        )

    def test_sign_force_still_replaces_a_valid_signature(self) -> None:
        # Key rotation must keep working — only a *broken* signature is refused.
        run_cli(["keygen", "--out", str(self.key)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--sign-key", str(self.key)])
        newkey = self.keydir / "rotated.key"
        run_cli(["keygen", "--out", str(newkey)])

        code, out, err = run_cli(
            ["sign", "--manifest", str(self.manifest), "--key", str(newkey),
             "--force"]
        )
        self.assertEqual(code, cli.EXIT_OK, out + err)
        code, _out, err = run_cli(
            ["verify", "--folder", str(self.data), "--manifest", str(self.manifest),
             "--trusted-key", str(newkey.with_suffix(".key.pub"))]
        )
        self.assertEqual(code, cli.EXIT_OK, err)

    def test_incomplete_scan_is_never_signed(self) -> None:
        # A signature over a manifest that knowingly missed files would attest
        # to a folder description with holes in it.
        run_cli(["keygen", "--out", str(self.key)])
        import core.manifest_manager as mm

        real = mm.hash_file_with_snapshot

        def fail_on_b(path, *a, **kw):
            if Path(path).name == "b.txt":
                raise mm.HashError("simulated read failure")
            return real(path, *a, **kw)

        mm.hash_file_with_snapshot = fail_on_b
        try:
            code, _out, err = run_cli(
                ["hash", "--folder", str(self.data),
                 "--output", str(self.manifest), "--sign-key", str(self.key)]
            )
        finally:
            mm.hash_file_with_snapshot = real

        self.assertEqual(code, cli.EXIT_INCOMPLETE, err)
        self.assertFalse(self.manifest.exists())


@unittest.skipUnless(
    manifest_signing.is_available(),
    "signing needs the optional 'cryptography' backend",
)
class InspectCommandTests(unittest.TestCase):
    """
    `inspect` is the verify-only flow: it reports what a manifest claims
    without hashing anything, and — unlike `verify` — it can describe a
    manifest whose signature is broken instead of refusing to speak about it.
    """

    def setUp(self) -> None:
        self._tmp = DiagnosticTempDir()
        self.root = Path(self._tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "a.txt").write_text("alpha", encoding="utf-8")
        self.key = self.root / "signing.key"
        self.manifest = self.root / "sub" / "m.json"
        self.manifest.parent.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unsigned_manifest_reports_untrusted(self) -> None:
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest)])
        code, out, _err = run_cli(["inspect", "--manifest", str(self.manifest)])
        self.assertEqual(code, cli.EXIT_UNTRUSTED_REFERENCE)
        self.assertIn("unsigned", out.lower())

    def test_trusted_manifest_reports_trusted(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--sign-key", str(self.key)])
        code, out, _err = run_cli(
            ["inspect", "--manifest", str(self.manifest),
             "--trusted-key", str(self.key.with_suffix(".key.pub"))]
        )
        self.assertEqual(code, cli.EXIT_OK, out)
        self.assertIn("trusted", out.lower())

    def test_broken_signature_is_described_not_swallowed(self) -> None:
        run_cli(["keygen", "--out", str(self.key)])
        run_cli(["hash", "--folder", str(self.data), "--output", str(self.manifest),
                 "--sign-key", str(self.key)])
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        doc["signature"]["signature"] = "00" * 64
        self.manifest.write_text(json.dumps(doc), encoding="utf-8")

        code, out, err = run_cli(["inspect", "--manifest", str(self.manifest)])
        self.assertEqual(code, cli.EXIT_MANIFEST_INVALID, out)
        # It must say *why*, not just fail.
        self.assertTrue(
            "imza" in (out + err).lower() or "signature" in (out + err).lower(),
            f"no explanation of the signature failure:\n{out}\n{err}",
        )


if __name__ == "__main__":
    unittest.main()
