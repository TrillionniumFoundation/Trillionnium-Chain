#!/usr/bin/env python3
from external_evidence_auth_testkit_v1 import *

class AuthenticationEncodingTests(AuthenticationTestCase):
    def test_missing_and_malformed_policy_keys_reject(self) -> None:
        for keys in ([], {}, "not-keys", [self.policy["keys"][0]]):
            with self.subTest(keys=keys):
                policy = dict(self.policy, keys=keys)
                raw = encode(policy)
                self.reject(policy_raw=raw, policy_sha256=hashlib.sha256(raw).hexdigest())

    def test_boolean_success_counter_is_not_integer(self) -> None:
        self.row["claims"]["replayed_p0_mutants"] = True
        self.sign()
        self.reject()

    def test_json_size_and_depth_bounds_reject(self) -> None:
        with self.assertRaises(auth.AuthenticationError):
            auth.decode_json(b" " * (auth.MAX_JSON_BYTES + 1))
        with self.assertRaises(auth.AuthenticationError):
            auth.decode_json(b'{"a":' + b'[' * 40 + b'0' + b']' * 40 + b'}')

    def test_missing_or_timed_out_crypto_backend_never_passes(self) -> None:
        for error in (FileNotFoundError("openssl"), subprocess.TimeoutExpired("openssl", 5)):
            with self.subTest(error=type(error).__name__), mock.patch.object(auth.subprocess, "run", side_effect=error):
                self.reject()

    def test_cli_failure_does_not_emit_partial_success(self) -> None:
        self.row["signatures"][1]["signature"] = "00" * 64
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("authentication failed", result.stderr)

    def test_signed_wrong_domain_message_is_rejected(self) -> None:
        private, message = self.root / "wrong-domain-key", self.root / "wrong-domain-message"
        private.write_bytes(self.key_material[0][0])
        message.write_bytes(bytes.fromhex(auth.body_digest(self.row)))
        signature = openssl("pkeyutl", "-sign", "-keyform", "DER", "-inkey", str(private),
                            "-rawin", "-in", str(message))
        self.row["signatures"][0]["signature"] = signature.hex()
        self.reject()

    def test_malformed_trust_role_and_revocation_fail_without_traceback(self) -> None:
        original = copy.deepcopy(self.policy)
        for field, value in (("role", []), ("revoked", "false"), ("public_key_hex", []),
                             ("blocker_ids", [None])):
            with self.subTest(field=field):
                self.policy = copy.deepcopy(original)
                self.policy["keys"][0][field] = value
                self.policy_raw = encode(self.policy)
                self.pin = hashlib.sha256(self.policy_raw).hexdigest()
                result = self.cli()
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)

    def test_artifact_mutation_after_hash_before_postcheck_is_rejected(self) -> None:
        original = auth.file_identity
        calls = 0

        def replace_before_postcheck(value):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.file.write_bytes(b"changed after hashing")
            return original(value)

        with mock.patch.object(auth, "file_identity", side_effect=replace_before_postcheck):
            self.reject()
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.file.read_bytes(), b"changed after hashing")

    def test_document_symlink_and_size_bound_are_rejected(self) -> None:
        real, alias = self.root / "real.json", self.root / "alias.json"
        real.write_bytes(encode(self.row))
        alias.symlink_to(real)
        with self.assertRaises(OSError):
            auth.read_document(alias)
        with real.open("wb") as handle:
            handle.truncate(auth.MAX_JSON_BYTES + 1)
        with self.assertRaises(auth.AuthenticationError):
            auth.read_document(real)

    def test_signed_boolean_wall_clock_is_rejected(self) -> None:
        self.row["wall_clock_seconds"] = False
        self.sign()
        self.reject()

    def test_invalid_or_missing_source_identity_is_rejected(self) -> None:
        for field in ("source_commit", "source_tree"):
            for value in ("", "A" * 40, "1" * 39, None):
                with self.subTest(field=field, value=value):
                    self.reject(**{field: value})

    def test_json_numeric_range_and_nonstring_keys_reject(self) -> None:
        for value in (2**128, -(2**63) - 1, {1: "not a JSON string key"}):
            with self.subTest(value=value), self.assertRaises(auth.AuthenticationError):
                auth.validate_json_tree(value)

    def test_no_default_trust_or_release_cli_switch(self) -> None:
        for args in ([], ["--allow-untrusted"], ["--accept"], ["--production"]):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, str(pathlib.Path(auth.__file__).resolve()), *args],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_old_intake_still_cannot_accept_authenticated_fixture(self) -> None:
        script = pathlib.Path(auth.intake.__file__).resolve()
        root = self.root / "old-intake"
        target = root / "scripts/ci/check_external_evidence_v1.py"
        target.parent.mkdir(parents=True)
        shutil.copyfile(script, target)
        (root / "config").mkdir()
        (root / "config/repository-policy-v1.json").write_bytes(
            (auth.intake.ROOT / "config/repository-policy-v1.json").read_bytes())
        directory = root / "docs/evidence/external/submissions"
        directory.mkdir(parents=True)
        (directory / "authenticated-fixture.json").write_bytes(encode(self.row))
        result = subprocess.run([sys.executable, str(target), "--require-all", "--source-commit", SOURCE_COMMIT,
                                 "--source-tree", SOURCE_TREE], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["accepted"], {})

if __name__ == "__main__":
    unittest.main(verbosity=2)
