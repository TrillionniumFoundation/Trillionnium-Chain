#!/usr/bin/env python3
from external_evidence_auth_testkit_v1 import *

class AuthenticationArtifactTests(AuthenticationTestCase):
    def test_artifact_fifo_rejects_without_blocking(self) -> None:
        self.file.unlink()
        os.mkfifo(self.file)
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_artifact_root_symlink_is_rejected(self) -> None:
        alias = self.root / "artifact-alias"
        alias.symlink_to(self.artifacts, target_is_directory=True)
        self.reject(artifact_directory=alias)

    def test_mutable_or_traversing_uri_is_rejected(self) -> None:
        for value in ("https://example.invalid/latest", "../../elsewhere", "file:///etc/passwd"):
            with self.subTest(uri=value):
                self.row["artifacts"][0]["immutable_uri"] = value
                self.sign()
                self.reject()

    def test_oversized_artifact_is_rejected_before_hashing(self) -> None:
        with self.file.open("wb") as handle:
            handle.truncate(auth.MAX_ARTIFACT_BYTES + 1)
        self.reject()

    def test_total_artifact_limit_is_enforced(self) -> None:
        with mock.patch.object(auth, "MAX_TOTAL_ARTIFACT_BYTES", len(self.raw_artifact) - 1):
            self.reject()

    def test_duplicate_artifact_is_rejected(self) -> None:
        self.row["artifacts"].append(copy.deepcopy(self.row["artifacts"][0]))
        self.sign()
        self.reject()

    def test_signed_rejected_audit_is_authenticated_but_not_accepted(self) -> None:
        artifacts = self.row["artifacts"]
        self.row = submission("EXT-AUDIT-001")
        self.row["artifacts"] = artifacts
        self.row["result"] = "rejected"
        self.row["claims"]["open_critical"] = 2
        self.sign()
        result = self.verify()
        self.assertTrue(result["signatures_verified"])
        self.assertEqual(result["declared_result"], "rejected")
        self.assertFalse(result["all_external_blockers_closed"])

    def test_future_evidence_and_malformed_time_are_rejected(self) -> None:
        for value in ("2026-01-01T00:00:00Z", "2026-99-01T00:00:00Z", "2026-09-05", "2026-09-05T00:00:00+00:00"):
            with self.subTest(as_of=value):
                self.reject(as_of=value)

    def test_exact_whole_envelope_excludes_no_claim_fields(self) -> None:
        self.row["notes"] = "changed after signatures"
        self.reject()

    def test_json_whitespace_and_member_order_do_not_change_body(self) -> None:
        raw = json.dumps(dict(reversed(list(self.row.items())))).encode()
        decoded = auth.decode_json(raw)
        self.assertEqual(auth.body_digest(decoded), auth.body_digest(self.row))
        self.assertTrue(self.verify(row=decoded)["signatures_verified"])

    def test_duplicate_json_fields_fail_cleanly(self) -> None:
        raw = encode(self.row).rstrip()
        result = self.cli(row_raw=raw[:-1] + b',"result":"accepted"}')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_nonfinite_and_floating_json_rejected(self) -> None:
        raw = encode(self.row).rstrip()
        for value in (b"NaN", b"Infinity", b"1e999", b"1.0"):
            with self.subTest(value=value):
                result = self.cli(row_raw=raw[:-1] + b',"notes":' + value + b'}')
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_utf8_and_surrogates_rejected(self) -> None:
        for raw in (b"\xff", b'{"value":"\\ud800"}'):
            with self.subTest(raw=raw):
                result = self.cli(row_raw=raw)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    def test_unknown_envelope_policy_and_signature_fields_reject(self) -> None:
        self.row["unchecked"] = "not allowed"
        self.reject()
        del self.row["unchecked"]
        self.row["signatures"][0]["public_key_hex"] = self.key_material[0][1].hex()
        self.reject()
        del self.row["signatures"][0]["public_key_hex"]
        self.policy["unchecked"] = True
        self.policy_raw = encode(self.policy)
        self.pin = hashlib.sha256(self.policy_raw).hexdigest()
        self.reject()

if __name__ == "__main__":
    unittest.main(verbosity=2)
