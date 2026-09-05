#!/usr/bin/env python3
from external_evidence_auth_testkit_v1 import *

class AuthenticationCoreTests(AuthenticationTestCase):
    def test_actual_signatures_and_artifacts_authenticate_without_acceptance(self) -> None:
        result = self.verify()
        self.assertIs(result["signatures_verified"], True)
        self.assertIs(result["artifact_content_verified"], True)
        self.assertEqual(result["artifacts"][0]["bytes"], len(self.raw_artifact))
        self.assertEqual(result["accepted"], {})
        self.assertIs(result["all_external_blockers_closed"], False)
        self.assertIs(result["physical_claims_verified"], False)
        self.assertIs(result["production_candidate"], False)
        self.assertIs(result["production_consensus_activation"], False)
        self.assertEqual(result["independent_acceptance"], "not-assessed")

    def test_cli_success_is_content_authentication_not_release(self) -> None:
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["signatures_verified"])
        self.assertEqual(report["accepted"], {})

    def test_all_six_profiles_use_real_signatures_without_closing_blockers(self) -> None:
        for blocker in SCOPES:
            with self.subTest(blocker=blocker):
                self.row = submission(blocker)
                self.row["artifacts"] = [{"name": "synthetic", "sha256": self.digest,
                                         "immutable_uri": "urn:sha256:" + self.digest}]
                self.sign()
                self.assertTrue(self.verify()["signatures_verified"])
                self.assertFalse(self.verify()["all_external_blockers_closed"])

    def test_rfc8032_ed25519_vector_two_and_tamper(self) -> None:
        public = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        signature = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        auth.verify_ed25519(public, signature, bytes.fromhex("72"))
        with self.assertRaises(auth.AuthenticationError):
            auth.verify_ed25519(public, signature, bytes.fromhex("73"))

    def test_old_signature_shaped_strings_do_not_authenticate(self) -> None:
        for signature in self.row["signatures"]:
            signature["signature"] = "this-is-not-a-signature"
        self.reject()

    def test_recomputed_digest_without_resigning_is_rejected(self) -> None:
        self.row["claims"]["replayed_p0_mutants"] += 1
        for signature in self.row["signatures"]:
            signature["signed_digest"] = auth.body_digest(self.row)
        self.reject()

    def test_changed_claims_are_detected(self) -> None:
        self.row["claims"]["replayed_p0_mutants"] += 1
        self.reject()

    def test_changed_source_commit_and_tree_are_rejected(self) -> None:
        for field in ("source_commit", "source_tree"):
            with self.subTest(field=field):
                self.reject(**{field: "a" * 40})

    def test_wrong_policy_pin_is_rejected(self) -> None:
        self.reject(policy_sha256="a" * 64)

    def test_policy_update_invalidates_old_signatures_even_with_new_pin(self) -> None:
        self.policy["keys"][0]["independence_domain"] = "new-domain"
        raw = encode(self.policy)
        self.reject(policy_raw=raw, policy_sha256=hashlib.sha256(raw).hexdigest())

    def test_revoked_key_rejects_even_a_new_signature(self) -> None:
        self.policy["keys"][1]["revoked"] = True
        self.sign()
        self.reject()

    def test_key_expired_at_verification_is_rejected(self) -> None:
        self.policy["keys"][1]["valid_until"] = "2026-08-01T00:00:00Z"
        self.sign()
        self.reject()

    def test_key_not_valid_at_evidence_end_is_rejected(self) -> None:
        self.policy["keys"][0]["valid_from"] = "2026-03-01T00:00:00Z"
        self.sign()
        self.reject()

    def test_expired_policy_is_rejected(self) -> None:
        self.policy["valid_until"] = "2026-08-01T00:00:00Z"
        self.sign()
        self.reject()

if __name__ == "__main__":
    unittest.main(verbosity=2)
