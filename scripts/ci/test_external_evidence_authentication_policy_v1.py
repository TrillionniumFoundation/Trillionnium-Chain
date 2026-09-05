#!/usr/bin/env python3
from external_evidence_auth_testkit_v1 import *

class AuthenticationPolicyTests(AuthenticationTestCase):
    def test_reviewer_wrong_blocker_scope_rejects(self) -> None:
        self.policy["keys"][1]["blocker_ids"] = ["EXT-AUDIT-001"]
        self.sign()
        self.reject()

    def test_reviewer_wrong_role_rejects(self) -> None:
        self.policy["keys"][1]["role"] = "producer"
        self.sign()
        self.reject()

    def test_shared_independence_domain_rejects(self) -> None:
        self.policy["keys"][1]["independence_domain"] = self.policy["keys"][0]["independence_domain"]
        self.sign()
        self.reject()

    def test_same_key_cannot_supply_two_identities(self) -> None:
        self.policy["keys"][1]["public_key_hex"] = self.policy["keys"][0]["public_key_hex"]
        self.sign()
        self.reject()

    def test_duplicate_trust_signer_is_rejected(self) -> None:
        self.policy["keys"].append(copy.deepcopy(self.policy["keys"][0]))
        self.sign()
        self.reject()

    def test_unknown_signer_is_rejected(self) -> None:
        self.row["signatures"][1]["signer"] = "unknown"
        self.reject()

    def test_duplicate_or_missing_signature_is_rejected(self) -> None:
        original = copy.deepcopy(self.row["signatures"])
        for signatures in ([original[0]], [original[0], original[0]], original + [original[0]]):
            with self.subTest(count=len(signatures)):
                self.row["signatures"] = signatures
                self.reject()

    def test_role_signatures_cannot_be_swapped(self) -> None:
        a, b = self.row["signatures"]
        a["signature"], b["signature"] = b["signature"], a["signature"]
        self.reject()

    def test_unsupported_algorithm_has_no_fallback(self) -> None:
        self.row["signatures"][0]["algorithm"] = "ed25519"
        self.reject()

    def test_noncanonical_signature_scalars_are_rejected(self) -> None:
        signature = self.row["signatures"][0]["signature"]
        self.row["signatures"][0]["signature"] = signature[:64] + "ff" * 32
        self.reject()

    def test_degenerate_enrolled_keys_are_rejected(self) -> None:
        for public in (bytes(32), b"\x01" + bytes(31)):
            with self.subTest(public=public.hex()):
                self.policy["keys"][0]["public_key_hex"] = public.hex()
                self.sign()
                self.reject()

    def test_changed_artifact_bytes_are_rejected(self) -> None:
        self.file.write_bytes(b"tampered")
        self.reject()

    def test_missing_artifact_is_rejected(self) -> None:
        self.file.unlink()
        self.reject()

    def test_artifact_symlink_is_rejected(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(self.raw_artifact)
        self.file.unlink()
        self.file.symlink_to(outside)
        self.reject()

if __name__ == "__main__":
    unittest.main(verbosity=2)
