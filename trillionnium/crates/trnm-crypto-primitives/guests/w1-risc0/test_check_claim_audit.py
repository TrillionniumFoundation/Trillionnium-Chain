#!/usr/bin/env python3
"""Adversarial metadata controls. Synthetic rows below are never proof evidence."""
import copy
import unittest

import check_audit_one as original
import check_claim_audit as reader
from test_check_audit_one import synthetic_metadata


def synthetic():
    old, input_bytes, receipt_bytes = synthetic_metadata()
    cases = []
    for name in reader.CASES:
        changed = bytearray(input_bytes)
        if name in {"outer_journal_rebound", "coordinated_public_claim_forgery"}:
            changed[188] ^= 1
        _, journal = original.claimed_journal(changed)
        rows = []
        for route in ["original_sdk_order", "public_claims_first"]:
            for context in ["fresh", "reused"]:
                reference = route == "original_sdk_order"
                rows.append({"route":route, "context":context, "accepted":name == "valid",
                    "public_claims_entered":not reference, "sdk_entered":reference or name in reader.CONSISTENT,
                    "context_setup_wall_ns":10 if context == "fresh" else None,
                    "bounded_decode_wall_ns":10, "verification_wall_ns":50, "owned_objects_drop_wall_ns":10,
                    "receiver_total_wall_ns":100, "reason":None if name == "valid" else "synthetic refusal"})
        cases.append({"case":name, "input_sha256":original.sha(changed),
            "receipt_sha256":original.sha(receipt_bytes), "receipt_bytes":len(receipt_bytes),
            "expected_journal_sha256":original.sha(journal), "public_claims_consistent":name in reader.CONSISTENT,
            "observations":rows})
    record = {"schema":"pon-w1-public-claim-cost-audit-v1", "operation":"audit-claims",
        "prepared_context_setup_wall_ns":10, "positive_prerequisite_wall_ns":100,
        "real_proof_positive_control":True, "prerequisite_warms_runtime":True,
        "fresh_context_does_not_mean_cold_hardware":True, "exclusive_host":False,
        "receiver_scope":reader.SCOPE, "excluded_from_receiver_timing":reader.EXCLUDED.copy(),
        "original_input_sha256":original.sha(input_bytes), "original_receipt_sha256":original.sha(receipt_bytes),
        "original_receipt_bytes":len(receipt_bytes), "original_statement_id":old["original_statement_id"],
        "image_id":old["image_id"], "source_inputs":old["source_inputs"],
        "resource_caps":original.CAPS.copy(), "cases":cases, **{key:False for key in reader.FALSE_FLAGS}}
    return record, input_bytes, receipt_bytes


class ClaimAuditReaderControls(unittest.TestCase):
    def setUp(self):
        self.record, self.input, self.receipt = synthetic()

    def reject(self, change):
        row = copy.deepcopy(self.record)
        change(row)
        with self.assertRaises(ValueError):
            reader.validate(row, self.input, self.receipt)

    def test_readback_does_not_authenticate_a_synthetic_positive(self):
        result = reader.validate(self.record, self.input, self.receipt)
        self.assertTrue(result["metadata_bindings_pass"])
        for key in ("proof_reverified_by_reader", "sdk_mutations_independently_reconstructed",
                    "timings_independently_remeasured", "worst_case_rejection_cost_closed", "consensus_authority"):
            self.assertIs(result[key], False)

    def test_namespace_and_authority_promotions_are_rejected(self):
        for key in reader.FALSE_FLAGS | {"exclusive_host"}:
            self.reject(lambda row, key=key: row.update({key:True}))
        self.reject(lambda row: row.update(schema="pon-w1-receiver-case-v1"))
        self.reject(lambda row: row.update(operation="audit-one"))

    def test_missing_duplicate_cases_and_pair_selection_are_rejected(self):
        self.reject(lambda row: row["cases"].pop())
        self.reject(lambda row: row["cases"].__setitem__(1, copy.deepcopy(row["cases"][0])))
        self.reject(lambda row: row["cases"][0]["observations"].pop())
        self.reject(lambda row: row["cases"][0]["observations"].__setitem__(1, copy.deepcopy(row["cases"][0]["observations"][0])))

    def test_early_rejection_cannot_be_relabelled_as_sdk_work(self):
        self.reject(lambda row: row["cases"][1]["observations"][2].update(sdk_entered=True))
        self.reject(lambda row: row["cases"][1]["observations"][2].update(public_claims_entered=False))

    def test_consistent_forgery_cannot_claim_sdk_was_skipped(self):
        self.reject(lambda row: row["cases"][-1]["observations"][2].update(sdk_entered=False))
        self.reject(lambda row: row["cases"][-1].update(public_claims_consistent=False))
        self.reject(lambda row: row["cases"][-1]["observations"][2].update(accepted=True))

    def test_context_cost_and_warm_scope_cannot_be_hidden(self):
        self.reject(lambda row: row.update(fresh_context_does_not_mean_cold_hardware=False))
        self.reject(lambda row: row["cases"][0]["observations"][0].update(context_setup_wall_ns=None))
        self.reject(lambda row: row["cases"][0]["observations"][1].update(context_setup_wall_ns=0))
        self.reject(lambda row: row["cases"][0]["observations"][0].update(receiver_total_wall_ns=70))
        for value in (True, -1, 1.5):
            self.reject(lambda row, value=value: row["cases"][0]["observations"][0].update(verification_wall_ns=value))

    def test_original_caps_and_source_inputs_are_exact(self):
        self.reject(lambda row: row["resource_caps"].update(segments=2049))
        self.reject(lambda row: row["resource_caps"].update(segments=2048.0))
        self.reject(lambda row: row["source_inputs"].pop())
        self.reject(lambda row: row["source_inputs"][0].update(sha256="0" * 64))
        self.reject(lambda row: row.update(image_id="0" * 64))

    def test_rebound_statement_is_independently_reconstructed(self):
        self.reject(lambda row: row["cases"][1].update(input_sha256=original.sha(self.input)))
        self.reject(lambda row: row["cases"][1].update(expected_journal_sha256="0" * 64))
        self.reject(lambda row: row["cases"][0].update(receipt_sha256="0" * 64))


if __name__ == "__main__":
    unittest.main()
