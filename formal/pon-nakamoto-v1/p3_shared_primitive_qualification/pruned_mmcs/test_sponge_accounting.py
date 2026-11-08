"""Fault-injection checks for the independent MMCS accounting reader.

The small reports here are synthetic arithmetic fixtures, not native execution
evidence. Run check_sponge_accounting.py separately on a fresh Rust report.
"""
from pathlib import Path
import struct
import tempfile
import unittest

import check_sponge_accounting as check


def call(role, evaluation, number=1):
    # These frozen values are not obtained from the checker under test.
    payload, size, blocks = (16, 346, 5) if role == "Leaf" else (128, 458, 7)
    return {"call": number, "role": role, "evaluation": evaluation,
            "header_bytes": 322, "payload_bytes": payload, "length_suffix_bytes": 8,
            "complete_message_bytes": size, "complete_message_equivalent_absorption_blocks": blocks}


def ledger(calls):
    totals = dict.fromkeys(check.TOTAL_FIELDS, 0)
    for row in calls:
        blocks = row["complete_message_equivalent_absorption_blocks"]
        totals["whole_message_calls"] += 1
        totals["complete_message_bytes"] += row["complete_message_bytes"]
        totals["complete_message_equivalent_absorption_blocks"] += blocks
        if row["evaluation"] == check.CACHED:
            totals["native_cached_prefix_calls"] += 1
            totals["native_cached_prefix_reused_block_equivalents"] += 4
            totals["native_cached_prefix_continuation_block_equivalents"] += blocks - 4
        elif row["evaluation"] == check.FRESH:
            totals["native_full_message_calls"] += 1
            totals["native_full_message_block_equivalents"] += blocks
        else:
            totals["artificial_override_calls"] += 1
            totals["artificial_message_block_equivalents"] += blocks
    return {"schema": "p3.tagged-mmcs.sponge-accounting.v1", "rate_bytes": 72, "digest_bytes": 64,
            "counting_unit": "complete-message-equivalent-absorption-blocks",
            "prefix_initializations_counted": False, "native_permutation_telemetry": False,
            "native_permutation_calls": None, "adversary_lifetime_query_budget": None,
            "qualified": False, "security_bits": None, "totals": totals, "calls": calls}


def artificial_case(oracle, role):
    payload_size = 16 if role == "Leaf" else 128
    header = check.PREFIX + struct.pack("<I", 1) + bytes([1 if role == "Leaf" else 2]) + bytes([42]) * 64
    messages = [(header + bytes([value]) * payload_size + struct.pack("<Q", payload_size)).hex()
                for value in (1, 2)]
    verification = ledger([call(r, check.ARTIFICIAL if r == role else check.CACHED, i)
                           for i, r in enumerate(("Leaf", "Branch"), 1)])
    rechecks = ledger([call(role, check.ARTIFICIAL, 1), call(role, check.ARTIFICIAL, 2)])
    return {"oracle": oracle, "actual_p3_pruned_verifier": True, "real_sha3_collision": False,
            "w1_forgery": False, "verification_whole_hash_calls": 2,
            "verification_whole_hash_call_bound": 4, "verification_sponge_accounting": verification,
            "independent_collision_recheck_calls": 2, "collision_recheck_sponge_accounting": rechecks,
            "candidate_collision_padded_block_total": 10 if role == "Leaf" else 14,
            "collision": {"role0": role, "role1": role, "message0_hex": messages[0],
                          "message1_hex": messages[1], "full_digest_hex": "00" * 64}}


def report():
    return {"schema": "p3.tagged-mmcs.two-opening-reduction-check.v1", "qualification": "HOLD_NO_GO",
            "qualified": False, "security_bits": None, "native_permutation_telemetry": False,
            "actual_w1_forgery": False, "quantum_pcs_extraction": False,
            "fiat_shamir_knowledge_soundness": False, "production_activation": False,
            "concrete_hash_binding_bits": None, "complete_noninteractive_security_bits": None,
            "native": [{"component": component, "native_pruned_hash_calls": 1, "unpruned_upper_bound": 4,
                        "verification_sponge_accounting": ledger([call("Branch", check.CACHED)])}
                       for component in (1, 4)],
            "artificial_collision_extractions": [artificial_case(oracle, role)
                                                for oracle, role in check.ARTIFICIAL_ORACLES.items()]}


class SpongeAccountingTests(unittest.TestCase):
    def native_ledger(self, value):
        return value["native"][0]["verification_sponge_accounting"]

    def test_fixed_header_branch_and_padding_boundaries(self):
        self.assertEqual(check.HEADER_BYTES, 322)
        self.assertEqual(check.frame_cost(322, 128), (458, 7))
        for payload, expected in ((63, (71, 1)), (64, (72, 2)), (65, (73, 2)),
                                  (135, (143, 2)), (136, (144, 3)), (137, (145, 3))):
            self.assertEqual(check.frame_cost(0, payload), expected)
        self.assertEqual(check.frame_cost(322, 29), (359, 5))
        self.assertEqual(check.frame_cost(322, 30), (360, 6))

    def test_u64_overflow_and_noninteger_input_rejected(self):
        self.assertEqual(check.frame_cost(0, check.U64_MAX - 8)[0], check.U64_MAX)
        for header, payload in ((check.U64_MAX - 7, 0), (322, check.U64_MAX),
                                (True, 0), (0, -1), (0, 1.0)):
            with self.assertRaises(check.AccountingError):
                check.frame_cost(header, payload)

    def test_synthetic_fixture_never_grants_qualification(self):
        result = check.check_report(report())
        self.assertEqual(result["checked_call_records"], 10)
        self.assertIs(result["qualified"], False)
        self.assertIsNone(result["security_bits"])
        self.assertIsNone(result["adversary_lifetime_query_budget"])

    def test_duplicate_calls_cannot_be_charged_once(self):
        value = report()
        accounting = self.native_ledger(value)
        accounting["calls"].append(call("Branch", check.CACHED, 2))
        value["native"][0]["native_pruned_hash_calls"] = 2
        with self.assertRaises(check.AccountingError):
            check.check_report(value)
        accounting["totals"] = {key: number * 2 for key, number in accounting["totals"].items()}
        self.assertEqual(check.check_report(value)["checked_call_records"], 11)

    def test_incorrect_padding_suffix_or_frame_size_rejected(self):
        for key, changed in (("complete_message_bytes", 450),
                             ("complete_message_equivalent_absorption_blocks", 6),
                             ("length_suffix_bytes", 0), ("header_bytes", 321)):
            value = report()
            self.native_ledger(value)["calls"][0][key] = changed
            with self.assertRaises(check.AccountingError):
                check.check_report(value)

    def test_cached_prefix_not_charged_again_as_continuation(self):
        value = report()
        self.native_ledger(value)["totals"]["native_cached_prefix_continuation_block_equivalents"] = 7
        with self.assertRaises(check.AccountingError):
            check.check_report(value)

    def test_artificial_override_cannot_claim_native_sha3(self):
        for index in (0, 1):
            value = report()
            calls = value["artificial_collision_extractions"][index]["verification_sponge_accounting"]["calls"]
            for row in calls:
                if row["evaluation"] == check.ARTIFICIAL:
                    row["evaluation"] = check.CACHED
            with self.assertRaises(check.AccountingError):
                check.check_report(value)

    def test_other_role_is_not_artificially_overridden(self):
        value = report()
        rows = value["artificial_collision_extractions"][0]["verification_sponge_accounting"]["calls"]
        rows[1]["evaluation"] = check.ARTIFICIAL
        with self.assertRaises(check.AccountingError):
            check.check_report(value)

    def test_fresh_recheck_cannot_claim_cached_prefix(self):
        fresh = ledger([call("Branch", check.FRESH)])
        self.assertEqual(check.check_accounting(fresh, overridden_role=None, recheck=True), 1)
        fresh["calls"][0]["evaluation"] = check.CACHED
        with self.assertRaises(check.AccountingError):
            check.check_accounting(fresh, overridden_role=None, recheck=True)

    def test_collision_L_requires_both_complete_messages(self):
        value = report()
        value["artificial_collision_extractions"][0]["candidate_collision_padded_block_total"] = 5
        with self.assertRaises(check.AccountingError):
            check.check_report(value)

    def test_collision_preimages_bind_length_suffix_context_and_profile(self):
        for offset in (0, check.HEADER_BYTES - 1, -1):
            value = report()
            collision = value["artificial_collision_extractions"][0]["collision"]
            changed = bytearray.fromhex(collision["message1_hex"])
            changed[offset] ^= 1
            collision["message1_hex"] = changed.hex()
            with self.assertRaises(check.AccountingError):
                check.check_report(value)

    def test_call_order_and_whole_hash_bounds_are_checked(self):
        value = report()
        self.native_ledger(value)["calls"][0]["call"] = 2
        with self.assertRaises(check.AccountingError):
            check.check_report(value)
        value = report()
        value["native"][0]["unpruned_upper_bound"] = 0
        with self.assertRaises(check.AccountingError):
            check.check_report(value)

    def test_unknown_role_bool_count_and_component_are_rejected(self):
        for key, changed in (("role", "Transcript"), ("call", True), ("payload_bytes", False)):
            value = report()
            self.native_ledger(value)["calls"][0][key] = changed
            with self.assertRaises(check.AccountingError):
                check.check_report(value)
        value = report()
        value["native"][0]["component"] = True
        with self.assertRaises(check.AccountingError):
            check.check_report(value)

    def test_native_telemetry_budget_or_security_claims_are_rejected(self):
        for key, changed in (("qualified", True), ("native_permutation_telemetry", True),
                             ("native_permutation_calls", 7), ("security_bits", 128),
                             ("adversary_lifetime_query_budget", 7), ("prefix_initializations_counted", True)):
            value = report()
            self.native_ledger(value)[key] = changed
            with self.assertRaises(check.AccountingError):
                check.check_report(value)
        for key, changed in (("qualified", True), ("security_bits", 128),
                             ("complete_noninteractive_security_bits", 128)):
            value = report()
            value[key] = changed
            with self.assertRaises(check.AccountingError):
                check.check_report(value)

    def test_duplicate_json_keys_and_oversize_report_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"qualified": false, "qualified": true}')
            with self.assertRaises(check.AccountingError):
                check.load_report(path)
            path.write_bytes(b" " * (check.MAX_REPORT_BYTES + 1))
            with self.assertRaises(check.AccountingError):
                check.load_report(path)


if __name__ == "__main__":
    unittest.main()
