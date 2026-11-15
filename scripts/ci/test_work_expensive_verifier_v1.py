#!/usr/bin/env python3
"""Tamper controls against an actual native campaign, not invented native rows.

First run run_work_expensive_verifier_v1.py --out /absolute/new/directory, then
set TRNM_WORK_EXPENSIVE_NATIVE_LOG to its native.jsonl and run this test module.
Missing actual native input is explicitly skipped, never counted as execution.
"""
import copy
import hashlib
import os
from pathlib import Path
import unittest

import run_work_expensive_verifier_v1 as reader


class NativeRecordTamperControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("TRNM_WORK_EXPENSIVE_NATIVE_LOG")
        if not path:
            raise unittest.SkipTest("actual TRNM_WORK_EXPENSIVE_NATIVE_LOG is required")
        cls.original, cls.digest = reader.load_records(Path(path))
        cls.checked = reader.analyze_rows(cls.original)

    def setUp(self):
        self.rows = copy.deepcopy(self.original)

    def row(self, kind, **values):
        return next(row for row in self.rows if row["kind"] == kind and
                    all(row.get(key) == value for key, value in values.items()))

    def reject(self):
        with self.assertRaises(ValueError):
            reader.analyze_rows(self.rows)

    def test_actual_native_full_grid_and_limits_are_preserved(self):
        self.assertEqual(self.checked["native_component_records"], 216)
        self.assertIsNone(self.checked["consensus_accepted_work"])
        self.assertFalse(self.checked["node_runtime_measured"])
        self.assertFalse(self.checked["work_hardness_qualified"])

    def test_omitting_a_completed_loser_does_not_become_a_cheap_winner(self):
        candidate = next(row for row in self.rows if row["kind"] == "candidate"
                         and len(row["trials"]) > 1)
        self.assertFalse(candidate["trials"][0]["target_hit"])
        del candidate["trials"][0]
        self.reject()

    def test_missing_verifier_path_cannot_pass_the_complete_campaign(self):
        self.rows.remove(self.row("verification", path="native-raw"))
        self.reject()

    def test_negative_relation_cannot_be_promoted_by_renaming_the_verdict(self):
        self.row("verification", scenario="same-input-new-forgeries")["outcome"] = "Accepted"
        self.reject()

    def test_restarted_owner_cannot_relabel_a_cold_replay_as_hot(self):
        row = self.row("verification", scenario="owner-restart", index=2, path="negative-cache")
        row["tiles"] = 0
        self.reject()

    def test_owner_epoch_must_match_the_actual_reset_order(self):
        self.row("verification", scenario="owner-restart", index=2, path="negative-cache")["epoch"] = 0
        self.reject()

    def test_missing_expiry_wait_cannot_be_called_an_expired_observation(self):
        self.rows.remove(self.row("lifecycle-wait", index=1))
        self.reject()

    def test_unknown_boolean_or_float_cpu_never_becomes_zero_cost(self):
        for value in (None, False, 0.0, -1):
            with self.subTest(value=value):
                self.rows = copy.deepcopy(self.original)
                self.row("preparation")["timing"]["cpu_ns"] = value
                self.reject()

    def test_reencoding_proof_randomness_is_not_exact_reuse(self):
        row = self.row("candidate", scenario="exact-retransmission", index=1)
        proof = bytearray.fromhex(row["proof_hex"])
        proof[-1] ^= 1
        row["proof_hex"] = proof.hex()
        row["proof_sha256"] = hashlib.sha256(proof).hexdigest()
        self.reject()

    def test_recounting_the_same_verifier_call_is_rejected(self):
        self.rows.insert(-1, copy.deepcopy(self.row("verification")))
        self.reject()

    def test_component_results_cannot_be_promoted_to_node_fairness(self):
        self.rows[0]["resource_fairness_qualified"] = True
        self.reject()

    def test_boolean_epoch_cannot_alias_the_integer_owner(self):
        self.row("verification", scenario="owner-restart", index=2, path="negative-cache")["epoch"] = True
        self.reject()

    def test_nested_operation_cost_cannot_exceed_the_full_interval(self):
        row = self.row("candidate")
        row["operation_timing"]["cpu_ns"] = row["timing"]["cpu_ns"] + 1
        self.reject()

    def test_missing_operation_cost_cannot_fall_back_to_diagnostic_total(self):
        del self.row("candidate")["operation_timing"]
        self.reject()


if __name__ == "__main__":
    unittest.main()
