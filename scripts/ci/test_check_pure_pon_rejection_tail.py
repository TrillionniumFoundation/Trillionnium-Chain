#!/usr/bin/env python3
"""Mutate real retained observations; mutations never replace native evidence."""
import copy
import gzip
import json
from pathlib import Path
import unittest

from check_pure_pon_rejection_tail import check

FIXTURE = Path(__file__).resolve().parents[2] / "evidence/pon-pure-rejection-tail-20261027/native-run/stdout.jsonl.gz"


class RejectionTailEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(FIXTURE, "rt") as stream:
            cls.original = [json.loads(line) for line in stream]

    def setUp(self):
        self.rows = copy.deepcopy(self.original)

    def one(self, kind, **fields):
        return next(row for row in self.rows if row["kind"] == kind
                    and all(row.get(name) == value for name, value in fields.items()))

    def test_complete_native_tail_remains_finite(self):
        observed = check(self.rows)
        self.assertEqual((observed["cases"], observed["samples"], observed["measured_calls"]), (83, 747, 2988))
        self.assertEqual((observed["product_indices"][0], observed["product_indices"][-1]), (0, 4095))
        self.assertFalse(observed["global_upper_bound_proved"])

    def test_missing_final_product_position_is_rejected(self):
        self.rows.remove(self.one("case", case="product-cell-4095"))
        with self.assertRaisesRegex(ValueError, "complete fixed row coverage"):
            check(self.rows)

    def test_wrong_product_index_cannot_relabel_an_early_mismatch(self):
        self.one("case", case="product-cell-4095")["index"] = 63
        with self.assertRaisesRegex(ValueError, "exact case mutation"):
            check(self.rows)

    def test_trace_must_pass_native_target_and_is_only_a_digest_position(self):
        prepared = self.one("trace_preparation", case="trace-byte-31-passing-ticket")
        prepared["target_eligible_required"] = False
        with self.assertRaisesRegex(ValueError, "trace search outcome"):
            check(self.rows)
        self.rows = copy.deepcopy(self.original)
        self.one("trace_preparation", case="trace-byte-31-passing-ticket")["internal_tile_index"] = 31
        with self.assertRaisesRegex(ValueError, "digest scope"):
            check(self.rows)

    def test_correct_product_fact_cannot_be_promoted_to_full_work(self):
        sample = self.one("sample", family="false-trace")
        measured = next(row for row in sample["measurements"] if row["path"] == "filter-then-full")
        measured["outcome"] = "FactMatchOnly"
        with self.assertRaisesRegex(ValueError, "measured path outcome/order"):
            check(self.rows)

    def test_field_failure_cannot_be_reported_as_replay(self):
        self.one("case", case="invalid-field-word-12287")["progress"]["before_replay"] = True
        with self.assertRaisesRegex(ValueError, "early rejection stage"):
            check(self.rows)

    def test_unknown_cpu_is_not_zero_and_propagates_into_max_and_percentile(self):
        value = self.one("sample")["measurements"][0]["timing"]
        value["thread_cpu_before_ns"] = None
        value["thread_cpu_ns"] = 0
        with self.assertRaisesRegex(ValueError, "CPU unknown or interval accounting"):
            check(self.rows)
        value["thread_cpu_ns"], value["cpu_unknown"] = None, True
        observed = check(self.rows)
        self.assertFalse(observed["all_sample_cpu_known"])
        self.assertTrue(any(row["thread_cpu"]["max_ns"] is None for row in observed["family_statistics"]))

    def test_no_missing_control_or_qualification_promotion(self):
        self.one("sample")["measurements"].pop()
        with self.assertRaisesRegex(ValueError, "missing measured path"):
            check(self.rows)
        self.rows = copy.deepcopy(self.original)
        self.rows[-1]["global_upper_bound_proved"] = True
        with self.assertRaisesRegex(ValueError, "unearned qualification"):
            check(self.rows)


if __name__ == "__main__":
    unittest.main()
