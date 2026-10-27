#!/usr/bin/env python3
"""Mutations of retained real smoke observations, never replacement evidence."""
import copy
import gzip
import json
from pathlib import Path
import unittest
from check_pure_pon_ingress_campaign import check

FIXTURE = Path(__file__).resolve().parents[2] / "evidence/pon-pure-cost-bootstrap-20261027/ingress-smoke/stdout.jsonl.gz"


class IngressEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(FIXTURE, "rt") as stream:
            cls.original = [json.loads(line) for line in stream]

    def setUp(self):
        self.rows = copy.deepcopy(self.original)

    def one(self, kind, **conditions):
        return next(row for row in self.rows if row["kind"] == kind
                    and all(row.get(k) == v for k, v in conditions.items()))

    def test_complete_original_smoke_remains_unqualified(self):
        result = check(self.rows)
        self.assertEqual(len(result["phases"]), 3)
        self.assertFalse(result["public_fairness_qualified"])

    def test_dropped_receiver_call_is_rejected(self):
        self.rows.remove(self.one("client_call"))
        with self.assertRaisesRegex(ValueError, "missing fanout call"):
            check(self.rows)

    def test_reused_packet_cannot_claim_cache_miss_flood(self):
        packets = [r for r in self.rows if r["kind"] == "prepared_packet"]
        packets[1]["packet_sha256"] = packets[0]["packet_sha256"]
        with self.assertRaisesRegex(ValueError, "reused complete packet"):
            check(self.rows)

    def test_restart_cannot_mint_cpu_credit(self):
        self.one("receiver_start", phase="attack-cold-reopen")["budget"]["stored_credit_ns"] = 1
        with self.assertRaisesRegex(ValueError, "restart minted budget"):
            check(self.rows)

    def test_hidden_settlement_tail_is_rejected(self):
        self.one("receiver_end")["flow"]["settlement_residual_cpu_ns"] += 1
        with self.assertRaisesRegex(ValueError, "CPU debit double count or missing tail"):
            check(self.rows)

    def test_unknown_sender_cpu_cannot_be_silently_zeroed(self):
        call = self.one("client_call", honest=False)
        call["thread_cpu_ns"] = None
        with self.assertRaisesRegex(ValueError, "transport CPU accounting"):
            check(self.rows)
        self.one("class_summary", phase=call["phase"], honest=False)["client_transport_thread_cpu_ns"] = None
        result = check(self.rows)
        self.assertIsNone(result["observed_attack_dispatch_to_sender_cpu_ratio"])

    def test_invalid_acceptance_and_improved_tail_are_rejected(self):
        self.one("client_call", honest=False)["accepted"] = True
        with self.assertRaisesRegex(ValueError, "invalid work accepted"):
            check(self.rows)
        self.rows = copy.deepcopy(self.original)
        self.one("class_summary", honest=True)["accepted_p99_ns"] = 1
        with self.assertRaisesRegex(ValueError, "latency denominator or percentile"):
            check(self.rows)

    def test_shortened_runtime_or_promoted_qualification_is_rejected(self):
        self.one("phase_terminal")["elapsed_including_client_tails_ns"] = 1
        with self.assertRaisesRegex(ValueError, "short phase hidden"):
            check(self.rows)
        self.rows = copy.deepcopy(self.original)
        self.rows[-1]["public_fairness_qualified"] = True
        with self.assertRaisesRegex(ValueError, "unearned qualification"):
            check(self.rows)


if __name__ == "__main__":
    unittest.main()
