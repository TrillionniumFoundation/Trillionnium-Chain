"""Bounded actual PNW1 scalar proofs; explicitly NO native Node/WAN acceptance."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from contract_wire import H, header_encode
from daa_research_oracle import valid_time
from work_oracle import PROOF_BYTES, prove, task_id, verify, precheck
from w1_maintenance_daa_proof_research import (
    INITIAL_TARGET, POW_LIMIT, OBSERVED_NOW, MAX_ATTEMPTS,
    candidate_header, forged_false_trace, genesis, maintenance_material,
    next_target, required_work, run, timestamp_for,
)

EXPECTED_INVENTORY = "ecf015e262b03043b8a0395ee78a7cf04889a514dcf74f15c17106203ebfefbc"


class W1MaintenanceDaaProofResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run()

    def test_complete_real_proofs_not_assumed_tickets(self):
        r = self.report
        self.assertEqual(r["proof_count"], 31)
        self.assertEqual(r["proof_bytes_per_packet"], 49188)
        self.assertEqual(len(r["proof_inventory"]), 31)
        self.assertEqual(r["deterministic_proof_inventory_sha256"], EXPECTED_INVENTORY)
        self.assertTrue(all(b["full_verifier_pass"] is True for b in r["proof_inventory"]))
        self.assertTrue(all(1 <= b["attempts_including_misses"] <= MAX_ATTEMPTS
                            for b in r["proof_inventory"]))
        self.assertGreater(sum(b["attempts_including_misses"] for b in r["proof_inventory"]), 31)

    def test_timestamp_endpoint_retarg_and_heavier_validated_work(self):
        r = self.report
        self.assertEqual(int(r["honest_tip"]["target"], 16), INITIAL_TARGET)
        self.assertEqual(int(r["endpoint_push_tip"]["target"], 16), INITIAL_TARGET * 4)
        self.assertGreater(int(r["honest_tip"]["work_cumulative"]),
                           int(r["endpoint_push_tip"]["work_cumulative"]))
        self.assertEqual(r["heavier_branch"], "honest")
        self.assertEqual(r["timestamp_bounds_checked"], 31)
        self.assertTrue(valid_time(600, [0], OBSERVED_NOW, 120))
        self.assertFalse(valid_time(600, [0], 479, 120))

    def test_false_trace_ticket_never_mints_verified_work(self):
        forged = self.report["forged_false_trace"]
        self.assertTrue(forged["ticket_precheck_pass"])
        self.assertEqual(forged["full_relation_rejected"], "TRANSCRIPT")
        self.assertEqual(forged["valid_chainwork_added"], "0")
        self.assertGreater(forged["full_rejection_cpu_ns"], 0)
        self.assertGreater(forged["forgery_cpu_ns"], 0)
        self.assertGreaterEqual(forged["claimed_trace_hash_trials"], 1)
        self.assertFalse(self.report["qualification"]["native_Node_execution"])
        self.assertFalse(self.report["qualification"]["work_hardness_qualified"])

    def test_header_and_domain_mutations_invalidate_real_work(self):
        a, b = maintenance_material()
        task = task_id(a, b)
        header = candidate_header(genesis(), 1, 10, POW_LIMIT, task, 0)
        self.assertEqual(len(header), 318)
        challenge = H("challenge", header)
        proof = prove(challenge, a, b)
        ticket, product = verify(challenge, task, POW_LIMIT.to_bytes(32, "big"), proof)
        self.assertEqual(len(product), 4096)
        self.assertEqual(len(proof), PROOF_BYTES)
        self.assertEqual(len(ticket), 32)
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT"):
            verify(H("challenge", candidate_header(genesis(), 1, 10, POW_LIMIT, task, 1)),
                   task, POW_LIMIT.to_bytes(32,"big"), proof)
        with self.assertRaisesRegex(ValueError, "TASK"):
            verify(challenge, H("not-the-task"), POW_LIMIT.to_bytes(32,"big"), proof)
        with self.assertRaisesRegex(ValueError, "TARGET"):
            verify(challenge, task, bytes(32), proof)

    def test_no_hidden_task_authority_and_no_historical_daa_mutation(self):
        self.assertEqual(required_work(INITIAL_TARGET), 4)
        self.assertEqual(required_work(POW_LIMIT), 1)
        self.assertEqual(next_target([genesis()]), INITIAL_TARGET)
        self.assertNotEqual(self.report["task_id"], bytes(32).hex())
        q = self.report["qualification"]
        self.assertFalse(q["real_WAN"])
        self.assertFalse(q["independent_operators"])
        self.assertFalse(q["new_daa_activated"])
        self.assertFalse(q["consensus_security_qualified"])

    def test_bad_research_inputs_refuse(self):
        with self.assertRaises(ValueError):
            required_work(0)
        with self.assertRaises(ValueError):
            required_work(POW_LIMIT+1)
        with self.assertRaises(ValueError):
            timestamp_for([genesis()], "silently-auto-fallback")
        with self.assertRaises(ValueError):
            candidate_header(genesis(), 1, 10, POW_LIMIT, bytes(31), 0)

    def test_declared_publications_exclude_cpu_from_repeatability_identity(self):
        entries = self.report["proof_inventory"]
        static = [{k: value for k, value in row.items() if not k.endswith("_cpu_ns")}
                  for row in entries]
        actual = hashlib.sha256(json.dumps(static, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(actual, EXPECTED_INVENTORY)
        self.assertGreater(sum(row["producer_cpu_ns"] for row in entries), 0)
        self.assertGreater(sum(row["verifier_cpu_ns"] for row in entries), 0)


if __name__ == "__main__":
    unittest.main()
