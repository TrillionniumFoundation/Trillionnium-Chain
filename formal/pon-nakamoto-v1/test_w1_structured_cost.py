#!/usr/bin/env python3
"""Adversarial conformance tests; a sampled cost ratio is not a work theorem."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "experiments"))
import w1_valid_invalid_cost_v1 as cost

from contract_wire import PARAMS, H
import work_oracle as w1


class W1StructuredCostTests(unittest.TestCase):
    def test_all_structured_valid_proofs_and_ticket_qualified_forgeries(self):
        result = cost.run(trials=1)
        self.assertEqual(
            [row["family"] for row in result["observations"]],
            list(cost.FAMILIES),
        )
        self.assertTrue(result["all_ticket_qualified_invalid_rejected"])
        for row in result["observations"]:
            self.assertEqual(row["forged_full_replay_error"], "TRANSCRIPT")
            self.assertGreaterEqual(row["ticket_qualified_invalid_digest_guesses"], 1)
            self.assertLessEqual(row["ticket_qualified_invalid_digest_guesses"], cost.MAX_GUESSES)
            self.assertGreater(row["valid_scalar_prover_cpu_ns"], 0)
            self.assertGreater(row["valid_full_verify_cpu_ns"], 0)
            self.assertGreater(row["invalid_full_verify_cpu_ns"], 0)
            self.assertGreater(row["ticket_only_forgery_cpu_ns"], 0)
        for field in (
            "fastest_adversarial_valid_solver_qualified",
            "hardness_lower_bound_proven",
            "pq128_security_qualified",
            "sybil_safe_public_admission",
            "production_activation",
        ):
            self.assertIs(result[field], False)

    def test_zero_rank_one_and_diagonal_inputs_are_real_canonical_matrices(self):
        for name in cost.FAMILIES:
            a, b = cost.matrices(name)
            self.assertEqual(len(a), w1.CELLS)
            self.assertEqual(len(b), w1.CELLS)
            self.assertEqual(w1.task_id(a, b), w1.task_id(a[:], b[:]))
        a, b = cost.matrices("zero")
        self.assertEqual(a, [0] * w1.CELLS)
        self.assertEqual(b, [0] * w1.CELLS)
        self.assertNotEqual(
            w1.task_id(*cost.matrices("rank-one")),
            w1.task_id(*cost.matrices("dense")),
        )

    def test_forge_ticket_is_not_a_valid_transcript(self):
        a, b = cost.matrices("zero")
        challenge = H("strict-forgery-negative-v1")
        proof = w1.prove(challenge, a, b)
        target = bytes.fromhex(PARAMS["initial_target_hex"])
        forged, guesses = cost.forge_ticket_only(challenge, target, proof[-32:])
        self.assertNotEqual(forged, proof[-32:])
        self.assertGreater(guesses, 0)
        self.assertLessEqual(H("ticket", challenge, forged), target)
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT"):
            w1.verify(challenge, w1.task_id(a, b), target, proof[:-32] + forged)

    def test_bounded_samples_and_closed_family_list(self):
        for bad in (True, 0, -1, 4, 1.0, "2"):
            with self.subTest(trials=bad), self.assertRaises(ValueError):
                cost.run(bad)
        with self.assertRaisesRegex(ValueError, "unknown work family"):
            cost.matrices("fabricated-fast-proof")

    def test_highest_difficulty_has_no_forged_half_range_ticket(self):
        with self.assertRaisesRegex(AssertionError, "bounded half-range"):
            cost.forge_ticket_only(H("no-ticket"), b"\0" * 32, b"\xff" * 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
