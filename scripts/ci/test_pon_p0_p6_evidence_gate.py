#!/usr/bin/env python3
"""Negative controls: internal self-claims cannot become PoN release authority."""
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_p0_p6_evidence_gate as G

FIELDS = {
    "P0": ["four_w1_full_rejections", "no_verified_work", "unchanged_state_and_chainwork", "native_byte_identity"],
    "P1": ["all_w1_entrypoints_inventoried", "shared_real_host_cpu", "fail_closed_restart", "no_unmetered_external_path"],
    "P2": ["real_signed_cookie_cost", "attacker_cpu", "attacker_gpu", "honest_cost", "invalid_receiver_cost"],
    "P3": ["rotated_keys", "spent_replay", "distinct_false_traces", "wrong_state_root", "mixed_honest_timing"],
    "P4": ["preregistered", "actual_physical_host", "all_attempts_accounted", "honest_confirmations"],
    "P5": ["sound_w2_relation", "no_lottery_grinding", "bounded_generation_and_verification", "measured_hardware"],
    "P6": ["external_independent_reviewer", "blind_cross_language", "adversarial_fork_choice", "signed_review_receipt"],
}


def maximal_claim():
    rows = []
    for mode in G.MODES:
        for run in (1, 2, 3):
            rows.append(dict(mode=mode, run=run, on_time_confirmed=3,
                             required_confirmations=3, timeout_or_busy_excluded=False,
                             raw_receipt_sha256="ab"*32))
    item = {phase: dict.fromkeys(keys, True) for phase, keys in FIELDS.items()}
    item["P4"]["runs"] = rows
    return dict(schema="pon-p0-p6-readiness-evidence-v1",
                exact_source={"chain_sha":"cd"*20}, evidence=item)


class FailClosedEvidenceTests(unittest.TestCase):
    def test_absent_report_is_hold_no_go(self):
        result = G.check({})
        self.assertEqual(result["verdict"], "HOLD_NO_GO")
        self.assertEqual(sum(result["phase_pass"].values()), 0)

    def test_full_unverified_self_claim_never_activates(self):
        result = G.check(maximal_claim())
        self.assertTrue(all(result["phase_pass"].values()))
        self.assertEqual(result["verdict"], "HOLD_NO_GO")
        self.assertFalse(result["independent_attestation_verified"])
        self.assertFalse(result["production_activation"])

    def test_cannot_skip_any_phase_or_field(self):
        for phase in G.PHASES:
            for key in FIELDS[phase]:
                changed = maximal_claim()
                changed["evidence"][phase].pop(key)
                verdict = G.check(changed)
                self.assertFalse(verdict["phase_pass"][phase], (phase,key))
                self.assertEqual(verdict["verdict"], "HOLD_NO_GO")

    def test_a03_requires_all_nine_runs_with_true_denominator(self):
        changes = (
            lambda rows: rows.pop(),
            lambda rows: rows[0].update(on_time_confirmed=2),
            lambda rows: rows[0].update(timeout_or_busy_excluded=True),
            lambda rows: rows[0].update(mode="invented"),
            lambda rows: rows[0].update(raw_receipt_sha256="bad"),
            lambda rows: rows[0].update(run=2),
        )
        for mutate in changes:
            changed = maximal_claim()
            mutate(changed["evidence"]["P4"]["runs"])
            verdict = G.check(changed)
            self.assertFalse(verdict["phase_pass"]["P4"])
            self.assertIn("P4_A03_COVERAGE", verdict["errors"])

    def test_source_pin_rejects_noncanonical_sha(self):
        for value in ("", "A"*40, "a"*39, "g"*40):
            changed = maximal_claim()
            changed["exact_source"]["chain_sha"] = value
            self.assertIn("EXACT_SOURCE", G.check(changed)["errors"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
