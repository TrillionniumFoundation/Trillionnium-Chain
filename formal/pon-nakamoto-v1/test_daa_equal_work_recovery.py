"""Research-only equal-work tie negative controls; never native evidence."""
from __future__ import annotations
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from daa_equal_work_recovery import (
    EqualWorkForkSimulator, force_equal_fork, campaign,
)
from daa_fork_outage_research import ForkSimulator, Parameters, required_work, INITIAL


class EqualWorkHealingTests(unittest.TestCase):
    def params(self, **changes):
        return replace(Parameters(seed=1138, timestamp_policy_a="mtp_min",
                                  timestamp_policy_b="mtp_min",
                                  task_outage_at=1000), **changes)

    def test_research_regression_old_model_arbitrarily_selects_a_on_tie(self):
        # This explicitly documents the historical model flaw without altering
        # or repinning the original frozen screening campaign.
        old = ForkSimulator(self.params())
        old.wall += 20
        old.tip_a = old.mine("A", 0)
        old.wall += 20
        old.tip_b = old.mine("B", 0)
        self.assertEqual(old.blocks[old.tip_a].chainwork,
                         old.blocks[old.tip_b].chainwork)
        self.assertNotEqual(old.tip_a, old.tip_b)
        old.heal()
        self.assertEqual(old.heal_preferred, "A")
        self.assertEqual(old.tip_a, old.tip_b)

    def test_unhealed_partition_never_reports_global_confirmation(self):
        s = force_equal_fork(self.params(), 7)
        snapshot = s.report()
        self.assertFalse(snapshot["partition_healed"])
        self.assertFalse(snapshot["partition_converged"])
        self.assertTrue(snapshot["equal_work_unresolved"])
        self.assertIsNone(snapshot["chosen_global_tip"])
        self.assertIsNone(snapshot["claimed_global_confirmations"])

    def test_unhealed_unequal_work_still_has_no_global_observation(self):
        s = force_equal_fork(self.params(), 2)
        s.wall += 11
        s.tip_b = s.mine("B", s.tip_b)
        snapshot = s.report()
        self.assertFalse(snapshot["partition_healed"])
        self.assertFalse(snapshot["partition_converged"])
        self.assertFalse(snapshot["equal_work_unresolved"])
        self.assertIsNone(snapshot["chosen_global_tip"])
    def test_no_automatic_tie_breaker_or_global_confirmation(self):
        s = force_equal_fork(self.params(), 7)
        old_a, old_b = s.tip_a, s.tip_b
        s.heal()
        self.assertTrue(s.equal_work_pending)
        self.assertEqual((s.tip_a, s.tip_b), (old_a, old_b))
        receipt = s.report()
        self.assertIsNone(receipt["chosen_global_tip"])
        self.assertIsNone(receipt["claimed_global_confirmations"])
        self.assertFalse(receipt["partition_converged"])
        self.assertEqual(receipt["work_a"], receipt["work_b"])
        self.assertFalse(receipt["consensus_activated"])
        with self.assertRaisesRegex(ValueError, "HEAL_ALREADY_OBSERVED"):
            s.heal()

    def test_first_strictly_heavier_new_simulated_block_resolves_tie(self):
        for algo in ("legacy16", "asert_raw", "asert_mtp11"):
            with self.subTest(algo=algo):
                s = force_equal_fork(self.params(algorithm=algo), 7)
                s.heal()
                self.assertTrue(s.round("healed"))
                s.verify_all()
                self.assertFalse(s.equal_work_pending)
                self.assertEqual(s.equal_work_resolution_discoveries, 1)
                self.assertEqual(s.tip_a, s.tip_b)
                self.assertEqual(s.reorg_removed, 7)
                self.assertEqual(s.reorg_confirmed_depth6, 1)
                self.assertIn(s.heal_preferred, ("A", "B"))
                self.assertTrue(s.report()["partition_converged"])

    def test_no_legal_work_preserves_disagreement_after_network_heals(self):
        s = force_equal_fork(self.params(), 7)
        # Source outage occurs only AFTER both legal historical branches exist.
        s.p = replace(s.p, task_outage_at=0,
                      a_maintenance_fraction=0, b_maintenance_fraction=0)
        s.heal()
        self.assertFalse(s.round("healed"))
        self.assertTrue(s.equal_work_pending)
        self.assertEqual(s.stop_reason, "no_assumed_work_capacity")
        self.assertFalse(s.report()["partition_converged"])

    def test_stale_timestamp_does_not_mint_strictly_heavier_successor(self):
        s = force_equal_fork(self.params(), 7)
        s.heal()
        previous = (s.tip_a, s.tip_b, s.found)
        # A research candidate whose MTP time is beyond local future skew
        # must NOT alter either acknowledged tip.
        s.p = replace(s.p, timestamp_policy_a="endpoint_push",
                      timestamp_policy_b="endpoint_push")
        s.wall = float(s.p.genesis_time - 119)
        self.assertIsNone(s.mine("A", s.tip_a))
        self.assertEqual((s.tip_a, s.tip_b, s.found), previous)
        self.assertTrue(s.equal_work_pending)

    def test_non_tie_matches_original_strict_chainwork_fork_choice(self):
        s = force_equal_fork(self.params(), 2)
        s.wall += 11
        s.tip_b = s.mine("B", s.tip_b)
        prior_b = s.tip_b
        self.assertGreater(s.blocks[s.tip_b].chainwork,
                           s.blocks[s.tip_a].chainwork)
        s.heal()
        self.assertFalse(s.equal_work_pending)
        self.assertEqual((s.tip_a, s.tip_b), (prior_b, prior_b))
        self.assertEqual(s.heal_preferred, "B")
        self.assertFalse(s.equal_work_seen)

    def test_bounds_invalid_inputs_and_untrusted_synthetic_authority(self):
        for bad in (True, 0, -1, 13, 1.5, "7"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                force_equal_fork(self.params(), bad)
        self.assertGreater(required_work(INITIAL), 0)
        s = force_equal_fork(self.params(), 1)
        s.heal()
        self.assertEqual(s.report()["actual_w1_proofs"], 0)

    def test_fixed_campaign_is_bounded_and_reproducible(self):
        a, b = campaign(), campaign()
        self.assertEqual(a["cases"], 18)
        self.assertEqual(a["sha256"], b["sha256"])
        self.assertTrue(all(not x["healed_status"] for x in a["rows"]))
        self.assertTrue(all(x["remaining_unresolved"] for x in a["rows"]
                            if x["source_outage"]))
        self.assertTrue(all(x["resolved"] for x in a["rows"]
                            if not x["source_outage"]))
        self.assertFalse(a["qualification"]["production_daa"])

    def test_create_only_campaign_output(self):
        import subprocess, sys
        script = Path(__file__).with_name("daa_equal_work_recovery.py")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)/"cohort.json"
            subprocess.run([sys.executable, str(script), "--output", str(out)],
                           check=True, capture_output=True)
            first = out.read_bytes()
            duplicate = subprocess.run([sys.executable, str(script), "--output", str(out)],
                                       capture_output=True)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(out.read_bytes(), first)
            self.assertEqual(json.loads(first)["cases"], 18)


if __name__ == "__main__":
    unittest.main()
