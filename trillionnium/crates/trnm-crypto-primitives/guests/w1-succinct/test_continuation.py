#!/usr/bin/env python3
"""Reader controls only; no synthetic evidence is admitted as a proof."""
import copy
import unittest
import continuation as c


class Controls(unittest.TestCase):
    def names(self):
        # The dependency-closed frontier observed in the pinned failed window.
        return [c.r.name(t) for batch in c.r.batches()[:3] for t in batch] + [
            "join-0-8", "join-8-16", "join-16-24", "join-24-32"]

    def test_original_finite_policy_is_preserved(self):
        p = c.policy()
        self.assertEqual(p["retained_successful_stages"] + p["new_stages_required"], 123)
        self.assertEqual(c.r.policy()["budgets"]["complete_new_recursion_work_stop_seconds"], 3500)
        self.assertEqual(c.PRIOR_PHASES[-1], "compress")

    def test_actual_frontier_shape_leaves_eleven_stages(self):
        names = self.names()
        self.assertEqual(len(names), 112)
        self.assertEqual(c.completed_names({"completed": names}), names)
        missing = set(c.BY_NAME) - set(names)
        self.assertEqual(len(missing), 11)
        self.assertIn("join-0-62", missing)
        self.assertTrue(set(c.policy()["interrupted_stages"]).issubset(missing))

    def test_duplicate_missing_and_foreign_checkpoints_are_rejected(self):
        names = self.names()
        for changed in (names[:-1], names + [names[0]], names[:-1] + [names[0]], names[:-1] + ["foreign"]):
            with self.assertRaises(ValueError):
                c.completed_names({"completed": changed})

    def test_equal_count_with_missing_child_is_rejected(self):
        names = self.names()
        names[names.index("join-0-2")] = "join-0-62"
        with self.assertRaises(ValueError):
            c.completed_names({"completed": names})

    def test_stage_profile_cannot_change_range_or_enable_pow(self):
        task = c.BY_NAME["join-0-2"]
        row = {"schema": "pon-w1-succinct-stage-v1", "operation": "join", "start": 0, "split": 1, "end": 2,
               "real_recursion_stark_verified": True, "complete_w1_proof_verified": False,
               "additional_pow": False, "povw_requested": False, "dev_mode": False, "consensus_authority": False}
        for key, value in (("start", 1), ("split", 2), ("end", 3), ("operation", "lift"),
                           ("additional_pow", True), ("povw_requested", True), ("dev_mode", True),
                           ("complete_w1_proof_verified", True), ("real_recursion_stark_verified", False)):
            changed = dict(row); changed[key] = value
            with self.assertRaises(ValueError):
                c.stage_result(changed, task)

    def test_revalidation_requires_original_bytes_claim_and_no_generation(self):
        task = c.BY_NAME["lift-0-1"]
        old = {"receipt_bytes": 1, "receipt_sha256": "reader-control", "claim_digest": "reader-control"}
        row = {"schema": "pon-w1-succinct-retained-range-v1", "start": 0, "end": 1, **old,
               "real_recursion_stark_verified": True, "complete_w1_proof_verified": False,
               "new_proof_generated": False, "additional_pow": False, "povw_requested": False,
               "dev_mode": False, "consensus_authority": False, "verify_wall_ns": 1, "verify_process_cpu_ns": 1}
        for key, value in (("receipt_bytes", 2), ("receipt_sha256", "changed"), ("claim_digest", "changed"),
                           ("new_proof_generated", True), ("verify_wall_ns", -1), ("verify_process_cpu_ns", True)):
            changed = dict(row); changed[key] = value
            with self.assertRaises(ValueError):
                c.retained_result(changed, task, old)

    def test_prior_failed_costs_cannot_be_negative_boolean_or_nonfinite(self):
        base = {"wall_seconds": 1, "user_cpu_seconds": 2, "system_cpu_seconds": 0}
        for key in base:
            for value in (-1, True, float("nan"), float("inf"), "0", None):
                changed = copy.deepcopy(base); changed[key] = value
                with self.assertRaises(ValueError):
                    c.costs(changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
