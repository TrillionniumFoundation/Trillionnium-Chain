"""Independent new-domain/reference checks; never counted as native execution."""
import json
import unittest
from native_evaluation_quorum_oracle import PROFILE, VECTOR, frozen, vectors


class NativeEvaluationQuorumReferenceTests(unittest.TestCase):
    def test_exact_retained_vectors_recompute_without_native_output(self):
        self.assertEqual(json.loads(VECTOR.read_bytes()), vectors())

    def test_one_missing_is_tolerated_but_never_becomes_a_vote(self):
        cases = {row["name"]: row for row in vectors()["cases"]}
        one = cases["one-absent-completes"]
        self.assertTrue(one["expected_adoption"])
        self.assertEqual(one["expected_closed"]["quorum"], 2)
        self.assertEqual(one["expected_closed"]["matching_reveal_count"], 2)
        self.assertEqual(one["expected_closed"]["missing_reveal_count"], 1)
        self.assertFalse(cases["two-absent-aborts"]["expected_adoption"])
        self.assertFalse(cases["no-synthetic-timeout-votes"]["expected_adoption"])
        self.assertFalse(cases["legacy-one-absent-aborts"]["expected_adoption"])

    def test_plan_commits_disqualification_without_shrinking_threshold(self):
        old = frozen(PROFILE, 0, ())
        next_round = frozen(PROFILE, 1, (1,))
        self.assertEqual(len(old["plan"]["roster"]), 3)
        self.assertEqual(next_round["plan"]["roster"], old["plan"]["roster"])
        self.assertEqual(next_round["plan"]["quorum"], old["plan"]["quorum"])
        self.assertNotEqual(next_round["plan"]["generation_context"], old["plan"]["generation_context"])
        self.assertNotEqual(next_round["round"], old["round"])

    def test_actual_conflicts_recount_and_hash_appeal_is_record_only(self):
        cases = {row["name"]: row for row in vectors()["cases"]}
        for name in ("early-conflict-needed-voter", "late-conflict-needed-voter",
                     "other-candidate-conflict-before-close", "other-candidate-conflict-after-close"):
            self.assertFalse(cases[name]["expected_adoption"], name)
        for name in ("early-conflict-absent-key", "late-conflict-absent-key", "hash-only-appeal-cannot-veto"):
            self.assertTrue(cases[name]["expected_adoption"], name)
        self.assertEqual(cases["late-conflict-needed-voter"]["expected_closed"],
                         cases["one-absent-completes"]["expected_closed"])


if __name__ == "__main__":
    unittest.main()
