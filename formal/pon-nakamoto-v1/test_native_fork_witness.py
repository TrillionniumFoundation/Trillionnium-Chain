"""Independent finite controls for native_fork_witness; no native security verdict."""
import unittest
from itertools import combinations, product

from native_fork_witness import (
    Tree, burst_counterexample, confirmation, cross_node_witness,
    exhaustive_small_tree_check, first_local_removal, local_removal_witness,
    paced_honest_events,
)


def chain(tree, prefix, n, *, weight=1, producer="H", parent="g", start=1):
    tip = parent
    for i in range(n):
        block = f"{prefix}{i+1}"
        tree.add(block, tip, weight, producer, start+i)
        tip = block
    return tip


class ForkWitnessTests(unittest.TestCase):
    def test_six_descendants_and_sixfold_work_gates_both_required(self):
        tree = Tree()
        tree.add("b", "g", 10, "H", 1)
        tip = chain(tree, "d", 6, parent="b", start=2)
        obs = confirmation(tree, "b", tip)
        self.assertEqual((obs["depth"], obs["work_delta"], obs["threshold"]), (6, 6, 60))
        self.assertFalse(obs["confirmed"])
        tree.add("b2", "g", 1, "H", 1)
        tree.add("heavy", "b2", 6, "H", 2)
        self.assertFalse(confirmation(tree, "b2", "heavy")["confirmed"])

    def test_inclusion_adds_exact_seventh_unit_at_equal_weights(self):
        tree = Tree()
        tip = chain(tree, "a", 7, weight=2)
        tree.add("equal", "g", 14, "A", 8)
        tree.add("over", "g", 15, "A", 8)
        self.assertEqual(tree.activate(tip, "equal"), tip)
        with self.assertRaisesRegex(ValueError, "NOT_STRICTLY_HEAVIER"):
            local_removal_witness(tree, "a1", tip, tip, "equal", 7)
        row = local_removal_witness(tree, "a1", tip, tip, "over", 7)
        self.assertEqual(row["confirmation_cut_weight"], 14)
        self.assertEqual(row["required_new_adversarial_integer_weight"], 15)

    def test_same_b_reorganization_preserves_score_not_old_suffix(self):
        tree = Tree()
        initial = chain(tree, "a", 7)
        tree.add("new_b_child", "a1", 7, "H", 8)
        tree.add("rival", "g", 9, "A", 9)
        self.assertNotIn(initial, tree.path("new_b_child"))
        row = local_removal_witness(tree, "a1", initial, "new_b_child", "rival", 7)
        self.assertEqual((row["native_score_growth"], row["incumbent_suffix_weight"]), (1, 8))

    def test_trace_selects_first_removal_and_preserves_ties(self):
        tree = Tree()
        initial = chain(tree, "a", 7)
        tree.add("tie", "g", 7, "A", 8)
        tree.add("preserve", "a1", 7, "H", 9)
        tree.add("remove", "g", 9, "A", 10)
        tree.add("later", "g", 100, "A", 11)
        row = first_local_removal(tree, "a1", initial,
                                  ["tie", "preserve", "remove", "later"], 7)
        self.assertEqual((row["incumbent"], row["challenger"]), ("preserve", "remove"))
        self.assertIsNone(first_local_removal(tree, "a1", initial, ["tie", "preserve"], 7))

    def test_older_fork_adds_preinclusion_cut(self):
        tree = Tree()
        tree.add("pre", "g", 5, "H", 1)
        tip = chain(tree, "a", 7, parent="pre", start=2)
        tree.add("rival", "g", 13, "A", 9)
        row = local_removal_witness(tree, "a1", tip, tip, "rival", 8)
        self.assertEqual(row["confirmation_cut_weight"], 12)
        self.assertEqual(row["six_successor_minimum_cut"], 7)

    def test_inventory_and_honest_competing_blocks_cannot_be_omitted(self):
        tree = Tree()
        tip = chain(tree, "a", 7)
        tree.add("old_private", "g", 5, "A", 6)
        tree.add("new_honest", "old_private", 2, "H", 8)
        tree.add("new_attack", "new_honest", 1, "A", 9)
        row = local_removal_witness(tree, "a1", tip, tip, "new_attack", 7)
        self.assertEqual((row["inventory_weight"], row["new_honest_offbranch_weight"],
                          row["new_adversarial_weight"]), (5, 2, 1))
        self.assertEqual(row["competing_suffix_weight"], 8)
        self.assertEqual(row["required_new_adversarial_integer_weight"], 1)

    def test_complete_hidden_inventory_allows_zero_new_attack_work(self):
        tree = Tree()
        tip = chain(tree, "a", 7)
        tree.add("hidden", "g", 8, "A", 6)
        row = local_removal_witness(tree, "a1", tip, tip, "hidden", 7)
        self.assertEqual((row["inventory_weight"], row["new_adversarial_weight"]), (8, 0))

    def test_block_weight_cap_does_not_cap_a_release_batch(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        parent = "g"
        for i in range(8):
            child = f"r{i}"
            tree.add(child, parent, 1, "A", 8)
            parent = child
        row = local_removal_witness(tree, "a1", a, a, parent, 7)
        self.assertEqual(max(block.weight for block in tree.blocks.values()), 1)
        self.assertEqual(row["new_adversarial_weight"], 8)

    def test_unbounded_stale_parent_pipeline_requires_separate_assumption(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        # An old-parent computation selected genesis before a1 existed and only
        # completes at 100. A propagation bound alone does not rule this out;
        # a freshness/cancellation or start-to-completion bound must do so.
        tree.add("late_stale_honest", "g", 8, "H", 100)
        row = local_removal_witness(tree, "a1", a, a, "late_stale_honest", 7)
        self.assertEqual(row["new_adversarial_weight"], 0)
        self.assertEqual(row["new_honest_offbranch_weight"], 8)

    def test_all_honest_partition_or_burst_is_real_algebraic_failure(self):
        result = burst_counterexample()
        self.assertTrue(result["confirmation"]["confirmed"])
        self.assertEqual(result["local_removal"]["new_adversarial_weight"], 0)
        self.assertGreater(result["local_removal"]["new_honest_offbranch_weight"], 0)

    def test_equal_cross_node_tips_need_nonstrict_witness(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        b = chain(tree, "b", 7)
        self.assertEqual(tree.activate(a, b), a)
        self.assertEqual(tree.activate(b, a), b)
        row = cross_node_witness(tree, "a1", a, b,
                                 earlier_chain_available_to_later=True)
        self.assertFalse(row["strict"])
        self.assertEqual(row["earlier_cut"], row["later_cut"])

    def test_early_cross_node_cp_failure_has_no_score_witness(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        tree.add("b", "g", 1, "H", 1)
        with self.assertRaisesRegex(ValueError, "AVAILABILITY_NOT_ESTABLISHED"):
            cross_node_witness(tree, "a1", a, "b",
                                earlier_chain_available_to_later=False)
        with self.assertRaisesRegex(ValueError, "NOT_HEAVIEST"):
            cross_node_witness(tree, "a1", a, "b",
                                earlier_chain_available_to_later=True)

    def test_unavailable_heavier_header_cannot_activate(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        tree.add("hidden", "g", 100, "A", 8)
        self.assertEqual(tree.activate(a, "hidden", fully_valid_available=False), a)

    def test_first_removal_preconditions_refuse_invalid_paths(self):
        tree = Tree()
        a = chain(tree, "a", 7)
        tree.add("rival", "g", 8, "A", 8)
        with self.assertRaisesRegex(ValueError, "BEFORE_MODEL_COMPLETION"):
            local_removal_witness(tree, "a1", a, a, "rival", 6)
        with self.assertRaisesRegex(ValueError, "INCUMBENT_ALREADY_REMOVED"):
            local_removal_witness(tree, "a1", a, "rival", "g", 7)
        with self.assertRaisesRegex(ValueError, "CHALLENGER_PRESERVES"):
            local_removal_witness(tree, "a1", a, a, a, 7)
        with self.assertRaisesRegex(ValueError, "NONMONOTONE"):
            local_removal_witness(tree, "a1", a, "a1", "rival", 7)

    def test_positive_weight_and_causal_identity_refusals(self):
        tree = Tree()
        for weight in (0, -1, True):
            with self.assertRaises(ValueError):
                tree.add("bad", "g", weight, "H", 1)
        tree.add("x", "g", 1, "A", 2)
        with self.assertRaisesRegex(ValueError, "DUPLICATE"):
            tree.add("x", "g", 1, "A", 2)
        with self.assertRaisesRegex(ValueError, "UNKNOWN_PARENT"):
            tree.add("orphan", "absent", 1, "H", 3)
        with self.assertRaisesRegex(ValueError, "NONCAUSAL"):
            tree.add("old_child", "x", 1, "H", 1)

    def test_pacer_final_publication_slack_at_most_one_block(self):
        checked = 0
        # Enumerate event times, legal weights, horizons, and lag pairs.
        for n in range(5):
            for times in combinations(range(1, 9), n):
                for weights in product((1, 2), repeat=n):
                    events = list(zip(times, weights))
                    for public_delay in range(1, 4):
                        for stale_delay in range(3):
                            paced = paced_honest_events(events, after=0,
                                                       spacing=public_delay + stale_delay)
                            for horizon in range(10):
                                tail = [(t,w) for t,w in paced
                                        if horizon-public_delay < t <= horizon]
                                self.assertLessEqual(len(tail), 1)
                                self.assertLessEqual(sum(w for _,w in tail), 2)
                                checked += 1
        self.assertGreater(checked, 100_000)

    def test_small_tree_exhaustive_branch_algebra(self):
        report = exhaustive_small_tree_check(4)
        self.assertEqual(report["enumerated_trees"], 6564)
        self.assertGreater(report["ordered_branch_pairs"], 100_000)
        self.assertGreater(report["confirmed_strict_removal_witnesses"], 30_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
