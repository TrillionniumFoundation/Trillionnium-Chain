"""Adversarial tests for non-activated branch-local ASERT activation research."""
import hashlib
import unittest
from dataclasses import replace

from daa_activation_branch_oracle import ActivationContext, activation_shadow_from_ancestry
from daa_branch_context_oracle import ResearchHeader
from daa_research_oracle import asert_target, mtp11, UINT64_MAX

N = bytes.fromhex('12' * 32)
P = bytes.fromhex('34' * 32)
G = bytes.fromhex('56' * 32)
RULE = bytes.fromhex('78' * 32)
START = 1_000_000
BASE = 1 << 220
LIMIT = (1 << 250) - 1


def ctx(activation=16, clock='raw', max_reads=4096):
    return ActivationContext(N, P, G, START, activation, 10, 7200,
                             LIMIT, clock, RULE, max_reads)


def branch(activation=16, count=32, divergent_at=None, tweak=0):
    """Synthetic already-validated ancestry fixture, NOT native W1 validity."""
    records = {}
    parent = G
    for height in range(1, count + 1):
        changed = tweak if divergent_at is not None and height >= divergent_at else 0
        digest = hashlib.sha256(
            parent + height.to_bytes(8, 'little') + changed.to_bytes(4, 'little')
        ).digest()
        # Two branches can have different work histories and time stamps.
        target = BASE + (height + changed) * (1 << 199)
        ts = START + height * 10 + (changed * (height - divergent_at + 1)
                                     if divergent_at is not None and height >= divergent_at else 0)
        records[digest] = ResearchHeader(digest, N, P, parent, height, ts, target)
        parent = digest
    return records, parent


class ActivationResearch(unittest.TestCase):
    def test_non_genesis_activation_uses_real_ancestor_target_and_parent_time(self):
        records, tip = branch()
        result = activation_shadow_from_ancestry(ctx(), tip, records)
        anchor = next(v for v in records.values() if v.height == 16)
        predecessor = next(v for v in records.values() if v.height == 15)
        self.assertEqual((result.anchor_block, result.anchor_parent),
                         (anchor.claimed_id, predecessor.claimed_id))
        self.assertEqual(result.anchor_parent_time, predecessor.timestamp)
        self.assertEqual(result.anchor_target, anchor.target)
        self.assertEqual(result.target, asert_target(anchor.target,
            predecessor.timestamp, START + 32*10, 16, 33, 10, 7200, LIMIT))
        self.assertGreater(result.ancestry_reads, 11)

    def test_deep_fork_crossing_activation_derives_two_branch_anchors(self):
        left, left_tip = branch(divergent_at=14, tweak=1)
        right, right_tip = branch(divergent_at=14, tweak=7)
        union = {**left, **right}
        l = activation_shadow_from_ancestry(ctx(), left_tip, union)
        r = activation_shadow_from_ancestry(ctx(), right_tip, union)
        self.assertNotEqual(l.anchor_block, r.anchor_block)
        self.assertNotEqual(l.anchor_parent, r.anchor_parent)
        self.assertNotEqual(l.anchor_target, r.anchor_target)
        self.assertNotEqual(l.target, r.target)
        self.assertEqual(l.candidate_height, r.candidate_height)
        self.assertEqual(l.anchor_height, 16)
        # No global hash is pinned; switching back to original fork produces
        # exactly the same target even after inspecting a heavier alternate.
        self.assertEqual(l, activation_shadow_from_ancestry(ctx(), left_tip, union))

    def test_mtp_needs_parent_window_even_before_anchor(self):
        records, tip = branch(count=17)
        raw = activation_shadow_from_ancestry(ctx(), tip, records)
        med = activation_shadow_from_ancestry(ctx(clock='mtp11'), tip, records)
        ancestor_times = [v.timestamp for v in records.values() if 7 <= v.height <= 17]
        self.assertEqual(med.observed_parent_time, mtp11(ancestor_times))
        self.assertNotEqual(raw.observed_parent_time, med.observed_parent_time)
        self.assertEqual(med.target, raw.target)
        self.assertEqual(med.ancestry_reads, 13)
        pred_times = [v.timestamp for v in records.values() if 5 <= v.height <= 15]
        self.assertEqual(med.anchor_parent_time, mtp11(pred_times))
        # Both clocks see the expected two honest 10-second intervals, so
        # the anchored target is stationary across the activation boundary.
        self.assertEqual(raw.target, med.target)
        self.assertEqual(raw.target, med.anchor_target)

    def test_mixed_mtp_parent_raw_anchor_would_bias_honest_cadence(self):
        records, tip = branch(count=17)
        correct = activation_shadow_from_ancestry(ctx(clock='mtp11'), tip, records)
        anchor = next(v for v in records.values() if v.height == 16)
        predecessor = next(v for v in records.values() if v.height == 15)
        mixed = asert_target(anchor.target, predecessor.timestamp,
                             correct.observed_parent_time, 16, 18, 10, 7200, LIMIT)
        self.assertNotEqual(mixed, correct.target)
        self.assertEqual(correct.target, anchor.target)

    def test_same_anchor_is_stable_on_forks_after_activation(self):
        records, tip = branch(count=32)
        anchor = next(v for v in records.values() if v.height == 16)
        l = activation_shadow_from_ancestry(ctx(), tip, records)
        # Extend two competing descendants of the SAME validated anchor; no
        # automatic anchor rotation occurs merely because later blocks fork.
        p = next(k for k, v in records.items() if v.height == 22)
        a = hashlib.sha256(b'fork-A' + p).digest()
        b = hashlib.sha256(b'fork-B' + p).digest()
        aa = ResearchHeader(a, N, P, p, 23, START + 230, BASE,)
        bb = ResearchHeader(b, N, P, p, 23, START + 248, BASE,)
        for hh in (aa, bb):
            result = activation_shadow_from_ancestry(ctx(), hh.claimed_id,
                                                     {**records, hh.claimed_id: hh})
            self.assertEqual(result.anchor_block, anchor.claimed_id)
            self.assertEqual(result.anchor_target, anchor.target)
        self.assertEqual(l.anchor_target, anchor.target)

    def test_genesis_adjacent_anchor_and_short_mtp(self):
        records, tip = branch(activation=1, count=2)
        result = activation_shadow_from_ancestry(ctx(activation=1, clock='mtp11'), tip, records)
        anchor = next(v for v in records.values() if v.height == 1)
        self.assertEqual(result.anchor_block, anchor.claimed_id)
        self.assertEqual(result.anchor_parent, G)
        self.assertEqual(result.anchor_parent_time, START)
        self.assertEqual(result.observed_parent_time, START + 10)
        self.assertEqual(result.ancestry_reads, 2)
        # Query with an exact one-header budget: the genesis terminal itself
        # consumes no fetched header and must not incorrectly spend a read.
        at_one = next(k for k,v in records.items() if v.height == 1)
        self.assertEqual(activation_shadow_from_ancestry(
            ctx(activation=1, clock='mtp11', max_reads=1), at_one, records
        ).ancestry_reads, 1)

    def test_old_regime_cannot_query_new_target(self):
        records, _ = branch(count=32)
        old_parent = next(k for k,v in records.items() if v.height == 15)
        with self.assertRaisesRegex(ValueError, 'ASERT_NOT_ACTIVE'):
            activation_shadow_from_ancestry(ctx(), old_parent, records)

    def test_missing_and_forged_ancestry_do_not_become_approval(self):
        records, tip = branch()
        for candidate in (
            {tip: records[tip]},
            {**records, tip: replace(records[tip], claimed_id=bytes(32))},
            {**records, tip: replace(records[tip], network=bytes(32))},
            {**records, tip: replace(records[tip], height=30)},
            {**records, tip: replace(records[tip], parent=tip)},
            {**records, tip: replace(records[tip], timestamp=-1)},
            {**records, tip: replace(records[tip], target=0)},
        ):
            with self.subTest(case=str(list(candidate)[-1])[:8]):
                with self.assertRaises(ValueError):
                    activation_shadow_from_ancestry(ctx(), tip, candidate)

    def test_anchor_predecessor_is_not_a_peer_supplied_timestamp(self):
        records, tip = branch()
        anchor_id = next(k for k,v in records.items() if v.height == 16)
        modified = {**records, anchor_id: replace(records[anchor_id], parent=bytes.fromhex('ee'*32))}
        with self.assertRaises(ValueError):
            activation_shadow_from_ancestry(ctx(), tip, modified)

    def test_history_is_bounded_without_unverified_skip_cache(self):
        records, tip = branch(count=32)
        with self.assertRaisesRegex(ValueError, 'ASERT_ANCESTRY_BUDGET'):
            activation_shadow_from_ancestry(ctx(max_reads=11), tip, records)
        records, tip = branch(count=4120)
        with self.assertRaisesRegex(ValueError, 'ASERT_ANCESTRY_BUDGET'):
            activation_shadow_from_ancestry(ctx(), tip, records)

    def test_disallow_unreviewed_context_changes_and_noncanonical_values(self):
        records, tip = branch()
        original = ctx()
        changes = (
            {'network': bytes(32)}, {'parameters': bytes(32)}, {'genesis': bytes(32)},
            {'rule_commitment': bytes(32)}, {'max_reads': 0}, {'max_reads': 4097},
            {'clock': 'peer-selected'}, {'activation_height': 0},
            {'activation_height': UINT64_MAX}, {'spacing': 0}, {'half_life': 0},
            {'pow_limit': 0}, {'pow_limit': 1 << 256},
            {'genesis_timestamp': -1}, {'spacing': True},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                activation_shadow_from_ancestry(replace(original, **change), tip, records)
        with self.assertRaises(ValueError):
            activation_shadow_from_ancestry(original, G, records)
        with self.assertRaises(ValueError):
            activation_shadow_from_ancestry(original, bytes(4), records)


if __name__ == '__main__':
    unittest.main()
