"""Independent negative controls for bounded per-block branch-local DAA projections."""
import hashlib
import random
import unittest
from dataclasses import replace

from daa_incremental_summary import (Context, Header, OwnedBranchIndex,
                                     expected_shadow_target, extend, genesis)
from daa_research_oracle import asert_target, mtp11

N, P, G, RULE = (hashlib.sha256(s).digest()
                  for s in (b'network', b'params', b'genesis', b'rule'))
START = 10000
BASE = 1 << 220
LIMIT = (1 << 240) - 1


def ctx(clock='raw', activation=16):
    return Context(N, P, G, START, activation, 10, 7200, LIMIT, clock, RULE)


def child(parent, ts, *, changed=b''):
    h = parent.height + 1
    ident = hashlib.sha256(parent.block_id + h.to_bytes(8, 'little')
                           + ts.to_bytes(8, 'little') + changed).digest()
    return Header(ident, N, P, parent.block_id, h, ts, BASE)


class SummaryResearch(unittest.TestCase):
    def test_genesis_parent_and_activation_legacy_rule_remain_distinct(self):
        c = ctx()
        ix = OwnedBranchIndex(c)
        p = ix.at(G)
        for h in range(1, 18):
            if h <= 16:
                with self.assertRaisesRegex(ValueError, 'ASERT_NOT_ACTIVE'):
                    expected_shadow_target(c, p)
            p = ix.observe_already_validated(child(p, START + h * 10))
        self.assertEqual(p.height, 17)
        self.assertEqual(p.anchor_target, BASE)
        self.assertEqual(p.anchor_parent_time, START + 150)
        self.assertEqual(expected_shadow_target(c, p), BASE)

    def test_8192_height_stays_constant_lookback_without_peer_skip(self):
        c = ctx()
        ix = OwnedBranchIndex(c)
        p = ix.at(G)
        for height in range(1, 8193):
            p = ix.observe_already_validated(child(p, START + height * 10))
        self.assertEqual(p.height, 8192)
        self.assertEqual(len(p.recent_parent_first), 11)
        self.assertEqual(p.recent_parent_first[-1], START + (8192 - 10) * 10)
        self.assertEqual(expected_shadow_target(c, p), BASE)
        self.assertEqual(len(ix), 8193)
        self.assertTrue(all(len(s.recent_parent_first) <= 11 for s in
                            list(ix._summaries.values())[::300]))

    def test_early_mtp_freezes_parent_anchor_median_not_raw(self):
        c = ctx(clock='mtp11')
        ix = OwnedBranchIndex(c)
        p = ix.at(G)
        for height in range(1, 18):
            p = ix.observe_already_validated(child(p, START + height * 10))
        self.assertEqual(p.anchor_parent_time, START + 100)
        self.assertEqual(p.recent_parent_first[0], START + 170)
        self.assertEqual(expected_shadow_target(c, p), BASE)

    def test_fork_before_activation_freezes_independent_anchors(self):
        c = ctx()
        ix = OwnedBranchIndex(c)
        p = ix.at(G)
        for height in range(1, 14):
            p = ix.observe_already_validated(child(p, START + height * 10))
        fork = p
        a, b = fork, fork
        for height in range(14, 40):
            a = ix.observe_already_validated(child(a, START + height * 10, changed=b'A'))
            b = ix.observe_already_validated(child(b, START + height * 10 + (height-13)*2, changed=b'B'))
        self.assertNotEqual(a.anchor_id, b.anchor_id)
        self.assertNotEqual(a.anchor_parent_id, b.anchor_parent_id)
        self.assertNotEqual(expected_shadow_target(c, a), expected_shadow_target(c, b))
        self.assertEqual(ix.at(a.block_id), a)
        self.assertEqual(ix.at(b.block_id), b)

    def test_fork_after_activation_keeps_anchor_but_changes_clock(self):
        c = ctx()
        ix = OwnedBranchIndex(c)
        p = ix.at(G)
        for h in range(1, 24):
            p = ix.observe_already_validated(child(p, START + h * 10))
        left = ix.observe_already_validated(child(p, START + 240, changed=b'L'))
        right = ix.observe_already_validated(child(p, START + 290, changed=b'R'))
        self.assertEqual(left.anchor_id, right.anchor_id)
        self.assertNotEqual(expected_shadow_target(c, left),
                            expected_shadow_target(c, right))

    def test_mtp_vs_raw_match_on_honest_constant_cadence(self):
        for clock in ('raw', 'mtp11'):
            c=ctx(clock=clock)
            ix=OwnedBranchIndex(c)
            p=ix.at(G)
            for h in range(1, 150):
                p=ix.observe_already_validated(child(p, START+h*10))
                if h > 16:
                    self.assertEqual(expected_shadow_target(c, p), BASE)

    def test_missing_parent_is_unavailable_not_invalid_consensus(self):
        c=ctx()
        ix=OwnedBranchIndex(c)
        p=ix.at(G)
        for h in range(1, 24):
            p=ix.observe_already_validated(child(p, START+h*10))
        ix.mark_unavailable(p.block_id)
        with self.assertRaisesRegex(ValueError, 'ASERT_SUMMARY_UNAVAILABLE'):
            ix.observe_already_validated(child(p, START+240))
        self.assertNotIn(child(p, START+240).claimed_id, ix._summaries)

    def test_context_parent_mutation_duplicate_and_untrusted_summary_refusal(self):
        c=ctx()
        ix=OwnedBranchIndex(c)
        p=ix.at(G)
        h=child(p, START+10)
        for bad in (replace(h, parent=bytes.fromhex('fe'*32)),
                    replace(h, network=bytes.fromhex('cd'*32)),
                    replace(h, parameters=bytes.fromhex('de'*32)),
                    replace(h, height=4),replace(h, timestamp=-1),
                    replace(h, target=0),replace(h, claimed_id=G)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ix.observe_already_validated(bad)
        p=ix.observe_already_validated(h)
        with self.assertRaisesRegex(ValueError,'ASERT_SUMMARY_DUPLICATE'):
            ix.observe_already_validated(h)
        with self.assertRaisesRegex(ValueError,'ASERT_SUMMARY_CONTEXT'):
            expected_shadow_target(replace(c,rule_commitment=bytes.fromhex('bb'*32)),p)
        with self.assertRaisesRegex(ValueError,'ASERT_NOT_ACTIVE'):
            expected_shadow_target(c,p)

    def test_compare_full_ancestry_asert_without_skipping_under_4096(self):
        for clock in ('raw','mtp11'):
            c=ctx(clock=clock)
            ix=OwnedBranchIndex(c)
            p=ix.at(G)
            timestamps=[START]
            rng=random.Random(20261025)
            anchor_parent_time=None
            for h in range(1, 303):
                # Exogenous chain time, NOT a mined PoN header sequence.
                ts=max(timestamps[-1]+1, START+h*10+rng.randint(-20,20))
                if h==16:
                    anchor_parent_time=(timestamps[-1] if clock=='raw'
                                        else mtp11(list(reversed(timestamps))[:11]))
                p=ix.observe_already_validated(child(p,ts))
                timestamps.append(ts)
                if h>=16:
                    now_time=(ts if clock=='raw'
                              else mtp11(list(reversed(timestamps))[:11]))
                    full=asert_target(BASE,anchor_parent_time,now_time,16,h+1,10,7200,LIMIT)
                    self.assertEqual(expected_shadow_target(c,p),full)

    def test_zero_automatic_authority_or_activation_flags(self):
        import daa_incremental_summary as m
        self.assertFalse(hasattr(m, 'validate_block'))
        self.assertFalse(hasattr(m, 'activate_consensus'))
        self.assertFalse(hasattr(m, 'sign_lease'))
        self.assertFalse(hasattr(m, 'import_peer_summary'))
        self.assertRaisesRegex(ValueError,'ASERT_SUMMARY_CONTEXT',Context,
            N,P,G,START,16,10,7200,LIMIT,'mtp11',bytes(32))

if __name__ == '__main__':
    unittest.main()
