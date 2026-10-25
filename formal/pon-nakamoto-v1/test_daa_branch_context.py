"""Negative controls for a research observer; no W1 work is performed."""
import hashlib
import unittest
from dataclasses import replace
from daa_branch_context_oracle import (
    ResearchHeader, ResearchContext, shadow_target_from_ancestry,
)
GENESIS = hashlib.sha256(b"genesis").digest()
NETWORK = hashlib.sha256(b"network").digest()
PARAMETERS = hashlib.sha256(b"parameters").digest()
BASE = 1 << 220
LIMIT = (1 << 240) - 1

def branch(tweak=0, pivot=0, length=20):
    records, predecessor, anchor = {}, GENESIS, None
    for height in range(1, length + 1):
        stamp = height * 10 if height <= pivot else height * 10 + tweak
        rid = hashlib.sha256(predecessor + height.to_bytes(8, "little")
                             + stamp.to_bytes(8, "little")).digest()
        records[rid] = ResearchHeader(rid, NETWORK, PARAMETERS,
                                      predecessor, height, stamp, BASE)
        predecessor = rid
        if height == 1:
            anchor = rid
    return records, predecessor, anchor

def context(anchor, **changes):
    return replace(ResearchContext(NETWORK, PARAMETERS, GENESIS, 0, anchor,
                                   BASE, 1, 10, 7200, LIMIT, "raw", 32), **changes)

class BranchResearchTests(unittest.TestCase):
    def test_forks_are_independent(self):
        a, tip_a, anchor = branch()
        b, tip_b, other_anchor = branch(-4, pivot=1)
        self.assertEqual(anchor, other_anchor)
        rows = {**a, **b}
        raw = shadow_target_from_ancestry(context(anchor), tip_a, rows)
        altered = shadow_target_from_ancestry(context(anchor), tip_b, rows)
        self.assertEqual(raw, BASE)
        self.assertLess(altered, raw)
        self.assertEqual(shadow_target_from_ancestry(context(anchor), tip_a, rows), BASE)

    def test_mtp_is_branch_local(self):
        records, tip, anchor = branch()
        raw = shadow_target_from_ancestry(context(anchor), tip, records)
        mtp = shadow_target_from_ancestry(context(anchor, clock="mtp11"),
                                           tip, records)
        self.assertEqual(raw, BASE)
        self.assertLess(mtp, raw)

    def test_wrong_context_anchor_and_read_budget(self):
        records, tip, anchor = branch()
        cases = (
            context(anchor, network=bytes.fromhex("22" * 32)),
            context(anchor, parameters=bytes.fromhex("21" * 32)),
            context(anchor, anchor_block=bytes.fromhex("17" * 32)),
            context(anchor, anchor_target=BASE + 1),
            context(anchor, genesis=bytes.fromhex("19" * 32)),
            context(anchor, max_reads=2),
            context(anchor, clock="peer-selected"),
        )
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                shadow_target_from_ancestry(invalid, tip, records)

    def test_corrupt_and_missing_ancestor(self):
        records, tip, anchor = branch()
        for bad in (
            replace(records[tip], claimed_id=bytes(32)),
            replace(records[tip], network=bytes(32)),
            replace(records[tip], parameters=bytes(32)),
            replace(records[tip], height=7),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                shadow_target_from_ancestry(context(anchor), tip,
                                            {**records, tip: bad})
        with self.assertRaises(ValueError):
            shadow_target_from_ancestry(context(anchor), tip, {tip: records[tip]})
        with self.assertRaises(ValueError):
            shadow_target_from_ancestry(context(anchor), tip, {
                **records, anchor: replace(records[anchor], parent=anchor),
            })

    def test_only_genesis_adjacent_anchor(self):
        records, tip, anchor = branch()
        for bad in (
            context(anchor, anchor_height=2), context(anchor, genesis=bytes(32)),
            context(anchor, spacing=0), context(anchor, max_reads=5000),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                shadow_target_from_ancestry(bad, tip, records)

    def test_short_parent_window_mtp(self):
        records, _, anchor = branch(length=2)
        tip = next(key for key, row in records.items() if row.height == 2)
        self.assertEqual(shadow_target_from_ancestry(context(anchor), tip, records),
                         shadow_target_from_ancestry(
                             context(anchor, clock="mtp11"), tip, records))

if __name__ == "__main__":
    unittest.main()
