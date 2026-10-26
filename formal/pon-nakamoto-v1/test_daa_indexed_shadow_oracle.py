"""Local tests for a RESEARCH simulation of bounded branch indexing only."""
import unittest
from daa_indexed_shadow_oracle import ValidatedInputIndex, GENESIS


def chain(index, number, *, parent=GENESIS, offset=0, target=None):
    path = {0: parent}
    for h in range(1, number + 1):
        parent = index.append(parent, h * 10 + offset) if target is None else index.append(parent, h * 10 + offset, target)
        path[h] = parent
    return path


class IndexedAsertShadowTests(unittest.TestCase):
    def test_4105_height_and_mtp_windows_have_bounded_cost(self):
        ix = ValidatedInputIndex()
        path = chain(ix, 4105)
        for median in (False, True):
            target, cost, anchor = ix.asert_shadow(path[4105], 16, median)
            self.assertGreater(target, 0)
            self.assertEqual(anchor, path[16])
            self.assertLessEqual(cost, 1024)
        entries, cost = ix.heights(path[4105], [4105, 4104, 4097, 4096, 16, 15, 0])
        self.assertLessEqual(cost, 1024)
        self.assertEqual(entries[4096], path[4096])
        self.assertEqual(entries[0], GENESIS)

    def test_fork_below_anchor_uses_its_own_target_and_time(self):
        ix = ValidatedInputIndex()
        trunk = chain(ix, 60)
        parent = trunk[10]
        fork = {}
        for height in range(11, 62):
            parent = ix.append(parent, height * 10 + 2, ix.headers[parent].target)
            fork[height] = parent
        trunk_result = ix.asert_shadow(trunk[60], 16, False)
        fork_result = ix.asert_shadow(fork[61], 16, False)
        self.assertNotEqual(trunk_result[2], fork_result[2])
        self.assertEqual(trunk_result[2], trunk[16])
        self.assertEqual(fork_result[2], fork[16])
        for median in (False, True):
            self.assertLess(ix.asert_shadow(fork[61], 16, median)[1], 400)

    def test_corruption_and_budget_fail_closed(self):
        ix = ValidatedInputIndex()
        path = chain(ix, 4105)
        with self.assertRaisesRegex(ValueError, "INDEX_ORDER"):
            ix.heights(path[4105], [4000, 4000])
        with self.assertRaisesRegex(ValueError, "INDEX_HEIGHT"):
            ix.heights(path[4105], [4106])
        with self.assertRaisesRegex(ValueError, "INDEX_BUDGET"):
            ix.heights(path[4105], [1], 3)
        ix.jumps[path[4105]][12] = GENESIS
        with self.assertRaisesRegex(ValueError, "INDEX_STRUCTURE_CORRUPT|INDEX_HEIGHT_CORRUPT"):
            ix.heights(path[4105], [4105, 9])

    def test_predecessor_mtp_not_mixed_with_raw_timestamp(self):
        ix = ValidatedInputIndex()
        path = chain(ix, 80)
        raw, _, _ = ix.asert_shadow(path[80], 16, False)
        median, _, _ = ix.asert_shadow(path[80], 16, True)
        self.assertGreater(raw, 0)
        self.assertGreater(median, 0)
        self.assertEqual(raw, median)


if __name__ == "__main__":
    unittest.main()
