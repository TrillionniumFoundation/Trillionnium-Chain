"""Executable local negative controls for unactivated branch-local ASERT state."""
import hashlib
import random
import unittest
from dataclasses import replace

from daa_anchor_projection import (
    ProjectedAsertContext, VerifiedHeaderObservation, ForkLocalAnchorProjection,
)
from daa_research_oracle import asert_target, mtp11

N = hashlib.sha256(b'projection-network').digest()
P = hashlib.sha256(b'projection-parameters').digest()
G = hashlib.sha256(b'projection-genesis').digest()
RULE = hashlib.sha256(b'projection-rule').digest()
CAP = (1 << 250) - 1
BASE = 1 << 220
START = 1_700_000_000


def context(clock='raw', activation=16):
    return ProjectedAsertContext(N, P, G, RULE, START, activation,
                                 10, 7200, CAP, clock)


def produce(ledger, parent, height, timestamp, target=BASE, marker=0):
    item = hashlib.sha256(parent + height.to_bytes(8, 'big')
                          + timestamp.to_bytes(8, 'big')
                          + marker.to_bytes(4, 'big')).digest()
    observation = VerifiedHeaderObservation(item, parent, N, P, height,
                                            timestamp, target)
    return ledger.observe_assumed_validated(observation), observation


class AnchorProjectionResearch(unittest.TestCase):
    def test_12000_headers_do_not_hit_genesis_4096_read_horizon(self):
        for clock in ('raw', 'mtp11'):
            ledger = ForkLocalAnchorProjection(context(clock))
            parent = G
            previous = []
            for h in range(1, 12001):
                row, source = produce(ledger, parent, h, START + h * 10)
                parent = row.block_id
                previous.insert(0, source.timestamp)
                del previous[11:]
                self.assertLessEqual(len(row.times_parent_first), 11)
                if h >= 16:
                    self.assertEqual(ledger.expected_shadow_target(parent), BASE)
            self.assertEqual(ledger.read_local(parent).height, 12000)
            self.assertTrue(ledger.validate_local_chain(parent))

    def test_fork_spanning_activation_keeps_own_anchor(self):
        ledger = ForkLocalAnchorProjection(context())
        parent = G
        for h in range(1, 15):
            row, _ = produce(ledger, parent, h, START + h * 10)
            parent = row.block_id
        root = parent
        tips = []
        anchors = []
        for marker, shift in ((1, 0), (2, 31)):
            parent = root
            for h in range(15, 80):
                row, _ = produce(ledger, parent, h, START + h * 10 + shift,
                                 BASE + (marker << 195), marker)
                parent = row.block_id
            tips.append(parent)
            anchors.append(ledger.read_local(parent).anchored.anchor_id)
        self.assertNotEqual(anchors[0], anchors[1])
        self.assertNotEqual(ledger.expected_shadow_target(tips[0]),
                            ledger.expected_shadow_target(tips[1]))
        # Reading an alternate fork does not overwrite the old fork's anchor.
        for tip in tips:
            self.assertEqual(ledger.read_local(tip).anchored.anchor_id,
                             anchors[tips.index(tip)])
            self.assertTrue(ledger.validate_local_chain(tip))

    def test_research_projection_matches_independent_full_window_equations(self):
        rng = random.Random(20261026)
        for clock in ('raw', 'mtp11'):
            ledger = ForkLocalAnchorProjection(context(clock))
            chain = [START]
            parent = G
            for h in range(1, 300):
                ts = START + h * 10 + rng.randint(0, 4)
                row, _ = produce(ledger, parent, h, ts)
                parent = row.block_id
                chain.append(ts)
                if h >= 16:
                    raw_pred = chain[15]
                    mtp_pred = mtp11(list(reversed(chain[5:16])))
                    obs = ts if clock == 'raw' else mtp11(list(reversed(chain[max(0,h-10):h+1])))
                    expected = asert_target(BASE, raw_pred if clock == 'raw' else mtp_pred,
                                            obs, 16, h + 1, 10, 7200, CAP)
                    self.assertEqual(ledger.expected_shadow_target(parent), expected)

    def test_context_replay_and_corruption_negative_cases(self):
        ledger = ForkLocalAnchorProjection(context())
        with self.assertRaisesRegex(ValueError, 'PROJECTION_NOT_ACTIVE'):
            ledger.expected_shadow_target(G)
        row, header = produce(ledger, G, 1, START + 10)
        self.assertEqual(ledger.observe_assumed_validated(header), row)
        for bad in (
            replace(header, claimed_id=bytes(32)),
            replace(header, claimed_id=G),
            replace(header, claimed_id=header.parent_id),
            replace(header, network=bytes(32)),
            replace(header, timestamp=-1),
            replace(header, target=0),
        ):
            with self.assertRaisesRegex(ValueError, 'PROJECTION_HEADER_CONTEXT'):
                ledger.observe_assumed_validated(bad)
        with self.assertRaisesRegex(ValueError, 'PROJECTION_ID_COLLISION'):
            ledger.observe_assumed_validated(replace(header, timestamp=header.timestamp + 5))
        with self.assertRaisesRegex(ValueError, 'PROJECTION_HEIGHT'):
            produce(ledger, row.block_id, 3, START + 30)
        with self.assertRaisesRegex(ValueError, 'PROJECTION_PARENT_UNAVAILABLE'):
            ledger.expected_shadow_target(hashlib.sha256(b'absent').digest())
        self.assertTrue(ledger.validate_local_chain(row.block_id))
        ledger._rows[row.block_id] = replace(row, timestamp=START + 20)
        self.assertFalse(ledger.validate_local_chain(row.block_id))
        with self.assertRaisesRegex(ValueError, 'PROJECTION_INTEGRITY'):
            ledger.observe_assumed_validated(VerifiedHeaderObservation(
                hashlib.sha256(b'child').digest(), row.block_id, N, P, 2,
                START + 30, BASE))

    def test_rebuild_is_idempotent_and_fail_closed(self):
        base = ForkLocalAnchorProjection(context('mtp11'))
        observed = []
        parent = G
        for h in range(1, 80):
            row, header = produce(base, parent, h, START + h * 10)
            parent = row.block_id
            observed.append(header)
        restarted = ForkLocalAnchorProjection.rebuild_from_validated_order(
            context('mtp11'), observed)
        self.assertEqual(restarted.read_local(parent), base.read_local(parent))
        self.assertEqual(restarted.expected_shadow_target(parent), BASE)
        last = restarted.read_local(parent)
        restarted._rows[parent] = replace(last, times_parent_first=(last.timestamp,))
        with self.assertRaisesRegex(ValueError, 'PROJECTION_INTEGRITY'):
            restarted.expected_shadow_target(parent)
        with self.assertRaisesRegex(ValueError, 'PROJECTION_PARENT_UNAVAILABLE'):
            ForkLocalAnchorProjection.rebuild_from_validated_order(
                context('mtp11'), observed[1:])
        with self.assertRaisesRegex(ValueError, 'PROJECTION_HEADER_CONTEXT'):
            ForkLocalAnchorProjection.rebuild_from_validated_order(
                context('mtp11'), observed[:40] +
                [replace(observed[40], parameters=bytes(32))] + observed[41:])

    def test_zero_and_overflowed_profile_refused(self):
        for name, value in (("activation_height", 0), ("half_life", 0),
                            ("target_spacing", -1), ("pow_limit", 0),
                            ("clock", 'peer-choice'), ("network", bytes(32)),
                            ("genesis_timestamp", 1 << 65),
                            ("activation_height", (1 << 64) - 1)):
            with self.subTest(name=name, value=value):
                with self.assertRaisesRegex(ValueError, 'PROJECTION_CONTEXT'):
                    ForkLocalAnchorProjection(replace(context(), **{name: value}))


if __name__ == '__main__':
    unittest.main()
