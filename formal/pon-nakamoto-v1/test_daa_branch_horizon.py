"""Research-only >4096-height ancestry liveness boundary.

This is a negative control: the current shadow DAA is NOT production eligible.
A genesis-fixed anchor and a 4096-read budget cannot validate an unbounded
chain. Never interpret a local budget exhaustion as INVALID chainwork or
silently accept a peer-provided summary.
"""
import hashlib
import unittest
from daa_branch_context_oracle import (
    ResearchHeader, ResearchContext, shadow_target_from_ancestry,
)

GENESIS = hashlib.sha256(b"daa-horizon-genesis").digest()
NETWORK = hashlib.sha256(b"daa-horizon-network").digest()
PARAMS = hashlib.sha256(b"daa-horizon-parameters").digest()
BASE = 1 << 220
LIMIT = (1 << 240) - 1


def chain(length):
    if length not in (4096, 4097):
        raise ValueError("frozen lengths only")
    nodes = {}
    parent = GENESIS
    anchor = None
    for height in range(1, length + 1):
        timestamp = height * 10
        node_id = hashlib.sha256(
            parent + height.to_bytes(8, "little")
            + timestamp.to_bytes(8, "little")
        ).digest()
        nodes[node_id] = ResearchHeader(
            node_id, NETWORK, PARAMS, parent, height, timestamp, BASE
        )
        if height == 1:
            anchor = node_id
        parent = node_id
    assert anchor is not None
    ctx = ResearchContext(
        NETWORK, PARAMS, GENESIS, 0, anchor, BASE, 1,
        10, 7200, LIMIT, "raw", 4096,
    )
    return ctx, parent, nodes


class AsertResearchHorizonTests(unittest.TestCase):
    def test_last_supported_genesis_anchored_parent(self):
        ctx, tip, nodes = chain(4096)
        self.assertEqual(shadow_target_from_ancestry(ctx, tip, nodes), BASE)

    def test_next_parent_is_unavailable_not_consensus_invalid(self):
        ctx, tip, nodes = chain(4097)
        with self.assertRaisesRegex(ValueError, "^ASERT_ANCESTRY_BUDGET$"):
            shadow_target_from_ancestry(ctx, tip, nodes)

    def test_peer_supplied_skip_without_authentication_cannot_fix_horizon(self):
        ctx, tip, nodes = chain(4097)
        # A fabricated short-circuit record must fail exact parent/height binding,
        # rather than turning a cheaper ancestor walk into trusted authority.
        skip = nodes[tip]
        nodes[tip] = ResearchHeader(
            skip.claimed_id, skip.network, skip.parameters,
            ctx.anchor_block, skip.height, skip.timestamp, skip.target
        )
        with self.assertRaisesRegex(ValueError, "^ASERT_ANCESTRY_HEIGHT$"):
            shadow_target_from_ancestry(ctx, tip, nodes)


if __name__ == "__main__":
    unittest.main()
