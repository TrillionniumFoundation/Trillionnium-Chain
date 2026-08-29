#!/usr/bin/env python3
"""Additional candidate-only state-sync fault and binding controls.

These tests stay on the in-memory candidate boundary.  They do not imply that
the canonical node has a production state-sync, external HSM/KMS anchor, or
normative manifest decoder.
"""

from __future__ import annotations

import copy
from dataclasses import replace
import unittest

try:  # package invocation and direct unittest discovery
    from .fixture import fixture
    from .state_sync import MAX_CHUNKS, MAX_CHUNK_BYTES, StateSyncError, StagedStateSync, verify_manifest
except ImportError:  # pragma: no cover
    from conformance.g2f.fixture import fixture
    from conformance.g2f.state_sync import MAX_CHUNKS, MAX_CHUNK_BYTES, StateSyncError, StagedStateSync, verify_manifest


def _args(f):
    return {
        "expected_block_id": bytes.fromhex(f.manifest["block_id"]),
        "expected_root": bytes.fromhex(f.manifest["state_root"]),
    }


class StateSyncFaultAndBindingTests(unittest.TestCase):
    def test_profile_ceiling_downgrade_rejects_before_chunk_decode(self) -> None:
        f = fixture()
        for field, value in (
            ("max_chunk_uncompressed_bytes", MAX_CHUNK_BYTES - 1),
            ("max_chunk_count", MAX_CHUNKS - 1),
        ):
            with self.subTest(field=field):
                manifest = copy.deepcopy(f.manifest)
                manifest[field] = value
                with self.assertRaises(StateSyncError):
                    verify_manifest(manifest, f.chunks, f.context, **_args(f))

    def test_torn_and_sidecar_faults_fence_reopen_and_future_stage(self) -> None:
        f = fixture()
        for fault in ("torn", "sidecar"):
            with self.subTest(fault=fault):
                owner = StagedStateSync(f.context["chain_id"])
                with self.assertRaises(StateSyncError):
                    owner.stage(
                        f.manifest,
                        f.chunks,
                        f.context,
                        **_args(f),
                        generation=1,
                        fault=fault,
                    )
                with self.assertRaises(StateSyncError):
                    owner.reopen()
                with self.assertRaises(StateSyncError):
                    owner.stage(
                        f.manifest,
                        f.chunks,
                        f.context,
                        **_args(f),
                        generation=1,
                    )

    def test_active_full_store_rollback_is_fenced_after_successor_commit(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(first, generation=1, expected_anchor=owner.anchor)
        old_active = owner.active
        predecessor = owner.anchor
        second = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=2)
        owner.commit(second, generation=2, expected_anchor=predecessor)
        self.assertEqual(owner.anchor.generation, 2)
        owner._active = old_active  # hostile full-store rollback mutant
        with self.assertRaises(StateSyncError):
            owner.reopen()

    def test_copied_active_token_is_fenced_on_reopen(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        token = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(token, generation=1, expected_anchor=owner.anchor)
        # A copied namespace can retain bytes and labels but not the owner
        # instance identity.  Reopen must reject it before authority use.
        copied = owner.clone_namespace("copied-active")
        with self.assertRaises(StateSyncError):
            copied.reopen()

    def test_validator_and_da_context_swaps_cannot_reuse_manifest_digest(self) -> None:
        f = fixture()
        for field in ("validator_set_hash", "da_policy_hash"):
            with self.subTest(field=field):
                context = copy.deepcopy(f.context)
                context[field] = "ab" * 32
                manifest = copy.deepcopy(f.manifest)
                manifest[field] = context[field]
                with self.assertRaises(StateSyncError):
                    verify_manifest(manifest, f.chunks, context, **_args(f))


if __name__ == "__main__":
    unittest.main()
