#!/usr/bin/env python3
"""Additional candidate-only state-sync fault and binding controls.

These tests stay on the in-memory candidate boundary.  They do not imply that
the canonical node has a production state-sync, external HSM/KMS anchor, or
normative manifest decoder.
"""

from __future__ import annotations

import copy
from dataclasses import replace
import json
import unittest

try:  # package invocation and direct unittest discovery
    from .fixture import fixture
    from .state_sync import MAX_CHUNKS, MAX_CHUNK_BYTES, StateSyncError, StagedStateSync, verify_manifest
    from .state_tree import digest, encode_records, sparse_root
    from .wire import header_id
except ImportError:  # pragma: no cover
    from conformance.g2f.fixture import fixture
    from conformance.g2f.state_sync import MAX_CHUNKS, MAX_CHUNK_BYTES, StateSyncError, StagedStateSync, verify_manifest
    from conformance.g2f.state_tree import digest, encode_records, sparse_root
    from conformance.g2f.wire import header_id


def _args(f):
    return {
        "expected_block_id": bytes.fromhex(f.manifest["block_id"]),
        "expected_root": bytes.fromhex(f.manifest["state_root"]),
        "expected_height": f.height,
    }


def _alternate_manifest(f):
    """Build a second valid candidate checkpoint at the same height."""

    records = list(f.records)
    records[0] = replace(records[0], value=records[0].value + b"-fork")
    records = tuple(sorted(records, key=lambda record: record.key))
    payload = encode_records(records)
    root = sparse_root(records)
    block = header_id(f.context, f.height, root)
    descriptor = {
        "chunk_index": 0,
        "first_state_key": records[0].key.hex(),
        "last_state_key": records[-1].key.hex(),
        "uncompressed_bytes": len(payload),
        "compressed_bytes": len(payload),
        "uncompressed_hash": digest(
            "trnm.poco-ai.state-sync-chunk-bytes.v1", payload
        ).hex(),
        "compressed_hash": digest(
            "trnm.poco-ai.state-sync-chunk-bytes.v1", payload
        ).hex(),
    }
    # Keep this helper independent of state_sync's private implementation;
    # the manifest is rebuilt using the published candidate digest domains.
    manifest = copy.deepcopy(f.manifest)
    manifest.update(
        {
            "block_id": block.hex(),
            "state_root": root.hex(),
            "epoch_checkpoint_id": digest(
                "trnm.poco-ai.epoch-checkpoint-id.candidate.v1", block + root
            ).hex(),
            "chunk_manifest_root": digest(
                "trnm.poco-ai.state-sync-chunk-manifest-root.v1",
                json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode(),
            ).hex(),
            "chunk_entries": [descriptor],
            "total_uncompressed_bytes": len(payload),
        }
    )
    return manifest, payload


class StateSyncFaultAndBindingTests(unittest.TestCase):
    def test_context_is_closed_and_height_header_is_bound(self) -> None:
        f = fixture()
        extra = copy.deepcopy(f.context)
        extra["unexpected"] = "must-reject"
        with self.assertRaises(StateSyncError):
            verify_manifest(f.manifest, f.chunks, extra, **_args(f))

        wrong_height = copy.deepcopy(f.manifest)
        wrong_height["height"] = f.height + 1
        wrong_height["catch_up_start_height"] = f.height + 2
        with self.assertRaises(StateSyncError):
            verify_manifest(wrong_height, f.chunks, f.context, **_args(f))
        with self.assertRaises(StateSyncError):
            verify_manifest(
                f.manifest,
                f.chunks,
                f.context,
                expected_block_id=bytes.fromhex(f.manifest["block_id"]),
                expected_root=bytes.fromhex(f.manifest["state_root"]),
            )
        wrong_height_args = _args(f)
        wrong_height_args["expected_height"] = f.height + 1
        with self.assertRaises(StateSyncError):
            verify_manifest(
                f.manifest,
                f.chunks,
                f.context,
                **wrong_height_args,
            )

    def test_same_height_fork_is_rejected_before_active_swap(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        predecessor = owner.anchor
        owner.commit(first, generation=1, expected_anchor=predecessor)

        fork_manifest, fork_payload = _alternate_manifest(f)
        fork = owner.stage(
            fork_manifest,
            (fork_payload,),
            f.context,
            expected_block_id=bytes.fromhex(fork_manifest["block_id"]),
            expected_root=bytes.fromhex(fork_manifest["state_root"]),
            expected_height=f.height,
            generation=2,
        )
        with self.assertRaises(StateSyncError):
            owner.commit(fork, generation=2, expected_anchor=owner.anchor)

    def test_generation_must_be_contiguous(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        with self.assertRaises(StateSyncError):
            owner.stage(
                f.manifest,
                f.chunks,
                f.context,
                **_args(f),
                generation=2,
            )

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
