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
        # An equivocation is a terminal safety finding, not a retryable
        # predecessor mismatch.  Retain the rejected fork for evidence but
        # quarantine every later authority-bearing operation.
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.reopen()
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=2)

    def test_rejected_fork_blocks_a_previously_staged_sibling(self) -> None:
        """A valid sibling cannot win after a fork is observed."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(first, generation=1, expected_anchor=owner.anchor)

        # Stage the valid successor first, then retain a different same-height
        # candidate at the same generation.  Seeing both candidates is itself
        # an equivocation, even if the caller later presents the valid token.
        sibling = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=2)
        fork_manifest, fork_payload = _alternate_manifest(f)
        fork_owner = StagedStateSync(f.context["chain_id"])
        fork_predecessor = fork_owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        fork_owner.commit(
            fork_predecessor,
            generation=1,
            expected_anchor=fork_owner.anchor,
        )
        fork_candidate = fork_owner.stage(
            fork_manifest,
            (fork_payload,),
            f.context,
            expected_block_id=bytes.fromhex(fork_manifest["block_id"]),
            expected_root=bytes.fromhex(fork_manifest["state_root"]),
            expected_height=f.height,
            generation=2,
        )
        # Model a second durable stage record arriving from the same owner;
        # the identity fields are preserved while the source instance label is
        # rewritten to this namespace for the retained-storage mutant.
        fork = replace(
            fork_candidate,
            instance_id=owner._instance_id,
            namespace_id=owner._namespace_id,
        )
        owner._stages[fork.stage_id] = fork
        with self.assertRaises(StateSyncError):
            owner.commit(fork, generation=2, expected_anchor=owner.anchor)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.commit(sibling, generation=2, expected_anchor=owner.anchor)

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

    def test_exact_duplicate_stage_is_idempotent(self) -> None:
        """A byte-identical retry reuses one token instead of forking."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        retry = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        self.assertIs(retry, first)
        self.assertEqual(len(owner._stages), 1)

    def test_distinct_same_generation_token_is_quarantined(self) -> None:
        """Same-identity duplicate tokens remain a retained mutant."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        duplicate = replace(first, stage_id="injected-duplicate")
        owner._stages[duplicate.stage_id] = duplicate
        with self.assertRaisesRegex(StateSyncError, "duplicate staged generation"):
            owner.reopen()
        self.assertIn("injected-duplicate", owner._stages)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.commit(first, generation=1, expected_anchor=owner.anchor)

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
        self.assertIs(owner.active, old_active)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=3)

    def test_malformed_anchor_and_stage_quarantine_before_authority(self) -> None:
        """Malformed persisted state is retained but permanently fenced."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        token = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(token, generation=1, expected_anchor=owner.anchor)
        bad_anchor = replace(owner.anchor, block_id=b"\x01" * 32)
        owner._anchor = bad_anchor
        with self.assertRaises(StateSyncError):
            owner.reopen()
        self.assertEqual(owner.anchor, bad_anchor)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=2)

        staged_owner = StagedStateSync(f.context["chain_id"])
        staged_owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        staged_owner._stages["malformed-stage"] = object()
        with self.assertRaises(StateSyncError):
            staged_owner.reopen()
        self.assertIn("malformed-stage", staged_owner._stages)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            staged_owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

        sidecar_owner = StagedStateSync(f.context["chain_id"])
        sidecar_owner._sidecars = None
        with self.assertRaisesRegex(StateSyncError, "malformed sidecar state"):
            sidecar_owner.reopen()
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            sidecar_owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

    def test_stage_token_bytes_and_digest_mutants_quarantine(self) -> None:
        """Active/staged token bytes are authenticated before reopen/use."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        token = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(token, generation=1, expected_anchor=owner.anchor)
        active = owner.active
        assert active is not None
        mutated_active = replace(active, chunks=(active.chunks[0] + b"\x00",))
        owner._active = mutated_active
        with self.assertRaisesRegex(StateSyncError, "stage"):
            owner.reopen()
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=2)

        staged_owner = StagedStateSync(f.context["chain_id"])
        staged = staged_owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        corrupted = replace(staged, stage_digest=b"\x00" * 32)
        staged_owner._stages[staged.stage_id] = corrupted
        with self.assertRaisesRegex(StateSyncError, "stage digest"):
            staged_owner.reopen()
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            staged_owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

    def test_missing_or_mutated_own_stage_quarantines(self) -> None:
        """A lost or altered local stage cannot be retried as authority."""

        f = fixture()
        missing_owner = StagedStateSync(f.context["chain_id"])
        missing = missing_owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        del missing_owner._stages[missing.stage_id]
        with self.assertRaisesRegex(StateSyncError, "missing staged state"):
            missing_owner.commit(
                missing,
                generation=1,
                expected_anchor=missing_owner.anchor,
            )
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            missing_owner.reopen()
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            missing_owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

        mutated_owner = StagedStateSync(f.context["chain_id"])
        original = mutated_owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        mutated = replace(original, stage_digest=b"\x01" * 32)
        with self.assertRaisesRegex(StateSyncError, "unknown or mutated stage"):
            mutated_owner.commit(
                mutated,
                generation=1,
                expected_anchor=mutated_owner.anchor,
            )
        self.assertIs(mutated_owner._stages[original.stage_id], original)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
            mutated_owner.reopen()

    def test_zero_manifest_digest_cannot_advance_anchor(self) -> None:
        """A recomputed zero stage digest remains an invalid predecessor."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        original = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_args(f),
            generation=1,
        )
        zero_view = replace(original.view, digest=b"\x00" * 32)
        zero_stage_digest = digest(
            "trnm.poco-ai.state-sync-stage.v1",
            zero_view.digest + original.generation.to_bytes(8, "little"),
        )
        mutant = replace(original, view=zero_view, stage_digest=zero_stage_digest)
        owner._stages[original.stage_id] = mutant
        with self.assertRaisesRegex(StateSyncError, "stage digest"):
            owner.commit(mutant, generation=1, expected_anchor=owner.anchor)
        self.assertEqual(owner.anchor.generation, 0)
        self.assertEqual(owner.anchor.manifest_digest, b"\x00" * 32)
        self.assertIs(owner._stages[original.stage_id], mutant)
        with self.assertRaisesRegex(StateSyncError, "quarantined state-sync"):
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

    def test_same_namespace_copy_with_staged_residue_is_fenced(self) -> None:
        """A same-label copy cannot reuse pre-activation staged residue."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"], namespace_id="same-boundary")
        owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

        # clone_namespace intentionally models a storage copy: it preserves
        # labels and bytes but receives a new owner instance identity.  The
        # copied stage must fence every operation, even when the namespace
        # label itself is unchanged.
        copied = owner.clone_namespace("same-boundary")
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            copied.reopen()
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            copied.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

    def test_namespace_copy_fence_covers_empty_and_active_same_id(self) -> None:
        """Copy quarantine is permanent, including empty and active copies."""

        f = fixture()
        owner = StagedStateSync(f.context["chain_id"], namespace_id="copy-boundary")
        empty_copy = owner.clone_namespace("copy-boundary")
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            empty_copy.reopen()
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            empty_copy.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)

        token = owner.stage(f.manifest, f.chunks, f.context, **_args(f), generation=1)
        owner.commit(token, generation=1, expected_anchor=owner.anchor)
        active_copy = owner.clone_namespace("copy-boundary")
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            active_copy.reopen()
        # A token from the source owner must not be usable by the quarantined
        # copy even when the namespace label and anchor are identical.
        with self.assertRaisesRegex(StateSyncError, "copied namespace"):
            active_copy.commit(token, generation=1, expected_anchor=active_copy.anchor)

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
