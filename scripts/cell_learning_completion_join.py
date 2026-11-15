"""Bind one completed native learning checkpoint to its original next-task use.

The existing Selection-cut reader remains the first gate. This continuation
requires exactly one additional original NextUse receipt, unchanged prior
receipts, and an acknowledged native use. A complete structural receipt chain
does not authenticate owners, training, evaluation, payment, or current use.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import cell_adoption_readback as native
import cell_learning_iteration_join as iteration

REPORT_SCHEMA = "trnm-cell-learning-completed-use-review-v1"
TRAINER_NO_UPDATE_REPORT_SCHEMA = "trnm-cell-learning-completed-use-review-v2"


def review_native_learning_completion(
        selection_raw, completed_raw, readback_raw, *, expected_selection_sha256,
        expected_completed_sha256, expected_readback_sha256, frozen, expected,
        root_profile_raw=None, expected_root_profile_sha256=None):
    """Check the exact continuation, with no synthesized final receipt or grant.

    ACK completion is required for this review profile. Model STOP is separately
    reported and is not inferred from an acknowledged output or a drained owner.
    Both candidate adoption and complete-incumbent NoUpdate use are preserved.
    """
    native.require(type(completed_raw) is bytes and
                   len(completed_raw) <= iteration.MAX_CHECKPOINT, "COMPLETION_CHECKPOINT_LIMIT")
    native.require(native.sha(completed_raw) == native.hex_digest(expected_completed_sha256),
                   "COMPLETION_CHECKPOINT_PIN")
    prior = iteration.review_native_learning_iteration(
        selection_raw, readback_raw, expected_checkpoint_sha256=expected_selection_sha256,
        expected_readback_sha256=expected_readback_sha256, frozen=frozen, expected=expected,
        root_profile_raw=root_profile_raw, expected_root_profile_sha256=expected_root_profile_sha256)
    selection, selection_replay = iteration.decode_native_learning_checkpoint(selection_raw)
    completed, replay = iteration.decode_native_learning_checkpoint(completed_raw)
    native.require(completed["request"] == selection["request"] and
                   completed["owners"] == selection["owners"] and
                   replay["initial_head"] == selection_replay["initial_head"],
                   "COMPLETION_ORIGINAL_ITERATION")
    native.require(len(completed["receipts"]) == len(selection["receipts"]) + 1 and
                   completed["receipts"][:-1] == selection["receipts"],
                   "COMPLETION_EXACT_RECEIPT_PREFIX")
    native.require(replay["next_stage"] is None, "COMPLETION_NEXT_USE_REQUIRED")
    final = completed["receipts"][-1]
    native.require(final["predecessor"] == selection_replay["head"],
                   "COMPLETION_SELECTION_PREDECESSOR")
    use_review = prior["native_readback_review"]
    native.require(not use_review["pending_work"] and not use_review["pending_delivery"],
                   "COMPLETION_ACK_PENDING")

    envelope = native.decode(readback_raw, native.MAX_WIRE)
    _, payload = native.raw_json(envelope["payload_json"])
    _, publication = native.raw_json(payload["publication_json"])
    scope = publication["intent"]["target"]["scope"]
    use = payload["observation"]
    retained = replay["no_update"]
    observed = dict(
        tag=7 if retained else 6,
        state_partition=dict(
            principal_id=native.native_digest(scope["principal_digest"]),
            agent_id=scope["agent_id"], cell_id=scope["cell_id"], run_id=scope["run_id"]),
    )
    observed["retained_bundle" if retained else "candidate_bundle"] = native.native_digest(use["bundle_digest"])
    for name in ("checkpoint_digest", "selection_digest", "committed_step_receipt",
                 "task_owner_publication" if retained else "state_cutover_receipt"):
        observed[name] = native.native_digest(use[name])
    native.require(final["observation"] == observed, "COMPLETION_ORIGINAL_NEXT_USE")

    return dict(
        schema=TRAINER_NO_UPDATE_REPORT_SCHEMA if "training_no_update" in replay else REPORT_SCHEMA,
        scope="pinned-native-completed-receipt-chain-and-acknowledged-use-only",
        selection_checkpoint_sha256=expected_selection_sha256,
        completed_checkpoint_sha256=expected_completed_sha256,
        native_readback_sha256=expected_readback_sha256,
        frozen_initial_head=replay["initial_head"], selection_head=selection_replay["head"],
        completed_learning_head=replay["head"], receipt_count=len(completed["receipts"]),
        next_use_evidence_digest=final["evidence_digest"],
        next_use_observed_unix_seconds=final["observed_unix_seconds"],
        no_update=retained, final_observation=observed,
        original_receipt_prefix_preserved=True, native_receipt_chain_complete=True,
        final_next_use_matches_original_actor=True, acknowledged_use_observed=True,
        model_stop_observed=use_review["model_stop_observed"],
        terminal_episode_observed=use_review["terminal_episode_observed"],
        selection_use_review=prior, authority="DENY_ALL", current_permission="NOT_EXPORTED",
        full_learning_iteration_completed=False, native_origin_authenticated=False,
        pre_dispatch_freeze_authenticated=False, learning_signatures_verified=False,
        grant_signature_verified_by_this_reader=False, independent_control_accepted=False,
        cost_completeness_verified=False, current_permission_exported=False,
        real_model_training_verified=False, physical_installation_accepted=False,
        settlement_verified=False, hepta_final_use_accepted=False, production_activation=False,
        qualification="HOLD_NO_GO")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection-checkpoint", "completed-checkpoint", "readback", "freeze", "expected"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--root-profile", type=Path)
    parser.add_argument("--root-profile-sha256")
    args = parser.parse_args()
    if (args.root_profile is None) != (args.root_profile_sha256 is None):
        parser.error("--root-profile and --root-profile-sha256 must be supplied together")
    frozen_raw = native.read_bounded(args.freeze, iteration.MAX_FREEZE)
    expected_raw = native.read_bounded(args.expected, native.MAX_EXPECTED)
    native.require(native.sha(frozen_raw) == native.hex_digest(args.freeze_sha256), "LEARNING_FREEZE_PIN")
    native.require(native.sha(expected_raw) == native.hex_digest(args.expected_sha256), "EXPECTATIONS_PIN")
    result = review_native_learning_completion(
        native.read_bounded(args.selection_checkpoint, iteration.MAX_CHECKPOINT),
        native.read_bounded(args.completed_checkpoint, iteration.MAX_CHECKPOINT),
        native.read_bounded(args.readback, native.MAX_WIRE),
        expected_selection_sha256=args.selection_checkpoint_sha256,
        expected_completed_sha256=args.completed_checkpoint_sha256,
        expected_readback_sha256=args.readback_sha256,
        root_profile_raw=None if args.root_profile is None else native.read_bounded(args.root_profile, 16384),
        expected_root_profile_sha256=args.root_profile_sha256,
        frozen=native.decode(frozen_raw, iteration.MAX_FREEZE),
        expected=native.decode(expected_raw, native.MAX_EXPECTED))
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
