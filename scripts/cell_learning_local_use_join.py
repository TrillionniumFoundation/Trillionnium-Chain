"""Bind original HEPLCP04 local decisions to acknowledged native next-task use.

This explicit profile joins the original Selection and completed checkpoint cuts
to the existing production use export. Qualified Defer/Retain keep the parent
without becoming training/evaluation NoUpdate. All inputs remain read-only;
matching commitments never grant use, evaluation, mining or payment authority.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import cell_adoption_readback as native
import cell_learning_iteration_join as legacy
import cell_learning_local_decision_join as local

REPORT_SCHEMA = "trnm-cell-learning-local-decision-completed-use-review-v1"


def review_native_local_learning_completion(
        selection_raw, completed_raw, readback_raw, *, expected_selection_sha256,
        expected_completed_sha256, expected_readback_sha256, frozen, expected):
    """Check original request, exact receipt continuation, selected model and ACK.

    Expectations must be retained by the invoking owner independently of the
    submitted materials. Fixture-derived pins only support engineering tests.
    This reader does not authenticate a Root scope profile, receipt signatures,
    independent evaluator/consumer, real training, or current permission.
    """
    decoded = []
    for raw, pin in ((selection_raw, expected_selection_sha256),
                     (completed_raw, expected_completed_sha256)):
        native.require(type(raw) is bytes and len(raw) <= legacy.MAX_CHECKPOINT,
                       "LOCAL_USE_CHECKPOINT_LIMIT")
        native.require(native.sha(raw) == native.hex_digest(pin), "LOCAL_USE_CHECKPOINT_PIN")
        decoded.append(local.decode_native_local_checkpoint(raw))
    (selection, before), (completed, replay) = decoded
    native.fields(frozen, "schema initial_head request owners", "LEARNING_FREEZE_FIELDS")
    native.require(frozen["schema"] == legacy.FREEZE_SCHEMA, "LEARNING_FREEZE_SCHEMA")
    initial = legacy._initial_head(frozen["request"], frozen["owners"])
    native.require(initial == native.hex_digest(frozen["initial_head"]), "LEARNING_FREEZE_HEAD")
    native.require(selection["request"] == completed["request"] == frozen["request"] and
                   selection["owners"] == completed["owners"] == frozen["owners"] and
                   before["initial_head"] == replay["initial_head"] == initial,
                   "LEARNING_FROZEN_REQUEST")
    native.require(before["next_stage"] == 6 and replay["next_stage"] is None and
                   len(selection["receipts"]) == 7 and len(completed["receipts"]) == 8 and
                   completed["receipts"][:-1] == selection["receipts"],
                   "LOCAL_USE_EXACT_CONTINUATION")

    original = native.review_native_learning_use(
        readback_raw, expected_readback_sha256=expected_readback_sha256, expected=expected)
    envelope = native.decode(readback_raw, native.MAX_WIRE)
    _, payload = native.raw_json(envelope["payload_json"])
    selected = selection["receipts"][-1]
    request = selection["request"]
    native.require(before["head"] == native.native_digest(payload["learning_head"]) and
                   selected["predecessor"] == native.native_digest(payload["learning_decision_head"]),
                   "LOCAL_USE_READBACK_HEAD")
    native.require(request["operation_id"] == payload["learning_operation_id"] and
                   request["source_run_id"] == payload["source_run_id"] and
                   request["completed_task_receipt"] == native.native_digest(payload["source_task_receipt"]) and
                   request["selected_artifact_digest"] == native.native_digest(payload["source_selected_artifact"]) and
                   replay["selected_bundle"] == native.native_digest(payload["source_selected_bundle"]),
                   "LOCAL_USE_READBACK_SOURCE")
    _, publication = native.raw_json(payload["publication_json"])
    scope = publication["intent"]["target"]["scope"]
    native.require(request["principal_id"] == native.native_digest(scope["principal_digest"]) and
                   request["agent_id"] == scope["agent_id"] and request["cell_id"] == scope["cell_id"],
                   "LOCAL_USE_READBACK_SCOPE")
    use = payload["observation"]
    native.require(selected["observation"]["selection_digest"] == native.native_digest(use["selection_digest"]) and
                   replay["next_task_bundle"] == native.native_digest(use["bundle_digest"]),
                   "LOCAL_USE_READBACK_SELECTION")
    retained = replay["retained_model"]
    native.require((payload["disposition"] == "retained_model") == retained,
                   "LOCAL_USE_READBACK_DISPOSITION")
    native.require(not original["pending_work"] and not original["pending_delivery"],
                   "LOCAL_USE_ACK_PENDING")
    observed = dict(tag=7 if retained else 6, state_partition=dict(
        principal_id=native.native_digest(scope["principal_digest"]),
        agent_id=scope["agent_id"], cell_id=scope["cell_id"], run_id=scope["run_id"]))
    observed["retained_bundle" if retained else "candidate_bundle"] = native.native_digest(use["bundle_digest"])
    for name in ("checkpoint_digest", "selection_digest", "committed_step_receipt",
                 "task_owner_publication" if retained else "state_cutover_receipt"):
        observed[name] = native.native_digest(use[name])
    final = completed["receipts"][-1]
    native.require(final["predecessor"] == before["head"] and final["observation"] == observed,
                   "LOCAL_USE_ORIGINAL_NEXT_USE")
    choice = replay["local_decision"]
    return dict(
        schema=REPORT_SCHEMA, scope="pinned-heplcp04-receipts-and-acknowledged-native-use-only",
        checkpoint_schema=local.MAGIC.decode("ascii"),
        selection_checkpoint_sha256=expected_selection_sha256,
        completed_checkpoint_sha256=expected_completed_sha256,
        native_readback_sha256=expected_readback_sha256, frozen_initial_head=initial,
        selection_head=before["head"], completed_learning_head=replay["head"], receipt_count=8,
        local_disposition=local.CHOICES[choice["disposition"]], local_decision=copy.deepcopy(choice),
        evaluation_disposition="qualified", proposal_disposition="update_candidates", no_update=False,
        retained_model=retained, selected_bundle_digest=replay["next_task_bundle"],
        final_observation=observed, original_receipt_prefix_preserved=True,
        native_receipt_chain_complete=True, final_next_use_matches_original_actor=True,
        acknowledged_use_observed=True, model_stop_observed=original["model_stop_observed"],
        terminal_episode_observed=original["terminal_episode_observed"], native_readback_review=original,
        authority="DENY_ALL", current_permission="NOT_EXPORTED", qualification="HOLD_NO_GO",
        full_learning_iteration_completed=False, native_origin_authenticated=False,
        source_execution_authenticated=False, pre_dispatch_freeze_authenticated=False,
        learning_signatures_verified=False, root_scope_authenticated=False,
        independent_consumer_verified=False, independent_control_accepted=False,
        real_model_training_verified=False, cost_completeness_verified=False,
        physical_installation_accepted=False, settlement_verified=False,
        current_permission_exported=False, grant_signature_verified_by_this_reader=False,
        full_state_restore_qualified=False, hepta_final_use_accepted=False, production_activation=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection-checkpoint", "completed-checkpoint", "readback", "freeze", "expected"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args()
    frozen_raw = native.read_bounded(args.freeze, legacy.MAX_FREEZE)
    expected_raw = native.read_bounded(args.expected, native.MAX_EXPECTED)
    native.require(native.sha(frozen_raw) == native.hex_digest(args.freeze_sha256), "LEARNING_FREEZE_PIN")
    native.require(native.sha(expected_raw) == native.hex_digest(args.expected_sha256), "EXPECTATIONS_PIN")
    result = review_native_local_learning_completion(
        native.read_bounded(args.selection_checkpoint, legacy.MAX_CHECKPOINT),
        native.read_bounded(args.completed_checkpoint, legacy.MAX_CHECKPOINT),
        native.read_bounded(args.readback, native.MAX_WIRE),
        expected_selection_sha256=args.selection_checkpoint_sha256,
        expected_completed_sha256=args.completed_checkpoint_sha256,
        expected_readback_sha256=args.readback_sha256,
        frozen=native.decode(frozen_raw, legacy.MAX_FREEZE),
        expected=native.decode(expected_raw, native.MAX_EXPECTED))
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
