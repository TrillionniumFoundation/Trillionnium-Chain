"""Read one pinned learning/business operation without creating authority.

Original HEPLCP02 and owner exports are replayed, never replaced by a summary.
The source pair and funded request/result mapping are explicit declarations;
hash equality does not authenticate execution, independent control or payment.
This module has no network, signing, dispatch, payment or recovery-write path.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration
import cell_learning_business_economics as economics

BINDINGS_SCHEMA = "trnm-cell-learning-business-bindings-v1"
REPORT_SCHEMA = "trnm-cell-learning-business-review-v2"
MAX_BINDINGS = 256 * 1024
MATERIAL_NAMES = ("selection", "completed", "readback", "freeze", "expected")
REQUEST_DOMAIN = b"trnm.cell.learning.business-request.v1\0"
RESULT_DOMAIN = b"trnm.cell.learning.business-result.v1\0"
LEARNING_FIELDS = ("initial_head evaluation_profile baseline_bundle selected_bundle "
                   "source_run_id next_run_id next_task_digest next_input_digest cost_source_digest")


def _commit(value):
    native.require(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None
                   and value != "0" * 40, "BUSINESS_SOURCE_IDENTITY")
    return value


def _digest(value):
    native.hex_digest(value)
    native.require(value != "0" * 64, "BUSINESS_ZERO_DIGEST")
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _source_pair(value):
    native.fields(value, "chain hepta", "BUSINESS_SOURCE_PAIR_FIELDS")
    for source in value.values():
        native.fields(source, "commit tree", "BUSINESS_SOURCE_FIELDS")
        _commit(source["commit"])
        _commit(source["tree"])


def _material(raw, pin, bindings):
    native.fields(pin, "sha256 operation_id source_pair", "BUSINESS_MATERIAL_FIELDS")
    _source_pair(pin["source_pair"])
    native.require(pin["source_pair"] == bindings["source_pair"], "BUSINESS_SOURCE_PAIR")
    native.require(pin["operation_id"] == bindings["operation_id"], "BUSINESS_OPERATION")
    native.require(type(raw) is bytes and native.sha(raw) == _digest(pin["sha256"]),
                   "BUSINESS_MATERIAL_PIN")


def funded_request_digest(bindings, initial):
    """New application mapping, not a replacement for any native signed domain."""
    request = initial["request"]
    return native.sha(REQUEST_DOMAIN + _json(dict(
        operation_id=bindings["operation_id"], invocation_id=bindings["invocation_id"],
        source_pair=bindings["source_pair"], initial_head=bindings["learning"]["initial_head"],
        source_task_receipt=request["completed_task_receipt"],
        evaluation_profile=request["evaluation_profile"],
        baseline_bundle=iteration.bundle_digest(request["selected_bundle"]))))


def funded_result_digest(request_digest, review):
    use = review["selection_use_review"]["native_readback_review"]
    final = review["final_observation"]
    return native.sha(RESULT_DOMAIN + _json(dict(
        request_digest=request_digest, completed_learning_head=review["completed_learning_head"],
        decision="NoUpdate" if review["no_update"] else "Selection",
        selected_bundle=final["retained_bundle" if review["no_update"] else "candidate_bundle"],
        next_task_digest=use["task_digest"], next_input_digest=use["input_digest"],
        committed_step_receipt=final["committed_step_receipt"],
        cost_source_digest=use["cost_source_digest"])))


def _retained_facts(raw):
    # Called only after the complete paid-v3 parser has checked these bytes.
    report = native.decode(raw, economics.MAX_REPORT)
    return {name: report[name] for name in
            ("declared_costs", "historical_payment", "historical_delivery_anchor")}


def _recovery(observations, retained_facts):
    """Compare up to sixteen read-only cuts, retaining gaps and original facts."""
    result = dict(status="NOT_OBSERVED", original_operation_preserved=None,
                  reconciliation_heads_monotonic=None, recovery_authenticated=False,
                  redispatch_authorized=False, repayment_authorized=False,
                  compensation_authorized=False, full_state_restore_qualified=False,
                  journal_prefix_verified=False, missing_observation_recovery_verified=False,
                  observation_count=len(observations),
                  missing_observations=sum(item is None for item in observations))
    native.require(len(observations) == len(retained_facts), "BUSINESS_RECOVERY_FACTS")
    prior = None
    known = 0
    for entry, facts in zip(observations, retained_facts):
        if entry is None:
            native.require(facts is None, "BUSINESS_RECOVERY_FACTS")
            continue
        native.require(type(facts) is dict, "BUSINESS_RECOVERY_FACTS")
        known += 1
        after = entry["expected"]
        if prior is not None:
            before, old_facts = prior
            native.require(before["service"] == after["service"] and
                           before["context"] == after["context"] and
                           before["decision"] == after["decision"], "BUSINESS_RECOVERY_IDENTITY")
            native.require(old_facts == facts, "BUSINESS_RECOVERY_RETAINED_FACTS")
            old, new = before["observation"], after["observation"]
            epoch = "declared_reconciliation_epoch"
            sequence = "retained_reconciliation_sequence"
            native.require(new[epoch] >= old[epoch] and new[sequence] >= old[sequence],
                           "BUSINESS_RECOVERY_REWIND")
            if new[sequence] == old[sequence]:
                native.require(new == old, "BUSINESS_RECOVERY_SAME_SEQUENCE")
            old_anchor, new_anchor = old["observed_anchor"], new["observed_anchor"]
            native.require(new_anchor["generation"] >= old_anchor["generation"],
                           "BUSINESS_RECOVERY_ANCHOR_REWIND")
            if new_anchor["generation"] == old_anchor["generation"]:
                native.require(new_anchor == old_anchor, "BUSINESS_RECOVERY_SAME_GENERATION_ANCHOR")
            old_checkpoint, new_checkpoint = old["m12_checkpoint"], new["m12_checkpoint"]
            native.require(new_checkpoint["max_records"] == old_checkpoint["max_records"] and
                           new_checkpoint["sequence"] >= old_checkpoint["sequence"],
                           "BUSINESS_RECOVERY_CHECKPOINT")
            if new_checkpoint["sequence"] == old_checkpoint["sequence"]:
                native.require(new_checkpoint == old_checkpoint, "BUSINESS_RECOVERY_SAME_CHECKPOINT")
        prior = after, facts
    if known:
        result["status"] = "SINGLE_OBSERVATION_ONLY"
    if known >= 2:
        result.update(status="DECLARED_HEADS_CONSISTENT_ONLY", original_operation_preserved=True,
                      reconciliation_heads_monotonic=True, retained_facts_preserved=True)
    if observations and observations[-1] is None:
        result.update(status="LATEST_OBSERVATION_MISSING", current_payment_status="UNKNOWN")
    return result


def review_business_iteration(materials, *, bindings_raw, expected_bindings_sha256,
                              native_task_raws=()):
    native.require(type(bindings_raw) is bytes and len(bindings_raw) <= MAX_BINDINGS,
                   "BUSINESS_BINDINGS_LIMIT")
    native.require(native.sha(bindings_raw) == _digest(expected_bindings_sha256),
                   "BUSINESS_BINDINGS_PIN")
    bindings = native.decode(bindings_raw, MAX_BINDINGS)
    native.fields(bindings, "schema operation_id invocation_id capture_basis source_pair "
                  "root_envelope_schema materials learning consumer economics", "BUSINESS_BINDINGS_FIELDS")
    native.require(bindings["schema"] == BINDINGS_SCHEMA, "BUSINESS_BINDINGS_SCHEMA")
    native.stable_id(bindings["operation_id"])
    native.stable_id(bindings["invocation_id"])
    native.require(bindings["capture_basis"] in (
        "retrospective-research-readback", "engineering-control", "original-owner-export"),
        "BUSINESS_CAPTURE_BASIS")
    _source_pair(bindings["source_pair"])
    if bindings["root_envelope_schema"] is not None:
        native.integer(bindings["root_envelope_schema"], minimum=1, maximum=2)
    native.fields(materials, " ".join(MATERIAL_NAMES), "BUSINESS_INPUT_FIELDS")
    native.fields(bindings["materials"], " ".join(MATERIAL_NAMES), "BUSINESS_PIN_FIELDS")
    limits = dict(selection=iteration.MAX_CHECKPOINT, completed=iteration.MAX_CHECKPOINT,
                  readback=native.MAX_WIRE, freeze=iteration.MAX_FREEZE, expected=native.MAX_EXPECTED)
    for name in MATERIAL_NAMES:
        native.require(type(materials[name]) is bytes and len(materials[name]) <= limits[name],
                       "BUSINESS_INPUT_LIMIT")
        _material(materials[name], bindings["materials"][name], bindings)
    frozen = native.decode(materials["freeze"], iteration.MAX_FREEZE)
    expected = native.decode(materials["expected"], native.MAX_EXPECTED)
    review = completion.review_native_learning_completion(
        materials["selection"], materials["completed"], materials["readback"],
        expected_selection_sha256=bindings["materials"]["selection"]["sha256"],
        expected_completed_sha256=bindings["materials"]["completed"]["sha256"],
        expected_readback_sha256=bindings["materials"]["readback"]["sha256"],
        frozen=frozen, expected=expected)
    snapshot, _ = iteration.decode_native_learning_checkpoint(materials["completed"])
    request, receipts = snapshot["request"], snapshot["receipts"]
    native.require(request["operation_id"] == bindings["operation_id"], "BUSINESS_OPERATION")
    final = review["final_observation"]
    use = review["selection_use_review"]["native_readback_review"]
    selected = request["selected_bundle"] if review["no_update"] else receipts[2]["observation"]["candidate"]
    observed = dict(initial_head=review["frozen_initial_head"], evaluation_profile=request["evaluation_profile"],
                    baseline_bundle=iteration.bundle_digest(request["selected_bundle"]),
                    selected_bundle=iteration.bundle_digest(selected), source_run_id=request["source_run_id"],
                    next_run_id=final["state_partition"]["run_id"], next_task_digest=use["task_digest"],
                    next_input_digest=use["input_digest"], cost_source_digest=use["cost_source_digest"])
    native.fields(bindings["learning"], LEARNING_FIELDS, "BUSINESS_LEARNING_FIELDS")
    native.require(bindings["learning"] == observed, "BUSINESS_LEARNING_BINDINGS")
    native.fields(bindings["consumer"], "principal_id agent_id cell_id", "BUSINESS_CONSUMER_FIELDS")
    native.require(bindings["consumer"] == {k: final["state_partition"][k]
                   for k in ("principal_id", "agent_id", "cell_id")}, "BUSINESS_CONSUMER_BINDING")
    source_actor = {k: request[k] for k in ("principal_id", "agent_id", "cell_id", "source_run_id")}
    next_use_actor = {k: final["state_partition"][k]
                      for k in ("principal_id", "agent_id", "cell_id", "run_id")}
    actor_relation = dict(same_principal=source_actor["principal_id"] == next_use_actor["principal_id"],
                          same_agent=source_actor["agent_id"] == next_use_actor["agent_id"],
                          same_cell=source_actor["cell_id"] == next_use_actor["cell_id"],
                          distinct_run=source_actor["source_run_id"] != next_use_actor["run_id"])
    # The original reader requires this actor/run relation. It does not attest
    # an independent consumer, even when the bindings label this actor consumer.
    native.require(all(actor_relation.values()), "BUSINESS_NEXT_USE_ACTOR_RELATION")
    request_digest = funded_request_digest(bindings, snapshot)
    result_digest = funded_result_digest(request_digest, review)
    entries = bindings["economics"]
    native.require(type(entries) is list and len(entries) <= 16 and
                   type(native_task_raws) in (list, tuple) and
                   sum(entry is not None for entry in entries) == len(native_task_raws),
                   "BUSINESS_ECONOMICS_INPUTS")
    economic_reviews = []
    retained_facts = []
    raw_iterator = iter(native_task_raws)
    for entry in entries:
        if entry is None:
            retained_facts.append(None)
            economic_reviews.append(economics.review_native_economics(
                None, expected_sha256=None, expected=None))
            continue
        raw = next(raw_iterator)
        native.fields(entry, "material expected", "BUSINESS_ECONOMICS_FIELDS")
        native.require(type(raw) is bytes and len(raw) <= 256 * 1024, "BUSINESS_ECONOMICS_LIMIT")
        _material(raw, entry["material"], bindings)
        economic = economics.review_native_economics(
            raw, expected_sha256=entry["material"]["sha256"], expected=entry["expected"])
        declaration = entry["expected"]
        native.require(declaration["decision"] == ("NoUpdate" if review["no_update"] else "Selection"),
                       "BUSINESS_DECISION_BINDING")
        native.require(declaration["service"]["terms"]["request"] == request_digest and
                       declaration["service"]["output"] == result_digest,
                       "BUSINESS_FUNDED_REQUEST_RESULT")
        economic_reviews.append(economic)
        retained_facts.append(_retained_facts(raw))
    recovery = _recovery(entries, retained_facts)
    training, dataset = receipts[2]["observation"], receipts[1]["observation"]
    return dict(
        schema=REPORT_SCHEMA, scope="same-operation-structural-readback-only",
        bindings_sha256=expected_bindings_sha256, operation_id=bindings["operation_id"],
        invocation_id=bindings["invocation_id"], capture_basis=bindings["capture_basis"],
        declared_source_pair=bindings["source_pair"], source_execution_authenticated=False,
        declared_source_pair_consistent=True, same_operation_bindings_consistent=True,
        checkpoint_codec=iteration.MAGIC.decode("ascii"),
        declared_root_envelope_schema=bindings["root_envelope_schema"], root_envelope_verified=False,
        request_profile_bound_in_checkpoint=True, pre_dispatch_freeze_authenticated=False,
        decision="NoUpdate" if review["no_update"] else "Selection", receipt_count=review["receipt_count"],
        selected_bundle_digest=observed["selected_bundle"], complete_version_descriptor=selected,
        complete_version_custody_verified=False, physical_installation_accepted=False,
        consumer=bindings["consumer"], independent_consumer_verified=False,
        next_use_provenance=dict(
            status="SAME_ORIGINAL_ACTOR_DISTINCT_RUN_ONLY",
            scope="decoded-checkpoint-actor-and-run-identifiers-only",
            completed_checkpoint_sha256=native.sha(materials["completed"]),
            source_actor=source_actor, next_use_actor=next_use_actor,
            **actor_relation, authenticated=False),
        independent_consumer_gate=dict(
            status="MISSING_ORIGINAL_INDEPENDENT_CONSUMER_RECEIPT", verified=False),
        next_task_digest=observed["next_task_digest"], acknowledged_next_use_observed=True,
        funded_request_digest=request_digest, funded_result_digest=result_digest,
        funded_mapping_observed=any(entry is not None for entry in entries), funded_mapping_authenticated=False,
        declared_costs=dict(dataset_rows=dataset["rows"], dataset_bytes=dataset["bytes"],
                            training_steps=training["steps"], training_milliseconds=training["milliseconds"],
                            training_artifact_bytes=training["artifact_bytes"],
                            next_use_cost_source_digest=observed["cost_source_digest"]),
        cost_completeness_verified=False, physical_costs_verified=False,
        economic_observations=economic_reviews,
        economic_categories=dict(
            service_fee=dict(no_update_forces_zero=False, execution_authorized=False,
                             external_payment_verified=False, actual_external_amount=None),
            improvement_reward=dict(evidence_required="independent-prefrozen-paid-cost-benefit",
                                    no_update_eligible=False, amount_authorized_by_reader=0,
                                    actual_external_amount=None),
            consensus_credit=dict(evidence_required="independent-legal-strategy-resource-cost-relation",
                                  amount_authorized_by_reader=0, actual_qualified_credit=None)),
        recovery=recovery, completion_review=review,
        unresolved_obligations=[
            "authenticate-same-source-pair-and-original-operation",
            "authenticate-client-authorization-data-rights-and-external-budget",
            "authenticate-original-training-owner-and-all-attempts",
            "authenticate-prefrozen-independent-evaluation-and-decision",
            "prove-complete-version-custody-and-cold-retrieval",
            "authenticate-loaded-bytes-and-current-original-Hepta-FinalUse",
            "authenticate-independent-consumer-and-next-task-outcome",
            "reconcile-complete-physical-costs-benefit-and-original-financial-owners",
            "authenticate-failure-reorg-and-full-state-restore-reconciliation",
            "qualify-improvement-reward-separately-from-contract-service-fee",
            "prove-consensus-cost-relation-separately-from-useful-computation"],
        full_learning_iteration_completed=False, real_model_training_verified=False,
        independent_control_accepted=False, settlement_verified=False,
        hepta_final_use_accepted=False, authority="DENY_ALL", current_permission="NOT_EXPORTED",
        production_activation=False, qualification="HOLD_NO_GO")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--bindings-sha256", required=True)
    for name in MATERIAL_NAMES:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-task", type=Path, action="append", default=[])
    args = parser.parse_args()
    limits = dict(selection=iteration.MAX_CHECKPOINT, completed=iteration.MAX_CHECKPOINT,
                  readback=native.MAX_WIRE, freeze=iteration.MAX_FREEZE, expected=native.MAX_EXPECTED)
    result = review_business_iteration(
        {name: native.read_bounded(getattr(args, name), limit) for name, limit in limits.items()},
        bindings_raw=native.read_bounded(args.bindings, MAX_BINDINGS),
        expected_bindings_sha256=args.bindings_sha256,
        native_task_raws=[native.read_bounded(path, 256 * 1024) for path in args.native_task])
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
