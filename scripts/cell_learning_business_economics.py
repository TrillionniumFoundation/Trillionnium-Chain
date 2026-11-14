"""Review a pinned native paid-Task export without importing monetary authority.

The input is the original ``pon-native-task-operation-current-v3`` display
export. Its producer checks native owners; this JSON reader cannot authenticate
that producer or replay its native chain. Matching the export to separately
retained expectations establishes a structural relation only. Native development
ledger units are not evidence of an independent customer's external payment.

The existing native domains, payment owner and service/bonus adapter are
unchanged. No function here dispatches, pays, reobserves a live owner or grants
FinalUse. Historical and current payment observations are never summed.
"""
from __future__ import annotations

import hashlib

import cell_adoption_readback as native

EXPECTED_SCHEMA = "trnm-cell-learning-business-economics-expectations-v1"
REPORT_SCHEMA = "trnm-cell-learning-business-economics-review-v1"
NATIVE_SCHEMA = "pon-native-task-operation-current-v3"
LEDGER_PROFILE = "funded-service-contract-dev-v1"
MONETARY_UNIT = "native-development-ledger-unit"
MAX_REPORT = 32768
U64_MAX = (1 << 64) - 1

TERM_DIGESTS = (
    "request provider model input output_spec qualified_work evaluation_protocol "
    "fee_schedule dispute_policy arbitrator"
).split()
TERM_NUMBERS = "budget delivery_deadline dispute_deadline".split()
SERVICE_DIGESTS = (
    "claim task binding operation target_scope_commitment "
    "target_receipt_commitment output payer contract_digest "
    "original_delivery_operation payment_operation cost_unit cost_measurement_receipt"
).split()
OBSERVATION_FIELDS = (
    "declared_reconciliation_epoch retained_reconciliation_sequence "
    "retained_reconciliation_root m12_checkpoint observed_anchor"
)
FALSE_NATIVE_FIELDS = (
    "current_branch_payment_finality physical_costs_verified "
    "independent_customer_verified external_budget_origin_verified "
    "authenticated_target_authorization authenticated_target_receipt "
    "current_consumer_authorization_verified actual_consumer_use_verified "
    "atomic_external_final_use learning_improvement_bonus execution_authority "
    "authorizes_native_payment consensus_weight_eligible production_activation"
).split()
REPORT_FIELDS = (
    "schema scope claim task binding operation target_scope_commitment "
    "target_receipt_commitment declared_reconciliation_epoch "
    "retained_reconciliation_sequence retained_reconciliation_root m12_checkpoint "
    "observed_anchor original_full_contract native_status remaining_native_escrow "
    "output original_delivery_operation historical_delivery_anchor "
    "current_delivery_anchor historical_payment current_payment "
    "current_branch_delivery_membership current_branch_payment_membership "
    "declared_costs chainwork_awarded " + " ".join(FALSE_NATIVE_FIELDS)
)


def _hex(value, *, nonzero=True):
    value = native.hex_digest(value)
    native.require(not nonzero or value != "0" * 64, "ECONOMICS_ZERO_DIGEST")
    return value


def _native_hash(tag, *parts):
    """The existing trnm_protocol::pon_wire::hash; no new signed domain."""
    value = bytearray(b"TRNM-PON1\0")
    value.extend(len(tag).to_bytes(2, "little"))
    value.extend(tag)
    for part in parts:
        value.extend(len(part).to_bytes(4, "little"))
        value.extend(part)
    return hashlib.sha256(value).hexdigest()


def _terms(value, *, wire):
    native.fields(value, " ".join(TERM_DIGESTS + TERM_NUMBERS), "ECONOMICS_TERMS_FIELDS")
    result = {}
    for key in TERM_DIGESTS:
        result[key] = native.nonzero_native_digest(value[key]) if wire else _hex(value[key])
    for key in TERM_NUMBERS:
        result[key] = native.integer(value[key], minimum=1)
    native.require(result["dispute_deadline"] > result["delivery_deadline"] and
                   result["arbitrator"] != result["provider"], "ECONOMICS_TERMS")
    return result


def _contract_identities(terms, context, payer, nonce):
    encoded = b"".join(bytes.fromhex(terms[key]) for key in TERM_DIGESTS)
    encoded += b"".join(terms[key].to_bytes(8, "little") for key in TERM_NUMBERS)
    network, parameters, payer_bytes = (
        bytes.fromhex(context["network"]), bytes.fromhex(context["parameters"]),
        bytes.fromhex(payer))
    contract = _native_hash(b"funded-service-contract-v1", network, parameters, payer_bytes, encoded)
    task = _native_hash(b"funded-service-task-instance-v1", network, parameters,
                        payer_bytes, nonce.to_bytes(8, "little"), bytes.fromhex(contract))
    return contract, task


def _anchor(value, context):
    native.fields(value, "network parameters genesis block state_root height generation",
                  "ECONOMICS_ANCHOR_FIELDS")
    for key in ("network", "parameters", "genesis", "block", "state_root"):
        actual = native.nonzero_native_digest(value[key])
        if key in context:
            native.require(actual == context[key], "ECONOMICS_ANCHOR_CONTEXT")
    native.integer(value["height"])
    native.integer(value["generation"])
    return value


def _observation(value, context):
    native.fields(value, OBSERVATION_FIELDS, "ECONOMICS_OBSERVATION_FIELDS")
    native.integer(value["declared_reconciliation_epoch"])
    native.integer(value["retained_reconciliation_sequence"], minimum=1, maximum=128)
    _hex(value["retained_reconciliation_root"])
    checkpoint = value["m12_checkpoint"]
    native.fields(checkpoint, "max_records sequence root", "ECONOMICS_CHECKPOINT_FIELDS")
    native.integer(checkpoint["max_records"], minimum=1, maximum=65536)
    native.integer(checkpoint["sequence"], minimum=6,
                   maximum=checkpoint["max_records"] * 6)
    native.nonzero_native_digest(checkpoint["root"])
    _anchor(value["observed_anchor"], context)


def _expectations(expected):
    native.fields(expected, "schema ledger_profile monetary_unit decision context service observation",
                  "ECONOMICS_EXPECTED_FIELDS")
    native.require(expected["schema"] == EXPECTED_SCHEMA and
                   expected["ledger_profile"] == LEDGER_PROFILE and
                   expected["monetary_unit"] == MONETARY_UNIT and
                   expected["decision"] in ("NoUpdate", "Selection"), "ECONOMICS_EXPECTED_SCOPE")
    context = expected["context"]
    native.fields(context, "network parameters genesis", "ECONOMICS_CONTEXT_FIELDS")
    for value in context.values():
        _hex(value)
    service = expected["service"]
    native.fields(service, " ".join(SERVICE_DIGESTS) + " reservation_nonce terms",
                  "ECONOMICS_SERVICE_FIELDS")
    for key in SERVICE_DIGESTS:
        _hex(service[key])
    native.integer(service["reservation_nonce"], minimum=1)
    terms = _terms(service["terms"], wire=False)
    native.require(terms["arbitrator"] != service["payer"], "ECONOMICS_ARBITRATOR")
    contract, task = _contract_identities(terms, context, service["payer"],
                                        service["reservation_nonce"])
    native.require((contract, task) == (service["contract_digest"], service["task"]),
                   "ECONOMICS_EXPECTED_NATIVE_IDENTITIES")
    _observation(expected["observation"], context)
    return context, service, terms


def _record(value, context, service, terms, anchor):
    native.fields(value, "schema network parameters payer reservation_nonce contract_digest terms "
                  "reserved_at receipt_height delivered_output resolution", "ECONOMICS_CONTRACT_FIELDS")
    native.require(value["schema"] == "funded-service-task-record-v1", "ECONOMICS_CONTRACT_SCHEMA")
    for key in ("network", "parameters"):
        native.require(native.nonzero_native_digest(value[key]) == context[key],
                       "ECONOMICS_CONTRACT_CONTEXT")
    payer = native.nonzero_native_digest(value["payer"])
    nonce = native.integer(value["reservation_nonce"], minimum=1)
    actual_terms = _terms(value["terms"], wire=True)
    native.require(payer == service["payer"] and nonce == service["reservation_nonce"] and
                   actual_terms == terms, "ECONOMICS_FROZEN_CONTRACT")
    contract, task = _contract_identities(actual_terms, context, payer, nonce)
    native.require(native.nonzero_native_digest(value["contract_digest"]) == contract ==
                   service["contract_digest"] and task == service["task"],
                   "ECONOMICS_NATIVE_IDENTITIES")
    native.integer(value["reserved_at"])
    native.integer(value["receipt_height"])
    native.require(value["reserved_at"] < terms["delivery_deadline"] and
                   value["reserved_at"] <= value["receipt_height"] <= terms["delivery_deadline"] and
                   native.nonzero_native_digest(value["delivered_output"]) == service["output"],
                   "ECONOMICS_DELIVERY")
    resolution = value["resolution"]
    native.fields(resolution, "kind actor nonce height evidence", "ECONOMICS_RESOLUTION_FIELDS")
    native.integer(resolution["nonce"], minimum=1)
    native.integer(resolution["height"])
    native.require(value["receipt_height"] <= resolution["height"] < terms["dispute_deadline"] and
                   resolution["height"] <= anchor["height"], "ECONOMICS_RESOLUTION_HEIGHT")
    actor = native.nonzero_native_digest(resolution["actor"])
    if resolution["kind"] == "customer_accepted":
        native.require(actor == payer and resolution["evidence"] is None,
                       "ECONOMICS_CUSTOMER_RESOLUTION")
    elif resolution["kind"] == "arbitrator_paid":
        native.require(actor == terms["arbitrator"], "ECONOMICS_ARBITRATOR_RESOLUTION")
        native.nonzero_native_digest(resolution["evidence"])
    else:
        native.require(False, "ECONOMICS_PAID_RESOLUTION_REQUIRED")


def _payment(value, context, service, terms):
    native.fields(value, "anchor source subject beneficiary operation gross_escrow_debit beneficiary_credit",
                  "ECONOMICS_PAYMENT_FIELDS")
    _anchor(value["anchor"], context)
    for key in ("subject", "beneficiary", "operation"):
        _hex(value[key])
    native.integer(value["gross_escrow_debit"], minimum=1)
    native.integer(value["beneficiary_credit"], minimum=1)
    native.require(value["source"] == "task:" + service["task"] and
                   value["subject"] == service["output"] and
                   value["beneficiary"] == terms["provider"] and
                   value["operation"] == service["payment_operation"] and
                   value["gross_escrow_debit"] == value["beneficiary_credit"] == terms["budget"],
                   "ECONOMICS_PAYMENT_BINDING")


def _empty(expected_available, decision=None):
    return dict(
        schema=REPORT_SCHEMA, scope="pinned-native-development-payment-statements-only",
        status="UNKNOWN", expected_contract_available=expected_available,
        native_report_sha256=None, native_report_bindings_consistent=False,
        native_contract_digest_recomputed=False, native_task_id_recomputed=False,
        ledger_profile=LEDGER_PROFILE, monetary_unit=MONETARY_UNIT, learning_decision=decision,
        service_fee=dict(observation="MISSING", historical=None, current=None,
                         authorized_units_by_this_reader=0, actual_external_payment_units=None),
        improvement_reward=dict(observed_external_units=None, authorized_units_by_this_reader=0,
                                no_update_bonus_permitted=False if decision == "NoUpdate" else None),
        consensus_credit=dict(observed_external_units=None, awarded_units_by_this_reader=0,
                              native_report_declared_chainwork=None),
        declared_costs=None, declared_cost_total_units=None,
        authority="DENY_ALL", current_permission="NOT_EXPORTED",
        native_origin_authenticated=False, native_payment_signatures_verified=False,
        native_transition_replayed_by_this_reader=False, current_branch_membership_authenticated=False,
        real_customer_payment_verified=False, independent_customer_verified=False,
        external_budget_origin_verified=False, cost_completeness_verified=False,
        physical_costs_verified=False, independent_evaluation_verified=False,
        journal_prefix_verified_by_this_reader=False, common_restore_protection_verified=False,
        settlement_verified=False, hepta_final_use_accepted=False,
        authorizes_native_payment=False, execution_dispatch_authorized=False,
        production_activation=False, qualification="HOLD_NO_GO")


def review_native_economics(raw: bytes | None, *, expected_sha256: str | None,
                            expected: dict | None) -> dict:
    """Check exact native statements; absent payment observations stay unknown.

    ``expected`` is independently retained mapping/observation material, never
    generated here from the submitted export. Upper layers bind its exact bytes
    to the learning operation, complete version and source pair. A higher native
    generation is not itself a proof of chain ancestry or recovery continuity.
    """
    if expected is None:
        native.require(raw is None and expected_sha256 is None, "ECONOMICS_EXPECTATIONS_REQUIRED")
        return _empty(False)
    context, service, terms = _expectations(expected)
    result = _empty(True, expected["decision"])
    if raw is None:
        native.require(expected_sha256 is None, "ECONOMICS_MISSING_PINNED_REPORT")
        return result
    native.require(type(raw) is bytes and len(raw) <= MAX_REPORT, "ECONOMICS_REPORT_LIMIT")
    native.require(native.sha(raw) == _hex(expected_sha256), "ECONOMICS_REPORT_PIN")
    report = native.decode(raw, MAX_REPORT)
    native.fields(report, REPORT_FIELDS, "ECONOMICS_REPORT_FIELDS")
    native.require(report["schema"] == NATIVE_SCHEMA and
                   report["scope"] == "CURRENT_PAID_NATIVE_TASK_OBSERVATION" and
                   report["native_status"] == "settled", "ECONOMICS_REPORT_SCOPE")
    for key in FALSE_NATIVE_FIELDS:
        native.require(report[key] is False, "ECONOMICS_NATIVE_SCOPE_ESCALATION")
    for key in ("current_branch_delivery_membership", "current_branch_payment_membership"):
        native.require(report[key] is True, "ECONOMICS_NATIVE_MEMBERSHIP_STATEMENT")
    native.integer(report["chainwork_awarded"], maximum=0)
    native.integer(report["remaining_native_escrow"], maximum=0)
    for key in SERVICE_DIGESTS:
        if key not in ("payer", "contract_digest", "payment_operation", "cost_unit",
                       "cost_measurement_receipt"):
            native.require(_hex(report[key]) == service[key], "ECONOMICS_OPERATION_BINDING")
    observation = {key: report[key] for key in OBSERVATION_FIELDS.split()}
    _observation(observation, context)
    native.require(observation == expected["observation"], "ECONOMICS_OBSERVATION_BINDING")
    anchor = report["observed_anchor"]
    _record(report["original_full_contract"], context, service, terms, anchor)

    historical, current = report["historical_payment"], report["current_payment"]
    _payment(historical, context, service, terms)
    _payment(current, context, service, terms)
    identity_fields = "source subject beneficiary operation gross_escrow_debit beneficiary_credit".split()
    native.require(all(historical[key] == current[key] for key in identity_fields),
                   "ECONOMICS_PAYMENT_CONTINUITY")
    native.require(current["anchor"] == anchor and
                   historical["anchor"]["generation"] <= anchor["generation"] and
                   (historical["anchor"]["generation"] != anchor["generation"] or
                    historical["anchor"] == anchor), "ECONOMICS_PAYMENT_ANCHOR")
    old_delivery = _anchor(report["historical_delivery_anchor"], context)
    current_delivery = _anchor(report["current_delivery_anchor"], context)
    native.require(old_delivery["height"] <= historical["anchor"]["height"] and
                   old_delivery["generation"] <= historical["anchor"]["generation"] and
                   current_delivery["height"] == report["original_full_contract"]["receipt_height"] and
                   current_delivery["height"] <= anchor["height"] and
                   current_delivery["generation"] == anchor["generation"] and
                   (current_delivery["height"] != anchor["height"] or current_delivery == anchor),
                   "ECONOMICS_DELIVERY_ANCHOR")

    costs = report["declared_costs"]
    native.fields(costs, "outcome training_units evaluation_units storage_units serving_units "
                  "unit measurement_receipt", "ECONOMICS_COST_FIELDS")
    native.require(costs["outcome"] in ("Positive", "NoGain"), "ECONOMICS_PAID_OUTCOME")
    for key in ("unit", "measurement_receipt"):
        _hex(costs[key])
    native.require(costs["unit"] == service["cost_unit"] and
                   costs["measurement_receipt"] == service["cost_measurement_receipt"],
                   "ECONOMICS_COST_BINDING")
    total = sum(native.integer(costs[key]) for key in
                ("training_units", "evaluation_units", "storage_units", "serving_units"))
    native.integer(total)
    result.update(status="STRUCTURALLY_CONSISTENT_UNAUTHENTICATED",
                  native_report_sha256=expected_sha256, native_report_bindings_consistent=True,
                  native_contract_digest_recomputed=True, native_task_id_recomputed=True,
                  declared_costs=dict(costs), declared_cost_total_units=total)
    result["service_fee"].update(observation="DECLARED_NATIVE_CURRENT_AND_HISTORICAL",
                                  historical=dict(historical), current=dict(current))
    result["consensus_credit"]["native_report_declared_chainwork"] = report["chainwork_awarded"]
    return result
