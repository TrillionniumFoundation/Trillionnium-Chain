#!/usr/bin/env python3
"""Read-only projection of eight system-security blockers; never grants GO.

The existing Chain/Hepta reviewer owns plan, source-pair, record, stage and
effect binding checks. This module calls it, retains its complete report and
adds schema-specific negative facts. It does not run a theory program, native
campaign, signature verifier, acceptance validator or external effect.

Optional inputs have schema trnm-chain-system-security-inputs-v1 and artifacts:
[{id, source_commit, source_tree, source_url, evidence: {path, sha256}}].
source_commit/tree describe the claimed executed/source identity, not the
commit which later archived the evidence. They may be null. URLs are provenance
text, never fetched or authenticated. A matching declared identity is only
SAME_DECLARED_SOURCE_UNAUTHENTICATED. Any different declared or embedded source
stays historical, including a different commit with the same tree. Every
artifact has same_source_acceptance=false, even when all declarations agree.

Only the listed schemas are projected. Types, missing/duplicate cost points and
inconsistent campaign denominators get explicit diagnostics. These are checks
of supplied declarations and arithmetic, not validation of actual execution.
True qualification flags remain DECLARED_UNVERIFIED; missing evidence never
becomes false measured work or zero cost. All eight blockers remain open.

CLI uses the existing --plan/--plan-sha256/--packet/--evidence-root arguments,
plus optional --security-inputs. Exit 2 is a valid HOLD report; exit 1 means
malformed/unreadable input. No exit or result grants production authority.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import chain_hepta_qualification as qualification


INPUT_SCHEMA = "trnm-chain-system-security-inputs-v1"
REPORT_SCHEMA = "trnm-chain-system-security-review-v1"
MAX_ARTIFACTS = 128
EXPECTED_COST_POINTS = {(kind, units) for kind in ("classical", "quantum")
                        for units in range(1, 9)}
MATRIX = {
    "P0_WORK_COST_CREDIT": dict(
        priority="P0", boundary="work cost and consensus credit",
        obligations=("w1_minimum_cost", "quantum_work_daa_weight"), stages=(),
        kinds=("fixed_probability_cost",),
        unverified=("ALL_LEGAL_STRATEGY_COST_BOUND_UNVERIFIED", "NATIVE_CREDIT_CALIBRATION_UNVERIFIED")),
    "P0_TIME_DIFFICULTY_FORK_PROGRESS": dict(
        priority="P0", boundary="time, difficulty, forks and progress",
        obligations=("timestamp_daa_chainweight", "quantum_work_daa_weight"), stages=(),
        kinds=("joint_daa",),
        unverified=("JOINT_COMMON_PREFIX_CHAIN_GROWTH_CHAIN_QUALITY_UNVERIFIED",
                    "PARTICIPATION_DELAY_AND_CLOCK_MAPPING_UNVERIFIED")),
    "P0_VERIFICATION_COST_HONEST_SERVICE": dict(
        priority="P0", boundary="verification cost and honest service",
        obligations=("hostile_honest_confirmation", "cost_decomposition", "matched_confirmation_tail_latency"),
        stages=(), kinds=("original_campaign", "local_resource_owner"),
        unverified=("ORIGINAL_HOST_HONEST_SERVICE_UNVERIFIED", "ALL_ENTRY_PHYSICAL_COST_COVERAGE_UNVERIFIED")),
    "P0_MODEL_EVALUATION_POISONING": dict(
        priority="P0", boundary="model evaluation and poisoning",
        obligations=("same_iteration", "no_update"), stages=("training", "evaluation", "selection"), kinds=(),
        unverified=("INDEPENDENT_EVALUATION_AND_FUTURE_DATA_UNVERIFIED", "MATCHED_STRONG_CONTROLS_UNVERIFIED")),
    "P0_AUTHORIZATION_EXTERNAL_EFFECTS": dict(
        priority="P0", boundary="authorization through real external effects",
        obligations=("entry_to_effect", "current_revocation_load", "recovery_effects",
                     "unknown_timeout", "revocation", "restart", "reorg"),
        stages=("payment", "load", "next_task"), kinds=(),
        unverified=("ORIGINAL_OWNER_FINAL_USE_AND_EFFECT_RECONCILIATION_UNVERIFIED",)),
    "P0_WHOLE_STATE_ROLLBACK": dict(
        priority="P0", boundary="all retained authority restored to old state",
        obligations=("recovery_effects", "rollback_external_effects"), stages=(),
        kinds=("local_resource_owner",),
        unverified=("SURVIVING_NEWER_INDEPENDENT_FACT_UNVERIFIED", "WHOLE_STATE_RECOVERY_QUALIFICATION_UNVERIFIED")),
    "P1_STORAGE_COMMON_FAILURE": dict(
        priority="P1", boundary="storage availability and common failure",
        obligations=("dependency_closure", "independent_custody_wan", "renewal_repair_recovery", "content_commitment"),
        stages=("cold_fetch", "installation"), kinds=(),
        unverified=("INDEPENDENT_OPERATOR_ADMIN_BACKUP_NETWORK_POWER_RECOVERY_UNVERIFIED",
                    "COMPLETE_VERSION_RENEWAL_AND_WAN_REPAIR_UNVERIFIED")),
    "P1_SAME_SOURCE_INTEGRATION": dict(
        priority="P1", boundary="complete acceptance on one integrated source",
        obligations=("source_locks", "build_load", "native_registry"), stages=(), kinds=(),
        unverified=("SAME_SOURCE_COMPLETE_NATIVE_ACCEPTANCE_UNVERIFIED",)),
}


def integer_field(value, name, diagnostics, *, prefix="", minimum=0):
    label = prefix + name
    if name not in value:
        diagnostics.append("MISSING_FIELD:" + label)
        return None
    observed = value[name]
    if type(observed) is not int or not minimum <= observed <= 2**63 - 1:
        diagnostics.append("INVALID_INTEGER:" + label)
        return None
    return observed


def indicators(value, expected, diagnostics, blockers, prefix=""):
    """Report literal declarations. Agreement never authenticates a claim."""
    result = {}
    for name, wanted in expected.items():
        present = name in value
        observed = value.get(name)
        if not present:
            status = "NOT_REPORTED"
            diagnostics.append("MISSING_FIELD:" + prefix + name)
        elif type(observed) is not bool:
            status = "INVALID_DECLARATION"
            diagnostics.append("INVALID_BOOLEAN:" + prefix + name)
        elif observed is wanted:
            status = "DECLARED_UNVERIFIED"
        else:
            status = "NOT_ESTABLISHED"
        blockers.append("DECLARATION_NOT_VERIFIED:" + prefix + name)
        result[name] = dict(expected=wanted, present=present,
                            observed=observed if type(observed) is bool else None,
                            observed_type=type(observed).__name__ if present else "missing",
                            declaration_status=status)
    return result


def cost_projection(value):
    diagnostics, blockers, points, rows = [], [], [], []
    audit = value["schema"] == "pon-fixed-probability-cost-audit-result-v1"
    if audit:
        supplied = value.get("unknown_cost_points")
        if type(supplied) is not list or len(supplied) > qualification.MAX_RECORDS:
            diagnostics.append("INVALID_COST_GRID:unknown_cost_points")
            supplied = []
        groups = [(None, supplied)]
    else:
        envelope = value.get("cost_envelopes")
        if type(envelope) is not dict or set(envelope) != {"classical", "quantum"}:
            diagnostics.append("INVALID_COST_CLASSES")
            envelope = envelope if type(envelope) is dict else {}
        groups = [(kind, envelope.get(kind)) for kind in ("classical", "quantum")]
    for kind, supplied in groups:
        if type(supplied) is not list or len(supplied) > qualification.MAX_RECORDS:
            diagnostics.append("INVALID_COST_GRID:" + str(kind))
            continue
        for index, row in enumerate(supplied):
            expected = {"class", "units"} if audit else {"units", "lower", "upper", "status"}
            if type(row) is not dict or set(row) != expected:
                diagnostics.append("COST_ROW_FIELDS:" + str(kind) + ":" + str(index))
                continue
            category = row["class"] if audit else kind
            units = row["units"]
            if type(category) is not str or category not in ("classical", "quantum") or type(units) is not int or not 1 <= units <= 8:
                diagnostics.append("COST_POINT_IDENTITY:" + str(index))
                continue
            points.append((category, units))
            observed = dict(category=category, units=units)
            if not audit:
                observed.update(lower=copy.deepcopy(row["lower"]), upper=copy.deepcopy(row["upper"]),
                                status=copy.deepcopy(row["status"]))
                if row["lower"] is not None or row["upper"] is not None or row["status"] != "unproved":
                    diagnostics.append("UNSUPPORTED_V1_COST_CERTIFICATE:" + category + ":" + str(units))
            rows.append(observed)
    missing = sorted(EXPECTED_COST_POINTS - set(points))
    duplicate = sorted({point for point in points if points.count(point) > 1})
    if missing:
        diagnostics.append("COST_GRID_MISSING_POINTS")
    if duplicate:
        diagnostics.append("COST_GRID_DUPLICATE_POINTS")
    obligations = value.get("unclosed_obligations")
    if type(obligations) is not list or len(obligations) > qualification.MAX_RECORDS or any(type(item) is not str for item in obligations):
        diagnostics.append("INVALID_UNCLOSED_OBLIGATIONS")
        obligations = None
    elif not obligations:
        diagnostics.append("EMPTY_V1_UNCLOSED_OBLIGATIONS")
    elif len(obligations) != len(set(obligations)):
        diagnostics.append("DUPLICATE_UNCLOSED_OBLIGATION")
    blockers.extend(("ACTUAL_ALL_LEGAL_COST_BOUND_UNVERIFIED", "INITIAL_POTENTIAL_AND_CREDIT_BRIDGE_UNVERIFIED"))
    facts = dict(expected_cost_points=16, observed_cost_rows=rows,
                 unknown_cost_point_count=sum(audit or row["lower"] is None or row["upper"] is None for row in rows),
                 missing_cost_points=[dict(category=k, units=u) for k, u in missing],
                 duplicate_cost_points=[dict(category=k, units=u) for k, u in duplicate],
                 unclosed_obligations=copy.deepcopy(obligations), cost_bound_verified=False)
    if audit:
        facts["binding_validation_declaration"] = copy.deepcopy(value.get("binding_validation"))
        facts["qualification_declaration"] = copy.deepcopy(value.get("qualification"))
        facts["source_binding_scope_declaration"] = copy.deepcopy(value.get("source_binding_scope"))
        facts["indicators"] = indicators(value, {"full_execution_identity_verified": True,
            "finite_model_certificate_is_actual_w1_lower_bound": True, "production_activation": False}, diagnostics, blockers)
    else:
        accounting, relation = value.get("accounting"), value.get("relation")
        if type(accounting) is not dict or "initial_potential_bound" not in accounting:
            diagnostics.append("MISSING_INITIAL_POTENTIAL_BOUND_FIELD")
        if type(relation) is not dict:
            diagnostics.append("INVALID_RELATION_FIELDS")
        facts["initial_potential_bound_declaration"] = copy.deepcopy(accounting.get("initial_potential_bound")) if type(accounting) is dict else None
        facts["ideal_probability_declaration"] = copy.deepcopy(relation.get("ideal_probability")) if type(relation) is dict else None
        facts["native_credit_indicator"] = indicators(relation if type(relation) is dict else {},
            {"native_consensus_credit": True}, diagnostics, blockers, "relation.")
    probability = value.get("ideal_probability") if audit else facts["ideal_probability_declaration"]
    if type(probability) is not dict or set(probability) != {"numerator", "denominator"} or any(type(probability.get(key)) is not int for key in ("numerator", "denominator")):
        diagnostics.append("INVALID_FIXED_PROBABILITY")
    elif probability != {"numerator": 1, "denominator": 16}:
        diagnostics.append("FIXED_PROBABILITY_CONTEXT_MISMATCH")
    return "fixed_probability_cost", facts, diagnostics, blockers, None


def daa_projection(value):
    diagnostics, blockers = [], ["JOINT_NETWORK_SECURITY_THEOREM_UNVERIFIED"]
    limits = value.get("limitations")
    if type(limits) is not dict:
        diagnostics.append("INVALID_DAA_LIMITATIONS")
        limits = {}
    flags = indicators(limits, {
        "uniform_iid_ticket_premise_proved_for_w1": True,
        "w1_oracle_cost_measured_or_synthesized": True,
        "native_node_activation_executed": True,
        "network_profitability_or_consensus_safety_theorem": True,
        "proof_latency_propagation_availability_and_reorg_state_priced": True,
        "production_consensus_activation": False}, diagnostics, blockers, "limitations.")
    facts = dict(scope_declaration=copy.deepcopy(value.get("scope")), indicators=flags,
                 native_w1_proofs_declared=integer_field(limits, "native_w1_proofs_generated", diagnostics),
                 security_theorem_verified=False)
    return "joint_daa", facts, diagnostics, blockers, None


def daa_extract_projection(value):
    """An explicitly partial copy never impersonates the original DAA report."""
    kind, facts, diagnostics, blockers, embedded = daa_projection(value)
    if set(value) != {"schema", "source_schema", "original_sha256", "extraction", "limitations"}:
        diagnostics.append("DAA_EXTRACT_FIELDS")
    if value.get("source_schema") != "trnm-joint-consensus-boundaries-v1":
        diagnostics.append("DAA_EXTRACT_SOURCE_SCHEMA")
    if value.get("extraction") != "limitations-only":
        diagnostics.append("DAA_EXTRACT_SCOPE")
    try:
        qualification.digest(value.get("original_sha256"))
    except qualification.Refusal:
        diagnostics.append("DAA_EXTRACT_ORIGINAL_DIGEST")
    facts.update(extraction="limitations-only", original_schema_declaration=value.get("source_schema"),
                 original_sha256_declaration=value.get("original_sha256"), original_report_authenticated=False,
                 original_report_replayed=False, extraction_completeness_verified=False)
    blockers.append("EXTRACTED_FIELDS_NOT_FULL_ORIGINAL")
    return kind, facts, diagnostics, blockers, embedded


def campaign_projection(value):
    diagnostics, blockers = [], ["ORIGINAL_ACCEPTANCE_VALIDATOR_NOT_EXECUTED", "NATIVE_CAMPAIGN_NOT_AUTHENTICATED"]
    names = ("complete_campaigns", "actual_campaigns", "planned_campaigns")
    counts = {name: integer_field(value, name, diagnostics) for name in names}
    if all(number is not None for number in counts.values()):
        if not counts["complete_campaigns"] <= counts["actual_campaigns"] <= counts["planned_campaigns"]:
            diagnostics.append("CAMPAIGN_COUNTS_INCONSISTENT")
        if counts["planned_campaigns"] != 3:
            diagnostics.append("ORIGINAL_CAMPAIGN_COUNT_CHANGED")
        if counts["complete_campaigns"] != counts["planned_campaigns"]:
            blockers.append("REPORTED_CAMPAIGN_ACCEPTANCE_INCOMPLETE")
    total_names = ("scheduled_confirmation_rounds", "observed_confirmation_rounds", "confirmed_rounds", "unobserved_scheduled_rounds")
    total = value.get("totals")
    if type(total) is not dict:
        diagnostics.append("INVALID_CAMPAIGN_TOTALS")
        total = {}
    totals = {name: integer_field(total, name, diagnostics, prefix="totals.") for name in total_names}
    phases = value.get("phases")
    if type(phases) is not list or len(phases) > qualification.MAX_RECORDS:
        diagnostics.append("INVALID_CAMPAIGN_PHASES")
        phases = []
    projected, seen = [], set()
    expected_phases = {(run, mode) for run in range(1, 4) for mode in ("baseline", "from-zero", "late-product")}
    phase_sum = dict.fromkeys(total_names, 0)
    complete_totals = True
    for index, phase in enumerate(phases):
        if type(phase) is not dict:
            diagnostics.append("INVALID_CAMPAIGN_PHASE:" + str(index))
            complete_totals = False
            continue
        run = integer_field(phase, "run", diagnostics, minimum=1)
        mode = phase.get("mode")
        if type(mode) is not str or mode not in ("baseline", "from-zero", "late-product"):
            diagnostics.append("INVALID_CAMPAIGN_MODE:" + str(index))
            mode = None
        key = (run, mode)
        if key in seen:
            diagnostics.append("DUPLICATE_CAMPAIGN_PHASE:" + str(index))
        seen.add(key)
        numbers = {name: integer_field(phase, name, diagnostics, prefix="phase." + str(index) + ".") for name in total_names}
        if all(number is not None for number in numbers.values()):
            scheduled, observed, confirmed, unobserved = (numbers[name] for name in total_names)
            if scheduled != 3:
                diagnostics.append("ORIGINAL_PHASE_CONFIRMATION_COUNT_CHANGED:" + str(index))
            if not confirmed <= observed <= scheduled or unobserved != scheduled - observed:
                diagnostics.append("CAMPAIGN_PHASE_DENOMINATOR_INCONSISTENT:" + str(index))
            for name in total_names:
                phase_sum[name] += numbers[name]
        else:
            complete_totals = False
        projected.append(dict(run=run, mode=mode, **numbers))
    if all(number is not None for number in totals.values()):
        scheduled, observed, confirmed, unobserved = (totals[name] for name in total_names)
        if counts["planned_campaigns"] == 3 and scheduled != 27:
            diagnostics.append("ORIGINAL_CAMPAIGN_CONFIRMATION_COUNT_CHANGED")
        if not confirmed <= observed <= scheduled or unobserved != scheduled - observed:
            diagnostics.append("CAMPAIGN_TOTAL_DENOMINATOR_INCONSISTENT")
        if complete_totals and seen == expected_phases and totals != phase_sum:
            diagnostics.append("CAMPAIGN_TOTALS_DO_NOT_MATCH_PHASES")
        elif complete_totals and any(phase_sum[name] > totals[name] for name in total_names):
            diagnostics.append("OBSERVED_PHASE_COUNTS_EXCEED_CAMPAIGN_TOTALS")
        if unobserved:
            blockers.append("UNOBSERVED_CONFIRMATION_ROUNDS_RETAINED")
        if confirmed != scheduled:
            blockers.append("REPORTED_CONFIRMATION_TARGET_INCOMPLETE")
    planned = counts["planned_campaigns"]
    missing_phases = sorted(expected_phases - seen) if planned == 3 else []
    if missing_phases:
        blockers.append("MISSING_ORIGINAL_CAMPAIGN_PHASES")
    if seen - expected_phases:
        diagnostics.append("UNEXPECTED_CAMPAIGN_PHASE")
    valid_runs = {run for run, mode in seen if type(run) is int and mode is not None}
    if counts["actual_campaigns"] is not None:
        if len(valid_runs) < counts["actual_campaigns"]:
            blockers.append("ATTEMPT_PHASE_COVERAGE_INCOMPLETE")
        elif len(valid_runs) > counts["actual_campaigns"]:
            diagnostics.append("PHASE_RUNS_EXCEED_ACTUAL_CAMPAIGNS")
    placement = value.get("measured_public_phase_placement")
    if type(placement) is not dict:
        diagnostics.append("MISSING_PUBLIC_PHASE_RESOURCE_DECLARATION")
    else:
        for name, expected in (("profile", "fixed-public-phase-external-actors-v1"),
                               ("receiver_and_verifier_cpu_max", "25000 100000"),
                               ("receiver_and_verifier_memory_max", "2147483648")):
            if placement.get(name) != expected:
                diagnostics.append("ORIGINAL_PUBLIC_PHASE_RESOURCE_CHANGED:" + name)
    flags = indicators(value, {"all_reports_valid": True}, diagnostics, blockers)
    finalization = value.get("finalization_failures")
    if "finalization_failures" in value and type(finalization) is not list:
        diagnostics.append("INVALID_FINALIZATION_FAILURES")
    if finalization:
        blockers.append("REPORTED_FINALIZATION_FAILURES_RETAINED")
    if value.get("failure") is not None:
        blockers.append("REPORTED_ORIGINAL_CAMPAIGN_FAILURE")
    facts = dict(**counts, totals=totals, phase_totals=phase_sum if complete_totals else None,
                 phase_coverage_complete=complete_totals and seen == expected_phases,
                 phases=projected, missing_original_phases=[dict(run=r, mode=m) for r, m in missing_phases],
                 build_returncode=integer_field(value, "build_returncode", diagnostics, minimum=-255),
                 failure_declaration=copy.deepcopy(value.get("failure")),
                 finalization_failures_declaration=copy.deepcopy(finalization), indicators=flags,
                 public_phase_placement_declaration=copy.deepcopy(value.get("measured_public_phase_placement")),
                 controller_resources_declaration=copy.deepcopy(value.get("controller_resources")),
                 acceptance_verified=False, unobserved_cost=None)
    return "original_campaign", facts, diagnostics, blockers, {"sha": value.get("source"), "tree": value.get("tree")}


def resource_projection(value):
    diagnostics, blockers = [], ["ALL_ENTRY_RESOURCE_BOUND_AND_HONEST_SERVICE_UNVERIFIED"]
    flags = indicators(value, {"observer_actual_cpu_measured": True, "observer_actual_io_measured": True,
        "whole_entry_coverage_qualified": True, "physical_resource_bound_qualified": True,
        "honest_service_bound_qualified": True, "independent_rollback_anchor_qualified": True,
        "production_activation": False}, diagnostics, blockers)
    return "local_resource_owner", dict(status_declaration=copy.deepcopy(value.get("status")),
        native_integration_declaration=copy.deepcopy(value.get("native_integration")), indicators=flags,
        physical_cost_bound_verified=False), diagnostics, blockers, None


ADAPTERS = {
    "pon-fixed-probability-cost-contract-v1": cost_projection,
    "pon-fixed-probability-cost-audit-result-v1": cost_projection,
    "trnm-joint-consensus-boundaries-v1": daa_projection,
    "trnm-joint-consensus-limitations-extract-v1": daa_extract_projection,
    "pon-root-original-campaign-crosscheck-v1": campaign_projection,
    "trnm-local-resource-owner-contract-v1": resource_projection,
}


def source_classification(descriptor, embedded, expected, diagnostics):
    declared = dict(sha=descriptor["source_commit"], tree=descriptor["source_tree"])
    sources = [declared]
    if embedded is not None:
        for name in ("sha", "tree"):
            try:
                qualification.digest(embedded[name], 40)
            except qualification.Refusal:
                diagnostics.append("INVALID_EMBEDDED_SOURCE:" + name)
        sources.append(embedded)
        if any(declared[name] is not None and declared[name] != embedded[name] for name in ("sha", "tree")):
            diagnostics.append("DECLARED_EMBEDDED_SOURCE_MISMATCH")
    different = any(source[name] is not None and source[name] != expected[name]
                    for source in sources for name in ("sha", "tree"))
    complete = any(all(source[name] is not None for name in ("sha", "tree")) for source in sources)
    state = ("HISTORICAL_SOURCE" if different else
             "SAME_DECLARED_SOURCE_UNAUTHENTICATED" if complete else "SOURCE_UNOBSERVED_OR_INCOMPLETE")
    return dict(classification=state, declared=declared, embedded=copy.deepcopy(embedded),
                source_verified=False, same_source_acceptance=False)


def review_artifact(descriptor, root, remaining, expected_source):
    diagnostics, blockers = [], []
    kind, facts, embedded, schema = None, {}, None, None
    try:
        raw = qualification.evidence_hash(root, descriptor["evidence"], remaining)
        value = qualification.decode(raw)
        if type(value) is not dict:
            diagnostics.append("SECURITY_ARTIFACT_NOT_OBJECT")
        else:
            schema = value.get("schema")
            if type(schema) is not str:
                diagnostics.append("INVALID_SECURITY_ARTIFACT_SCHEMA")
            elif schema not in ADAPTERS:
                blockers.append("UNSUPPORTED_SECURITY_ARTIFACT_SCHEMA")
            else:
                kind, facts, diagnostics, blockers, embedded = ADAPTERS[schema](value)
    except (OSError, qualification.Refusal) as error:
        diagnostics.append(str(error))
    source = source_classification(descriptor, embedded, expected_source, diagnostics)
    blockers.append("SOURCE_AND_ORIGINAL_EVIDENCE_UNAUTHENTICATED")
    if source["classification"] == "HISTORICAL_SOURCE":
        blockers.append("HISTORICAL_EVIDENCE_NOT_CURRENT_ACCEPTANCE")
    return dict(id=descriptor["id"], kind=kind, reported_schema=schema, evidence=copy.deepcopy(descriptor["evidence"]),
                source_url=descriptor["source_url"], source=source, facts=facts,
                input_diagnostics=sorted(set(diagnostics)), blockers=sorted(set(blockers)),
                projection_status="INPUT_REFUSED" if diagnostics else "UNSUPPORTED" if kind is None else "DECLARATIONS_PROJECTED",
                qualification="HOLD_NO_GO", qualified=False, original_evidence_authenticated=False,
                native_outcome_verified=False, same_source_acceptance=False)


def review(plan_raw, expected_plan_sha256, packet_raw, evidence_root, security_inputs_raw=None):
    original = qualification.review(plan_raw, expected_plan_sha256, packet_raw, evidence_root)
    stages = qualification.stage_qualification_gaps(original)
    plan = qualification.decode(plan_raw)
    if security_inputs_raw is None:
        security_inputs_raw = qualification.canonical(dict(schema=INPUT_SCHEMA, artifacts=[]))
    inputs = qualification.decode(security_inputs_raw)
    qualification.fields(inputs, "schema artifacts", "SYSTEM_SECURITY_INPUT_FIELDS")
    qualification.require(inputs["schema"] == INPUT_SCHEMA, "SYSTEM_SECURITY_INPUT_SCHEMA")
    qualification.sequence(inputs["artifacts"], MAX_ARTIFACTS)
    seen_ids, seen_paths = set(), set()
    for item in inputs["artifacts"]:
        qualification.fields(item, "id source_commit source_tree source_url evidence", "SECURITY_ARTIFACT_FIELDS")
        qualification.label(item["id"])
        qualification.digest(item["source_commit"], 40, nullable=True)
        qualification.digest(item["source_tree"], 40, nullable=True)
        qualification.require(type(item["source_url"]) is str and len(item["source_url"]) <= 2048 and
                              item["source_url"].startswith("https://github.com/TrillionniumFoundation/") and
                              not any(c in item["source_url"] for c in "\r\n\x00"), "SECURITY_PROVENANCE_URL")
        qualification.fields(item["evidence"], "path sha256", "SECURITY_EVIDENCE_FIELDS")
        qualification.relative_path(item["evidence"]["path"])
        qualification.digest(item["evidence"]["sha256"])
        qualification.require(item["id"] not in seen_ids, "DUPLICATE_SECURITY_ARTIFACT_ID")
        qualification.require(item["evidence"]["path"] not in seen_paths, "DUPLICATE_SECURITY_EVIDENCE_PATH")
        seen_ids.add(item["id"]); seen_paths.add(item["evidence"]["path"])
    remaining = [128 * 1024 * 1024]
    artifacts = [review_artifact(item, evidence_root, remaining, original["source_pair"]["chain"])
                 for item in inputs["artifacts"]]
    matrix = {}
    for name, spec in MATRIX.items():
        blockers = list(spec["unverified"])
        records = [row for row in original["records"] if row["record"]["obligation"] in spec["obligations"]]
        for obligation in spec["obligations"]:
            cases = plan["cases"][obligation]
            if not cases:
                blockers.append("UNCONFIGURED_CASE_ROSTER:" + obligation)
            for case in cases:
                if not any(row["record"]["obligation"] == obligation and row["record"]["case_id"] == case for row in records):
                    blockers.append("MISSING_CASE:" + obligation + ":" + case)
        for row in records:
            blockers.extend(row["record"]["id"] + ":" + issue for issue in row["issues"])
        for stage in spec["stages"]:
            blockers.extend("STAGE:" + stage + ":" + issue for issue in stages["stages"][stage]["blockers"])
        selected = [item for item in artifacts if item["kind"] in spec["kinds"]]
        for kind in spec["kinds"]:
            if not any(item["kind"] == kind for item in selected):
                blockers.append("MISSING_SCHEMA_SPECIFIC_EVIDENCE:" + kind)
        for item in selected:
            blockers.extend("ARTIFACT:" + item["id"] + ":" + issue for issue in item["blockers"] + item["input_diagnostics"])
        if name in ("P0_MODEL_EVALUATION_POISONING", "P0_AUTHORIZATION_EXTERNAL_EFFECTS"):
            blockers.extend("LEARNING:" + issue for issue in original["learning_blockers"])
        if name == "P0_AUTHORIZATION_EXTERNAL_EFFECTS":
            blockers.extend("EFFECT:" + issue for issue in original["effect_blockers"])
            for effect in original["effects"]:
                blockers.extend("EFFECT:" + effect["effect"]["operation_id"] + ":" + issue for issue in effect["issues"])
        if name == "P1_SAME_SOURCE_INTEGRATION":
            blockers.extend(original["gates"]["P0_INTEGRATION"]["blockers"])
            if any(item["source"]["classification"] == "HISTORICAL_SOURCE" for item in artifacts):
                blockers.append("HISTORICAL_MATERIALS_RETAINED_WITHOUT_ACCEPTANCE_TRANSFER")
        matrix[name] = dict(priority=spec["priority"], boundary=spec["boundary"],
                            obligations=list(spec["obligations"]), stages=list(spec["stages"]),
                            record_ids=[row["record"]["id"] for row in records], artifact_ids=[item["id"] for item in selected],
                            qualification="HOLD_NO_GO", material_status="BLOCKED", qualified=False,
                            blockers=sorted(set(blockers)))
    return dict(schema=REPORT_SCHEMA, qualification="HOLD_NO_GO", authority="DENY_ALL", qualified=False,
                all_blockers_closed=False, source_pair=copy.deepcopy(original["source_pair"]),
                plan_sha256=expected_plan_sha256, packet_sha256=original["packet_sha256"],
                security_inputs_sha256=qualification.sha(security_inputs_raw),
                original_review=original, stage_review=stages, system_blockers=matrix, artifacts=artifacts,
                input_refused=any(item["input_diagnostics"] for item in artifacts),
                engineering_controls_only=True, original_evidence_authenticated=False,
                native_outcome_verified=False, source_objects_verified=False,
                same_source_acceptance=False, independent_control_accepted=False,
                independent_wan_accepted=False, settlement_verified=False,
                full_pq_security_qualified=False, production_final_use_qualified=False, production_activation=False,
                scope="negative declarations and retained arithmetic only; no original acceptance or independence is authenticated")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--security-inputs", type=Path)
    args = parser.parse_args(argv)
    try:
        result = review(qualification.read_regular(args.plan), args.plan_sha256,
                        qualification.read_regular(args.packet), args.evidence_root,
                        qualification.read_regular(args.security_inputs) if args.security_inputs else None)
    except (OSError, qualification.Refusal) as error:
        result = dict(schema=REPORT_SCHEMA, qualification="HOLD_NO_GO", authority="DENY_ALL",
                      qualified=False, input_refused=str(error), all_blockers_closed=False,
                      production_final_use_qualified=False, production_activation=False)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 1 if result["input_refused"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
