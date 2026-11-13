#!/usr/bin/env python3
"""Recompute experiment 3 from the retained F0 readback; never execute a node.

This is a consistency reader for a published, derived evidence document. Its
checks cannot authenticate an adversarial document or replace the original raw
report, binary, source and independent Host execution. No result here grants
service, release or consensus qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

PHASES = ("baseline", "valid-work-root")
STARTS_NS = (1_000_000_000, 5_000_000_000, 9_000_000_000)
SLO_NS = 4_000_000_000
PHASE_NS = 30_000_000_000
HOST_LIMITS = {
    "cpu.max": "25000 100000", "cpu.max.burst": "0",
    "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256",
}
INPUTS = {
    "seed_transfers": 1024, "seed_blocks": 4, "business_blocks": 21,
    "phase_seconds": 30, "actor_call_cap": 480, "planned_complete_runs": 1,
    "attackers": 24, "m06_workers": 1, "confirmation_depth": 6,
    "round_start_seconds": [1, 5, 9], "cpu_burst_ns": 2_000_000_000,
    "cpu_refill_ns_per_second": 250_000_000, "start_reserve_ns": 100_000_000,
    "phase_profile": "fixed-public-root-phase-external-actors-v1",
    "planned_phases": list(PHASES), "planned_confirmations": 6,
    "planned_business_packets": 42, "four_second_slo_ns": SLO_NS,
    "slo_starts_at_scheduled_offset": True,
    "legacy_four_second_from_zero_epoch_changed": False, "f1_implemented": False,
    "controller_resource_schema": "fixed-host-root-controller-resources-v1",
    "controller_resource_boundary_samples": 6,
}


def _integer(value):
    return type(value) is int and value >= 0


def _exact(value, expected):
    # Python considers True == 1; measured fields do not.
    if type(value) is not type(expected):
        return False
    if isinstance(expected, list):
        return len(value) == len(expected) and all(_exact(a, b) for a, b in zip(value, expected))
    return value == expected


def _object(value):
    return value if isinstance(value, dict) else {}


def _hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def evaluate(value):
    """Retain six scheduled confirmations and 42 packets even for bad input."""
    value = _object(value)
    errors = []

    def require(condition, code):
        if not condition:
            errors.append(code)

    require(value.get("schema") == "pon-fixed-host-root-f0-readback-analysis-v1", "READBACK_SCHEMA")
    inputs = _object(value.get("inputs"))
    for key, expected in INPUTS.items():
        require(_exact(inputs.get(key), expected), "ORIGINAL_INPUT:" + key)
    head, tree = value.get("head"), value.get("tree")
    require(_hex(head, 40) and _hex(tree, 40), "SOURCE_IDENTITIES")
    bindings = _object(value.get("bindings"))
    before, after = _object(bindings.get("source_before")), _object(bindings.get("source_after"))
    require(before == after and _hex(before.get("sha256"), 64), "UNCHANGED_SOURCE_RECEIPTS")
    binary = _object(bindings.get("prepared_binary"))
    require(_hex(binary.get("sha256"), 64) and _integer(binary.get("bytes")) and binary["bytes"] > 0,
            "PREPARED_BINARY_IDENTITY")
    report = _object(value.get("raw_report_binding"))
    require(_hex(report.get("sha256"), 64), "RAW_REPORT_IDENTITY")
    finalization = _object(value.get("finalization"))
    denominator = _object(finalization.get("denominator"))
    require(denominator.get("report_sha256") == report.get("sha256"), "RAW_REPORT_BINDING")
    require(denominator.get("report_observed") is True, "RAW_REPORT_OBSERVED")
    require(denominator.get("controller_resources_complete") is True, "CONTROLLER_RESOURCES")
    require(finalization.get("all_services_known_empty") is True, "OWNED_SERVICES_EMPTY")
    require(denominator.get("native_result_observed") is True, "NATIVE_RESULT_OBSERVED")
    require(_hex(denominator.get("native_result_sha256"), 64), "NATIVE_RESULT_IDENTITY")
    require(type(denominator.get("native_complete_success")) is bool, "NATIVE_SUCCESS_TYPE")
    require(type(finalization.get("complete_success")) is bool, "FINAL_SUCCESS_TYPE")
    for key, expected in (("planned_confirmations", 6), ("planned_business_packet_exposures", 42)):
        require(_exact(denominator.get(key), expected), "ORIGINAL_DENOMINATOR:" + key)

    raw_rounds = value.get("rounds")
    require(isinstance(raw_rounds, list), "ROUNDS_ARRAY")
    raw_rounds = raw_rounds if isinstance(raw_rounds, list) else []
    for row in raw_rounds:
        row = _object(row)
        require(row.get("phase") in PHASES and type(row.get("round")) is int
                and row.get("round") in range(3), "UNPLANNED_ROUND")
    rounds, results = [], []
    phase_values = _object(value.get("phases"))
    for name in PHASES:
        phase = _object(phase_values.get(name))
        phase_errors_before = len(errors)
        require(phase.get("state_backend") == "authenticated-v1", name + ":ORIGINAL_BACKEND")
        require(phase.get("observer_complete") is True, name + ":OBSERVER_INCOMPLETE")
        host = _object(phase.get("public_host_observations"))
        for boundary in ("inside-before", "outside-before", "inside-after", "outside-after"):
            sample = _object(host.get(boundary))
            require(sample.get("limits") == HOST_LIMITS, name + ":ORIGINAL_HOST:" + boundary)
            require(sample.get("read_errors") == {}, name + ":HOST_READ_ERRORS:" + boundary)
        packets = _object(phase.get("packets"))
        require(_exact(packets.get("planned"), 21), name + ":ORIGINAL_PACKET_DENOMINATOR")
        for key in ("observed_attempts", "timely_network_ack", "unobserved"):
            require(_integer(packets.get(key)), name + ":PACKET_COUNTER:" + key)
        require(packets.get("ack_is_not_confirmation") is True, name + ":ACK_SEPARATION")
        attempts = packets.get("observed_attempts")
        ack = packets.get("timely_network_ack")
        unobserved = packets.get("unobserved")
        if _integer(ack) and _integer(unobserved):
            require(ack <= 21 and unobserved <= 21 and ack + unobserved <= 21,
                    name + ":PACKET_COUNTS_OUT_OF_RANGE")
        if _integer(attempts) and _integer(unobserved) and _integer(ack):
            require(attempts + unobserved == 21 and ack <= attempts,
                    name + ":PACKET_ATTEMPT_RECONCILIATION")
        require(type(phase.get("finite_phase_criteria_met")) is bool, name + ":FINITE_CRITERIA_TYPE")
        slots = []
        for ordinal, scheduled in enumerate(STARTS_NS):
            matches = [r for r in raw_rounds if isinstance(r, dict) and r.get("phase") == name
                       and type(r.get("round")) is int and r["round"] == ordinal]
            require(len(matches) == 1, name + ":ROUND_ROSTER:" + str(ordinal))
            row = matches[0] if len(matches) == 1 else {}
            require(_exact(row.get("scheduled_offset_ns"), scheduled), name + ":ORIGINAL_SCHEDULE:" + str(ordinal))
            started, ended = row.get("actual_started_ns"), row.get("actual_ended_ns")
            require(type(row.get("observed_exactly_once")) is bool,
                    name + ":ROUND_OBSERVATION_TYPE:" + str(ordinal))
            require(type(row.get("confirmed_inside_original_window")) is bool,
                    name + ":ROUND_CONFIRMATION_TYPE:" + str(ordinal))
            observed = row.get("observed_exactly_once") is True and len(matches) == 1
            require(observed or (started is None and ended is None
                    and row.get("confirmed_inside_original_window") is False),
                    name + ":UNOBSERVED_ROUND_HAS_RESULT:" + str(ordinal))
            known = observed and _integer(started) and _integer(ended) and scheduled <= started <= ended
            confirmed = observed and row.get("confirmed_inside_original_window") is True
            if confirmed:
                require(known and ended < PHASE_NS, name + ":CONFIRMATION_CLOCK:" + str(ordinal))
            elapsed = ended - scheduled if _integer(ended) and ended >= scheduled else None
            met = bool(confirmed and known and elapsed < SLO_NS and ended < PHASE_NS)
            require(row.get("four_second_slo_met") is met, name + ":SLO_RECOMPUTATION:" + str(ordinal))
            require(_exact(row.get("elapsed_from_scheduled_ns"), elapsed), name + ":ELAPSED_RECOMPUTATION:" + str(ordinal))
            slots.append({"phase": name, "round": ordinal, "scheduled_offset_ns": scheduled,
                          "observed_exactly_once": observed, "actual_started_ns": started,
                          "actual_ended_ns": ended, "elapsed_from_schedule_ns": elapsed,
                          "confirmed_inside_original_window": confirmed, "four_second_slo_met": met})
        rounds.extend(slots)
        success = sum(row["four_second_slo_met"] for row in slots)
        valid = len(errors) == phase_errors_before
        finite = phase.get("finite_phase_criteria_met") is True
        root = _object(phase.get("root_checks"))
        root_fields = ("aggregate_membership_verified", "checked_acquisitions_complete",
                       "cold_state_equal", "criteria_met", "expected_legal_counts_and_tip",
                       "hostile_packets_absent_cold", "hostile_packets_absent_live",
                       "whole_domain_paid_reconciled")
        root_checks_pass = name == "baseline" or all(root.get(k) is True for k in root_fields)
        passed = valid and success == 3 and finite and ack == 21 and unobserved == 0 and root_checks_pass
        # Keep nested categories separate; do not create a false total cost.
        costs = {"client_import": phase.get("client_import"),
                 "client_host_checks": phase.get("client_host_checks_sum"),
                 "native_stages": phase.get("client_stage_after_minus_before"),
                 "overlap_policy": "Nested intervals. Never add across categories."}
        results.append({"phase": name, "status": "PASS_IN_SUPPLIED_OBSERVATION" if passed else "FAIL",
                        "original_finite_phase_criteria_met": finite, "scheduled_slo_successes": success,
                        "root_protection_observations": root, "root_protection_checks_pass": root_checks_pass,
                        "planned_confirmations": 3, "planned_packet_exposures": 21,
                        "reported_timely_network_ack": ack, "reported_unobserved_packets": unobserved,
                        "independent_confirmation_is_not_ack": True, "cost_observations": costs})
    successes = sum(row["four_second_slo_met"] for row in rounds)
    require(_exact(denominator.get("four_second_slo_successes"), successes), "FINAL_SLO_COUNT")
    baseline_pass = results[0]["status"] == "PASS_IN_SUPPLIED_OBSERVATION"
    attack_pass = results[1]["status"] == "PASS_IN_SUPPLIED_OBSERVATION"
    original_pass = not errors and baseline_pass and attack_pass and denominator.get("native_complete_success") is True and finalization.get("complete_success") is True
    return {
        "schema": "pon-fixed-host-service-readback-v1", "evidence_consistent": not errors,
        "evidence_errors": sorted(set(errors)), "source_head": head, "source_tree": tree,
        "prepared_binary_sha256": binary.get("sha256"), "original_raw_report_sha256": report.get("sha256"),
        "scope": "Recomputed published derived readback; no new native execution or source repair.",
        "phase_results": results, "all_planned_rounds": rounds,
        "planned_confirmations": 6, "planned_business_packet_exposures": 42,
        "scheduled_slo_successes": successes,
        "original_gate_status": "INVALID_EVIDENCE" if errors else ("PASS_IN_SUPPLIED_OBSERVATION" if original_pass else "FAIL"),
        "next_required_gate": "BASELINE_MUST_PASS" if not baseline_pass else ("ATTACK_MUST_PASS" if not attack_pass else "INDEPENDENT_NATIVE_REPLAY_REQUIRED"),
        "invalid_input_service_economics": "UNQUALIFIED", "legal_cheap_work_economics": "NOT_MEASURED_BY_F0",
        "original_issue_639_16_producer_gate_covered": False, "new_native_runs": 0,
        "continuous_novel_attack_service_qualified": False,
        "service_qualified": False, "release_ready": False, "production_activation": False,
    }


def load_strict(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY:" + key)
            result[key] = value
        return result

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("NONFINITE_JSON:" + text)
        return value

    with path.open("rb") as source:
        raw = source.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("READBACK_TOO_LARGE")
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError("NONFINITE_JSON:" + value)))
    return raw, value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw, value = load_strict(args.input)
    result = evaluate(value)
    result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    result["input_bytes"] = len(raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("evidence_consistent", "original_gate_status", "next_required_gate", "scheduled_slo_successes", "planned_confirmations", "new_native_runs")}))
    # The command verifies consistency, not success of the original experiment.
    return 0 if result["evidence_consistent"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
