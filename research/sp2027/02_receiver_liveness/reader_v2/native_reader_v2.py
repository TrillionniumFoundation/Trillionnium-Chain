#!/usr/bin/env python3
"""Versioned native-window reader; retained v1 bytes are never rewritten.

The old reader is loaded in a private module instance for unchanged archive,
packet and resource checks. Only the two native-confirmation readers below
replace its historical endpoint predicates. This does not alter a raw record,
execute the native verifier, relax a Host gate, or authenticate an observation.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERSION = "sp27-02-native-reader-v2"
FROZEN = {
    "legacy": ("legacy_reader_v1.py", "b62034432a144927fe570012aefc5c438bf364a31888047bac1bee1585310930"),
    "analyzer": ("analyzer_06_v1.py", "9719f822394e6295a7787be0be2c8d394d25ab19e8d17be543e4145f6bae9acc"),
    "exporter": ("exporter_06_v1.py", "9585e0bde16e0bc1776501c16a1f97ff646d3e2751d14e62a575f92b1c84fdc7"),
}
M = "11e242dbaaae14a9d16282fe8deaf36827e98395"
M_ARCHIVE = ("chain-throughput-m-campaign.zip", 81779634,
             "96b801074e063222a807a75a012da57f3255f95f3cc0301b7eb012f8188aec78", M)


def require(value, code):
    if not value:
        raise ValueError(code)


def integer(value):
    return type(value) is int and value >= 0


def load_frozen(role):
    """Load exactly the independently read-back upstream source bytes."""
    name, expected = FROZEN[role]
    path = HERE / "frozen" / name
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            "FROZEN_SOURCE_DIGEST:" + role)
    spec = importlib.util.spec_from_file_location("sp27_02_frozen_" + role, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def window_decision(observation, ended_ns, window_ns, native_gate):
    """Credit requires a strict endpoint AND the original final native gate.

The native fixture samples its final gate after recording the endpoint. Thus an
endpoint below T with gate=false is coherent and gets no credit. Missing fields
remain UNKNOWN, malformed fields or impossible positive gates are refused.
"""
    require(integer(window_ns) and window_ns > 0, "WINDOW_TYPE")
    require(ended_ns is None or integer(ended_ns), "ENDPOINT_TYPE")
    require(native_gate is None or type(native_gate) is bool, "NATIVE_GATE_TYPE")
    require(observation is None or isinstance(observation, dict), "OBSERVATION_TYPE")
    observed = None if observation is None else observation.get("confirmed")
    require(observed is None or type(observed) is bool, "OBSERVED_CONFIRMATION_TYPE")
    before = None if ended_ns is None else ended_ns < window_ns
    if native_gate is True:
        require(observed is True, "NATIVE_GATE_WITHOUT_CONFIRMATION")
        require(before is True, "NATIVE_GATE_CLOCK_CONTRADICTION")
    confirmed = observed is True and before is True and native_gate is True
    reasons = []
    if observed is not True:
        reasons.append("OBSERVATION_NOT_CONFIRMED" if observed is False else "OBSERVATION_MISSING")
    if before is not True:
        reasons.append("ENDPOINT_NOT_STRICTLY_BEFORE_T" if before is False else "ENDPOINT_MISSING")
    if native_gate is not True:
        reasons.append("NATIVE_GATE_FALSE" if native_gate is False else "NATIVE_GATE_MISSING")
    status = "CONFIRMED" if confirmed else (
        "UNKNOWN" if native_gate is None else "NOT_CONFIRMED")
    return {
        "reader_version": VERSION, "recorded_endpoint_ns": ended_ns,
        "window_end_ns": window_ns, "window_end_rule": "exclusive",
        "observed_confirmed": observed, "endpoint_before_window_end": before,
        "native_window_gate": native_gate, "confirmed_in_window": confirmed,
        "status": status, "exclusion_reasons": reasons,
        "endpoint_alone_is_not_native_final_gate": True,
    }


def _native_confirmation(lib, row, window):
    obs = row.get("observation")
    if isinstance(obs, dict) and obs.get("confirmed") is True:
        require(obs.get("transaction") == row.get("transaction"), "TRANSACTION_BINDING")
        require(obs.get("included_block") == row.get("included_block"), "BLOCK_BINDING")
        require(obs.get("policy") == "installed-depth-and-required-work", "CONFIRMATION_POLICY")
        require(type(obs.get("depth")) is int and obs["depth"] >= 6
                and int(obs["work_delta"], 16) >= int(obs["required_work_delta"], 16), "DEPTH_WORK")
        require(obs.get("execution_authority") is False, "OBSERVATION_AUTHORITY")
    return window_decision(obs, row.get("ended_ns"), window,
                           row.get("confirmed_inside_pressure_window"))["confirmed_in_window"]


def _native_phase(lib, a, member, p, prep, run, mode_index, fixture):
    """Keep every v1 binding/accounting check, with the versioned endpoint."""
    window = p["duration_seconds"] * 1_000_000_000
    require(window == 30_000_000_000 and len(prep["business"]) == 21, "ORIGINAL_NATIVE_INPUTS")
    business_tx = [(i, len(x["transactions"])) for i, x in enumerate(prep["business"]) if x["transactions"]]
    require(business_tx == [(0, 1), (7, 1), (14, 1)], "THREE_SIGNED_TRANSACTIONS")
    require(prep["actual_signed_seed_transfers"] == 1024, "SEED_DENOMINATOR")
    rounds = []
    for i in range(3):
        matches = [r for r in p["confirmations"] if r["round"] == i]
        require(len(matches) <= 1, "DUPLICATE_ROUND")
        r = matches[0] if matches else None
        scheduled = (1 + 4 * i) * 1_000_000_000
        confirmed = bool(r and _native_confirmation(lib, r, window))
        decision = None
        if r:
            require(r["included_block"] == prep["business"][7 * i]["id"], "PREPARED_BLOCK_BINDING")
            expected_tx = lib.wire_hash(b"tx-id", bytes.fromhex(prep["business"][7 * i]["transactions"][0]))
            require(r["transaction"] == expected_tx, "PREPARED_TRANSACTION_BINDING")
            decision = window_decision(r.get("observation"), r.get("ended_ns"), window,
                                       r.get("confirmed_inside_pressure_window"))
            if decision["native_window_gate"] is not None:
                require(confirmed == decision["native_window_gate"], "ORIGINAL_CONFIRM_FLAG")
        rounds.append({"round": i, "scheduled_ns": scheduled, "observed": r is not None,
                       "started_ns": r["started_ns"] if r else None,
                       "ended_ns": r["ended_ns"] if r else None,
                       "confirmed_in_30s": confirmed,
                       "four_second_slo_from_schedule": bool(confirmed and r["ended_ns"] <= scheduled + 4_000_000_000),
                       "start_lateness_ns": max(0, r["started_ns"] - scheduled) if r else None,
                       "reported_observation_confirmed": (r.get("observation") or {}).get("confirmed") if r else None,
                       "confirmation_not_finality": True, "window_decision_v2": decision})
    require(len(p["confirmations"]) == sum(r["observed"] for r in rounds), "UNEXPECTED_ROUND")
    packets = []
    for i in range(21):
        calls = [x for x in p["submissions"] if x["packet_index"] == i]
        # ACK interval telemetry retains the old inclusive convention; it never
        # grants confirmation credit. Resource spans remain half-open intervals.
        timely = [x for x in calls if x.get("status") == "ok" and integer(x.get("ended_ns")) and x["ended_ns"] <= window]
        packets.append({"packet_index": i, "signed_transactions": len(prep["business"][i]["transactions"]),
                        "attempts": len(calls), "ack_inside_window": bool(timely), "ack_is_not_confirmation": True})
    require(sum(x["attempts"] for x in packets) == len(p["submissions"]), "UNEXPECTED_PACKET")
    imports = [x["client_import"] for x in p["history"] if isinstance(x.get("client_import"), dict)]
    out = {
        "reader_version": VERSION, "phase_id": f"{a.key}/run-{run}/{p['mode']}", "fixture": fixture,
        "archive_key": a.key, "report_member": member, "report_sha256": a.reads[member]["sha256"],
        "json_pointer": f"/phases/{mode_index}", "source_commit": a.commit, "run": run, "mode": p["mode"],
        "window_ns": window, "window_epoch": "original native phase epoch; no setup/drain credit",
        "seed_transfers_excluded_from_goodput": 1024, "planned_packets": 21, "planned_signed_transactions": 3,
        "planned_rounds": rounds, "planned_packet_records": packets,
        "rounds_observed": len(p["confirmations"]), "rounds_unstarted": sum(not r["observed"] for r in rounds),
        "confirmed_in_window": sum(r["confirmed_in_30s"] for r in rounds),
        "four_second_slo_successes": sum(r["four_second_slo_from_schedule"] for r in rounds),
        "successful_ack_packets": sum(r["ack_inside_window"] for r in packets),
        "packets_unattempted": sum(not r["attempts"] for r in packets),
        "submissions": lib.interval_summary(p["submissions"], window),
        "history_network": lib.interval_summary(p["history"], window),
        "history_import": lib.interval_summary(imports, window),
        "history_import_calling_thread_cpu_ns": lib.complete_sum(i.get("thread_cpu_ns") for i in imports),
        "history_rows_without_import": len(p["history"]) - len(imports),
        "history_import_failed": sum(i.get("succeeded") is False for i in imports),
        "history_import_errors": dict(lib.Counter(str(i.get("error")) for i in imports if i.get("error") is not None)),
        "stage_audit": lib.stage_audit(imports), "receiver": lib.receiver_audit(p["receiver_observation"]),
        "original_finite_phase_criteria_met": p["finite_phase_criteria_met"],
        "original_all_signed_rounds_confirmed": p["all_signed_rounds_confirmed_in_window"],
        "original_depletion_observed": p["genuine_budget_depletion_observed"],
        "receiver_client_state_equal": p["receiver_client_state_equal"],
        "attacker_processes_requested": p["attacker_processes_requested"],
        "attacker_processes_ready": p["attacker_processes_ready"],
        "observed_attack_overlap_by_started_round": p["attack_calls_overlapping_each_signed_round"],
        "verifier_errors": p["verifier_errors"],
        "whole_parent_phase_cpu_ns": p["whole_parent_phase_cpu_ns"],
        "whole_parent_phase_wall_ns": p["whole_parent_phase_wall_ns"],
        "phase_parent_totals_are_not_exact_window_costs": True,
        "same_host_only": True, "stark_adapter_executed": False,
    }
    if "root_supplement" in p:
        q = p["root_supplement"]
        out["root_supplement"] = {k: q[k] for k in ["criteria_met", "cold_state_equal", "hostile_packets_absent_cold", "hostile_packets_absent_live", "whole_domain_paid_reconciled", "expected_legal_counts_and_tip", "aggregate_scoped_cpu_ns", "mutation_owner_cpu_ns"]}
        out["root_supplement"]["scope"] = q["scope"]
        out["root_supplement"]["acquisitions"] = len(q["acquisitions"])
    return out


def _pair_phase(lib, a, member, p, phase_index, pair_name):
    """Same v1 pair validation, without reconstructing the later native gate."""
    window = p["requested_window_ns"]
    require(window == 4_000_000_000, "ORIGINAL_FOUR_SECOND_WINDOW")
    calls = [c for actor in p["attacks"] for c in actor["calls"]]
    start = p["business_started_ns"]
    overlap = [c for c in calls if c["started_ns"] < window and c["ended_ns"] > start]
    reported_end = p["confirmation_ended_ns"]
    conditioned = 0 if reported_end is None else sum(c["started_ns"] < reported_end and c["ended_ns"] > start for c in calls)
    require(conditioned == p["overlapping_false_calls"], "CONFIRMATION_CONDITIONED_OVERLAP")
    require(p["no_attack_accepted"] == all(c["status"] != "ok" for c in calls), "ATTACK_ACCEPTANCE")
    decision = window_decision(p.get("independent_client_confirmation"), reported_end, window,
                               p.get("client_confirmed_before_original_window_end"))
    confirmed = decision["confirmed_in_window"]
    if decision["native_window_gate"] is not None:
        require(confirmed == decision["native_window_gate"], "PAIR_CONFIRMATION_FLAG")
    require(type(p["client_confirmed_transactions"]) is int
            and int(confirmed) == p["client_confirmed_transactions"], "PAIR_DENOMINATOR")
    clock = p["business_receive_clock"]
    require(clock["clock_scope"] == "same-process-monotonic-observer", "PAIR_CLOCK_SCOPE")
    require(clock["independent_confirmation_in_observer_ns"] == (
        None if reported_end is None else reported_end + clock["traffic_epoch_in_observer_ns"]), "PAIR_CLOCK_MAPPING")
    replays = p["independent_history_page_replay"]
    imports = [{"native_import_observation": x["native_import_observation"]} for x in replays]
    return {
        "reader_version": VERSION, "window_decision_v2": decision,
        "phase_id": f"{a.key}/{pair_name}/{p['mode']}", "fixture": "original-four-second-pair",
        "archive_key": a.key, "report_member": member, "report_sha256": a.reads[member]["sha256"],
        "json_pointer": f"/phases/{phase_index}", "source_commit": a.commit, "pair_name": pair_name,
        "mode": p["mode"], "window_ns": window, "window_epoch": "original traffic epoch, NOT business start plus four seconds",
        "business_started_ns": start, "planned_packets": 7, "planned_signed_transactions": 1,
        "confirmed_in_window": int(confirmed), "confirmation_ended_ns": reported_end,
        "confirmation_latency_ns": p["client_confirmation_latency_ns"], "confirmed_failure_is_not_zero_latency": True,
        "attack_workers": p["workers"], "attack_calls": lib.interval_summary(calls, window),
        "attack_calls_overlapping_fixed_business_window": len(overlap),
        "reported_confirmation_conditioned_overlap_count": conditioned,
        "reported_overlap_demonstrated": p["overlap_demonstrated"],
        "confirmation_conditioned_overlap_censored": reported_end is None,
        "no_attack_accepted": p["no_attack_accepted"], "invariant_target_met": p["invariant_target_met"],
        "accounting_closed": p["accounting_closed"],
        "original_finite_business_target_met": p["finite_business_target_met"],
        "full_native_state_equal": p["full_native_state_equal"],
        "receiver_matches_valid_honest_prefix": p["receiver_matches_valid_honest_prefix"],
        "honest_head_successes_in_window": p["honest_head_successes_in_window"],
        "submissions": lib.interval_summary(p["honest_submissions"], window),
        "history_network": lib.interval_summary(p["honest_history"], window),
        "history_import": lib.interval_summary(replays, window, "replay_started_ns", "replay_ended_ns"),
        "history_replay_failed": sum(x.get("replay_accepted") is False for x in replays),
        "receiver": lib.receiver_audit(p["observations"]), "stage_audit": lib.stage_audit(imports),
        "clock_mapping": clock, "verification_errors": p["verification_errors"],
        "resource_fairness_qualified": p["resource_fairness_qualified"],
        "same_host_only": True, "stark_adapter_executed": False,
    }


def get_reader(version=2):
    """Return one isolated reader instance; version=1 retains historical behavior."""
    require(version in (1, 2), "READER_VERSION")
    lib = load_frozen("legacy")
    lib.ARCHIVES["m_campaign"] = M_ARCHIVE
    if version == 2:
        lib.is_native_confirmation = lambda row, window: _native_confirmation(lib, row, window)
        lib.native_phase = lambda *args: _native_phase(lib, *args)
        lib.pair_phase = lambda *args: _pair_phase(lib, *args)
    return lib
