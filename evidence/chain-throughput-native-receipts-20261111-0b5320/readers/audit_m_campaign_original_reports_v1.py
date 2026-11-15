#!/usr/bin/env python3
"""Independent read-only arithmetic over the pinned M campaign's original reports.

No node, test, subprocess, network client, archive extraction or report mutation.
Only the explicitly named new output file is created. Exit zero means this audit
completed; business acceptance is recorded separately and is never repaired here.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SOURCE = "11e242dbaaae14a9d16282fe8deaf36827e98395"
TREE = "1f42f41923d7761c02fc68b478df5b019c7d83e8"
BASE = Path("/tmp/chain-throughput-0b5320-publication/ci-artifacts/13833660378-campaign")
RECEIPT_SHA = "7efd094afe906968e84b0b9f0c34bae43c76db78c3de61adb7215a6bfc384cc0"
MANIFEST_SHA = "bda048160c169725984bf07326301114be96ce0468a5bb71c480a6a78b7f57e9"
ARTIFACT = {"id": 13833660378, "bytes": 81779634,
            "sha256": "96b801074e063222a807a75a012da57f3255f95f3cc0301b7eb012f8188aec78",
            "name": "pon-native-campaign-x64-head-release-" + SOURCE + "-1"}
REPORTS = {
    1: (53733948, "20b0610468fa9b781e69f80a1210442cbfc8536a99b28c567ed6ee2b0b0bc08f"),
    2: (54506951, "5d56f8557c165a8ed326c54f329767ad60d28b2c366ba17b1dff404042cace86"),
    3: (55257612, "4866a9ed85a261de4b7d4fa427b719e40009dd9b930fb62cfde8aaa22dc49327"),
}
MODES = ("baseline", "from-zero", "late-product")
WINDOW = 30_000_000_000
BURST, RESERVE, REFILL = 2_000_000_000, 100_000_000, 250_000_000
INPUTS = {"attacker_processes": [0, 24, 24], "business_blocks": 21,
          "modes": list(MODES), "phase_seconds": 30, "seed_blocks": 4,
          "seed_transfers": 1024}


def need(value, message):
    if not value:
        raise ValueError(message)


def number(value, signed=False):
    need(type(value) is int and (-(2**127) if signed else 0) <= value < 2**127,
         "invalid integer")
    return value


def boolean(value):
    need(type(value) is bool, "invalid boolean")
    return value


def hex_digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid digest")
    return value


def receiver_digest(value):
    if value is None:
        return None
    need(type(value) is list and len(value) == 32
         and all(type(x) is int and 0 <= x < 256 for x in value), "receiver digest grammar")
    return bytes(value).hex()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("nonfinite JSON number: " + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def read_pinned(path, size, digest, limit=64 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path
         and not path.is_symlink(), "noncanonical input path")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size == size <= limit,
             "input size/type mismatch: " + str(path))
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        need(all(getattr(before, k) == getattr(after, k) for k in
                 ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
             "input changed while reading")
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == hex_digest(digest),
         "input hash mismatch: " + str(path))
    return strict_json(raw)


def tri_counts(rows, field):
    result = {"true": 0, "false": 0, "unknown": 0}
    for row in rows:
        value = row.get(field)
        need(value is None or type(value) is bool, "invalid tri-state: " + field)
        result["unknown" if value is None else str(value).lower()] += 1
    return result


def call_on_time(row):
    start, end = number(row["started_ns"]), number(row["ended_ns"])
    need(start <= end, "caller time order")
    late = boolean(row["returned_after_window"])
    need(late == (end >= WINDOW), "caller original-window flag mismatch")
    need(row["status"] in ("ok", "refused", "error"), "unknown client status")
    return row["status"] == "ok" and not late


def flow_equations(flow):
    """All equations use one actual_flow snapshot, not separately sampled meter credit."""
    for field in ("initial_credit_ns", "remaining_paid_credit_ns", "stored_credit_ns"):
        number(flow[field], signed=True)
    for field in ("credited_refill_ns", "discarded_refill_ns", "booked_reservation_ns",
                  "live_debited_cpu_ns", "settlement_residual_cpu_ns", "settled_full_cpu_ns",
                  "unsettled_known_live_cpu_ns", "paid_cpu_debit_ns", "settlement_discard_ns",
                  "live_owners"):
        number(flow[field])
    termination = number(flow.get("termination_reserved_ns", 0))
    debit = flow["paid_cpu_debit_ns"]
    remaining = flow["initial_credit_ns"] + flow["credited_refill_ns"] - debit - flow["settlement_discard_ns"]
    checks = {
        "debit_equals_live_plus_residual": debit == flow["live_debited_cpu_ns"] + flow["settlement_residual_cpu_ns"],
        "paid_balance": remaining == flow["remaining_paid_credit_ns"],
        "stored_balance": remaining - flow["booked_reservation_ns"] - termination == flow["stored_credit_ns"],
        "booked_principal": flow["booked_reservation_ns"] == flow["live_owners"] * RESERVE,
        "unsettled_known_live": debit - flow["settled_full_cpu_ns"] == flow["unsettled_known_live_cpu_ns"],
    }
    return checks


def budget_observation(samples):
    counts = Counter(samples=len(samples))
    equation_failures = Counter()
    computed = []
    minimum, maximum = None, None
    for index, sample in enumerate(samples):
        start = number(sample["observation_started_ns"])
        end = number(sample["observation_ended_ns"])
        need(start <= end and number(sample["at_ns"]) == end, "budget sample interval")
        observed = sample["meter"].get("Ok")
        if observed is None:
            counts["unknown_meter_samples"] += 1
            computed.append(False)
            continue
        meter = observed["meter"]
        need((meter["burst_ns"], meter["start_reserve_ns"], meter["refill_ns_per_second"])
             == (BURST, RESERVE, REFILL), "original scalar constants changed")
        need(start <= number(observed["sample_at_ns"]) <= end, "sample clock scope mismatch")
        reported = boolean(observed["depleted"])
        counts["reported_depleted_samples"] += reported
        unavailable = boolean(meter["accounting_unavailable"])
        clock_failures = number(observed["clock_failures"])
        counts["samples_with_clock_failures"] += clock_failures != 0
        counts["samples_with_accounting_unavailable"] += unavailable
        flow = observed.get("actual_flow")
        decision = False
        if flow is None:
            counts["missing_actual_flow_samples"] += 1
        else:
            checks = flow_equations(flow)
            for name, passed in checks.items():
                equation_failures[name] += not passed
            counts["flow_equation_mismatch_samples"] += not all(checks.values())
            identity = boolean(flow["balance_identity_verified"])
            decision = (identity and flow["initial_credit_ns"] == BURST
                        and flow["remaining_paid_credit_ns"] < RESERVE
                        and flow["paid_cpu_debit_ns"] > BURST - RESERVE
                        and clock_failures == 0 and not unavailable)
            counts["predicate_would_change_with_independent_identity"] += (
                decision != (decision and all(checks.values())))
            counts["debit_above_original_threshold_samples"] += flow["paid_cpu_debit_ns"] > BURST - RESERVE
            counts["unverified_flow_identity_samples"] += not identity
            # observe() and observe_actual_flow() take separate locks. Differences
            # here are diagnostics, never false contradictions of the flow ledger.
            counts["separate_meter_flow_snapshots_differ"] += (
                meter["stored_credit_ns"] != flow["stored_credit_ns"]
                or meter["in_flight"] != flow["live_owners"])
            point = {"sample_index": index, "observation_started_ns": start,
                     "observation_ended_ns": end, "actual_flow": flow}
            if minimum is None or flow["remaining_paid_credit_ns"] < minimum["actual_flow"]["remaining_paid_credit_ns"]:
                minimum = point
            if maximum is None or flow["paid_cpu_debit_ns"] > maximum["actual_flow"]["paid_cpu_debit_ns"]:
                maximum = point
        computed.append(decision)
        counts["computed_original_depleted_samples"] += decision
        counts["reported_predicate_mismatch_samples"] += decision != reported
    for key in ("unknown_meter_samples", "missing_actual_flow_samples", "reported_depleted_samples",
                "computed_original_depleted_samples", "reported_predicate_mismatch_samples",
                "flow_equation_mismatch_samples", "predicate_would_change_with_independent_identity",
                "debit_above_original_threshold_samples", "unverified_flow_identity_samples",
                "samples_with_clock_failures", "samples_with_accounting_unavailable",
                "separate_meter_flow_snapshots_differ"):
        counts.setdefault(key, 0)
    return {"counts": dict(counts), "flow_equation_mismatches": dict(equation_failures),
            "minimum_paid_credit_sample": minimum, "maximum_paid_debit_sample": maximum,
            "credit_freshness_used": False,
            "scope": "original sample.meter.Ok.actual_flow only; receiver domain; no live CPU refresh or inter-sample exclusion proof"}, computed


def analyze_phase(phase, run, ordinal, report_record, member_record):
    mode = MODES[ordinal]
    need(phase["mode"] == mode and phase["duration_seconds"] == 30
         and phase["state_backend"] == "authenticated-v1"
         and phase["attacker_processes_requested"] == (0 if ordinal == 0 else 24)
         and phase.get("startup_or_campaign_error") is None, "original phase identity changed")
    pointer = "/phases/" + str(ordinal)
    rounds = phase["confirmations"]
    need(type(rounds) is list and len(rounds) <= 3
         and [number(r["round"]) for r in rounds] == list(range(len(rounds))), "round prefix/denominator")
    budget, computed = budget_observation(phase["budget_samples"])
    round_rows = []
    for index, row in enumerate(rounds):
        start, end = number(row["started_ns"]), number(row["ended_ns"])
        need(start <= end, "round time order")
        confirmed = boolean(row["confirmed_inside_pressure_window"])
        observation = row["observation"]
        if confirmed:
            need(isinstance(observation, dict) and observation["confirmed"] is True
                 and observation["finalized"] is False and observation["execution_authority"] is False
                 and observation["depth"] == 6 and end < WINDOW
                 and observation["transaction"] == row["transaction"]
                 and observation["included_block"] == row["included_block"]
                 and observation["observed_tip"] == row["tip"], "ineligible reported confirmation")
        need(confirmed or index == len(rounds) - 1, "rounds continued after original stop")
        overlap = any(start <= s["observation_started_ns"] <= s["observation_ended_ns"] <= end and d
                      for s, d in zip(phase["budget_samples"], computed))
        need(boolean(row["paid_credit_depletion_observed_during_round"]) == overlap,
             "round depletion overlap mismatch")
        round_rows.append({"round": index, "transaction": hex_digest(row["transaction"]),
                           "started_ns": start, "ended_ns": end,
                           "confirmed_inside_pressure_window": confirmed,
                           "computed_paid_depletion_during_round": overlap})
    confirmed = sum(r["confirmed_inside_pressure_window"] for r in round_rows)
    all_confirmed = len(rounds) == 3 and confirmed == 3
    need(boolean(phase["all_signed_rounds_confirmed_in_window"]) == all_confirmed,
         "original all-rounds predicate mismatch")
    observer = phase["receiver_observation"]
    need(observer["monotonic_epoch_is_observer_local"] is True, "receiver clock scope changed")
    records = observer["records"]
    digest_index = defaultdict(list)
    ids = set()
    for index, row in enumerate(records):
        ident = number(row["connection_id"])
        need(ident not in ids, "duplicate receiver connection ID")
        ids.add(ident)
        digest = receiver_digest(row["body_digest"])
        if row.get("operation") == 1 and digest is not None:
            digest_index[digest].append(index)
    submissions = phase["submissions"]
    honest_counts = Counter(hex_digest(c["public_request_body_digest"]) for c in submissions)
    matches, matched_indices = [], set()
    for index, call in enumerate(submissions):
        on_time = call_on_time(call)
        if call["status"] == "ok":
            need(call["response"]["ok"] is True, "ACK disagrees with raw response")
        digest = hex_digest(call["public_request_body_digest"])
        matched = digest_index[digest]
        matched_indices.update(matched)
        matches.append({"call_index": index, "packet_index": number(call["packet_index"]),
                        "public_request_body_digest": digest, "client_on_time": on_time,
                        "client_started_ns": call["started_ns"], "client_ended_ns": call["ended_ns"],
                        "receiver_indices": matched,
                        "receiver_connection_ids": [records[j]["connection_id"] for j in matched]})
    matched_records = [records[j] for j in sorted(matched_indices)]
    remaining = [r for j, r in enumerate(records) if j not in matched_indices]
    imports, import_errors, page_owners, packet_owners = [], Counter(), Counter(), Counter()
    for index, call in enumerate(phase["history"]):
        call_on_time(call)
        imported = call.get("client_import")
        if imported is None:
            continue
        succeeded = boolean(imported["succeeded"])
        need(succeeded == (imported["error"] is None), "import status/error inconsistency")
        start, end = number(imported["started_ns"]), number(imported["ended_ns"])
        need(start <= end and call["ended_ns"] <= start, "caller History/import chronology")
        observation = imported.get("native_import_observation") or {}
        attribution = observation.get("native_attribution") or {}
        owner = (attribution.get("page") or {}).get("owner_mode", "<missing>")
        need(owner in ("exclusive", "shared", None, "<missing>"), "unknown page owner mode")
        page_owners[str(owner)] += 1
        for packet in attribution.get("packets", []):
            packet_owners[str((packet.get("attribution") or {}).get("owner_mode", "<missing>"))] += 1
        if not succeeded:
            import_errors[imported["error"]] += 1
        imports.append({"history_call_index": index, "succeeded": succeeded,
                        "error": imported["error"], "page_owner_mode": owner,
                        "started_ns": start, "ended_ns": end})
    attack_calls, children_without_calls = [], 0
    for child in phase["children"]:
        calls = ((child.get("report") or {}).get("result") or {}).get("calls")
        if isinstance(calls, list):
            attack_calls.extend(calls)
        else:
            children_without_calls += 1
    full_work = tri_counts(records, "full_work_accepted")
    need(phase["full_work_accepted"] == full_work["true"]
         and phase["full_work_failed"] == full_work["false"], "receiver work counter mismatch")
    service = phase["service_outcome"].get("Ok")
    final_meter = phase["final_meter"]
    common = {"three_rounds_confirmed": all_confirmed,
              "receiver_client_state_equal": boolean(phase["receiver_client_state_equal"]),
              "observer_complete": boolean(phase["observer_complete"]),
              "service_returned_ok": isinstance(service, dict),
              "service_cpu_clocks_known": isinstance(service, dict) and service["mutation_cpu_clock_failures"] == 0,
              "no_final_live_owner": final_meter["in_flight"] == 0,
              "final_accounting_available": not boolean(final_meter["accounting_unavailable"]),
              "no_verifier_error": phase["verifier_errors"] == []}
    depletion = any(computed)
    need(boolean(phase["genuine_budget_depletion_observed"]) == depletion, "phase depletion mismatch")
    attack = {}
    if ordinal:
        overlaps = phase["attack_calls_overlapping_each_signed_round"]
        attack = {"paid_depletion_observed": depletion,
                  "all_24_actors_ready": phase["attacker_processes_ready"] == 24,
                  "actor_reports_successful": boolean(phase["actor_reports_successful_without_cap_or_kill"]),
                  "three_rounds_have_attack_overlap": len(overlaps) == 3 and all(x > 0 for x in overlaps),
                  "receiver_rejected_work": full_work["false"] > 0,
                  "at_least_21_accepted_work": full_work["true"] >= 21,
                  "confirmation_round_has_depletion": any(r["computed_paid_depletion_during_round"] for r in round_rows),
                  "every_recorded_round_has_rejection": all(r["receiver_hostile_work_rejected_during_round"] is True for r in rounds),
                  "no_recorded_attack_call_ok": all(c["status"] != "ok" for c in attack_calls)}
    calculated_phase = all(common.values()) and all(attack.values())
    need(boolean(phase["finite_phase_criteria_met"]) == calculated_phase, "phase decision recomputation mismatch")
    final_flow = phase.get("final_actual_flow")
    return {"run": run, "mode": mode,
            "source": {"report_member": report_record["zip_member"], "report_sha256": report_record["sha256"],
                       "phase_json_pointer": pointer, "separate_phase_member": member_record,
                       "honest_join_paths": [pointer + "/submissions/*/public_request_body_digest", pointer + "/receiver_observation/records/*/body_digest"],
                       "owner_mode_path": pointer + "/history/*/client_import/native_import_observation/native_attribution/page/owner_mode",
                       "budget_path": pointer + "/budget_samples/*/meter/Ok/actual_flow"},
            "counts": {"planned_rounds": 3, "observed_rounds": len(rounds), "unexecuted_rounds": 3 - len(rounds),
                       "confirmed_rounds": confirmed, "complete_phases": int(calculated_phase),
                       "honest_submit_attempts": len(submissions), "honest_client_ok": sum(c["status"] == "ok" for c in submissions),
                       "honest_ack_in_original_window": sum(m["client_on_time"] for m in matches),
                       "honest_digest_matched_receiver_records": len(matched_records),
                       "honest_receiver_full_work_accepted": tri_counts(matched_records, "full_work_accepted")["true"],
                       "honest_receiver_dispatch_accepted": tri_counts(matched_records, "dispatch_accepted")["true"],
                       "history_calls": len(phase["history"]), "history_calls_on_time": sum(call_on_time(c) for c in phase["history"]),
                       "client_import_calls": len(imports), "client_import_successes": sum(r["succeeded"] for r in imports),
                       "client_import_failures": sum(not r["succeeded"] for r in imports),
                       "receiver_records": len(records), "remaining_receiver_records": len(remaining),
                       "recorded_attack_client_calls": len(attack_calls), "children_without_call_rows": children_without_calls},
            "honest_match_one_to_one": all(v == 1 for v in honest_counts.values()) and all(len(m["receiver_indices"]) == 1 for m in matches),
            "honest_matches": matches, "honest_receiver_full_work_outcomes": tri_counts(matched_records, "full_work_accepted"),
            "honest_receiver_dispatch_outcomes": tri_counts(matched_records, "dispatch_accepted"),
            "remaining_receiver_full_work_outcomes": tri_counts(remaining, "full_work_accepted"),
            "remaining_receiver_scope": "excludes exact honest Submit digest matches; includes History and unknown/authentication rows; not an attribution of every remaining row to an attacker",
            "receiver_coverage": {k: observer[k] for k in ("accepted_connections_seen", "records_not_retained", "counter_overflow", "measurement_failures")},
            "receiver_clock_scope": "observer-local; never subtracted from caller timestamps or directly qualified against the caller window",
            "rounds": round_rows, "imports": imports, "import_error_counts": dict(import_errors),
            "page_owner_mode_counts": dict(page_owners), "packet_attribution_owner_mode_counts": dict(packet_owners),
            "verifier_errors": phase["verifier_errors"], "attack_client_status_counts": dict(Counter(c["status"] for c in attack_calls)),
            "common_required_conditions": common, "attack_required_conditions": attack,
            "failed_required_conditions": [k for k, passed in {**common, **attack}.items() if not passed],
            "reported_phase_pass": phase["finite_phase_criteria_met"], "computed_phase_pass": calculated_phase,
            "budget": budget, "final_actual_flow_equations": None if final_flow is None else flow_equations(final_flow)}


def source_guard(value):
    need(value["schema"] == "trnm-ci-source-v1" and value["kind"] == "head"
         and value["tested_commit"] == value["candidate"] == SOURCE
         and value["tested_tree"] == TREE and value["base"] is None
         and value["prospective_merge"] is None and value["tracked_worktree_verified"] is True
         and value["tests_executed_by_identity_check"] is False, "M source identity mismatch")


def audit(receipt_path):
    need(receipt_path == BASE / "retention-receipt.json", "fixed receipt path required")
    receipt = read_pinned(receipt_path, 2091, RECEIPT_SHA, 65536)
    need(receipt["artifact"] == ARTIFACT, "artifact identity mismatch")
    manifest_info = receipt["original_text_manifest"]
    need(manifest_info["path"] == str(BASE / "original-text-manifest.json")
         and manifest_info["sha256"] == MANIFEST_SHA and manifest_info["bytes"] == 921390,
         "original manifest identity mismatch")
    manifest = read_pinned(manifest_info["path"], manifest_info["bytes"], MANIFEST_SHA, 2 * 1024 * 1024)
    members = {}
    for row in manifest["original_text"]:
        name = row["zip_member"]
        need(name not in members, "duplicate original member")
        members[name] = row

    def original(name):
        row = members[name]
        need(row["retained_path"] == str(BASE / "original-text" / name), "retained member path mismatch")
        return read_pinned(row["retained_path"], row["bytes"], row["sha256"])

    results = original("results.json")
    need(results["expected_head"] == SOURCE and results["expected_tree"] == TREE
         and results["state_backend"] == "authenticated-v1" and results["profile"] == "release"
         and results["toolchain"] == "1.95.0" and results["planned_complete_runs"] == 3
         and results["original_inputs"] == INPUTS and results["finalization_failures"] == [], "original M runner inputs")
    source_guard(results["source_after"])
    source_guard(original("source-before.json"))
    source_guard(original("source-after.json"))
    need(results["build"]["returncode"] == 0 and results["build"]["error"] is None, "original build did not complete")
    need(len(receipt["cohort_reports"]) == 3 and len(results["attempts"]) == 3, "three complete report observations required")
    report_rows = {r["zip_member"]: r for r in receipt["cohort_reports"]}
    need(len(report_rows) == 3, "duplicate cohort report")
    phases, campaigns = [], []
    for run, (size, digest) in REPORTS.items():
        name = f"run-{run}-raw/report.json"
        record = report_rows[name]
        need(record["bytes"] == size and record["sha256"] == digest
             and record["retained_path"] == str(BASE / "original-text" / name)
             and members[name]["sha256"] == digest and members[name]["bytes"] == size,
             "pinned cohort report mismatch")
        attempt = results["attempts"][run - 1]
        need(attempt["number"] == run and attempt["report_sha256"] == digest
             and attempt["phase_startup_errors"] == [] and attempt["report_validation_failure"] is None
             and attempt["step"]["error"] is None and attempt["step"]["returncode"] == 101
             and attempt["step"]["outer_stage_timeout_seconds"] == 600
             and attempt["step"]["stdout_truncated"] is False
             and attempt["step"]["stderr_truncated"] is False,
             "original invocation/report binding mismatch")
        report = read_pinned(record["retained_path"], size, digest)
        need(report["schema"] == "native-public-v3-separate-process-campaign-v2"
             and report["state_backend"] == "authenticated-v1" and len(report["phases"]) == 3,
             "original raw campaign schema")
        prep = report["preparation"]
        need((prep["actual_signed_seed_transfers"], prep["seed_blocks"], prep["business_blocks"])
             == (1024, 4, 21), "raw original workload denominator")
        current = []
        for ordinal, phase in enumerate(report["phases"]):
            phase_name = f"run-{run}-raw/{MODES[ordinal]}.json"
            member = {k: members[phase_name][k] for k in ("zip_member", "bytes", "sha256")}
            current.append(analyze_phase(phase, run, ordinal, record, member))
        calculated = boolean(report["economics_complete"]) and all(p["computed_phase_pass"] for p in current)
        need(boolean(report["finite_experiment_criteria_met"]) == calculated
             and boolean(attempt["original_criteria_met"]) == calculated,
             "campaign decision recomputation mismatch")
        phases.extend(current)
        campaigns.append({"run": run, "report": record, "native_exit": attempt["step"]["returncode"],
                          "elapsed_ns": attempt["step"]["elapsed_ns"], "economics_complete": report["economics_complete"],
                          "reported_campaign_pass": report["finite_experiment_criteria_met"], "computed_campaign_pass": calculated})
        del report
        gc.collect()
    counts, budget_counts, owners, import_errors, remaining_work = Counter(), Counter(), Counter(), Counter(), Counter()
    for phase in phases:
        counts.update(phase["counts"])
        budget_counts.update(phase["budget"]["counts"])
        owners.update(phase["page_owner_mode_counts"])
        import_errors.update(phase["import_error_counts"])
        remaining_work.update(phase["remaining_receiver_full_work_outcomes"])
    counts.update(planned_campaigns=3, planned_phases=9,
                  complete_campaigns=sum(c["computed_campaign_pass"] for c in campaigns))
    confirmed_ids = sorted({r["transaction"] for p in phases for r in p["rounds"] if r["confirmed_inside_pressure_window"]})
    minima = [p["budget"]["minimum_paid_credit_sample"] for p in phases if p["budget"]["minimum_paid_credit_sample"] is not None]
    return {"schema": "original-M-campaign-independent-report-audit-v1", "audit_complete": True,
            "source": SOURCE, "tree": TREE, "artifact": ARTIFACT,
            "input_receipt": {"path": str(receipt_path), "bytes": 2091, "sha256": RECEIPT_SHA},
            "input_manifest": manifest_info, "results_member": members["results.json"],
            "scope": "three hash-pinned original M reports only; original recorded predicates and independent arithmetic; no node replay, new campaign, native execution, consensus oracle, TPS or qualification",
            "archive_and_ELF_reread_by_this_auditor": False,
            "campaigns": campaigns, "phases": phases, "counts": dict(counts),
            "all_honest_phase_joins_one_to_one": all(p["honest_match_one_to_one"] for p in phases),
            "page_owner_mode_counts": dict(owners), "import_error_counts": dict(import_errors),
            "remaining_receiver_full_work_outcomes": dict(remaining_work),
            "confirmed_distinct_transaction_ids": confirmed_ids,
            "budget_counts": dict(budget_counts),
            "minimum_sampled_paid_credit_ns": None if not minima else min(p["actual_flow"]["remaining_paid_credit_ns"] for p in minima),
            "freshness_projection_used": False,
            "causal_limit": "deadline/error and unmet predicates are observed outcomes; this readback does not identify an exclusive CPU bottleneck or prove depletion impossible",
            "current_business_acceptance_passed": all(c["computed_campaign_pass"] for c in campaigns),
            "qualified": {"throughput": False, "WAN": False, "production_activation": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=BASE / "retention-receipt.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(),
         "new absolute audit output required")
    need(args.output.parent.resolve(strict=True) == args.output.parent,
         "canonical existing output parent required")
    need(not args.output.is_relative_to(BASE / "original-text"), "original report directory is read-only")
    script_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    try:
        value = audit(args.receipt)
        need(value["budget_counts"]["flow_equation_mismatch_samples"] == 0
             and value["budget_counts"]["reported_predicate_mismatch_samples"] == 0,
             "original flow/predicate mismatch")
        code = 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        value = {"schema": "original-M-campaign-independent-report-audit-v1", "audit_complete": False,
                 "source": SOURCE, "tree": TREE, "error": type(error).__name__ + ": " + str(error),
                 "scope": "audit refusal, not a new native outcome; no source or original report modified"}
        code = 1
    value.update(auditor_sha256=script_sha, completed_utc=datetime.now(timezone.utc).isoformat())
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({k: value[k] for k in ("audit_complete", "source", "tree", "auditor_sha256")} | {
        "output": str(args.output), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "counts": value.get("counts"), "budget_counts": value.get("budget_counts"), "error": value.get("error")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
