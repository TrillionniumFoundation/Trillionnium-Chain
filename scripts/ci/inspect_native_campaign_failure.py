#!/usr/bin/env python3
"""Compact ORIGINAL native-campaign failure facts; never issue a PASS verdict.

Inputs are the three fixed raw campaign reports. Missing/malformed runs and
nonoriginal workloads stay visible; no retries, changed thresholds, or silent
shrinking of denominators. This is *diagnostic*, not execution evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

RUNS = 3
PHASES = (("baseline", 0), ("from-zero", 24), ("late-product", 24))
SCHEMA = "native-public-v3-separate-process-campaign-v2"
MAX_REPORT_BYTES = 128 * 1024 * 1024
PACKET_PHASES = (
    "context_owner_wait", "context", "work", "admission_owner_wait",
    "admission", "admission_prepare", "execution", "commit_owner_wait",
    "commit", "history_import",
)


def _sum_observed(rows: list, *keys: str) -> dict:
    """Never silently turn missing timing into zero or add unlike intervals."""
    values = []
    for row in rows:
        value = row
        for key in keys:
            value = value.get(key) if isinstance(value, dict) else None
        if type(value) is int and value >= 0:
            values.append(value)
    return {"records": len(rows), "observed": len(values),
            "total": sum(values) if rows and len(values) == len(rows) else None}


def _checkpoint_observations(history: list) -> dict:
    """Actual fresh Host checks; CPU is nested inside History import CPU.

    A missing/malformed stage is not a zero-cost check, and the same phase
    may not be counted twice. This is a measurement, not permission to cache
    kernel identity, thread membership or resource limits.
    """
    rows = []
    for item in history:
        imported = item.get("client_import")
        native = imported.get("native_import_observation") if isinstance(imported, dict) else None
        stages = native.get("host_checks") if isinstance(native, dict) else None
        matching = [stage for stage in stages if isinstance(stage, dict)
                    and stage.get("phase") == "checkpoint"] if isinstance(stages, list) else []
        rows.append(matching[0] if len(matching) == 1 else {})
    names = ("calls_started", "calls_completed", "calls_accepted",
             "calls_rejected", "calls_unfinished", "cpu_clock_unknown_calls",
             "wall_clock_unknown_calls", "thread_cpu_ns", "wall_ns")
    return {name: _sum_observed(rows, name) for name in names}


def _checkpoint_fraction(checks: dict, import_cpu: dict) -> int | None:
    """Measured nested CPU fraction, in ppm, NEVER a potential speedup."""
    spent = checks["thread_cpu_ns"]["total"]
    whole = import_cpu["total"]
    if spent is None or whole is None or whole == 0:
        return None
    return spent * 1_000_000 // whole


def _packet_stage_observations(history: list) -> dict:
    """Keep per-native-packet phase spans distinct; nested intervals overlap."""
    observed = {name: [] for name in PACKET_PHASES}
    missing_lists = 0
    count = 0
    for item in history:
        imported = item.get("client_import")
        native = imported.get("native_import_observation") if isinstance(imported, dict) else None
        packets = native.get("packets") if isinstance(native, dict) else None
        if not isinstance(packets, list):
            missing_lists += 1
            continue
        for packet in packets:
            count += 1
            entries = packet.get("phases") if isinstance(packet, dict) else None
            for name in PACKET_PHASES:
                matches = [entry for entry in entries if isinstance(entry, dict)
                           and entry.get("phase") == name] if isinstance(entries, list) else []
                observed[name].append(matches[0] if len(matches) == 1 else {})
    return {
        "history_calls_missing_packet_list": missing_lists,
        "native_packet_instances": count,
        "phases": {name: {"wall_ns": _sum_observed(rows, "wall_ns"),
                          "thread_cpu_ns": _sum_observed(rows, "thread_cpu_ns")}
                   for name, rows in observed.items()},
        "non_additive": "admission contains its prepare/commit; history_import contains packets; no category totals should be summed together",
    }


TERMINAL_STAGES = ("admission", "commit", "submit_result", "history_import")


def _terminal_import_boundary(history: list) -> dict:
    """Observe the *last* History import; this is diagnostic, not causal proof.

    Outer HTTP read status can be ok while native import fails. Nested admission
    and commit may propagate one deadline; classify only the earliest observed
    failing stage. Missing/duplicate packet-stage evidence is unknown, not a
    silent success or zero duration.
    """
    record = {"last_history_present": bool(history), "network_status": None,
              "network_error": None, "client_import_succeeded": None,
              "client_import_error": None, "boundary_stage": None,
              "boundary_status": "unknown", "native_packet_count": None,
              "stage_observations": {},
              "warning": "diagnostic only; not proof of cause, atomic commit, or qualification"}
    if not history or not isinstance(history[-1], dict):
        return record
    last = history[-1]
    record["network_status"] = last.get("status")
    record["network_error"] = last.get("error")
    imported = last.get("client_import")
    if not isinstance(imported, dict):
        return record
    record["client_import_succeeded"] = imported.get("succeeded")
    record["client_import_error"] = imported.get("error")
    native = imported.get("native_import_observation")
    packets = native.get("packets") if isinstance(native, dict) else None
    if not isinstance(packets, list):
        return record
    record["native_packet_count"] = len(packets)
    if len(packets) != 1 or not isinstance(packets[0], dict):
        return record
    spans = packets[0].get("phases")
    if not isinstance(spans, list):
        return record
    for name in TERMINAL_STAGES:
        matching = [s for s in spans if isinstance(s, dict) and s.get("phase") == name]
        if len(matching) != 1:
            record["stage_observations"][name] = {"ambiguous_or_absent": True}
            return record
        s = matching[0]
        record["stage_observations"][name] = {
            "started": s.get("started"), "completed": s.get("completed"),
            "accepted": s.get("accepted"), "error_code": s.get("error_code"),
        }
    # Retain the raw observations, but do not classify malformed or conflicting
    # flags. In particular bool is distinct from int in the original JSON.
    for stage in record["stage_observations"].values():
        started, completed, accepted, error = (
            stage["started"], stage["completed"], stage["accepted"], stage["error_code"])
        if (type(started) is not bool or type(completed) is not bool
                or (accepted is not None and type(accepted) is not bool)):
            return record
        if completed:
            if (not started or type(accepted) is not bool
                    or (accepted and error is not None)
                    or (not accepted and (not isinstance(error, str) or not error))):
                return record
        elif started or accepted is not None or error is not None:
            return record
    if type(imported.get("succeeded")) is not bool:
        return record
    if imported.get("succeeded") is True:
        # A report's claimed success cannot turn absent/unentered native stages
        # or a failed outer transport into an affirmative clean import.
        # Evidence for every named terminal stage must be returned and accepted.
        if (last.get("status") == "ok" and last.get("error") is None
                and imported.get("error") is None
                and all(stage["started"] is True and stage["completed"] is True
                        and stage["accepted"] is True
                        for stage in record["stage_observations"].values())):
            record["boundary_status"] = "no_terminal_import_failure"
        return record
    if imported.get("error") != "PUBLIC_REQUEST_DEADLINE":
        return record
    for name in TERMINAL_STAGES:
        stage = record["stage_observations"][name]
        if (stage["completed"] is True and stage["accepted"] is False
                and stage["error_code"] == "PUBLIC_REQUEST_DEADLINE"):
            record["boundary_stage"] = name
            record["boundary_status"] = "observed_deadline_at_stage"
            break
    return record


def _reported_native_confirmation_timing(confirmations: list, window_seconds: int) -> dict:
    """Preserve *reported* native success after the original deadline.

    A reported depth-six observation after 30 s is not an in-window
    confirmation. Missing or inconsistent clocks remain unknown rather than
    being silently classified as an on-time or late success. This does not
    independently verify signatures or grant a PASS.
    """
    window_ns = window_seconds * 1_000_000_000
    observed = 0
    late = []
    unknown_timing = 0
    conflicts = 0
    for index, row in enumerate(confirmations):
        value = row.get("observation")
        if not isinstance(value, dict):
            continue
        qualifies = (value.get("confirmed") is True
                     and value.get("finalized") is False
                     and value.get("execution_authority") is False
                     and type(value.get("depth")) is int
                     and value["depth"] == 6)
        if not qualifies:
            continue
        observed += 1
        ended = row.get("ended_ns")
        reported_on_time = row.get("confirmed_inside_pressure_window")
        if type(ended) is not int or ended < 0 or type(reported_on_time) is not bool:
            unknown_timing += 1
            continue
        if ended >= window_ns and reported_on_time is False:
            late.append({"round_index": index, "ended_ns": ended,
                         "over_deadline_ns": ended - window_ns})
        elif ended >= window_ns and reported_on_time is True:
            # Source reports conflicting signed-window evidence: not a pass.
            conflicts += 1
    return {
        "native_confirmation_reported": observed,
        "native_confirmation_reported_after_deadline": len(late),
        "after_deadline_rounds": late,
        "qualifying_observations_with_unknown_timing": unknown_timing,
        "deadline_conflicts": conflicts,
        "scope": "reported original native confirmation depth=6 only; not signature re-verification, in-window success, causal proof or qualification",
    }



def _final_history_page_activation(history: list) -> dict:
    """Characterize original last-page submit_result work without PASS inference.

    Bounded to the seven-page pattern observed in the three 6c35f94 native
    baseline reports. Unknown/malformed/duplicate spans remain UNKNOWN. Stage
    timing is nested in history_import and cannot be added to import CPU.
    """
    result = {
        "status": "unknown",
        "history_count": len(history) if isinstance(history, list) else None,
        "pages": [],
        "last_submit_result_wall_ns": None,
        "last_submit_result_thread_cpu_ns": None,
        "last_import_wall_ns": None,
        "prior_six_import_wall_median_ns": None,
        "last_vs_prior_six_import_wall_delta_ns": None,
        "same_last_two_packet_hex_chars": None,
        "qualification": False,
        "interpretation": (
            "Original reported stage intervals only; submit_result is nested "
            "in history_import. Not a proof of cause, avoidable cost, "
            "budget relaxation or service acceptance."
        ),
    }
    if not isinstance(history, list) or len(history) != 7:
        return result
    pages = []
    for index, row in enumerate(history):
        if not isinstance(row, dict):
            return result
        response = row.get("response")
        value = response.get("value") if isinstance(response, dict) else None
        page_packets = value.get("packets") if isinstance(value, dict) else None
        complete = value.get("complete") if isinstance(value, dict) else None
        imported = row.get("client_import")
        native = imported.get("native_import_observation") if isinstance(imported, dict) else None
        local_packets = native.get("packets") if isinstance(native, dict) else None
        if (type(complete) is not bool or not isinstance(page_packets, list)
                or len(page_packets) != 1 or type(page_packets[0]) is not str
                or not isinstance(local_packets, list) or len(local_packets) != 1
                or not isinstance(local_packets[0], dict)):
            return result
        phases = local_packets[0].get("phases")
        matches = ([stage for stage in phases if isinstance(stage, dict)
                    and stage.get("phase") == "submit_result"]
                   if isinstance(phases, list) else [])
        if len(matches) != 1:
            return result
        submit = matches[0]
        wall = imported.get("wall_ns")
        cpu = imported.get("thread_cpu_ns")
        if (type(wall) is not int or wall < 0 or type(cpu) is not int or cpu < 0
                or type(submit.get("started")) is not bool
                or type(submit.get("completed")) is not bool):
            return result
        started = submit["started"]
        if started:
            if (submit.get("completed") is not True
                    or submit.get("accepted") is not True
                    or submit.get("error_code") is not None
                    or type(submit.get("wall_ns")) is not int
                    or submit["wall_ns"] < 0
                    or submit["wall_ns"] > wall
                    or type(submit.get("thread_cpu_ns")) is not int
                    or submit["thread_cpu_ns"] < 0):
                return result
        elif (submit.get("completed") is not False
              or submit.get("accepted") is not None
              or submit.get("error_code") is not None
              or submit.get("wall_ns") is not None
              or submit.get("thread_cpu_ns") is not None):
            return result
        pages.append({
            "index": index, "complete": complete,
            "packet_hex_chars": len(page_packets[0]),
            "client_import_wall_ns": wall,
            "client_import_thread_cpu_ns": cpu,
            "submit_result_started": started,
            "submit_result_wall_ns": submit.get("wall_ns"),
            "submit_result_thread_cpu_ns": submit.get("thread_cpu_ns"),
        })
    result["pages"] = pages
    if (all(not page["complete"] and not page["submit_result_started"]
            for page in pages[:6])
            and pages[6]["complete"] and pages[6]["submit_result_started"]):
        earlier = sorted(page["client_import_wall_ns"] for page in pages[:6])
        median = (earlier[2] + earlier[3]) // 2
        result.update({
            "status": "observed_final_page_activation",
            "last_submit_result_wall_ns": pages[6]["submit_result_wall_ns"],
            "last_submit_result_thread_cpu_ns": pages[6]["submit_result_thread_cpu_ns"],
            "last_import_wall_ns": pages[6]["client_import_wall_ns"],
            "prior_six_import_wall_median_ns": median,
            "last_vs_prior_six_import_wall_delta_ns": (
                pages[6]["client_import_wall_ns"] - median
            ),
            "same_last_two_packet_hex_chars": (
                pages[6]["packet_hex_chars"] == pages[5]["packet_hex_chars"]
            ),
        })
    return result

def _phase(phase: dict, name: str, attackers: int) -> dict:
    history = phase.get("history", [])
    submissions = phase.get("submissions", [])
    confirmations = phase.get("confirmations", [])
    if not all(isinstance(value, list) and all(isinstance(row, dict) for row in value)
               for value in (history, submissions, confirmations)):
        raise ValueError("history, submissions and confirmations must be arrays")
    errors = phase.get("verifier_errors", [])
    if not isinstance(errors, list):
        raise ValueError("verifier_errors must be an array")
    original_inputs = (phase.get("mode") == name
                       and phase.get("duration_seconds") == 30
                       and phase.get("attacker_processes_requested") == attackers)
    flags = {
        "original_inputs": original_inputs,
        "observer_complete": phase.get("observer_complete") is True,
        "signed_rounds_confirmed": phase.get("all_signed_rounds_confirmed_in_window") is True,
        "receiver_client_state_equal": phase.get("receiver_client_state_equal") is True,
        "no_verifier_errors": not errors,
        "reported_finite_phase_criteria_met": phase.get("finite_phase_criteria_met") is True,
    }
    if attackers:
        flags["all_24_attackers_ready"] = phase.get("attacker_processes_ready") == attackers
        flags["budget_depletion_observed"] = phase.get("genuine_budget_depletion_observed") is True
        flags["attacker_actors_successful"] = phase.get("actor_reports_successful_without_cap_or_kill") is True
    signals = [key for key, value in flags.items() if not value]
    checkpoints = _checkpoint_observations(history)
    import_cpu = _sum_observed(history, "client_import", "thread_cpu_ns")
    return {
        "mode": name, "requested_attackers": attackers,
        "ready_attackers": phase.get("attacker_processes_ready"),
        "original_business_blocks": 21, "observed_submissions": len(submissions),
        "original_signed_rounds": 3,
        "confirmed_round_observations": sum(row.get("confirmed_inside_pressure_window") is True
                                            for row in confirmations if isinstance(row, dict)),
        "round_observations": len(confirmations),
        "reported_native_confirmation_timing": _reported_native_confirmation_timing(
            confirmations, 30),
        "history_calls": len(history),
        "history_network_wall_ns": _sum_observed(history, "elapsed_wall_ns"),
        "history_import_wall_ns": _sum_observed(history, "client_import", "wall_ns"),
        "history_import_thread_cpu_ns": import_cpu,
        "history_checkpoint_host_calls": checkpoints["calls_accepted"],
        "history_checkpoint_host_observations": checkpoints,
        "history_checkpoint_cpu_fraction_ppm": _checkpoint_fraction(checkpoints, import_cpu),
        "history_checkpoint_scope": (
            "Original kernel check each time: boot, root-owned inode, calling-thread "
            "membership and five fresh limits; CPU nested in import, not an avoidable-cost claim"
        ),
        "native_packet_stage_observations": _packet_stage_observations(history),
        "terminal_history_import_boundary": _terminal_import_boundary(history),
        "final_history_page_activation": _final_history_page_activation(history),
        "submit_client_wall_ns": _sum_observed(submissions, "elapsed_wall_ns"),
        "full_work_accepted": phase.get("full_work_accepted"),
        "full_work_failed": phase.get("full_work_failed"),
        "verifier_errors": errors, "flags": flags, "unmet_flags": signals,
        "timing_rule": "Separate sequential-call totals; nested Host/commit/CPU intervals are NOT additive across categories",
    }


def _read_report(path: Path) -> tuple[dict, str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("missing, symlink or oversized original report")
    raw = path.read_bytes()
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("original report must be an object")
    return result, hashlib.sha256(raw).hexdigest()


def inspect(root: Path) -> dict:
    runs = []
    for number in range(1, RUNS + 1):
        path = root / f"run-{number}-raw" / "report.json"
        record = {"run": number, "report_path": f"run-{number}-raw/report.json",
                  "original_input_shape_valid": False, "reported_finite_experiment_criteria_met": False,
                  "phases": [], "report_sha256": None, "error": None}
        try:
            report, digest = _read_report(path)
            record["report_sha256"] = digest
            stages = report.get("phases")
            if (report.get("schema") != SCHEMA or report.get("state_backend") != "authenticated-v1"
                    or not isinstance(stages, list) or len(stages) != len(PHASES)
                    or any(not isinstance(stage, dict) for stage in stages)):
                raise ValueError("unexpected native campaign schema/backend/phase denominator")
            prep = report.get("preparation", {})
            if not isinstance(prep, dict):
                raise ValueError("preparation must be an object")
            if (prep.get("actual_signed_seed_transfers") != 1024
                    or prep.get("seed_blocks") != 4 or prep.get("business_blocks") != 21):
                raise ValueError("original honest workload denominator changed")
            record["phases"] = [_phase(stage, name, attackers)
                                for stage, (name, attackers) in zip(stages, PHASES)]
            record["original_input_shape_valid"] = all(
                phase["flags"]["original_inputs"] for phase in record["phases"])
            record["reported_finite_experiment_criteria_met"] = (
                report.get("finite_experiment_criteria_met") is True)
            record["reported_economics_complete"] = (report.get("economics_complete") is True)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        runs.append(record)
    return {
        "schema": "pon-native-campaign-failure-inspection-v1",
        "diagnostics_only": True, "executes_native_test": False,
        "grants_qualification_or_activation": False,
        "original_run_denominator": RUNS,
        "report_files_with_original_input_shape": sum(r["original_input_shape_valid"] for r in runs),
        "reported_finite_criteria_true_runs": sum(r["reported_finite_experiment_criteria_met"] for r in runs),
        "scope": "Raw source-bound reports; reported booleans are not independently reexecuted, source/head/merge checks remain separate",
        "runs": runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Original campaign artifact directory")
    parser.add_argument("--output", type=Path, required=True, help="New immutable diagnostic output file")
    args = parser.parse_args()
    result = inspect(args.root)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"Original campaign diagnostic reports: {result['report_files_with_original_input_shape']}/{RUNS}; "
          f"reported complete: {result['reported_finite_criteria_true_runs']}/{RUNS}; diagnostics only")


if __name__ == "__main__":
    main()
