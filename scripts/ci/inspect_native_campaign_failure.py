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
            "total": sum(values) if len(values) == len(rows) else None}


def _checkpoint_calls(history: list) -> dict:
    rows = []
    for item in history:
        imported = item.get("client_import")
        native = imported.get("native_import_observation") if isinstance(imported, dict) else None
        stages = native.get("host_checks") if isinstance(native, dict) else None
        matching = [stage for stage in stages if isinstance(stage, dict) and stage.get("phase") == "checkpoint"] if isinstance(stages, list) else []
        rows.append(matching[0] if len(matching) == 1 else {})
    return _sum_observed(rows, "calls_accepted")


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
    return {
        "mode": name, "requested_attackers": attackers,
        "ready_attackers": phase.get("attacker_processes_ready"),
        "original_business_blocks": 21, "observed_submissions": len(submissions),
        "original_signed_rounds": 3,
        "confirmed_round_observations": sum(row.get("confirmed_inside_pressure_window") is True
                                            for row in confirmations if isinstance(row, dict)),
        "round_observations": len(confirmations),
        "history_calls": len(history),
        "history_network_wall_ns": _sum_observed(history, "elapsed_wall_ns"),
        "history_import_wall_ns": _sum_observed(history, "client_import", "wall_ns"),
        "history_import_thread_cpu_ns": _sum_observed(history, "client_import", "thread_cpu_ns"),
        "history_checkpoint_host_calls": _checkpoint_calls(history),
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
