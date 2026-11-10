#!/usr/bin/env python3
"""Fail-closed read-only diagnostic for the original native campaign Actions ZIP.

This is an artifact reader, not a protocol replay or a production qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

MODES = ("baseline", "from-zero", "late-product")
MAX_REPORT_BYTES = 40_000_000


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def summarize_phase(p):
    mode = p["mode"]
    if mode not in MODES:
        raise ValueError("unknown phase mode")
    if type(p["duration_seconds"]) is not int or p["duration_seconds"] != 30:
        raise ValueError("original phase duration must be 30 seconds")
    if type(p["finite_phase_criteria_met"]) is not bool:
        raise ValueError("invalid phase verdict")
    rounds = p["confirmations"]
    if not isinstance(rounds, list):
        raise ValueError("missing confirmation rows")
    if not all(type(c["confirmed_inside_pressure_window"]) is bool for c in rounds):
        raise ValueError("invalid confirmation field")
    succeeded = sum(c["confirmed_inside_pressure_window"] for c in rounds)
    if len(rounds) > 3:
        raise ValueError("impossible confirmation count")
    flow = p["final_actual_flow"]
    if not isinstance(flow, dict) or flow.get("balance_identity_verified") is not True:
        raise ValueError("unverified CPU balance")
    credit = {k: flow[k] for k in (
        "initial_credit_ns", "paid_cpu_debit_ns",
        "credited_refill_ns", "remaining_paid_credit_ns"
    )}
    if not all(type(v) is int and v >= 0 for v in credit.values()):
        raise ValueError("invalid CPU-credit fields")
    if (credit["initial_credit_ns"] + credit["credited_refill_ns"]
            - credit["paid_cpu_debit_ns"] != credit["remaining_paid_credit_ns"]):
        raise ValueError("inconsistent CPU-credit balance")
    all_confirmed = len(rounds) == 3 and succeeded == 3
    if p["all_signed_rounds_confirmed_in_window"] != all_confirmed:
        raise ValueError("confirmation verdict contradicts raw rounds")
    equal = p["final_receiver_tip"] == p["final_client_tip"]
    reported_state_equal = p["receiver_client_state_equal"]
    if type(reported_state_equal) is not bool or (reported_state_equal and not equal):
        raise ValueError("full state equality contradicts recorded tips")
    # False may mean an auxiliary checked state differed even with equal tips.
    if not isinstance(p["verifier_errors"], list):
        raise ValueError("invalid verifier errors")
    failed = []
    if not all_confirmed:
        failed.append("three_signed_rounds_not_confirmed_in_window")
    if not reported_state_equal:
        failed.append("receiver_client_state_mismatch")
    if not equal:
        failed.append("receiver_client_final_tip_mismatch")
    if p["verifier_errors"]:
        failed.append("verifier_errors_observed")
    if mode != "baseline" and p["genuine_budget_depletion_observed"] is not True:
        failed.append("no_genuine_credit_depletion_observed")
    if p["finite_phase_criteria_met"] is True and failed:
        raise ValueError("success contradicts failures")
    return {
        "mode": mode,
        "duration_seconds": p["duration_seconds"],
        "signed_rounds_started": len(rounds),
        "signed_rounds_confirmed_in_window": succeeded,
        "rounds": [{
            "round": c["round"],
            "started_seconds": round(c["started_ns"] / 1e9, 6),
            "ended_seconds": round(c["ended_ns"] / 1e9, 6),
            "confirmed_in_window": c["confirmed_inside_pressure_window"],
            "observation_present": c["observation"] is not None,
        } for c in rounds],
        "receiver_client_tip_equal": equal,
        "receiver_client_state_equal_reported": reported_state_equal,
        "verifier_errors": p["verifier_errors"],
        "budget_depletion_observed": p["genuine_budget_depletion_observed"],
        "cpu_credit_ns": credit,
        "attacker_processes_ready": p["attacker_processes_ready"],
        "attacker_processes_requested": p["attacker_processes_requested"],
        "attack_actor_reports_successful": p["actor_reports_successful_without_cap_or_kill"],
        "full_work_accepted": p["full_work_accepted"],
        "full_work_failed": p["full_work_failed"],
        "observer_complete": p["observer_complete"],
        "finite_phase_criteria_met": p["finite_phase_criteria_met"],
        "failed_prerequisites_observable": failed,
    }


def triage_zip(archive, expected_digest, run_id, source_head):
    archive = Path(archive)
    h = hashlib.sha256()
    with archive.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            h.update(block)
    actual_digest = h.hexdigest()
    if actual_digest != expected_digest.lower():
        raise ValueError("artifact ZIP SHA-256 mismatch")
    runs = []
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        for i in range(1, 4):
            raw_path = f"run-{i}-raw/report.json"
            result_path = f"run-{i}-result.json"
            if names.count(raw_path) != 1 or names.count(result_path) != 1:
                raise ValueError("missing or duplicate original run member")
            if z.getinfo(raw_path).file_size > MAX_REPORT_BYTES:
                raise ValueError("report exceeds parser bound")
            raw = z.read(raw_path)
            outcome = json.loads(z.read(result_path))
            if sha256(raw) != outcome["report_sha256"]:
                raise ValueError("raw report mismatches recorded runner SHA")
            if outcome["step"]["returncode"] != 101 or outcome["complete_success"] is not False:
                raise ValueError("run outcome differs from original failure")
            if outcome["report_validation_failure"] is not None or outcome["phase_startup_errors"]:
                raise ValueError("startup/report invalid; different failure profile")
            report = json.loads(raw)
            if report["finite_experiment_criteria_met"] is not False:
                raise ValueError("original report did not fail")
            if tuple(p["mode"] for p in report["phases"]) != MODES:
                raise ValueError("missing/duplicate/reordered phase")
            phases = [summarize_phase(p) for p in report["phases"]]
            if any(p["finite_phase_criteria_met"] for p in phases):
                raise ValueError("unexpected passing phase")
            runs.append({
                "run": i, "member": raw_path, "raw_sha256": sha256(raw),
                "returncode": outcome["step"]["returncode"],
                "economics_complete": report["economics_complete"],
                "phases": phases
            })
    return {
        "schema": "original-native-campaign-artifact-triage-v1",
        "scope": "Original hosted artifact diagnostic, not independent execution authentication, unique failure-cause proof, new acceptance or production permission",
        "source_head_from_github_run_metadata": source_head,
        "run_id_from_github_metadata": run_id,
        "artifact_zip_sha256": actual_digest,
        "status": "HOLD",
        "original_runs_passed": 0,
        "original_runs_total": 3,
        "production_activation": False,
        "whole_chain_pq_qualified": False,
        "actual_lifetime_failure_bound": None,
        "runs": runs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip", type=Path)
    parser.add_argument("--expected-zip-sha256", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = triage_zip(args.zip, args.expected_zip_sha256,
                        args.run_id, args.source_head)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("HOLD: original native campaign 0/3; wrote", args.output)


if __name__ == "__main__":
    main()
