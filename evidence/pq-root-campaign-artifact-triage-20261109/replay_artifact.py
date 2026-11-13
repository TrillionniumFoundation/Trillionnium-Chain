#!/usr/bin/env python3
"""Lossless-source, bounded-output triage of original native campaign Actions artifacts.

This is an offline artifact READER, not a new campaign or a qualification test.
It never changes the original workload, test predicates, budgets, or production state.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

MODES = ("baseline", "from-zero", "late-product")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_json(archive, name):
    return json.loads(archive.read(name))


def analyze(path, expected_zip_sha, expected_commit):
    path = Path(path)
    # Archive raw bytes are checked against the independent GitHub artifact digest.
    actual_zip_sha = sha256(path.read_bytes())
    require(actual_zip_sha == expected_zip_sha, "ARTIFACT_SHA_MISMATCH")
    with ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "DUPLICATE_ZIP_MEMBER")
        summary = read_json(archive, "results.json")
        require(summary["expected_head"] == expected_commit, "WRONG_EXECUTED_COMMIT")
        require(summary["profile"] == "release", "CHANGED_PROFILE")
        require(summary["planned_complete_runs"] == 3, "CHANGED_RUN_DENOMINATOR")
        require(summary["original_inputs"] == {
            "attacker_processes": [0, 24, 24],
            "business_blocks": 21,
            "modes": list(MODES),
            "phase_seconds": 30,
            "seed_blocks": 4,
            "seed_transfers": 1024,
        }, "CHANGED_ORIGINAL_INPUTS")
        require(summary["public_phase_placement"]["receiver_and_verifier_cpu_max"] == "25000 100000", "CHANGED_CPU_LIMIT")
        require(summary["public_phase_placement"]["receiver_and_verifier_memory_max"] == "2147483648", "CHANGED_MEMORY_LIMIT")
        require(summary["expected_resources"]["cpu_max"] == "400000 100000", "CHANGED_CONTROLLER_CPU_LIMIT")
        require(len(summary["attempts"]) == 3, "MISSING_ATTEMPT")
        rows = []
        for run, receipt in enumerate(summary["attempts"], start=1):
            require(receipt["number"] == run, "WRONG_RUN_IDENTITY")
            report_path = f"run-{run}-raw/report.json"
            report_bytes = archive.read(report_path)
            require(sha256(report_bytes) == receipt["report_sha256"], "FULL_REPORT_SHA_MISMATCH")
            report = json.loads(report_bytes)
            require(len(report["phases"]) == 3, "INCOMPLETE_PHASES")
            require(report["economics_complete"] is True, "ECONOMICS_INCOMPLETE")
            require(report["finite_experiment_criteria_met"] is False, "UNEXPECTED_CAMPAIGN_SUCCESS")
            require(receipt["step"]["returncode"] == 101, "CHANGED_NATIVE_EXIT")
            require(receipt["phase_startup_errors"] == [], "PHASE_STARTUP_ERRORS_PRESENT")
            for mode, phase in zip(MODES, report["phases"]):
                require(phase["mode"] == mode, "CHANGED_PHASE_ORDER")
                # Compare full parsed report phase against the separately retained raw phase.
                require(phase == read_json(archive, f"run-{run}-raw/{mode}.json"), "PHASE_REPORT_DIVERGENCE")
                host = read_json(archive, f"run-{run}-raw/{mode}-host-control/host/controller-result.json")
                require(host["host_readiness_only"] is True and host["passed"] is True, "HOST_READINESS_NOT_ESTABLISHED")
                service = phase["service_outcome"].get("Ok")
                require(isinstance(service, dict), "MISSING_SERVICE_OUTCOME")
                submissions = phase["submissions"]
                confirmation = phase["confirmations"]
                rows.append({
                    "run": run,
                    "mode": mode,
                    "original_seconds": phase["duration_seconds"],
                    "attacker_processes_ready": phase["attacker_processes_ready"],
                    "submissions": len(submissions),
                    "successful_submissions": sum(s["status"] == "ok" for s in submissions),
                    "submission_errors": dict(sorted(Counter(str(s["error"]) for s in submissions if s["error"]).items())),
                    "round_confirmations_observed": len(confirmation),
                    "rounds_confirmed_within_window": sum(c.get("confirmed_inside_pressure_window") is True for c in confirmation),
                    "all_signed_rounds_confirmed_in_window": phase["all_signed_rounds_confirmed_in_window"],
                    "receiver_client_state_equal": phase["receiver_client_state_equal"],
                    "genuine_budget_depletion_observed": phase["genuine_budget_depletion_observed"],
                    "paid_cpu_credit_remaining_ns": phase["final_actual_flow"]["remaining_paid_credit_ns"],
                    "work_accepted": phase["full_work_accepted"],
                    "work_failed": phase["full_work_failed"],
                    "executor_refusals": service["executor_refusals"],
                    "verifier_errors": phase["verifier_errors"],
                    "host_readiness_passed": True,
                    "finite_phase_criteria_met": phase["finite_phase_criteria_met"],
                })
    require(len(rows) == 9, "MISSING_ORIGINAL_PHASE")
    require(all(x["finite_phase_criteria_met"] is False for x in rows), "UNEXPECTED_PHASE_SUCCESS")
    return {
        "artifact_sha256": actual_zip_sha,
        "artifact_bytes": path.stat().st_size,
        "executed_head": expected_commit,
        "source_and_binary_receipts": "See complete artifact results.json; this analysis does not authenticate the executor.",
        "complete_original_campaigns_passed": 0,
        "complete_original_campaigns_expected": 3,
        "complete_original_phases_passed": 0,
        "complete_original_phases_expected": 9,
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", nargs=3, metavar=("ZIP", "SHA256", "HEAD"), required=True)
    args = parser.parse_args()
    artifacts = [analyze(*a) for a in args.artifact]
    rows = [row for artifact in artifacts for row in artifact["rows"]]
    print(json.dumps({
        "schema": "trnm-native-campaign-artifact-comparison-v1",
        "claim": "offline GitHub artifact readback, not a native rerun or root qualification",
        "artifact_count": len(artifacts),
        "phase_count": len(rows),
        "original_phases_passed": sum(row["finite_phase_criteria_met"] is True for row in rows),
        "signed_round_confirmations_within_window": sum(row["rounds_confirmed_within_window"] for row in rows),
        "budget_depletions_observed": sum(row["genuine_budget_depletion_observed"] is True for row in rows),
        "state_equal_phase_count": sum(row["receiver_client_state_equal"] is True for row in rows),
        "qualification_status": "HOLD_NO_GO",
        "production_activation": False,
        "root_cause_uniquely_identified": False,
        "artifacts": artifacts,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
