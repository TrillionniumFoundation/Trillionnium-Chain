#!/usr/bin/env python3
"""Render and classify one already sealed Node union. Does not run Cargo."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
TOOLS = ROOT / "recovery-evidence-tools"
OUT = TOOLS / "node-union-finalization-v1"
UNION = TOOLS / "node-cross-run-coverage-v1.json"
UNION_SHA = "e858131ad9b7e9e0ceb83a57d5c2bb665adbac6b395fedacd59f2d8a3e6ddde2"
DIAGNOSIS = TOOLS / "node-690f-diagnosis-v1.json"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"
NATIVE = ("no_gain_fees", "funded_service_contract", "native_demand_evidence",
          "native_task_operation_v2", "native_active_anchor")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fact(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write(name, raw):
    path = OUT / name
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def write_json(name, value):
    return write(name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def main():
    OUT.mkdir()
    union_id = fact(UNION)
    assert union_id["bytes"] == 918710 and union_id["sha256"] == UNION_SHA
    data = json.loads(UNION.read_bytes())
    assert data["schema"] == "pon-node-cross-run-coverage-diagnostic-recovery-v1"
    assert data["result"] == "COVERAGE_DIAGNOSTIC_RECORDED" and data["errors"] == []
    assert data["source_commit"] == COMMIT and data["source_tree"] == TREE
    assert data["qualification"] is False and data["single_complete_cargo_gate"] is False
    assert data["controlled_run_qualification_passed"] is False
    assert data["all_targets_have_unambiguous_complete_summary"] is True
    for key, n in (("inventory_target_count", 91), ("original_assignment_count", 30),
                   ("remainder_assignment_count", 61), ("completed_target_count", 91)):
        assert type(data[key]) is int and data[key] == n
    original = data["original_run"]
    remainder = data["remainder_run"]
    assert original["provenance"]["job_id"] == original["terminal"]["job_id"] == "1a1b6390138-12894-305"
    assert remainder["provenance"]["job_id"] == remainder["terminal"]["job_id"] == "1a1b6b4fa87-12894-60d"
    assert original["terminal"]["state"] == "timed_out" and original["terminal"]["exit_code"] == 124
    assert remainder["terminal"]["state"] == "failed" and remainder["terminal"]["exit_code"] == 101
    assert type(remainder["native_cargo_exit_code"]) is int and remainder["native_cargo_exit_code"] == 101
    assert remainder["native_result_present"] is True and remainder["native_log_bound"] is True
    assert original["source_after_missing_not_repaired_by_remainder"] is True
    assert remainder["source_after_present"] is True and remainder["source_before_after_identical"] is True
    wanted = {"passed": 1548, "failed": 15, "ignored": 55, "measured": 0, "filtered_out": 0}
    for key, n in wanted.items():
        assert type(data["cross_run_completed_target_totals"][key]) is int
        assert data["cross_run_completed_target_totals"][key] == n
    native_rows = []
    for name in NATIVE:
        matches = [r for r in data["coverage"] if r["target"]["kind"] == ["test"] and r["target"]["name"] == name]
        assert len(matches) == 1
        row = matches[0]
        assert row["counted_once"] is True and row["counted_summary"] is not None
        native_rows.append({"name": name, "target_key": row["target_key"],
                            "run": row["assigned_run"], "status": row["status"],
                            "counts": {k: row["counted_summary"][k] for k in wanted},
                            "provenance": row["summary_provenance"], "qualification": False})
    diagnosis_id = fact(DIAGNOSIS)
    assert diagnosis_id["sha256"] == "99dddd4fe1ec2249b02bd20da57b4a1a62803d7d108769be7e23ec4dbf6ea358"
    summary = {
        "schema": "pon-node-cross-run-coverage-summary-v1",
        "union": union_id, "source_commit": COMMIT, "source_tree": TREE,
        "original_job": original["provenance"]["job_id"], "remainder_job": remainder["provenance"]["job_id"],
        "original_terminal": original["terminal"], "remainder_terminal": remainder["terminal"],
        "original_log": original["provenance"]["raw_log"], "remainder_log": remainder["provenance"]["raw_log"],
        "inventory_target_count": data["inventory_target_count"],
        "original_assignment_count": data["original_assignment_count"],
        "remainder_assignment_count": data["remainder_assignment_count"],
        "completed_target_count": data["completed_target_count"],
        "all_targets_have_unambiguous_complete_summary": data["all_targets_have_unambiguous_complete_summary"],
        "uncovered_or_ambiguous_targets": data["uncovered_or_ambiguous_targets"],
        "original_completed_target_totals": data["original_completed_target_totals"],
        "remainder_completed_target_totals": data["remainder_completed_target_totals"],
        "cross_run_completed_target_totals": data["cross_run_completed_target_totals"],
        "original_source_after_present": original["provenance"]["source_after_present"],
        "remainder_source_after_present": remainder["source_after_present"],
        "remainder_source_before_after_identical": remainder["source_before_after_identical"],
        "remainder_native_cargo_exit_code": remainder["native_cargo_exit_code"],
        "native_five_targets": native_rows, "original_failure_diagnosis": diagnosis_id,
        "qualification": False, "single_complete_cargo_gate": False,
        "controlled_run_qualification_passed": False,
        "original_failures_superseded": False, "original_timeout_reclassified": False,
        "nested_summaries_added_to_totals": False,
        "scope": "Actual 91-target counting coverage across two independent invocations; not a complete successful Cargo gate.",
    }
    summary_id = write_json("coverage-summary.json", summary)
    steps = []
    commands = [
        ("render", [sys.executable, str(TOOLS / "render_node_union_report_recovery_v1.py"),
                    "--union", str(UNION), "--output-directory", str(TOOLS / "node-91-target-report-v1"),
                    "--original-diagnosis", str(DIAGNOSIS)]),
        ("classify", [sys.executable, str(TOOLS / "extract_node_failure_classification_recovery_v1.py"),
                      "--union", str(UNION), "--union-sha256", UNION_SHA,
                      "--original-diagnosis", str(DIAGNOSIS),
                      "--output-directory", str(TOOLS / "node-failure-classification-v1")]),
    ]
    for label, command in commands:
        start = time.time()
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        step = {"name": label, "command": command, "exit_code": result.returncode,
                "elapsed_seconds": time.time() - start,
                "stdout": write(label + ".stdout.log", result.stdout),
                "stderr": write(label + ".stderr.log", result.stderr),
                "script": fact(Path(command[1])), "qualification": False}
        write_json(label + ".receipt.json", step)
        steps.append(step)
    assert fact(UNION) == union_id
    final = {"schema": "pon-node-final-report-rendering-v1",
             "coverage_summary": summary_id, "union": union_id,
             "steps": steps, "script": fact(Path(__file__)),
             "qualification": False, "tests_started": False,
             "all_rendering_commands_exit_zero": all(step["exit_code"] == 0 for step in steps)}
    final_id = write_json("finalization.json", final)
    print(json.dumps({"finalization": final_id, "coverage_summary": summary_id,
                      "native_five": [{"name": r["name"], "run": r["run"], "status": r["status"], "counts": r["counts"]} for r in native_rows],
                      "steps": [{"name": s["name"], "exit_code": s["exit_code"]} for s in steps],
                      "qualification": False}, sort_keys=True))
    return 0 if final["all_rendering_commands_exit_zero"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
