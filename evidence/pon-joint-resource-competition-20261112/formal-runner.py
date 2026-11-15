#!/usr/bin/env python3
"""Run the frozen DAA formal qualification commands once, retaining all outcomes."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

MODULES = (
    "test_quantum_adversarial_search",
    "test_quantum_network_sim",
    "test_w1_marked_domain",
    "test_quantum_resource_clock",
    "test_quantum_candidate_check_clock",
    "test_quantum_probability_sampling",
    "test_joint_resource_competition_campaign",
    "test_quantum_daa_model",
    "test_fast_daa_reference_component",
    "test_branch_time_daa_v1",
    "test_joint_consensus_qualification",
)
ROOT = Path("/home/qian-qi/work/chain-daa-resource-competition-20261112-600e")


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return raw


def execute(out, label, argv, cwd, timeout):
    stdout_path = out / (label + ".stdout.log")
    stderr_path = out / (label + ".stderr.log")
    started = now()
    monotonic_started = time.monotonic()
    record = {"label": label, "argv": argv, "cwd": str(cwd),
              "started_utc": started, "timeout_seconds": timeout,
              "returncode": None, "timed_out": False, "spawn_error": None,
              "stdout_file": stdout_path.name, "stderr_file": stderr_path.name}
    write_json(out / (label + ".started.json"), record)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUNBUFFERED"] = "1"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            record["pid"] = process.pid
            try:
                record["returncode"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    record["returncode"] = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    record["returncode"] = process.wait(timeout=10)
        except Exception as error:
            record["spawn_error"] = {"type": type(error).__name__, "message": str(error)}
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
    record["ended_utc"] = now()
    record["wall_seconds"] = time.monotonic() - monotonic_started
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        raw = path.read_bytes()
        record[name + "_bytes"] = len(raw)
        record[name + "_sha256"] = sha(raw)
    record["passed"] = record["returncode"] == 0 and not record["timed_out"] and record["spawn_error"] is None
    write_json(out / (label + ".receipt.json"), record)
    print(json.dumps({"label": label, "returncode": record["returncode"], "timed_out": record["timed_out"],
                      "passed": record["passed"], "wall_seconds": record["wall_seconds"]}), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        raise ValueError("EXACT_SOURCE_REQUIRED")
    out = args.out.absolute()
    if out.is_relative_to(ROOT) or not out.is_relative_to(Path("/home/qian-qi/work")):
        raise ValueError("OUTPUT_MUST_BE_EXTERNAL_WORK_DIRECTORY")
    out.mkdir(exist_ok=False)
    python = "/usr/bin/python3"
    formal = ROOT / "formal/pon-nakamoto-v1"
    campaign_dir = out / "campaign"
    source_command = [python, "scripts/ci/verify_ci_source.py", "--kind", "head",
                      "--expected-head", args.source]
    plan = [
        ("00-preflight", ["bash", "scripts/project-preflight.sh"], ROOT, 60),
        ("01-source-before", source_command + ["--output", str(out / "source-before.json")], ROOT, 300),
        ("02-formal-tests", [python, "-m", "unittest", "-v", *MODULES], formal, 1200),
        ("03-campaign", [python, "experiments/joint_resource_competition_campaign.py",
                         "--out", str(campaign_dir)], formal, 1200),
        ("04-replay", [python, "experiments/joint_resource_competition_campaign.py",
                       "--verify", str(campaign_dir)], formal, 1200),
        ("05-source-after", source_command + ["--output", str(out / "source-after.json")], ROOT, 300),
    ]
    write_json(out / "command-plan.json", {
        "schema": "trnm-joint-resource-formal-execution-plan-v1",
        "expected_source": args.source,
        "root": str(ROOT),
        "runner_sha256": sha(Path(__file__).read_bytes()),
        "runner_file": str(Path(__file__).resolve()),
        "python": sys.version,
        "platform": platform.platform(),
        "planned_at_utc": now(),
        "commands": [{"label": label, "argv": argv, "cwd": str(cwd), "timeout_seconds": timeout}
                     for label, argv, cwd, timeout in plan],
        "formal_modules": list(MODULES),
        "campaign": {"runs": 128, "duration_seconds": 3600.0,
                     "per_case_cpu_limit_seconds": 10.0,
                     "seeds": [6101, 6102, 6103, 6104],
                     "replay_is_preplanned_second_execution_of_the_same_seeded_cases": True},
        "environment_overrides": {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        "outer_process_limits": {"cpu_quota_percent": 200, "memory_max_bytes": 8589934592},
        "old_cloud_validation_terminal_outcome": "UNKNOWN",
        "qualification": "conditional research, no production or security theorem",
    })
    records = []
    for label, argv, cwd, timeout in plan[:2]:
        records.append(execute(out, label, argv, cwd, timeout))
        if not records[-1]["passed"]:
            break
    gate = len(records) == 2 and all(record["passed"] for record in records)
    if gate:
        records.append(execute(out, *plan[2]))
        gate = records[-1]["passed"]
    if gate:
        # Exactly one planned campaign invocation. Never drop a failed case or
        # retry with a new seed, horizon, cutoff or resource setting.
        records.append(execute(out, *plan[3]))
        # Read back even a failed/incomplete campaign; retain the strict refusal
        # if originals are incomplete or their independent checks fail.
        records.append(execute(out, *plan[4]))
    records.append(execute(out, *plan[5]))
    source_equal = False
    before, after = out / "source-before.json", out / "source-after.json"
    if before.is_file() and after.is_file():
        source_equal = before.read_bytes() == after.read_bytes()
    expected_labels = [item[0] for item in plan]
    completed_labels = [record["label"] for record in records]
    summary = {"schema": "trnm-joint-resource-formal-execution-v1",
               "source": args.source, "ended_utc": now(),
               "planned_commands": len(plan), "completed_commands": len(records),
               "not_run": [label for label in expected_labels if label not in completed_labels],
               "all_planned_commands_pass": len(records) == len(plan) and all(record["passed"] for record in records),
               "source_before_after_identical": source_equal,
               "commands": records,
               "old_cloud_validation_terminal_outcome": "UNKNOWN",
               "production_consensus_activation": False, "release_ready": False}
    write_json(out / "execution-summary.json", summary)
    files = {}
    for path in sorted(out.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            files[str(path.relative_to(out))] = {"bytes": len(raw), "sha256": sha(raw)}
    write_json(out / "execution-manifest.json", {"schema": "trnm-joint-resource-formal-execution-manifest-v1",
                                                "files": files})
    print(json.dumps({"result": "FORMAL_EXECUTION_RECORDED", "output": str(out),
                      "all_planned_commands_pass": summary["all_planned_commands_pass"],
                      "source_before_after_identical": source_equal,
                      "not_run": summary["not_run"]}), flush=True)
    return 0 if summary["all_planned_commands_pass"] and source_equal else 2


if __name__ == "__main__":
    raise SystemExit(main())
