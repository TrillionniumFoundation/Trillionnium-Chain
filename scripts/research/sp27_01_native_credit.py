#!/usr/bin/env python3
"""Run the explicit SP27-01 native accounting test with a complete process roster.

The Rust test owns all protocol operations. This supervisor retains starts,
normal/rejected/cancelled outcomes, and a genuinely terminated partial attempt.
Process CPU is inclusive diagnostic telemetry, not a sum of nested stage costs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

TEST = "sp27_cost_attribution_tests::native_credit_observer"
MODES = ("full", "cancel", "fail", "unfinished")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def append_event(stream, value: dict) -> None:
    stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


def terminate_owned_process(proc: subprocess.Popen) -> None:
    """Only the fresh process group created by this invocation is addressed."""
    if proc.poll() is not None:
        return
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)


def run(args: argparse.Namespace) -> int:
    repo, binary, out = args.repo.resolve(), args.binary.resolve(), args.output.resolve()
    if git(repo, "rev-parse", "HEAD") != args.source_sha:
        raise ValueError("implementation HEAD differs from frozen source SHA")
    if git(repo, "rev-parse", "HEAD^{tree}") != args.source_tree:
        raise ValueError("implementation tree differs from frozen source tree")
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked implementation must be clean before execution")
    subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=repo, check=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("native test executable is required")
    out.mkdir(parents=True, exist_ok=False)
    source = {
        "source_commit": args.source_sha,
        "source_tree": args.source_tree,
        "binary_sha256": digest(binary),
        "binary_bytes": binary.stat().st_size,
        "lockfile_sha256": digest(repo / "trillionnium/Cargo.lock"),
    }
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    boot_id = boot_path.read_text().strip() if boot_path.exists() else None
    manifest = {
        "schema": "sp27-01-native-credit-supervision-v1",
        "run_id": args.run_id,
        "source": source,
        "test": TEST,
        "modes": list(MODES),
        "timeout_seconds_per_process": args.timeout_seconds,
        "boot_id": boot_id,
        "clock_id": f"supervisor-monotonic:{boot_id}:{os.getpid()}",
        "host": os.uname().nodename,
        "platform": list(os.uname()),
        "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "exclusive_host_proven": False,
        "timings_eligible_for_performance_claim": False,
        "business_demand_established": False,
        "registered_before_child_launch": True,
        "cpu_scope": "serial child process groups including descendants; inclusive diagnostic only",
        "stage_and_process_cpu_may_not_be_added": True,
        "unknown_costs_are_not_zero": True,
    }
    write_json(out / "manifest.json", manifest)
    manifest_sha = digest(out / "manifest.json")
    records = []
    with (out / "supervisor.jsonl").open("x", encoding="utf-8") as journal:
        for index, mode in enumerate(MODES):
            child_id = f"{args.run_id}:{mode}"
            child_out = out / mode
            env = os.environ.copy()
            env.update({"TRNM_SP27_COST_OUTPUT": str(child_out),
                        "TRNM_SP27_COST_MODE": mode,
                        "TRNM_SP27_RUN_ID": child_id,
                        "TRNM_SP27_SOURCE_SHA": args.source_sha,
                        "TRNM_SP27_SOURCE_TREE": args.source_tree})
            argv = [str(binary), "--exact", TEST, "--ignored", "--nocapture", "--test-threads=1"]
            start = time.monotonic_ns()
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            record = {"operation_id": child_id, "index": index, "mode": mode,
                      "manifest_sha256": manifest_sha, "started_ns": start,
                      "planned_termination": mode == "unfinished", "argv": argv}
            append_event(journal, {**record, "event": "process_start"})
            reason, marker_observed, proc = None, False, None
            with (out / f"{mode}.stdout").open("xb") as stdout, (out / f"{mode}.stderr").open("xb") as stderr:
                try:
                    proc = subprocess.Popen(argv, cwd=repo, env=env, stdout=stdout,
                                            stderr=stderr, start_new_session=True)
                    deadline = time.monotonic() + args.timeout_seconds
                    while proc.poll() is None:
                        if mode == "unfinished" and (child_out / "unfinished.ready").is_file():
                            marker_observed = True
                            append_event(journal, {"event": "termination_requested", "operation_id": child_id,
                                                   "at_ns": time.monotonic_ns(), "signal": "SIGTERM",
                                                   "reason": "retained_native_partial_attempt_marker"})
                            terminate_owned_process(proc)
                            reason = "planned_partial_attempt_termination"
                            break
                        if time.monotonic() >= deadline:
                            append_event(journal, {"event": "termination_requested", "operation_id": child_id,
                                                   "at_ns": time.monotonic_ns(), "signal": "SIGTERM",
                                                   "reason": "original_supervisor_deadline"})
                            terminate_owned_process(proc)
                            reason = "timeout"
                            break
                        try:
                            proc.wait(timeout=0.05)
                        except subprocess.TimeoutExpired:
                            pass
                except Exception as error:
                    reason = f"supervisor_error:{type(error).__name__}:{error}"
                    if proc is not None:
                        terminate_owned_process(proc)
                stdout.flush()
                stderr.flush()
                os.fsync(stdout.fileno())
                os.fsync(stderr.fileno())
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            code = proc.returncode if proc is not None else None
            events_exist = (child_out / "events.jsonl").is_file() and (child_out / "events.jsonl").stat().st_size > 0
            expected = events_exist and ((marker_observed and code == -signal.SIGTERM) if mode == "unfinished" else code == 0)
            record.update({"event": "process_end", "ended_ns": time.monotonic_ns(),
                           "exit_code": code, "reason": reason or "returned",
                           "expected_process_outcome": expected, "native_marker_observed": marker_observed,
                           "inclusive_child_user_cpu_ns_rounded": round((after.ru_utime-before.ru_utime)*1e9),
                           "inclusive_child_system_cpu_ns_rounded": round((after.ru_stime-before.ru_stime)*1e9),
                           "complete_native_operation_cost_known": False,
                           "native_process_completed_normally": mode != "unfinished" and code == 0,
                           "complete_stage_cpu_known": False,
                           "native_events_sha256": digest(child_out / "events.jsonl") if (child_out / "events.jsonl").is_file() else None,
                           "stdout_sha256": digest(out / f"{mode}.stdout"),
                           "stderr_sha256": digest(out / f"{mode}.stderr")})
            append_event(journal, record)
            records.append(record)
    source_after = {"source_commit": git(repo, "rev-parse", "HEAD"),
                    "source_tree": git(repo, "rev-parse", "HEAD^{tree}"),
                    "binary_sha256": digest(binary),
                    "tracked_dirty": bool(git(repo, "status", "--porcelain", "--untracked-files=no"))}
    unchanged = (source_after["source_commit"] == source["source_commit"] and
                 source_after["source_tree"] == source["source_tree"] and
                 source_after["binary_sha256"] == source["binary_sha256"] and not source_after["tracked_dirty"])
    result = {"schema": "sp27-01-native-credit-execution-v1", "run_id": args.run_id,
              "manifest_sha256": manifest_sha, "source_after": source_after,
              "source_and_binary_unchanged": unchanged, "processes": records,
              "declared_processes": len(MODES), "observed_processes": len(records),
              "all_expected_process_outcomes": all(x["expected_process_outcome"] for x in records),
              "native_claim_checker_required": True,
              "performance_qualification": False, "production_qualification": False}
    write_json(out / "execution.json", result)
    print(json.dumps({"output": str(out), "execution_sha256": digest(out / "execution.json"),
                      "all_expected_process_outcomes": result["all_expected_process_outcomes"],
                      "source_and_binary_unchanged": unchanged}, sort_keys=True))
    return 0 if unchanged and result["all_expected_process_outcomes"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("timeout must be positive")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
