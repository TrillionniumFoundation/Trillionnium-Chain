#!/usr/bin/env python3
"""Measure the actual W1 proof process, retaining killed and failed attempts.

This Linux experiment runner is not a resource authorization owner. wait4
reports the direct child's rusage, including descendants only when reaped
before that child's exit. Timeout group termination can leave the prover's
cost absent from this rusage. It is not aggregate process-tree peak memory.
Separate original process samples are required for descendant cost bounds.
The native host performs the cryptographic checks, including a fresh-process
saved-receipt verification. An exit code alone never qualifies consensus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write(path: Path, value: object) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def execute(command: list[str], directory: Path, seconds: float) -> dict:
    directory.mkdir()
    write(directory / "command.json", {"argv": command, "timeout_seconds": seconds})
    start = time.monotonic()
    timed_out = False
    escalated = False
    signal_at = None
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    break
                now = time.monotonic()
                if not timed_out and now - start >= seconds:
                    timed_out = True
                    signal_at = now
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                elif timed_out and not escalated and now - signal_at >= 5:
                    escalated = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                time.sleep(0.05)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            write(directory / "interrupted.json", {"returncode": child.returncode, "observer_interrupted": True})
            raise
    result = {
        "returncode": child.returncode, "timed_out": timed_out,
        "sigkill_after_timeout": escalated, "elapsed_wall_seconds": time.monotonic() - start,
        "child_user_cpu_seconds": usage.ru_utime, "child_system_cpu_seconds": usage.ru_stime,
        "child_peak_rss_bytes": usage.ru_maxrss * 1024,
        "resource_source": "Linux wait4 of direct host; descendant costs may be absent after group termination; peak RSS is not aggregate process-tree memory or a production budget authority",
        "prover_resource_completeness_established": False,
        "stdout_sha256": sha(directory / "stdout.log"), "stderr_sha256": sha(directory / "stderr.log"),
    }
    write(directory / "process.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("new_output", type=Path)
    parser.add_argument("--r0vm", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=3600)
    args = parser.parse_args()
    if not 1 <= args.trials <= 100 or not 1 <= args.timeout_seconds <= 24 * 3600:
        parser.error("bounded trials and timeout required")
    binary, output = args.binary.resolve(strict=True), args.new_output.resolve()
    r0vm = args.r0vm.resolve(strict=True)
    output.mkdir()
    root = Path(__file__).resolve().parents[3]
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tracked_delta = subprocess.check_output(["git", "diff", "HEAD", "--"], cwd=root)
    write(output / "source.json", {
        "source_commit": head, "tracked_dirty": bool(tracked_delta),
        "tracked_delta_sha256": hashlib.sha256(tracked_delta).hexdigest(),
        "binary_path": str(binary), "binary_sha256": sha(binary),
        "local_r0vm_path": str(r0vm), "local_r0vm_sha256": sha(r0vm),
        "runner_sha256": sha(Path(__file__)), "planned_proof_trials": args.trials,
        "environment": {name: os.environ.get(name) for name in ("CARGO_BUILD_JOBS", "RAYON_NUM_THREADS", "RISC0_HOME")},
        "machine": dict(zip(("sysname", "nodename", "release", "version", "machine"), os.uname())),
    })
    proof = execute([str(binary), "--r0vm", str(r0vm), str(output / "proof"), str(args.trials)], output / "proof-process", args.timeout_seconds)
    observations = output / "proof" / "observations.jsonl"
    rows = []
    unreadable_rows = []
    if observations.exists():
        for index, line in enumerate(observations.read_bytes().splitlines()):
            try:
                rows.append(json.loads(line))
            except (ValueError, UnicodeDecodeError) as error:
                unreadable_rows.append({"line": index + 1, "error": str(error), "sha256": hashlib.sha256(line).hexdigest()})
    successful = [row for row in rows if row.get("outcome") == "REAL_SUCCINCT_STARK_VERIFIED"]
    verifications = []
    for row in successful:
        trial = row["trial"]
        verification = execute([
            str(binary), "verify", str(output / "proof" / f"header-{trial}.bin"),
            str(output / "proof" / f"receipt-{trial}.bin"),
        ], output / f"fresh-verifier-{trial}", 120)
        verification["trial"] = trial
        verifications.append(verification)
    complete = proof["returncode"] == 0 and not proof["timed_out"] and len(successful) == args.trials and not unreadable_rows
    complete = complete and len(verifications) == args.trials and all(row["returncode"] == 0 and not row["timed_out"] for row in verifications)
    write(output / "process-summary.json", {
        "schema": "trnm-w1-real-proof-process-v1", "planned_trials": args.trials,
        "completed_successful_trials": len(successful), "terminal_host_rows": len(rows),
        "unreadable_host_rows": unreadable_rows,
        "uncompleted_trials": args.trials - len(successful), "proof_process": proof,
        "fresh_verifiers": verifications, "experiment_process_complete": complete,
        "prover_p99_established": False, "actual_benefit_established": False,
        "whole_chain_quantum_security_qualified": False, "consensus_admission": False,
        "production_activation": False,
    })
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
