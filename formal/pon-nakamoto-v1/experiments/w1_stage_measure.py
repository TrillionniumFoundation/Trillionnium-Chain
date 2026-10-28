#!/usr/bin/env python3
"""Bound one actual prover stage and preserve raw output with honest rusage scope."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wall-seconds", type=float, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 0 < args.wall_seconds <= 7200:
        parser.error("explicit command and wall bound in (0,7200] required")
    args.out.mkdir(parents=True, exist_ok=False)
    declared = {
        "schema": "TRNM-W1-STAGE-MEASUREMENT1",
        "command": command,
        "cwd": str(Path.cwd()),
        "wall_limit_seconds": args.wall_seconds,
        "termination_grace_seconds": 5,
        "started_unix_ns": time.time_ns(),
        "environment": {k: os.environ.get(k) for k in ["RAYON_NUM_THREADS", "RUST_LOG", "RISC0_HOME"]},
        "resource_scope": "wait4 direct child including descendants it has reaped; killed-stage CPU can be a lower bound; maxrss is largest single process, not summed peak",
        "shared_cgroup": {name: Path("/sys/fs/cgroup", name).read_text().strip() for name in ["cpu.max", "memory.max"]},
    }
    (args.out / "declaration.json").write_text(json.dumps(declared, indent=2) + "\n")
    started = time.monotonic()
    timed_out = False
    termination_at = None
    with (args.out / "stdout.log").open("wb") as stdout, (args.out / "stderr.log").open("wb") as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        while True:
            pid, status, usage = os.wait4(child.pid, os.WNOHANG)
            if pid:
                child.returncode = os.waitstatus_to_exitcode(status)
                break
            now = time.monotonic()
            if termination_at is None and now - started >= args.wall_seconds:
                timed_out = True
                termination_at = now
                os.killpg(child.pid, signal.SIGTERM)
            elif termination_at is not None and now - termination_at >= 5:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.1)
    group_remaining = False
    try:
        os.killpg(child.pid, 0)
        group_remaining = True
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    result = {
        **declared,
        "finished_unix_ns": time.time_ns(),
        "wall_seconds": time.monotonic() - started,
        "returncode": child.returncode,
        "timed_out": timed_out,
        "process_group_remaining_after_child_exit": group_remaining,
        "rusage": {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime, "max_single_process_rss_bytes": usage.ru_maxrss * 1024,
                   "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt, "voluntary_context_switches": usage.ru_nvcsw, "involuntary_context_switches": usage.ru_nivcsw},
        "complete_proof_claim": False,
        "note": "Stage exit 0 alone is not full proof success. Only a saved Succinct receipt checked in a fresh process against the fixed full image and journal can establish that gate.",
    }
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 124 if timed_out else child.returncode


if __name__ == "__main__":
    raise SystemExit(main())
