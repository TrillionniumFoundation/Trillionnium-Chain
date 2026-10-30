#!/usr/bin/env python3
"""Retain one actual subprocess result, including failures and bounded timeouts.

Each invocation measures a fresh child family; it does not estimate proof costs
or manufacture success. Timeout cleanup is confined to the child process group
created by this invocation. All stdout/stderr and exit status are retained.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import time

from proof_observer_v1 import COST_PROFILE, ORIGINAL_PROFILE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--observe-proof", action="store_true",
                        help="explicit prove-only diagnostic owner; original predicates unchanged")
    parser.add_argument("--proof-profile", choices=(ORIGINAL_PROFILE, COST_PROFILE),
                        default=ORIGINAL_PROFILE,
                        help="default original 5400s; explicit cost-only profile never qualifies that budget")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.name):
        raise SystemExit("invalid observation name")
    if args.proof_profile == COST_PROFILE:
        if not args.observe_proof or args.timeout != 14400:
            raise SystemExit("cost-only-14400-v1 requires --observe-proof and exactly 14400 seconds")
    elif not 1 <= args.timeout <= 5400:
        raise SystemExit("timeout must be between 1 and 5400 seconds")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing actual command")
    if args.observe_proof:
        from proof_observer_v1 import observed_prove
        raise SystemExit(observed_prove(command, args.out, args.name, args.timeout,
                                       proof_profile=args.proof_profile))
    args.out.mkdir(parents=True, exist_ok=True)
    report_path = args.out / f"{args.name}.process.json"
    report = {"schema": "pon-w1-actual-process-v1", "command": command,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "timeout_seconds": args.timeout,
              "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
              "timed_out": False, "consensus_authority": False}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    with report_path.open("x") as output:
        try:
            with (args.out / f"{args.name}.stdout.log").open("xb") as stdout, \
                 (args.out / f"{args.name}.stderr.log").open("xb") as stderr:
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                         start_new_session=True)
                try:
                    report["returncode"] = child.wait(timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    report["timed_out"] = True
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    report["returncode"] = 124
        except BaseException as error:
            report["runner_error"] = repr(error)
            report["returncode"] = 125
        finally:
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            report.update({
                "wall_seconds": time.monotonic() - started,
                "user_cpu_seconds": after.ru_utime - before.ru_utime,
                "system_cpu_seconds": after.ru_stime - before.ru_stime,
                "max_waited_descendant_rss_kib": after.ru_maxrss,
                "rss_scope": "maximum reported for the waited child family; not total cgroup peak",
                "finished_utc": datetime.now(timezone.utc).isoformat(),
            })
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report, indent=2))
    if report["returncode"] != 0:
        raise SystemExit(report["returncode"])


if __name__ == "__main__":
    main()
