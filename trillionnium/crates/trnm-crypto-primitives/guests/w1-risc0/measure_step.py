#!/usr/bin/env python3
"""Retain one actual subprocess result, including failures and bounded timeouts.

Each invocation measures a fresh child family; it does not estimate proof costs
or manufacture success. Timeout cleanup is confined to the child process group
created by this invocation. All stdout/stderr and exit status are retained.
"""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import time

from proc_group_sampler import INTERVAL_SECONDS, ProcGroupSampler


def wait_with_samples(child, timeout, sampler):
    if sampler is None:
        return child.wait(timeout=timeout)
    deadline = time.monotonic() + timeout
    sampler.sample("started")
    next_sample = time.monotonic() + INTERVAL_SECONDS
    while True:
        remaining = min(deadline, next_sample) - time.monotonic()
        if remaining <= 0 and time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(child.args, timeout)
        try:
            return child.wait(timeout=max(remaining, 0.001))
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                raise
            sampler.sample("periodic")
            next_sample = time.monotonic() + INTERVAL_SECONDS


def terminate_owned_group(child):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--sample-proc-group", action="store_true",
                        help="sample this new Linux process group every 15s; lower bounds only")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.name):
        raise SystemExit("invalid observation name")
    if not 1 <= args.timeout <= 5400:
        raise SystemExit("timeout must be between 1 and 5400 seconds")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing actual command")
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
            samples_path = args.out / f"{args.name}.proc-group.jsonl"
            with (args.out / f"{args.name}.stdout.log").open("xb") as stdout, \
                 (args.out / f"{args.name}.stderr.log").open("xb") as stderr, \
                 (samples_path.open("x") if args.sample_proc_group else nullcontext(None)) as samples:
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                         start_new_session=True)
                sampler = None
                termination_reason = None
                try:
                    if samples is not None:
                        sampler = ProcGroupSampler(child.pid, samples)
                    report["returncode"] = wait_with_samples(child, args.timeout, sampler)
                except subprocess.TimeoutExpired:
                    report["timed_out"] = True
                    termination_reason = "timeout"
                    if sampler is not None:
                        sampler.sample("before_timeout_termination")
                    terminate_owned_group(child)
                    report["returncode"] = 124
                except BaseException:
                    termination_reason = "runner_error"
                    if child.poll() is None:
                        terminate_owned_group(child)
                    raise
                finally:
                    # Also clean up if observation I/O failed inside a timeout
                    # handler; never leave a new unmeasured prover running.
                    if child.poll() is None:
                        termination_reason = termination_reason or "runner_error"
                        terminate_owned_group(child)
                    if sampler is not None:
                        event = f"terminated_{termination_reason}" if termination_reason else "exit_observed"
                        try:
                            sampler.sample(event, after_exit=True)
                        except (OSError, ValueError) as error:
                            report["proc_group_sampling_error"] = repr(error)
                        report["proc_group_sampling"] = sampler.summary()
                        report["proc_group_sampling"]["jsonl_file"] = samples_path.name
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
