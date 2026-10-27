#!/usr/bin/env python3
"""Retain one actual subprocess result, including failures and bounded timeouts.

Each invocation measures a fresh child family; it does not estimate proof costs
or manufacture success. Timeout cleanup is confined to the child process group
created by this invocation. All stdout/stderr and exit status are retained.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
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


def become_subreaper():
    # This fresh Linux wrapper owns only the one child family below. Reparent
    # orphaned r0vm children here if their host dies first, so cleanup can wait
    # for them instead of leaving live proving work or uncollected zombies.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot become the owned-child subreaper")


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def reap_owned_children(child, report):
    child.poll()
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
        code = os.waitstatus_to_exitcode(status)
        if pid == child.pid:
            child.returncode = code
        else:
            report["adopted_child_terminals"].append({"pid": pid, "returncode": code})


def finish_owned_group(child, report):
    reap_owned_children(child, report)
    # A successful leader that leaves a live descendant is not a successfully
    # bounded observation. Preserve its real terminal code separately.
    if child.returncode is not None and group_exists(child.pid):
        report["leader_exited_before_group"] = True
        if report["returncode"] == 0:
            report["returncode"] = 125
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        if not group_exists(child.pid):
            break
        try:
            os.killpg(child.pid, sig)
            report["cleanup_actions"].append(sig.name)
        except ProcessLookupError:
            break
        except OSError as error:
            report["cleanup_errors"].append(repr(error))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            reap_owned_children(child, report)
            if not group_exists(child.pid):
                break
            time.sleep(0.025)
    reap_owned_children(child, report)
    report["owned_process_group_empty"] = not group_exists(child.pid)
    if not report["owned_process_group_empty"]:
        report["cleanup_errors"].append("owned process group remains after bounded cleanup")


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
    report = {"schema": "pon-w1-actual-process-v2", "command": command,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "timeout_seconds": args.timeout,
              "source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA"),
              "timed_out": False, "consensus_authority": False,
              "child_pid": None, "child_returncode": None,
              "child_reaped": False, "cleanup_actions": [], "cleanup_errors": [],
              "subreaper_enabled": False, "leader_exited_before_group": False,
              "adopted_child_terminals": [], "owned_process_group_empty": None}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    child = None
    sampler = None
    samples = None
    samples_path = args.out / f"{args.name}.proc-group.jsonl"
    with report_path.open("x") as output:
        try:
            with (args.out / f"{args.name}.stdout.log").open("xb") as stdout, \
                 (args.out / f"{args.name}.stderr.log").open("xb") as stderr:
                if args.sample_proc_group:
                    samples = samples_path.open("x")
                become_subreaper()
                report["subreaper_enabled"] = True
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                         start_new_session=True)
                report["child_pid"] = child.pid
                try:
                    if samples is not None:
                        sampler = ProcGroupSampler(child.pid, samples)
                    report["returncode"] = wait_with_samples(child, args.timeout, sampler)
                except subprocess.TimeoutExpired:
                    report["timed_out"] = True
                    # 124 is this wrapper's timeout status. Preserve the actual
                    # child's signal/exit status independently in finally.
                    report["returncode"] = 124
                    if sampler is not None:
                        sampler.sample("before_timeout_cleanup")
        except BaseException as error:
            report["runner_error"] = repr(error)
            report["returncode"] = 125
        finally:
            if child is not None:
                try:
                    finish_owned_group(child, report)
                except OSError as error:
                    report["cleanup_errors"].append(repr(error))
                report["child_returncode"] = child.poll()
                report["child_reaped"] = child.returncode is not None
                if not report["child_reaped"] or report["cleanup_errors"]:
                    report["returncode"] = 125
            if sampler is not None:
                try:
                    event = "terminated_timeout" if report["timed_out"] else (
                        "terminated_runner_error" if "runner_error" in report else "exit_observed")
                    sampler.sample(event, after_exit=True)
                except (OSError, ValueError) as error:
                    report["proc_group_sampling_error"] = repr(error)
                report["proc_group_sampling"] = sampler.summary()
                report["proc_group_sampling"]["jsonl_file"] = samples_path.name
                report["proc_group_sampling"]["sampled_after_owned_group_cleanup"] = True
            if samples is not None:
                try:
                    samples.close()
                except OSError as error:
                    report["proc_group_sampling_error"] = repr(error)
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            report.update({
                "wall_seconds": time.monotonic() - started,
                "user_cpu_seconds": after.ru_utime - before.ru_utime,
                "system_cpu_seconds": after.ru_stime - before.ru_stime,
                "max_waited_descendant_rss_kib": after.ru_maxrss,
                "rss_scope": "maximum reported for the waited child family; not total cgroup peak",
                "finished_utc": datetime.now(timezone.utc).isoformat(),
            })
            report["raw_logs"] = {}
            for label in ["stdout", "stderr"]:
                path = args.out / f"{args.name}.{label}.log"
                if path.is_file():
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(block)
                    report["raw_logs"][label] = {"path": path.name,
                        "bytes": path.stat().st_size, "sha256": digest.hexdigest()}
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report, indent=2))
    if report["returncode"] != 0:
        raise SystemExit(report["returncode"])


if __name__ == "__main__":
    main()
