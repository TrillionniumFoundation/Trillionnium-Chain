#!/usr/bin/env python3
"""One Linux engineering launch; immutable inputs, existing metadata controls."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
PLAN = HERE / "ENGINEERING_PLAN.json"


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def cpu():
    own = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "owner_user": own.ru_utime,
        "owner_system": own.ru_stime,
        "reaped_children_user": child.ru_utime,
        "reaped_children_system": child.ru_stime,
    }


def verify_inputs(root, expected):
    observed = {}
    for relative, wanted in expected.items():
        path = root / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("source is not a unique regular file: " + relative)
        data = path.read_bytes()
        after = path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("source changed while reading: " + relative)
        actual = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if actual != wanted:
            raise ValueError("source bytes differ from reviewed input: " + relative)
        observed[relative] = actual
    return observed


def execute(command, root, output, deadline):
    start = time.monotonic_ns()
    log = output / (command["name"] + ".log")
    row = {"name": command["name"], "argv": command["argv"], "executed": False}
    if time.monotonic() >= deadline:
        return {**row, "error": "capsule deadline elapsed before launch", "passed": False}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", GIT_NO_LAZY_FETCH="1")
    with log.open("xb") as stream:
        process = subprocess.Popen(
            command["argv"], cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
        )
        row["executed"] = True
        timed_out = False
        try:
            while True:
                observation = os.waitid(
                    os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
                if observation is not None:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.01)
        except BaseException as error:
            # Lost wait ownership does not authorize a signal to a reusable PID.
            row.update(error=type(error).__name__, cleanup_resolved=False, passed=False)
            return row
        try:
            # WNOWAIT retains the leader until the one group cleanup and wait.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            row["cleanup_signal_error"] = repr(error)
        try:
            row["exit_code"] = process.wait(timeout=1.0)
            row["cleanup_resolved"] = "cleanup_signal_error" not in row
        except subprocess.TimeoutExpired:
            row["cleanup_resolved"] = False
        row["timed_out"] = timed_out
    data = log.read_bytes()
    row.update(log=log.name, log_bytes=len(data), log_sha256=hashlib.sha256(data).hexdigest())
    row["wall_seconds"] = (time.monotonic_ns() - start) / 1e9
    row["passed"] = row.get("exit_code") == 0 and not timed_out and row["cleanup_resolved"]
    if row["passed"]:
        text = data.decode("utf-8")
        if "expected_tests" in command:
            counts = re.findall(r"^Ran (\d+) tests in [0-9.]+s$", text, re.MULTILINE)
            row["observed_tests"] = int(counts[0]) if len(counts) == 1 else None
            row["passed"] = (
                row["observed_tests"] == command["expected_tests"]
                and len(re.findall(r"^OK$", text, re.MULTILINE)) == 1
                and not re.search(r"\b(?:skipped|expected failures|unexpected successes)\b", text)
            )
        elif command["name"] == "identity":
            row["passed"] = text.splitlines() == command["expected_lines"]
        elif command["name"] == "changed-paths":
            row["passed"] = sorted(text.splitlines()) == command["expected_lines"]
        else:
            result = json.loads(text)
            if command["name"] == "preflight":
                row["passed"] = result["result"] == "PASS" and result["packages"] == 26
            else:
                row["passed"] = result["status"] == "HOLD"
                row["passed"] &= all(result[key] is False for key in (
                    "whole_chain_pq_qualified", "pq_128_qualified", "production_activation",
                ))
                if command["name"] == "current-report":
                    row["passed"] &= result["actual_lifetime_failure_bound"] is None
                    row["passed"] &= result["composition_coverage_proved"] is False
                    row["passed"] &= result["theorem_applicability_verified"] is False
    return row


def main():
    plan_raw = PLAN.read_bytes()
    plan = json.loads(plan_raw)
    if sys.platform != "linux" or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise SystemExit("this capsule requires its reviewed Linux wait ownership")
    root = Path(plan["worktree"])
    output = Path(plan["output"])
    output.mkdir()  # Exclusive identity; never retry an unknown launch in place.
    start = time.monotonic()
    before_cpu = cpu()
    deadline = start + plan["budget_seconds"] - 1.25
    record = {
        "schema": "chain-pq-current-map-metadata-attempt-v1",
        "launch_identity": plan["launch_identity"], "plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "source_base": plan["source_base"], "scope": plan["scope"], "commands": [],
        "result": "FAIL", "old_E1_E6_budget_used": 0, "native_compile_or_tests": 0,
        "security_gate_qualified": False, "production_activation": False,
    }
    (output / "STARTED.json").write_bytes(encoded(record))
    try:
        record["source_before"] = verify_inputs(root, plan["inputs"])
        for command in plan["commands"]:
            row = execute(command, root, output, deadline)
            record["commands"].append(row)
            (output / "PROGRESS.json").write_bytes(encoded(record))
            if not row["passed"]:
                break
        record["source_after"] = verify_inputs(root, plan["inputs"])
        if len(record["commands"]) == len(plan["commands"]) and all(
            row["passed"] for row in record["commands"]
        ):
            record["result"] = "PASS_METADATA_ONLY"
    except BaseException as error:
        record["error"] = repr(error)
    after_cpu = cpu()
    record["wall_seconds"] = time.monotonic() - start
    record["cpu_seconds"] = {key: after_cpu[key] - before_cpu[key] for key in before_cpu}
    record["cpu_scope"] = "capsule owner and reaped children; command costs included once"
    record["within_budget"] = record["wall_seconds"] <= plan["budget_seconds"]
    if not record["within_budget"]:
        record["result"] = "FAIL"
    (output / "RESULT.json").write_bytes(encoded(record))
    print(json.dumps({key: record[key] for key in ("result", "wall_seconds", "within_budget")}))
    return 0 if record["result"] == "PASS_METADATA_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
