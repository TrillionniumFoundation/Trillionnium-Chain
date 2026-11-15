#!/usr/bin/env python3
"""One finite scheduler window; it never changes native runner controls."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path("/workspace/scratch/822cc50e24f0/state-scheduling-restored")
RUNNER = ROOT / "run-bounded.py"
OUT = ROOT / "native-red-canonical-retry2"
RECEIPT = ROOT / "resource-waiter-retry2.json"
MIN_START = 2 * 1024 * 1024 * 1024
STABLE_SECONDS = 30
WAIT_SECONDS = 600
if OUT.exists() or RECEIPT.exists():
    raise SystemExit("refuse to overwrite a prior attempt or scheduler receipt")
source = RUNNER.read_bytes()
if hashlib.sha256(source).hexdigest() != "ae20081596e452c1f0b8a5f7db17acc0fba650e840fed9a9914bdedd24cba52f":
    raise SystemExit("native runner changed")
tree = ast.parse(source.decode())
nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
         node.name in {"available_memory_estimate", "memory", "oom_increased"}]
scope = {"Path": Path}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNNER), "exec"), scope)
memory = scope["memory"]
oom_increased = scope["oom_increased"]
command = ["python3", str(RUNNER), "--phase", "red",
           "--source", "/workspace/scratch/822cc50e24f0/round2-chain",
           "--expected-head", "ffb43113b2e0065e6a8053bdb25fc5a9d7cf0637",
           "--target", str(ROOT / "native-target-canonical"),
           "--cargo-home", "/root/.cargo", "--toolchain-bin", "/root/.cargo/bin",
           "--rustc", "/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc",
           "--out", str(OUT)]
started = time.monotonic()
initial = memory()
record = {
    "schema": "growth-single-resource-waiter-v1",
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "runner_sha256": hashlib.sha256(source).hexdigest(),
    "scheduler_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "max_wait_seconds": WAIT_SECONDS, "continuous_ready_seconds": STABLE_SECONDS,
    "scheduling_min_estimated_available_bytes": MIN_START,
    "native_stop_floor_bytes_unchanged": 536870912,
    "native_timeout_seconds_unchanged": 600, "native_command": command,
    "initial_memory": initial, "samples": [], "actual_native_started": False,
    "state": "WAITING", "qualification": "HOLD", "production_activation": False,
    "scope": "One finite correctness-build scheduling window, not a resource guarantee or a change to the original production Host/4s/16 gate.",
}
child = None
stop_requested = False


def save():
    temp = RECEIPT.with_suffix(".json.tmp")
    temp.write_text(json.dumps(record, indent=2) + "\n")
    temp.replace(RECEIPT)


def stop(signum, frame):
    global stop_requested
    stop_requested = True
    record["interrupted_signal"] = signum
    if child is not None and child.poll() is None:
        child.send_signal(signal.SIGTERM)


signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
save()
ready_since = None
next_report = 0
while True:
    now = time.monotonic()
    sample = memory()
    elapsed = now - started
    record["last_memory"] = sample
    record["wait_elapsed_seconds"] = round(elapsed, 6)
    if stop_requested:
        record["state"] = "INTERRUPTED_BEFORE_NATIVE"
        break
    if initial.get("estimate_error") or sample.get("estimate_error"):
        record["state"] = "MEMORY_MONITOR_ERROR_BEFORE_NATIVE"
        break
    if oom_increased(initial, sample):
        record["state"] = "OOM_DURING_WAIT"
        break
    if elapsed >= WAIT_SECONDS:
        record["state"] = "WAIT_TIMEOUT"
        break
    if sample["effective_available"] >= MIN_START:
        if ready_since is None:
            ready_since = now
    else:
        ready_since = None
    continuous = 0 if ready_since is None else now - ready_since
    if elapsed >= next_report:
        entry = {"elapsed_seconds": round(elapsed, 3),
                 "continuous_ready_seconds": round(continuous, 3),
                 "memory": sample}
        record["samples"].append(entry)
        save()
        print(json.dumps({"stage": "resource_wait", **entry}), flush=True)
        next_report = elapsed + 20
    if continuous >= STABLE_SECONDS:
        record["actual_native_started"] = True
        record["native_started_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record["native_start_memory"] = sample
        record["state"] = "NATIVE_RUNNING"
        save()
        print(json.dumps({"stage": "canonical_red_retry2_started",
                          "command": command, "memory": sample}), flush=True)
        child = subprocess.Popen(command, cwd="/", start_new_session=True)
        record["native_runner_pid"] = child.pid
        save()
        record["native_runner_exit_code"] = child.wait()
        result_path = OUT / "result.json"
        if result_path.exists():
            native_result = json.loads(result_path.read_text())
            record["native_result"] = native_result.get("result")
            record["native_result_sha256"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
        else:
            record["native_result"] = "NO_TERMINAL_RECEIPT"
        record["state"] = "NATIVE_COMPLETED"
        break
    time.sleep(2)
record["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
save()
print(json.dumps({"stage": "resource_waiter_finished", "state": record["state"],
                  "actual_native_started": record["actual_native_started"],
                  "native_result": record.get("native_result"),
                  "wait_elapsed_seconds": record.get("wait_elapsed_seconds")}), flush=True)
