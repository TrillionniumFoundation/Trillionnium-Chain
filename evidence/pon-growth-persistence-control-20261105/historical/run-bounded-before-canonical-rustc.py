#!/usr/bin/env python3
"""Run only the two native Growth persistence-control tests on a pinned source.

This is a scoped regression launcher, not the original Host/4s/16 gate.
--phase red expects the preserved enum/test-only overlay; green expects the fix.
All output and Cargo targets must remain outside the checked source.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--phase", required=True, choices=("red", "green"))
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--expected-head", required=True)
parser.add_argument("--target", required=True, type=Path)
parser.add_argument("--cargo-home", required=True, type=Path)
parser.add_argument("--toolchain-bin", required=True, type=Path)
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
ROOT = args.source.resolve()
BASE = args.expected_head
TARGET = args.target.resolve()
TOOLCHAIN = args.toolchain_bin.resolve()
PHASE = args.phase
OUT = args.out.resolve()
if not re.fullmatch(r"[0-9a-f]{40}", BASE):
    parser.error("--expected-head must be one immutable full Git SHA")
if OUT.is_relative_to(ROOT) or TARGET.is_relative_to(ROOT):
    parser.error("--out and --target must be outside --source")
if not TARGET.is_dir():
    parser.error("--target must name the existing isolated Cargo target")
FILES = [
    "trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs",
    "trillionnium/crates/trnm-pon-node/tests/growth_persistence_cancellation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/growth.rs",
    "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
    "trillionnium/crates/trnm-pon-node/Cargo.toml",
]
EXPECTED_TESTS = sorted([
    "growth_admission_delta_write_control_rolls_back_and_retries_after_cold_open",
    "growth_admission_delta_readback_control_rolls_back_and_retries_after_cold_open",
])
COMMAND = [str(TOOLCHAIN / "cargo"),
    "--config", "profile.test.debug=0",
    "--config", "profile.test.package.trnm-pon-node.debug=0",
    "--config", "profile.test.package.trnm-pon-node.opt-level=0",
    "test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
    "-p", "trnm-pon-node", "--test", "growth_persistence_cancellation",
    "--", "--nocapture", "--test-threads=1"]
ENV_OVERRIDES = {
    "PATH": str(TOOLCHAIN) + ":/root/.cargo/bin:" + os.environ.get("PATH", ""),
    "CARGO_HOME": str(args.cargo_home.resolve()),
    "CARGO_TARGET_DIR": str(TARGET), "CARGO_BUILD_JOBS": "1",
    "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
    "RUSTUP_HOME": "/root/.rustup", "RUSTUP_TOOLCHAIN": "1.95.0-x86_64-unknown-linux-gnu",
    "RUST_TEST_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1", "GIT_OPTIONAL_LOCKS": "0",
    "TMPDIR": str(TARGET / "tmp"),
}
UNSET = ["RUSTC", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS"]
ENV = dict(os.environ, **ENV_OVERRIDES)
for key in UNSET:
    ENV.pop(key, None)


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, env=ENV, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def available_memory_estimate(host_available, cgroup_limit, cgroup_current, stats):
    """Conservative reclaim estimate for this runner, never a hard quota."""
    required = ("file", "shmem", "file_dirty", "file_writeback", "inactive_file")
    values = {"host_available": host_available, "cgroup_current": cgroup_current}
    values.update({name: stats[name] for name in required})
    if any(type(value) is not int or value < 0 for value in values.values()):
        raise ValueError("memory fields must be nonnegative integers")
    if cgroup_limit is not None and (type(cgroup_limit) is not int or cgroup_limit <= 0):
        raise ValueError("cgroup memory limit must be positive or unlimited")
    hard_headroom = None if cgroup_limit is None else max(0, cgroup_limit - cgroup_current)
    clean_file = max(0, stats["file"] - stats["shmem"] -
                     stats["file_dirty"] - stats["file_writeback"])
    reclaimable = min(stats["inactive_file"], clean_file)
    available = host_available if hard_headroom is None else min(
        host_available, hard_headroom + reclaimable)
    return {"effective_available": available, "hard_cgroup_headroom": hard_headroom,
            "reclaimable_inactive_file_estimate": reclaimable,
            "memory_stat_inputs": {name: stats[name] for name in required}}


def memory():
    details = {}
    try:
        details["host_available"] = next(
            int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:"))
        group = Path("/sys/fs/cgroup")
        limit = (group / "memory.max").read_text().strip()
        current = int((group / "memory.current").read_text().strip())
        details.update({"cgroup_limit": limit, "cgroup_current": current})
        stats = {key: int(value) for key, value in
                 (line.split() for line in (group / "memory.stat").read_text().splitlines())}
        details["events"] = (group / "memory.events").read_text()
        events = {key: int(value) for key, value in
                  (line.split() for line in details["events"].splitlines())}
        if any(value < 0 for value in events.values()) or not {"oom", "oom_kill"} <= events.keys():
            raise ValueError("missing or negative cgroup memory.events counters")
        details["event_counters"] = events
        details.update(available_memory_estimate(
            details["host_available"], None if limit == "max" else int(limit), current, stats))
    except (OSError, ValueError, KeyError, StopIteration) as exc:
        details["effective_available"] = 0
        details["estimate_error"] = f"{type(exc).__name__}: {exc}"
    return details


def oom_increased(before, after):
    return any(after.get("event_counters", {}).get(key, 0) >
               before.get("event_counters", {}).get(key, 0) for key in ("oom", "oom_kill"))


def inputs():
    digest = hashlib.sha256()
    manifest = []
    for directory in [ROOT / "trillionnium", ROOT / "config"]:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in {".rs", ".toml", ".lock", ".json"}:
                rel = str(path.relative_to(ROOT))
                checksum = sha(path)
                digest.update(rel.encode() + b"\0" + checksum.encode() + b"\n")
                manifest.append({"path": rel, "sha256": checksum, "bytes": path.stat().st_size})
    return {"files": len(manifest), "aggregate_sha256": digest.hexdigest()}, manifest


def bindings():
    return {rel: {"sha256": sha(ROOT / rel), "bytes": (ROOT / rel).stat().st_size} for rel in FILES}


def write_record(record):
    tmp = OUT / "result.json.tmp"
    tmp.write_text(json.dumps(record, indent=2) + "\n")
    tmp.replace(OUT / "result.json")


OUT.mkdir(parents=True, exist_ok=False)
preflight = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=ROOT, env=ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
(OUT / "preflight.log").write_text(preflight.stdout)
native_before, manifest = inputs()
(OUT / "native-inputs-before.json").write_text(json.dumps(manifest, indent=2) + "\n")
record = {
    "schema": "growth-persistence-control-native-v1", "phase": PHASE,
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "expected_base": BASE, "actual_head_before": git("rev-parse", "HEAD"),
    "source_mode": "immutable_clean_commit" if PHASE == "green" else "recorded_working_tree_overlay",
    "git_status_before": git("status", "--porcelain=v1"),
    "bindings_before": bindings(), "native_inputs_before": native_before,
    "command": COMMAND, "environment_overrides": ENV_OVERRIDES, "environment_unset": UNSET,
    "preflight_exit_code": preflight.returncode,
    "preflight_log_sha256": sha(OUT / "preflight.log"),
    "cargo_version": subprocess.check_output([str(TOOLCHAIN / "cargo"), "--version"], env=ENV, text=True).strip(),
    "rustc_version": subprocess.check_output([str(TOOLCHAIN / "rustc"), "-vV"], env=ENV, text=True).strip(),
    "timeout_seconds": 600, "effective_available_memory_stop_bytes": 512 * 1024 * 1024,
    "target_storage_available_stop_bytes": 128 * 1024 * 1024,
    "memory_before": memory(), "target_storage_before": shutil.disk_usage(TARGET)._asdict(),
    "expected_test_names": EXPECTED_TESTS, "result": "PREFLIGHT", "exit_code": None,
    "timeout_observed": False, "resource_abort_observed": False, "storage_abort_observed": False,
    "oom_observed": False,
    "memory_monitor_scope": "Estimated available memory includes conservative inactive clean file reclaim; this is not a hard quota or an OOM guarantee.",
    "qualification": "HOLD", "production_activation": False,
    "scope": "Two actual Growth admission integration tests, with cancellation/deadline/CPU-budget control cases and real SQLite rollback/retry/cold reopen. Not the original Host-qualified 4s/16 business performance gate.",
    "full_repository_source_guard": "NOT_CLAIMED: published evidence may be sparse; native/config inputs are independently recorded",
    "runner_sha256": sha(Path(__file__)),
}
if (preflight.returncode or record["actual_head_before"] != BASE or
        (PHASE == "green" and record["git_status_before"]) or
        record["memory_before"]["effective_available"] < 512 * 1024 * 1024 or
        record["target_storage_before"]["free"] < 128 * 1024 * 1024):
    record["result"] = "PREFLIGHT_BLOCKED"
    write_record(record)
    print(json.dumps(record), flush=True)
    raise SystemExit(2)
record["min_effective_mem_available_bytes"] = record["memory_before"]["effective_available"]
record["min_target_storage_available_bytes"] = record["target_storage_before"]["free"]
(TARGET / "tmp").mkdir(exist_ok=True)
record["result"] = "RUNNING"
write_record(record)
print(json.dumps({"stage": "native_start", "phase": PHASE, "head": BASE,
                  "native_inputs": native_before, "memory": memory(),
                  "target_storage_free": shutil.disk_usage(TARGET).free}), flush=True)
process = None
signals = []


def stop_owned():
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def interrupted(signum, frame):
    signals.append(signum)
    stop_owned()


signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)
started = time.monotonic()
try:
    with (OUT / "cargo.log").open("wb") as log:
        process = subprocess.Popen(COMMAND, cwd=ROOT, env=ENV, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        record["cargo_pid"] = process.pid
        write_record(record)
        next_report = 0
        while process.poll() is None:
            elapsed = time.monotonic() - started
            sample = memory()
            available = sample["effective_available"]
            record["oom_observed"] |= oom_increased(record["memory_before"], sample)
            if sample.get("estimate_error"):
                record["memory_monitor_error"] = sample["estimate_error"]
            free = shutil.disk_usage(TARGET).free
            record["min_effective_mem_available_bytes"] = min(record["min_effective_mem_available_bytes"], available)
            record["min_target_storage_available_bytes"] = min(record["min_target_storage_available_bytes"], free)
            if (elapsed >= 600 or available < 512 * 1024 * 1024 or
                    free < 128 * 1024 * 1024 or record["oom_observed"]):
                record["timeout_observed"] = elapsed >= 600
                record["resource_abort_observed"] = available < 512 * 1024 * 1024
                record["storage_abort_observed"] = free < 128 * 1024 * 1024
                stop_owned()
                break
            if elapsed >= next_report:
                print(json.dumps({"stage": "native_running", "phase": PHASE, "elapsed_s": round(elapsed),
                                  "effective_mem_available_bytes": available, "target_storage_available_bytes": free}), flush=True)
                next_report = elapsed + 20
            time.sleep(0.5)
    record["exit_code"] = process.returncode
except BaseException as exc:
    stop_owned()
    record["runner_error"] = str(exc)
finally:
    record["elapsed_seconds"] = round(time.monotonic() - started, 6)
    record["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record["actual_head_after"] = git("rev-parse", "HEAD")
    record["git_status_after"] = git("status", "--porcelain=v1")
    record["bindings_after"] = bindings()
    record["native_inputs_after"], after_manifest = inputs()
    (OUT / "native-inputs-after.json").write_text(json.dumps(after_manifest, indent=2) + "\n")
    record["bindings_unchanged"] = record["bindings_before"] == record["bindings_after"]
    record["native_inputs_unchanged"] = native_before == record["native_inputs_after"]
    record["head_unchanged"] = record["actual_head_before"] == record["actual_head_after"]
    record["git_status_unchanged"] = record["git_status_before"] == record["git_status_after"]
    raw = (OUT / "cargo.log").read_bytes() if (OUT / "cargo.log").exists() else b""
    text = raw.decode(errors="replace")
    record["cargo_log_sha256"] = hashlib.sha256(raw).hexdigest()
    record["cargo_log_bytes"] = len(raw)
    record["test_result_lines"] = re.findall(r"^test result: .*$", text, re.MULTILINE)
    record["passed_test_names"] = sorted(re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ok$", text, re.MULTILINE))
    record["expected_refusal_assertions"] = text.count("the original caller control must abort admission before commit")
    record["oom_log_evidence"] = bool(re.search(r"out of memory|memory allocation.*failed", text, re.I))
    record["memory_after"] = memory()
    record["oom_observed"] |= oom_increased(record["memory_before"], record["memory_after"])
    if record["memory_after"].get("estimate_error"):
        record["memory_monitor_error"] = record["memory_after"]["estimate_error"]
    before_events = record["memory_before"].get("event_counters", {})
    after_events = record["memory_after"].get("event_counters", {})
    record["memory_events_delta"] = {key: after_events[key] - value for key, value in
                                     before_events.items() if key in after_events}
    if any(value < 0 for value in record["memory_events_delta"].values()):
        record["memory_monitor_error"] = "cgroup memory.events counters regressed"
    record["target_storage_after"] = shutil.disk_usage(TARGET)._asdict()
    if "runner_error" in record:
        record["result"] = "RUNNER_ERROR"
    elif record["oom_observed"]:
        record["result"] = "OOM_OBSERVED"
    elif "memory_monitor_error" in record:
        record["result"] = "MEMORY_MONITOR_ERROR"
    elif signals:
        record["result"] = "INTERRUPTED"
        record["signals_received"] = signals
    elif record["timeout_observed"]:
        record["result"] = "TIMEOUT"
    elif record["resource_abort_observed"]:
        record["result"] = "ABORTED_RESOURCE"
    elif record["storage_abort_observed"]:
        record["result"] = "ABORTED_STORAGE"
    elif PHASE == "red":
        exact_failure = bool(re.search(r"test result: FAILED\. 0 passed; 2 failed; 0 ignored;", text))
        record["result"] = "EXPECTED_REGRESSION_REPRODUCED" if record["exit_code"] == 101 and exact_failure and record["expected_refusal_assertions"] == 2 else "RED_EXPECTATION_NOT_MET"
    else:
        exact_success = bool(re.search(r"test result: ok\. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", text))
        record["result"] = "PASS" if record["exit_code"] == 0 and record["passed_test_names"] == EXPECTED_TESTS and exact_success else "FAIL"
    if (not all([record["bindings_unchanged"], record["native_inputs_unchanged"],
                 record["head_unchanged"], record["git_status_unchanged"]]) or
            (PHASE == "green" and record["git_status_after"])):
        record["result"] = "SOURCE_CHANGED_DURING_EXECUTION"
    write_record(record)
    print(json.dumps(record), flush=True)
    print(text[-10000:], flush=True)
raise SystemExit(0 if record["result"] in {"PASS", "EXPECTED_REGRESSION_REPRODUCED"} else 1)
