#!/usr/bin/env python3
"""Prepare and execute the fixed ten-process value-pool component campaign."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

BASE = Path(__file__).resolve().parent
PLAN = BASE / "benchmark-plan.json"
FREEZE = BASE / "benchmark-execution-freeze.json"
MEASUREMENTS = BASE / "measurements"


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def save(path, value):
    pending = path.with_name(path.name + ".pending")
    with open(pending, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)


def git(directory, *args):
    return subprocess.check_output(["git", *args], cwd=directory)


def source_identity(plan, variant):
    source = plan["sources"][variant]
    directory = source["directory"]
    head = git(directory, "rev-parse", "HEAD").decode().strip()
    assert head == source["base_commit"], (variant, "HEAD changed")
    patch = hashlib.sha256(git(directory, "diff", "--binary", "HEAD", "--")).hexdigest()
    assert patch == source["production_patch_sha256"], (variant, "tracked source changed")
    driver = Path(directory) / plan["driver_path"]
    assert digest(driver) == plan["driver_sha256"], (variant, "driver changed")
    untracked = git(directory, "ls-files", "--others", "--exclude-standard").decode().splitlines()
    assert untracked == [plan["driver_path"]], (variant, "unexpected untracked source", untracked)
    return {"head": head, "tracked_patch_sha256": patch, "driver_sha256": digest(driver),
            "untracked_files": untracked, "expected_measured_tree": source["measured_tree_with_driver"]}


def build_receipt(plan, variant):
    path = BASE / f"{variant}-benchmark-build.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    assert len(finished) == 1 and finished[0]["success"], (variant, "build not successful")
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"]
    profiles = {}
    for name, expected in plan["profile_requirements"].items():
        choices = [row for row in artifacts if row["target"]["name"] == name and row["target"]["kind"] == ["lib"]]
        assert len(choices) == 1, (variant, name, "ambiguous/missing artifact")
        row = choices[0]
        assert row["target"]["src_path"].startswith(plan["sources"][variant]["directory"] + "/")
        for key, value in expected.items():
            assert row["profile"][key] == value, (variant, name, key, row["profile"], expected)
        profiles[name] = {"profile": row["profile"], "features": row["features"],
                          "package_id": row["package_id"], "source": row["target"]["src_path"]}
    choices = [row for row in artifacts if row["target"]["name"] == "value_pool_component" and row.get("executable")]
    assert len(choices) == 1, (variant, "ambiguous/missing driver ELF")
    executable = Path(choices[0]["executable"])
    assert str(executable).startswith(plan["sources"][variant]["target"] + "/")
    assert choices[0]["profile"]["test"] is True
    return {"source_identity": source_identity(plan, variant), "profiles": profiles,
            "driver_profile": choices[0]["profile"], "driver_features": choices[0]["features"],
            "executable": str(executable), "executable_bytes": executable.stat().st_size,
            "executable_sha256": digest(executable), "cargo_json_sha256": digest(path),
            "cargo_stderr_sha256": digest(BASE / f"{variant}-benchmark-build.stderr"),
            "preflight_sha256": digest(BASE / f"{variant}-benchmark-preflight.log")}


def files_frozen():
    return {name: digest(BASE / name) for name in [
        "benchmark-plan.json", "source-freeze.json", "source-freeze.patch",
        "value_pool_component.rs", "run_benchmark.py", "analyze_benchmark.py"]}


def prepare():
    assert not FREEZE.exists(), "execution freeze already exists; preserve it"
    plan = json.loads(PLAN.read_text())
    variants = {variant: build_receipt(plan, variant) for variant in ["baseline", "candidate"]}
    assert variants["baseline"]["executable"] != variants["candidate"]["executable"], "ELF paths must be independent"
    assert variants["baseline"]["executable_sha256"] != variants["candidate"]["executable_sha256"], "distinct source variants must not silently share one ELF"
    for name in plan["profile_requirements"]:
        assert variants["baseline"]["profiles"][name]["profile"] == variants["candidate"]["profiles"][name]["profile"]
        assert variants["baseline"]["profiles"][name]["features"] == variants["candidate"]["profiles"][name]["features"]
    assert variants["baseline"]["driver_profile"] == variants["candidate"]["driver_profile"]
    assert variants["baseline"]["driver_features"] == variants["candidate"]["driver_features"]
    save(FREEZE, {"schema": "value-pool-execution-freeze-v1", "created_utc": now(),
                  "measurement_started": False, "frozen_files": files_frozen(), "variants": variants,
                  "command_tail": ["--exact", "value_pool_component_registered", "--ignored", "--nocapture", "--test-threads=1"]})
    print(json.dumps({"freeze": str(FREEZE), "sha256": digest(FREEZE), "variants": variants}, sort_keys=True), flush=True)


def run():
    plan = json.loads(PLAN.read_text())
    freeze = json.loads(FREEZE.read_text())
    assert files_frozen() == freeze["frozen_files"], "frozen premeasurement files changed"
    for variant, receipt in freeze["variants"].items():
        assert source_identity(plan, variant) == receipt["source_identity"]
        assert digest(receipt["executable"]) == receipt["executable_sha256"], "ELF changed"
    MEASUREMENTS.mkdir(exist_ok=False)
    started = now()
    ledger = {"schema": "value-pool-execution-v1", "started_utc": started,
              "plan_sha256": digest(PLAN), "execution_freeze_sha256": digest(FREEZE),
              "planned_processes": 10, "planned_samples": plan["grid"]["total_planned_samples"],
              "retries": 0, "records": []}
    save(MEASUREMENTS / "execution.json", ledger)
    for pair, order in enumerate(plan["grid"]["process_order"]):
        for variant in order:
            prefix = f"pair-{pair:02}-{variant}"
            stdout = MEASUREMENTS / f"{prefix}.stdout"
            stderr = MEASUREMENTS / f"{prefix}.stderr"
            env = os.environ.copy()
            env.update(TRNM_VALUE_POOL_PAIR=str(pair), TRNM_VALUE_POOL_VARIANT=variant)
            command = [freeze["variants"][variant]["executable"], *freeze["command_tail"]]
            record = {"pair": pair, "variant": variant, "command": command,
                      "cwd": plan["sources"][variant]["directory"], "started_utc": now(),
                      "stdout": stdout.name, "stderr": stderr.name,
                      "timeout_seconds": plan["stops"]["process_timeout_seconds"],
                      "timed_out": False, "returncode": None, "exception": None}
            print(json.dumps({"event": "process_start", "pair": pair, "variant": variant}), flush=True)
            start = time.monotonic_ns()
            with open(stdout, "xb") as out, open(stderr, "xb") as err:
                try:
                    process = subprocess.Popen(command, cwd=record["cwd"], env=env, stdout=out, stderr=err)
                    try:
                        record["returncode"] = process.wait(timeout=record["timeout_seconds"])
                    except subprocess.TimeoutExpired:
                        record["timed_out"] = True
                        process.kill()
                        record["returncode"] = process.wait()
                except OSError as error:
                    record["exception"] = {"kind": type(error).__name__, "errno": error.errno, "message": str(error)}
            record["wall_ns"] = time.monotonic_ns() - start
            record["finished_utc"] = now()
            record["stdout_sha256"] = digest(stdout)
            record["stderr_sha256"] = digest(stderr)
            ledger["records"].append(record)
            save(MEASUREMENTS / "execution.json", ledger)
            print(json.dumps({"event": "process_end", **record}, sort_keys=True), flush=True)
    ledger["finished_utc"] = now()
    ledger["source_after"] = {}
    ledger["identity_errors"] = []
    for variant, receipt in freeze["variants"].items():
        try:
            identity = source_identity(plan, variant)
            assert identity == receipt["source_identity"]
            assert digest(receipt["executable"]) == receipt["executable_sha256"]
            ledger["source_after"][variant] = identity
        except (AssertionError, OSError, subprocess.CalledProcessError) as error:
            ledger["identity_errors"].append({"variant": variant, "error": repr(error)})
    ledger["frozen_files_after"] = files_frozen()
    if ledger["frozen_files_after"] != freeze["frozen_files"]:
        ledger["identity_errors"].append({"error": "frozen premeasurement files changed during execution"})
    save(MEASUREMENTS / "execution.json", ledger)
    print(json.dumps({"event": "campaign_execution_complete", "processes": len(ledger["records"]),
                      "identity_errors": ledger["identity_errors"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "run"])
    args = parser.parse_args()
    prepare() if args.mode == "prepare" else run()
