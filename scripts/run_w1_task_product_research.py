#!/usr/bin/env python3
"""Collect the registered, opt-in W1 task-product verifier comparison.

Per-operation native observations are wall time. Whole-child CPU includes proof
generation, reference checks, all arms and output, and is never allocated back to
an individual arm. This is neither a miner cost floor nor a Node service result.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from run_w1_cost_research import (
    cargo_configuration_observation, create_fresh_target, hardware_observation,
    require, run_step, sha, source_snapshot, validate_build_environment,
    validate_source, write_new,
)
from qualification_runtime import bind_gnu_time, verify_gnu_time
from run_w1_compact_miner_research import decode, usage_snapshot

SCHEMA = "pon-w1-task-product-research-bundle-v1"
PLAN_SCHEMA = "pon-w1-task-product-research-plan-v1"
BINARY = "pon_task_product_facts"
OUTPUT_LIMIT = 32 * 1024 * 1024


def registered_jobs():
    return [dict(name=f"task-product-s{seed}", args=["--seed", str(seed)],
                 timeout_seconds=180) for seed in (8101, 8102)]


def validate_plan(plan):
    require(type(plan) is dict and plan.get("schema") == PLAN_SCHEMA, "PLAN_SCHEMA")
    require(set(plan) == {"schema", "production_activation", "hardness_accepted",
                         "hardware_attested", "node_admission_measured",
                         "operation_clock", "collection_output_limit_bytes", "jobs"},
            "PLAN_FIELDS")
    for field in ("production_activation", "hardness_accepted", "hardware_attested",
                  "node_admission_measured"):
        require(plan[field] is False, "PLAN_AUTHORITY")
    require(plan["operation_clock"] == "std::time::Instant-wall", "PLAN_CLOCK")
    require(type(plan["collection_output_limit_bytes"]) is int and
            plan["collection_output_limit_bytes"] == OUTPUT_LIMIT, "PLAN_LIMIT")
    jobs = plan["jobs"]
    require(type(jobs) is list and len(jobs) == 2, "PLAN_JOBS")
    for observed, expected in zip(jobs, registered_jobs()):
        require(type(observed) is dict and set(observed) == set(expected), "JOB_FIELDS")
        require(type(observed["name"]) is str and observed["name"] == expected["name"],
                "JOB_NAME")
        require(type(observed["args"]) is list and
                all(type(v) is str for v in observed["args"]) and
                observed["args"] == expected["args"], "JOB_ARGS")
        require(type(observed["timeout_seconds"]) is int and
                observed["timeout_seconds"] == expected["timeout_seconds"], "JOB_TIMEOUT")
    return jobs


def executable_artifact(path, target):
    rows = [decode(line) for line in path.read_text().splitlines()]
    candidates = [row for row in rows if row.get("reason") == "compiler-artifact"
                  and row.get("target", {}).get("name") == BINARY and row.get("executable")]
    require(len(candidates) == 1, "UNIQUE_EXECUTABLE")
    row = candidates[0]
    expected = (target / "release/examples" / BINARY).resolve()
    require(Path(row["executable"]).resolve() == expected and expected.is_file(),
            "EXECUTABLE_PATH")
    require(row.get("fresh") is False, "FRESH_EXECUTABLE_REQUIRED")
    return dict(path=str(expected), bytes=expected.stat().st_size,
                sha256=sha(expected), cargo_artifact=row)


def run(args):
    require(sys.platform.startswith("linux"), "LINUX_OBSERVER_REQUIRED")
    require(all(re.fullmatch(r"[0-9a-f]{40}", v) for v in
                (args.expected_head, args.expected_tree)), "FULL_SOURCE_PINS")
    before = source_snapshot()
    raw_before = validate_source(before, args.expected_head, args.expected_tree, verify_raw=True)
    validate_build_environment(os.environ)
    out, target = args.out.resolve(), args.target_dir.resolve()
    require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT), "EXTERNAL_OUTPUT")
    require(not out.is_relative_to(target) and not target.is_relative_to(out), "DISJOINT_OUTPUT")
    plan_path = args.plan.resolve()
    require(plan_path.is_relative_to(ROOT), "COMMITTED_PLAN")
    subprocess.run(["git", "ls-files", "--error-unmatch", str(plan_path.relative_to(ROOT))],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    plan = decode(plan_path.read_text())
    jobs = validate_plan(plan)
    require(args.cpu in os.sched_getaffinity(0), "CPU_AFFINITY")
    launcher = shutil.which("taskset")
    require(launcher is not None, "TASKSET_REQUIRED")
    launcher = str(Path(launcher).resolve())
    launcher_pin = sha(launcher)
    cargo = args.cargo.resolve()
    rustc = cargo.parent / "rustc"
    require(cargo.is_file() and rustc.is_file(), "DIRECT_TOOLCHAIN")
    configurations = cargo_configuration_observation(args.cargo_home.resolve())
    env, observer = bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(args.gnu_time.resolve())))
    env.update(PATH=str(cargo.parent) + os.pathsep + env.get("PATH", ""),
               CARGO_HOME=str(args.cargo_home.resolve()), CARGO_TARGET_DIR=str(target),
               CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0",
               RUSTC=str(rustc), PYTHONDONTWRITEBYTECODE="1")
    out.mkdir(parents=True, exist_ok=False)
    create_fresh_target(target)
    (out / "preregistered-plan.json").write_bytes(plan_path.read_bytes())
    manifest = dict(schema=SCHEMA, started_utc=datetime.now(timezone.utc).isoformat(),
                    repository_root=str(ROOT), output_directory=str(out), target_directory=str(target),
                    source_before=before, raw_source_before=raw_before,
                    source_after=None, raw_source_after=None, source_unchanged=False,
                    plan_source_path=str(plan_path.relative_to(ROOT)), plan_sha256=sha(plan_path),
                    runner_sha256=sha(__file__), gnu_time_observer=observer,
                    cargo_configurations=configurations,
                    taskset=dict(path=launcher, sha256=launcher_pin),
                    compiler=dict(path=str(rustc), sha256=sha(rustc)),
                    cargo=dict(path=str(cargo), sha256=sha(cargo)),
                    declared_build_environment={k: env[k] for k in (
                        "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE",
                        "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "PYTHONDONTWRITEBYTECODE")},
                    fresh_target=True, profile="release", binary=None, steps=[],
                    complete_success=False, failure=None, production_activation=False,
                    hardware_attested=False, hardness_accepted=False,
                    node_admission_measured=False, operation_clock=plan["operation_clock"],
                    collection_output_limit_bytes=OUTPUT_LIMIT)
    write_new(out / "hardware-before.json", hardware_observation(args.cpu))
    manifest["hardware_before_sha256"] = sha(out / "hardware-before.json")
    try:
        setup = (
            ("preflight", ["bash", "scripts/project-preflight.sh"], 60),
            ("rustc-version", [str(rustc), "-Vv"], 60),
            ("cargo-version", [str(cargo), "-Vv"], 60),
            ("metadata", [str(cargo), "metadata", "--offline", "--locked", "--format-version", "1",
                          "--manifest-path", "trillionnium/Cargo.toml"], 120),
            ("build", [str(cargo), "build", "--offline", "--locked", "--release", "--jobs", "1",
                       "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-crypto-primitives",
                       "--example", BINARY, "--message-format=json"], 1200),
        )
        for name, command, timeout in setup:
            step = run_step(out, name, command, env, timeout, OUTPUT_LIMIT)
            manifest["steps"].append(step)
            require(step["complete_success"], "SETUP_FAILED:" + name)
            if name == "rustc-version":
                manifest["toolchain"] = (out / step["stdout"]).read_text()
                require(manifest["toolchain"].startswith("rustc 1.95.0 "), "RUST_1_95_0_REQUIRED")
        manifest["binary"] = executable_artifact(out / "build.stdout", target)
        retained = out / BINARY
        shutil.copy2(manifest["binary"]["path"], retained)
        require(sha(retained) == manifest["binary"]["sha256"], "RETAINED_EXECUTABLE_COPY")
        manifest["binary"]["retained_file"] = BINARY
        for job in jobs:
            validate_source(source_snapshot(), args.expected_head, args.expected_tree, verify_raw=True)
            verify_gnu_time(observer)
            require(sha(launcher) == launcher_pin, "TASKSET_CHANGED")
            require(sha(manifest["binary"]["path"]) == manifest["binary"]["sha256"], "BINARY_CHANGED")
            usage = out / (job["name"] + ".usage")
            require(not usage.exists(), "USAGE_EXISTS")
            command = [observer["executable"], "-f", "%U %S %M %e", "-o", str(usage),
                       launcher, "-c", str(args.cpu), manifest["binary"]["path"], *job["args"]]
            step = run_step(out, job["name"], command, env, job["timeout_seconds"], OUTPUT_LIMIT)
            manifest["steps"].append(step)
            try:
                step["command_usage"] = usage_snapshot(usage)
                step["command_usage"]["scope"] = (
                    "whole native verifier study including proof generation, reference checks, "
                    "all arms, controls, output and teardown; not per-arm CPU")
            except (OSError, ValueError, UnicodeError) as error:
                step["command_usage"] = None
                step["command_usage_error"] = str(error)
            write_new(out / (job["name"] + ".observer.json"), dict(
                usage=step["command_usage"], usage_error=step.get("command_usage_error"),
                original_step_receipt_sha256=sha(out / (job["name"] + ".step.json")),
                observer_sha256=observer["sha256"]))
            print(json.dumps(dict(job=job["name"], complete=step["complete_success"])), flush=True)
            require(step["complete_success"], "NATIVE_FAILED:" + job["name"])
            require(step["command_usage"] is not None, "OBSERVER_FAILED:" + job["name"])
        manifest["complete_success"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        manifest["failure"] = str(error)
    finally:
        manifest["source_after"] = source_snapshot()
        try:
            manifest["raw_source_after"] = validate_source(
                manifest["source_after"], args.expected_head, args.expected_tree, verify_raw=True)
            manifest["source_unchanged"] = before == manifest["source_after"]
            require(manifest["source_unchanged"], "SOURCE_CHANGED")
            if manifest["binary"] is not None:
                require(sha(manifest["binary"]["path"]) == manifest["binary"]["sha256"], "BINARY_CHANGED")
                require(sha(out / BINARY) == manifest["binary"]["sha256"], "RETAINED_BINARY_CHANGED")
            verify_gnu_time(observer)
            require(sha(launcher) == launcher_pin, "TASKSET_CHANGED")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            manifest["complete_success"] = False
            manifest["failure"] = manifest["failure"] or str(error)
        write_new(out / "hardware-after.json", hardware_observation(args.cpu))
        manifest["hardware_after_sha256"] = sha(out / "hardware-after.json")
        manifest["ended_utc"] = datetime.now(timezone.utc).isoformat()
        write_new(out / "campaign.json", manifest)
    print(json.dumps(dict(complete_success=manifest["complete_success"], failure=manifest["failure"])))
    return 0 if manifest["complete_success"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("out", "target-dir", "cargo", "cargo-home", "plan", "gnu-time"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--cpu", type=int, required=True)
    try:
        return run(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
