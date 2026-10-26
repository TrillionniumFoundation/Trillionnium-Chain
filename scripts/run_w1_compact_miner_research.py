#!/usr/bin/env python3
"""Freeze and collect compact-output and original deferred W1 miner experiments.

The existing cost campaign and public-service envelopes remain unchanged. This
runner builds the native miner research executable afresh, binds the real GNU time observer,
retains every raw record and failure, and never treats internal reconciliation as
hardware attestation, model improvement, or a universal work-cost lower bound.
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
from w1_lossless_raw import compress_completed_stdout

SCHEMA = "pon-w1-compact-miner-research-bundle-v1"
PLAN_SCHEMA = "pon-w1-compact-miner-plan-v1"
BINARIES = ("pon_w1_late_assembly_research", "pon_w1_compact_miner_research")
MAX_OUTPUT = 256 * 1024 * 1024
WAITED_CPU_ALLOWANCE_NS = 2000
GNU_TIME_PRINT_ALLOWANCE_NS = 20_000_000


def registered_jobs():
    """Frozen order and controls; never select seeds/envelopes after collection."""
    main = ((7101,128000000,"late"), (7101,128000000,"compact"),
            (7102,128000000,"compact"), (7102,128000000,"late"),
            (7101,512000000,"compact"), (7101,512000000,"late"),
            (7102,512000000,"late"), (7102,512000000,"compact"))
    jobs = []
    def add(name, kind, setup, miner, cap, seed):
        args = ["--setup-budget-ns", str(setup), "--miner-budget-ns", str(miner),
                "--max-attempts", str(cap), "--seed", str(seed)]
        if kind == "late":
            args += ["--mode", "deferred"]
        jobs.append(dict(name=name, binary=BINARIES[kind == "compact"], args=args,
                         timeout_seconds=180))
    for seed, budget, kind in main:
        add(f"main-s{seed}-b{budget}-{kind}", kind, 1000000000, budget, 4096, seed)
    for label, setup, miner, cap in (
        ("setupzero",0,128000000,4096), ("setuptight",1000000,128000000,4096),
        ("minerzero",1000000000,0,4096), ("minertight",1000000000,100000,4096),
        ("attemptcap2",1000000000,512000000,2)):
        add("control-"+label, "compact", setup, miner, cap, 7103)
    return jobs


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def decode(text):
    def bad_constant(_):
        raise ValueError("NONFINITE_JSON")
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=bad_constant)


def validate_plan(plan):
    require(type(plan) is dict and plan.get("schema") == PLAN_SCHEMA, "PLAN_SCHEMA")
    for flag in ("production_activation", "hardness_accepted", "hardware_attested"):
        require(plan.get(flag) is False, "PLAN_AUTHORITY")
    require(plan.get("proof_retention") == "compact-original-winner-packets-and-original-late-comparator",
            "PLAN_PROOF_RETENTION")
    require(plan.get("independent_replay") == "all-original-winners-and-all-deterministic-attempts-posthoc-no-feedback",
            "PLAN_REPLAY")
    for field, expected in (("waited_cpu_endpoint_allowance_ns", WAITED_CPU_ALLOWANCE_NS),
                            ("gnu_time_print_allowance_ns", GNU_TIME_PRINT_ALLOWANCE_NS)):
        require(type(plan.get(field)) is int and plan[field] == expected,
                "REGISTERED_OBSERVER_ALLOWANCES")
    require(plan.get("generation_then_receiver_then_audit") is True and
            plan.get("miner_feedback_from_receiver") is False, "PLAN_PHASE_SEPARATION")
    limit = plan.get("collection_output_limit_bytes")
    require(type(limit) is int and 1024 * 1024 <= limit <= MAX_OUTPUT, "PLAN_OUTPUT_LIMIT")
    jobs = plan.get("jobs")
    require(type(jobs) is list and 1 <= len(jobs) <= 96, "PLAN_JOB_COUNT")
    names = {"preflight", "rustc-version", "cargo-version", "metadata", "build"}
    for job in jobs:
        require(type(job) is dict and set(job) == {"name", "binary", "args", "timeout_seconds"},
                "PLAN_JOB_FIELDS")
        require(type(job["name"]) is str and
                re.fullmatch(r"[a-z0-9][a-z0-9._-]*", job["name"]) is not None,
                "PLAN_JOB_NAME")
        require(job["name"] not in names, "PLAN_DUPLICATE_JOB")
        names.add(job["name"])
        require(job["binary"] in BINARIES, "PLAN_BINARY")
        argv = job["args"]
        require(type(argv) is list and 2 <= len(argv) <= 40 and len(argv) % 2 == 0 and
                all(type(v) is str and 0 < len(v) <= 256 for v in argv), "PLAN_ARGS")
        require(all(k.startswith("--") for k in argv[::2]) and
                len(set(argv[::2])) == len(argv[::2]), "PLAN_OPTIONS")
        require(type(job["timeout_seconds"]) is int and
                1 <= job["timeout_seconds"] <= 1800, "PLAN_TIMEOUT")
        if job["binary"] == "pon_w1_compact_miner_research":
            from w1_compact_miner_reader import options_from_args
        else:
            from w1_late_assembly_reader import options_from_args
        options_from_args(argv)
    require(jobs == registered_jobs(), "EXACT_PREREGISTERED_COMPACT_GRID")
    return jobs


def usage_snapshot(path):
    """Actual GNU time command observation, never a sum of concurrent RSS peaks."""
    data = path.read_bytes()
    require(0 < len(data) <= 16 * 1024, "GNU_TIME_USAGE_LENGTH")
    rows = data.decode("utf-8").splitlines()
    require(len(rows) == 1, "GNU_TIME_USAGE_ROWS")
    values = rows[-1].split()
    require(len(values) == 4 and
            all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", v) for v in (values[0], values[1], values[3]))
            and re.fullmatch(r"[0-9]+", values[2]) is not None, "GNU_TIME_USAGE_FIELDS")
    return {"user_seconds_decimal": values[0], "system_seconds_decimal": values[1],
            "maximum_resident_set_kib": int(values[2]), "elapsed_seconds_decimal": values[3],
            "scope": "GNU time observation for this measured command, including setup, miner, receiver, audit and output; not miner-only or aggregate concurrent memory",
            "resolution": "GNU time printed precision; do not replace native nanosecond clocks with these rounded values",
            "file": path.name, "bytes": len(data), "sha256": sha(path)}


def build_artifacts(path, target):
    found = {}
    for line in path.read_text().splitlines():
        row = decode(line)
        name = row.get("target", {}).get("name")
        if row.get("reason") != "compiler-artifact" or name not in BINARIES or not row.get("executable"):
            continue
        require(name not in found, "DUPLICATE_EXECUTABLE_ARTIFACT")
        executable = (target / "release/examples" / name).resolve()
        require(Path(row["executable"]).resolve() == executable and executable.is_file(),
                "EXECUTABLE_ARTIFACT_BINDING")
        require(row.get("fresh") is False, "FRESH_EXECUTABLE_BUILD_REQUIRED")
        found[name] = {"path": str(executable), "bytes": executable.stat().st_size,
                       "sha256": sha(executable), "cargo_artifact": row}
    require(set(found) == set(BINARIES), "MISSING_EXECUTABLE_ARTIFACT")
    return found


def run(args):
    require(sys.platform.startswith("linux"), "LINUX_RUNNER_REQUIRED")
    require(all(re.fullmatch(r"[0-9a-f]{40}", v) for v in (args.expected_head, args.expected_tree)),
            "FULL_SOURCE_IDENTITIES")
    before = source_snapshot()
    raw_before = validate_source(before, args.expected_head, args.expected_tree, verify_raw=True)
    validate_build_environment(os.environ)
    out, target = args.out.resolve(), args.target_dir.resolve()
    require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT), "EXTERNAL_OUTPUT_AND_BUILD")
    require(not out.is_relative_to(target) and not target.is_relative_to(out), "DISJOINT_OUTPUT_AND_BUILD")
    plan_path = args.plan.resolve()
    require(plan_path.is_relative_to(ROOT), "COMMITTED_PLAN_REQUIRED")
    subprocess.run(["git", "ls-files", "--error-unmatch", str(plan_path.relative_to(ROOT))],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    plan = decode(plan_path.read_text())
    jobs = validate_plan(plan)
    require(args.cpu in os.sched_getaffinity(0), "CPU_AFFINITY_UNAVAILABLE")
    taskset = shutil.which("taskset")
    require(taskset is not None, "TASKSET_REQUIRED")
    taskset = str(Path(taskset).resolve())
    launcher = {"path": taskset, "sha256": sha(taskset)}
    cargo = args.cargo.resolve()
    rustc = cargo.parent / "rustc"
    require(cargo.is_file() and rustc.is_file(), "DIRECT_TOOLCHAIN_REQUIRED")
    configurations = cargo_configuration_observation(args.cargo_home.resolve())
    environment, observer = bind_gnu_time(dict(os.environ, TRNM_GNU_TIME=str(args.gnu_time.resolve())))
    environment.update(PATH=str(cargo.parent) + os.pathsep + environment.get("PATH", ""),
                       CARGO_HOME=str(args.cargo_home.resolve()), CARGO_TARGET_DIR=str(target),
                       CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
                       RUSTC=str(rustc), PYTHONDONTWRITEBYTECODE="1")
    out.mkdir(parents=True, exist_ok=False)
    create_fresh_target(target)
    (out / "preregistered-plan.json").write_bytes(plan_path.read_bytes())
    manifest = {
        "schema": SCHEMA, "started_utc": datetime.now(timezone.utc).isoformat(),
        "source_before": before, "raw_source_before": raw_before,
        "source_after": None, "raw_source_after": None, "source_unchanged": False,
        "plan_source_path": str(plan_path.relative_to(ROOT)), "plan_sha256": sha(plan_path),
        "runner_sha256": sha(__file__), "collection_output_limit_bytes": plan["collection_output_limit_bytes"],
        "gnu_time_observer": observer, "cargo_configurations": configurations,
        "taskset": launcher,
        "compiler": {"path": str(rustc), "sha256": sha(rustc)},
        "cargo": {"path": str(cargo), "sha256": sha(cargo)},
        "declared_build_environment": {k: environment[k] for k in (
            "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE",
            "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "PYTHONDONTWRITEBYTECODE")},
        "fresh_target": True, "profile": "release", "binaries": {}, "steps": [],
        "compression": {}, "complete_success": False, "failure": None, "hardness_accepted": False,
        "production_activation": False, "hardware_attested": False,
        "independent_hardware_qualification": False,
        "prior_campaign_or_service_acceptance_changed": False,
    }
    write_new(out / "hardware-before.json", hardware_observation(args.cpu))
    manifest["hardware_before_sha256"] = sha(out / "hardware-before.json")
    limit = plan["collection_output_limit_bytes"]
    try:
        build = [str(cargo), "build", "--offline", "--locked", "--release", "--jobs", "2",
                 "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node",
                 "--message-format=json"]
        for name in BINARIES:
            build.extend(("--example", name))
        setup = (
            ("preflight", ["bash", "scripts/project-preflight.sh"], 60),
            ("rustc-version", [str(rustc), "-Vv"], 60),
            ("cargo-version", [str(cargo), "-Vv"], 60),
            ("metadata", [str(cargo), "metadata", "--offline", "--locked", "--format-version", "1",
                          "--manifest-path", "trillionnium/Cargo.toml"], 120),
            ("build", build, 1200),
        )
        for name, command, timeout in setup:
            step = run_step(out, name, command, environment, timeout, limit)
            manifest["steps"].append(step)
            require(step["complete_success"], "SETUP_FAILED:" + name)
            if name == "rustc-version":
                manifest["toolchain"] = (out / step["stdout"]).read_text()
                require(manifest["toolchain"].startswith("rustc 1.95.0 "), "RUST_1_95_0_REQUIRED")
        manifest["binaries"] = build_artifacts(out / "build.stdout", target)
        for job in jobs:
            validate_source(source_snapshot(), args.expected_head, args.expected_tree, verify_raw=True)
            verify_gnu_time(observer)
            require(sha(taskset) == launcher["sha256"], "TASKSET_CHANGED")
            selected = manifest["binaries"][job["binary"]]
            require(sha(selected["path"]) == selected["sha256"], "BINARY_CHANGED")
            usage = out / (job["name"] + ".usage")
            require(not usage.exists(), "USAGE_ALREADY_EXISTS")
            command = [observer["executable"], "-f", "%U %S %M %e", "-o", str(usage),
                       taskset, "-c", str(args.cpu), selected["path"], *job["args"]]
            step = run_step(out, job["name"], command, environment, job["timeout_seconds"], limit)
            manifest["steps"].append(step)
            try:
                step["command_usage"] = usage_snapshot(usage)
            except (OSError, ValueError, UnicodeError) as error:
                step["command_usage"] = None
                step["command_usage_error"] = str(error)
            write_new(out / (job["name"] + ".observer.json"), {
                "usage": step["command_usage"], "usage_error": step.get("command_usage_error"),
                "original_step_receipt_sha256": sha(out / (job["name"] + ".step.json")),
                "observer_sha256": observer["sha256"],
            })
            print(json.dumps({"job": job["name"], "complete": step["complete_success"],
                              "command_usage_available": step["command_usage"] is not None}), flush=True)
            require(step["complete_success"], "NATIVE_JOB_FAILED:" + job["name"])
            require(step["command_usage"] is not None, "GNU_TIME_USAGE_UNAVAILABLE:" + job["name"])
            manifest["compression"][job["name"]] = compress_completed_stdout(out, step)
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
            for value in manifest["binaries"].values():
                require(sha(value["path"]) == value["sha256"], "BINARY_CHANGED")
            verify_gnu_time(observer)
            require(sha(taskset) == launcher["sha256"], "TASKSET_CHANGED")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            manifest["complete_success"] = False
            manifest["failure"] = manifest["failure"] or str(error)
        write_new(out / "hardware-after.json", hardware_observation(args.cpu))
        manifest["hardware_after_sha256"] = sha(out / "hardware-after.json")
        manifest["ended_utc"] = datetime.now(timezone.utc).isoformat()
        write_new(out / "campaign.json", manifest)
    print(json.dumps({"complete_success": manifest["complete_success"],
                      "failure": manifest["failure"], "output": str(out)}), flush=True)
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
