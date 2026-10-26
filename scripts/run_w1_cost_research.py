#!/usr/bin/env python3
"""Collect the explicitly separate W1 cost-security research campaign.

The original service/cost qualification runners and their resource envelopes are
unchanged. This runner records its actual local environment; it does not qualify
the original 400%-CPU/16-GiB campaign, another architecture, or energy consumption.
All native output, including failed runs, stays in a fresh external directory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from bounded_process import ProcessFailure, run_bounded
sys.path.insert(0, str(ROOT / "scripts/ci"))
from verify_ci_source import verify as verify_raw_source

SCHEMA = "pon-w1-cost-research-bundle-v1"
OVERRIDES = (
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_BOOTSTRAP",
    "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_RUSTDOC", "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTDOC", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "LIBRARY_PATH",
    "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "SDKROOT",
    "LIBSQLITE3_SYS_USE_PKG_CONFIG", "CRATE_CC_NO_DEFAULTS", "CROSS_COMPILE",
)
C_BUILD_OPTIONS = ("CC", "CXX", "AR", "ARFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "RANLIB", "CXXSTDLIB")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def git(*arguments):
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *arguments], text=True, timeout=30
    ).strip()


def source_snapshot():
    return {
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "branch": git("branch", "--show-current"),
        "status": git("status", "--porcelain", "--untracked-files=all"),
    }


def validate_source(observed, expected_head, expected_tree, *, verify_raw=False):
    require(observed["head"] == expected_head, "SOURCE_HEAD_CHANGED")
    require(observed["tree"] == expected_tree, "SOURCE_TREE_CHANGED")
    require(not observed["status"], "CLEAN_COMMITTED_SOURCE_REQUIRED")
    if verify_raw:
        receipt = verify_raw_source("head", expected_head, root=ROOT)
        require(receipt["tested_tree"] == expected_tree, "RAW_SOURCE_TREE_CHANGED")
        return receipt
    return None


def validate_build_environment(environment):
    require(all(not environment.get(key) for key in OVERRIDES), "BUILD_OVERRIDE")
    for key, value in environment.items():
        if not value:
            continue
        require(not key.startswith(("CARGO_PROFILE_", "CARGO_BUILD_")), "BUILD_PROFILE_OVERRIDE")
        require(not (key.startswith("CARGO_TARGET_") and
                     key.endswith(("_RUSTFLAGS", "_LINKER", "_RUNNER"))), "TARGET_BUILD_OVERRIDE")
        require(not key.startswith(("SQLITE3_", "SQLITE_", "LIBSQLITE3_", "PKG_CONFIG")), "NATIVE_BUILD_OVERRIDE")
        require(not any(key == name or key.startswith(name + "_") or
                        key in ("HOST_" + name, "TARGET_" + name)
                        for name in C_BUILD_OPTIONS), "NATIVE_BUILD_OVERRIDE")


def create_fresh_target(target):
    require(not target.exists() and not target.is_symlink(), "FRESH_TARGET_REQUIRED")
    target.mkdir(parents=True, exist_ok=False)


def read_optional(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def hardware_observation(cpu):
    cpuinfo = read_optional("/proc/cpuinfo") or ""
    models = sorted({line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                     if line.startswith("model name")})
    flags = sorted({line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                    if line.startswith("flags")})
    limits = []
    cgroup = read_optional("/proc/self/cgroup")
    if cgroup is not None:
        unified = [line.split(":", 2)[2] for line in cgroup.splitlines()
                   if line.startswith("0::")]
        if len(unified) == 1:
            path = Path("/sys/fs/cgroup") / unified[0].lstrip("/")
            while path.is_relative_to(Path("/sys/fs/cgroup")):
                limits.append({"path": str(path), **{
                    key: read_optional(path / key) for key in (
                        "cpu.max", "cpu.stat", "memory.max", "memory.events",
                        "cpuset.cpus.effective")}})
                if path == Path("/sys/fs/cgroup"):
                    break
                path = path.parent
    return {
        "machine": platform.machine(), "platform": platform.platform(),
        "cpu_models": models, "cpu_flags": flags,
        "logical_cpus": os.cpu_count(),
        "allowed_affinity": sorted(os.sched_getaffinity(0)),
        "requested_child_cpu": cpu, "exclusive_cpu": False,
        "nice": os.getpriority(os.PRIO_PROCESS, 0), "cgroup": cgroup,
        "cgroup_limits": limits,
        "gpu_devices": sorted(str(p) for p in Path("/dev").glob("nvidia*")),
        "powercap_entries": sorted(str(p) for p in Path("/sys/class/powercap").glob("*")),
        "hardware_attested": False, "independent_operators": 1,
        "energy_joules": None, "memory_bandwidth_bytes_per_second": None,
        "network_transfer_measured": False,
    }


def cargo_configuration_observation(cargo_home):
    """Refuse hidden Cargo configuration instead of claiming an empty override set."""
    paths = {cargo_home / "config", cargo_home / "config.toml"}
    for ancestor in (ROOT, *ROOT.parents):
        paths.update((ancestor / ".cargo/config", ancestor / ".cargo/config.toml"))
    observations = []
    for path in sorted(paths):
        exists = path.exists()
        observations.append({"path": str(path), "exists": exists,
                             "sha256": sha(path) if exists and path.is_file() else None})
    require(not any(item["exists"] for item in observations), "UNDECLARED_CARGO_CONFIGURATION")
    return observations


def run_step(output, name, command, env, timeout, output_limit):
    require(re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name) is not None, "STEP_NAME")
    stdout_path, stderr_path = output / (name + ".stdout"), output / (name + ".stderr")
    row = {
        "name": name, "command": command, "cwd": str(ROOT),
        "timeout_seconds": timeout, "output_limit_bytes": output_limit,
        "returncode": None, "error": None, "stdout_truncated": False,
        "stderr_truncated": False, "stdout": stdout_path.name,
        "stderr": stderr_path.name,
    }
    start = time.monotonic_ns()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with stdout_path.open("xb") as out_stream, stderr_path.open("xb") as err_stream:
        stdout = stderr = b""
        try:
            completed = run_bounded(
                command, b"", timeout=timeout, stdout_limit=output_limit,
                stderr_limit=4 * 1024 * 1024, cwd=ROOT, env=env,
            )
            row["returncode"] = completed.returncode
            stdout, stderr = completed.stdout, completed.stderr
        except ProcessFailure as error:
            row.update(returncode=error.returncode, error=str(error),
                       stdout_truncated=error.stdout_truncated,
                       stderr_truncated=error.stderr_truncated)
            stdout, stderr = error.stdout, error.stderr
        except (OSError, ValueError) as error:
            row["error"] = str(error)
        out_stream.write(stdout)
        err_stream.write(stderr)
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    row["whole_waited_child_resources"] = {
        "user_cpu_ns": round((child_after.ru_utime - child_before.ru_utime) * 1_000_000_000),
        "system_cpu_ns": round((child_after.ru_stime - child_before.ru_stime) * 1_000_000_000),
        "minor_page_faults": child_after.ru_minflt - child_before.ru_minflt,
        "major_page_faults": child_after.ru_majflt - child_before.ru_majflt,
        "input_blocks": child_after.ru_inblock - child_before.ru_inblock,
        "output_blocks": child_after.ru_oublock - child_before.ru_oublock,
        "voluntary_context_switches": child_after.ru_nvcsw - child_before.ru_nvcsw,
        "involuntary_context_switches": child_after.ru_nivcsw - child_before.ru_nivcsw,
        "runner_lifetime_max_child_rss_kib": child_after.ru_maxrss,
        "rss_scope": "Linux cumulative maximum over waited children, including setup; not this step's peak or a sum",
        "cpu_scope": "whole waited child including all observers, logging and teardown; not producer-only",
        "block_counts_are_network_bytes": False,
    }
    row.update(wall_ns=time.monotonic_ns() - start,
               stdout_bytes=len(stdout), stderr_bytes=len(stderr),
               stdout_sha256=sha(stdout_path), stderr_sha256=sha(stderr_path))
    row["complete_success"] = row["returncode"] == 0 and row["error"] is None
    write_new(output / (name + ".step.json"), row)
    return row


def validate_plan(plan):
    require(plan.get("schema") == "pon-w1-cost-research-plan-v1", "PLAN_SCHEMA")
    require(plan.get("production_activation") is False, "PLAN_AUTHORITY")
    require(plan.get("hardness_accepted") is False, "PLAN_HARDNESS")
    limit = plan.get("collection_output_limit_bytes", 64 * 1024 * 1024)
    require(type(limit) is int and limit in (64 * 1024 * 1024, 256 * 1024 * 1024),
            "PLAN_OUTPUT_LIMIT")
    jobs = plan.get("jobs")
    require(type(jobs) is list and 1 <= len(jobs) <= 64, "PLAN_JOB_COUNT")
    names = set()
    for job in jobs:
        require(set(job) == {"name", "args", "timeout_seconds"}, "PLAN_JOB_FIELDS")
        require(type(job["name"]) is str and
                re.fullmatch(r"[a-z0-9][a-z0-9._-]*", job["name"]) is not None,
                "PLAN_JOB_NAME")
        require(job["name"] not in names, "PLAN_DUPLICATE_JOB")
        names.add(job["name"])
        require(type(job["args"]) is list and 1 <= len(job["args"]) <= 64 and
                all(type(arg) is str and len(arg) <= 4096 for arg in job["args"]),
                "PLAN_JOB_ARGS")
        require(type(job["timeout_seconds"]) is int and
                1 <= job["timeout_seconds"] <= 1800, "PLAN_JOB_TIMEOUT")
    return jobs


def run(args):
    require(sys.platform.startswith("linux"), "LINUX_RESEARCH_RUNNER")
    require(all(re.fullmatch("[0-9a-f]{40}", value) for value in
                (args.expected_head, args.expected_tree)), "FULL_SOURCE_IDENTITIES")
    before = source_snapshot()
    raw_before = validate_source(before, args.expected_head, args.expected_tree, verify_raw=True)
    validate_build_environment(os.environ)
    out, target = args.out.resolve(), args.target_dir.resolve()
    require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT),
            "EXTERNAL_OUTPUT_AND_BUILD_REQUIRED")
    require(not out.is_relative_to(target) and not target.is_relative_to(out),
            "DISJOINT_OUTPUT_AND_BUILD_REQUIRED")
    plan_path = args.plan.resolve()
    require(plan_path.is_relative_to(ROOT), "COMMITTED_PLAN_REQUIRED")
    git("ls-files", "--error-unmatch", str(plan_path.relative_to(ROOT)))
    plan = json.loads(plan_path.read_text())
    jobs = validate_plan(plan)
    output_limit = plan.get("collection_output_limit_bytes", 64 * 1024 * 1024)
    require(args.cpu in os.sched_getaffinity(0), "CPU_AFFINITY_UNAVAILABLE")
    taskset = shutil.which("taskset")
    require(taskset is not None, "TASKSET_REQUIRED")
    cargo = args.cargo.resolve()
    rustc = cargo.parent / "rustc"
    require(cargo.is_file() and rustc.is_file(), "DIRECT_TOOLCHAIN_REQUIRED")
    cargo_configurations = cargo_configuration_observation(args.cargo_home.resolve())
    env = dict(os.environ)
    env.update(PATH=str(cargo.parent) + os.pathsep + env.get("PATH", ""),
               CARGO_HOME=str(args.cargo_home.resolve()),
               CARGO_TARGET_DIR=str(target), CARGO_NET_OFFLINE="true",
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
               RUSTC=str(rustc), PYTHONDONTWRITEBYTECODE="1")
    out.mkdir(parents=True, exist_ok=False)
    create_fresh_target(target)
    with (out / "preregistered-plan.json").open("xb") as stream:
        stream.write(plan_path.read_bytes())
    report = {
        "schema": SCHEMA, "started_utc": datetime.now(timezone.utc).isoformat(),
        "source_before": before, "source_after": None,
        "raw_source_before": raw_before, "raw_source_after": None,
        "target_directory_was_new": True,
        "source_unchanged": False, "plan_sha256": sha(plan_path),
        "runner_sha256": sha(__file__), "plan_source_path": str(plan_path.relative_to(ROOT)),
        "toolchain": None,
        "profile": "release", "inherited_build_overrides": {}, "binary": None,
        "cargo_configurations": cargo_configurations,
        "declared_build_environment": {key: env[key] for key in (
            "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE",
            "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "PYTHONDONTWRITEBYTECODE")},
        "compiler": {"path": str(rustc), "sha256": sha(rustc)},
        "cargo": {"path": str(cargo), "sha256": sha(cargo)},
        "steps": [], "complete_success": False, "failure": None,
        "hardness_accepted": False, "production_activation": False,
        "independent_hardware_qualification": False,
        "scope": "new local research cohort; original service qualification unchanged",
    }
    write_new(out / "hardware-before.json", hardware_observation(args.cpu))
    report["hardware_before_sha256"] = sha(out / "hardware-before.json")
    try:
        setup = (
            ("preflight", ["bash", "scripts/project-preflight.sh"], 60),
            ("rustc-version", [str(rustc), "-Vv"], 60),
            ("cargo-version", [str(cargo), "-Vv"], 60),
            ("metadata", [str(cargo), "metadata", "--offline", "--locked",
                          "--format-version", "1", "--manifest-path",
                          "trillionnium/Cargo.toml"], 120),
            ("build", [str(cargo), "build", "--offline", "--locked", "--release",
                       "--jobs", "2", "--manifest-path", "trillionnium/Cargo.toml",
                       "-p", "trnm-pon-node", "--example", "pon_w1_cost_game",
                       "--message-format=json"], 1200),
        )
        for name, command, timeout in setup:
            step = run_step(out, name, command, env, timeout, output_limit)
            report["steps"].append(step)
            require(step["complete_success"], "SETUP_FAILED:" + name)
            if name == "rustc-version":
                report["toolchain"] = (out / step["stdout"]).read_text()
                require(report["toolchain"].startswith("rustc 1.95.0 "),
                        "RUST_1_95_0_REQUIRED")
        binary = target / "release/examples/pon_w1_cost_game"
        require(binary.is_file(), "BUILT_BINARY_MISSING")
        artifacts = []
        for line in (out / "build.stdout").read_text().splitlines():
            message = json.loads(line)
            if (message.get("reason") == "compiler-artifact" and
                    message.get("target", {}).get("name") == "pon_w1_cost_game" and
                    message.get("executable")):
                artifacts.append(message)
        require(len(artifacts) == 1 and Path(artifacts[0]["executable"]).resolve() == binary.resolve(),
                "CARGO_EXECUTABLE_ARTIFACT_BINDING")
        require(artifacts[0].get("fresh") is False, "FRESH_EXECUTABLE_BUILD_REQUIRED")
        report["cargo_executable_artifact"] = artifacts[0]
        report["binary"] = {"path": str(binary), "sha256": sha(binary),
                            "bytes": binary.stat().st_size}
        for job in jobs:
            validate_source(source_snapshot(), args.expected_head, args.expected_tree, verify_raw=True)
            require(sha(binary) == report["binary"]["sha256"], "BINARY_CHANGED")
            command = [taskset, "-c", str(args.cpu), str(binary), *job["args"]]
            step = run_step(out, job["name"], command, env,
                            job["timeout_seconds"], output_limit)
            report["steps"].append(step)
            print(json.dumps({"job": job["name"], "complete": step["complete_success"],
                              "wall_ns": step["wall_ns"]}), flush=True)
            require(step["complete_success"], "NATIVE_JOB_FAILED:" + job["name"])
        report["complete_success"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    finally:
        report["source_after"] = source_snapshot()
        report["source_unchanged"] = report["source_before"] == report["source_after"]
        try:
            report["raw_source_after"] = validate_source(
                report["source_after"], args.expected_head, args.expected_tree, verify_raw=True)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report["source_unchanged"] = False
            report["failure"] = report["failure"] or "RAW_SOURCE_CHANGED:" + str(error)
        if not report["source_unchanged"]:
            report["complete_success"] = False
            report["failure"] = report["failure"] or "SOURCE_CHANGED"
        if report["binary"] is not None and sha(report["binary"]["path"]) != report["binary"]["sha256"]:
            report["complete_success"] = False
            report["failure"] = report["failure"] or "BINARY_CHANGED"
        write_new(out / "hardware-after.json", hardware_observation(args.cpu))
        report["hardware_after_sha256"] = sha(out / "hardware-after.json")
        report["ended_utc"] = datetime.now(timezone.utc).isoformat()
        write_new(out / "campaign.json", report)
    print(json.dumps({"complete_success": report["complete_success"],
                      "failure": report["failure"], "output": str(out)}), flush=True)
    return 0 if report["complete_success"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--cpu", type=int, required=True)
    try:
        raise SystemExit(run(parser.parse_args()))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
