#!/usr/bin/env python3
"""Run a separate finite owner-death lane with the original retained release ELF."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import re
import sys
import time

import read_history_verifier_lifeline_v1 as reader


def remaining_timeout(deadline, maximum, now=None):
    remaining = deadline - (time.monotonic() if now is None else now)
    if remaining <= 0:
        raise TimeoutError("owner-death lane budget exhausted before spawn")
    return min(maximum, remaining)


def capture_inventory(output):
    files = []
    for path in sorted(output.rglob("*")):
        reader.require(not path.is_symlink(), "retained artifact symlink refused")
        if path.is_dir():
            continue
        reader.require(path.is_file(), "retained artifact must be a regular file")
        files.append({"path": str(path.relative_to(output)), "bytes": path.stat().st_size,
                      "sha256": reader.hash_file(path)})
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--campaign-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    campaign = args.campaign_output.resolve(strict=True)
    output = args.output.resolve()
    reader.require(root == Path(__file__).resolve().parents[2], "executed source root mismatch")
    reader.require(re.fullmatch(r"[0-9a-f]{40}", args.head)
                   and re.fullmatch(r"[0-9a-f]{40}", args.tree), "full candidate head/tree required")
    reader.require(not output.is_relative_to(root) and not campaign.is_relative_to(root)
                   and output != campaign and not campaign.is_relative_to(output),
                   "new external output, separate from original build records")
    output.mkdir(parents=True, exist_ok=False)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "scripts"))
    import run_pon_w1_native_campaign as bounds
    reader.require(bounds.ROOT == root, "original bounded command helper source mismatch")
    started = time.monotonic()
    deadline = started + reader.TOTAL_SECONDS
    result = {
        "schema": "native-history-verifier-lifeline-ci-v1",
        "head": args.head, "tree": args.tree, "source_kind": "head",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "total_lane_timeout_seconds": reader.TOTAL_SECONDS,
        "small_control_timeout_seconds": reader.SMALL_SECONDS,
        "each_native_control_timeout_seconds": reader.CASE_SECONDS,
        "planned_small_methods": list(reader.SMALL_METHODS),
        "planned_native_boundaries": [stage for stage, _ in reader.CASES],
        "expected_outer_resources": {"cpu.max": "400000 100000",
                                     "memory.max": "17179869184", "nice": 10},
        "expected_verifier_parent": reader.PARENT,
        "expected_verifier_limits": dict(reader.LIMITS),
        "binary": None, "steps": [], "cases": [], "source_before": None, "source_after": None,
        "complete_success": False, "failure": None, "finalization_failures": [],
        "runner_sha256": reader.hash_file(__file__),
        "reader_sha256": reader.hash_file(Path(reader.__file__)),
        "original_campaign_qualified": False, "production_qualified": False,
        "scope": "six actual small-process methods and three actual systemd/Node death controls; "
                 "independent 600 second lane, no Cargo rebuild, no fabricated clean settlement, "
                 "original three 600 second campaigns and History 22/7/12 gates unchanged",
    }
    env = {key: value for key, value in os.environ.items() if not key.startswith("TRNM_")}
    env.update(RUST_TEST_THREADS="1", PYTHONDONTWRITEBYTECODE="1")
    binary = None
    binary_sha256 = None

    def check_deadline():
        if time.monotonic() > deadline:
            raise TimeoutError("owner-death lane total budget exhausted")

    def step(name, command, maximum, environment=None):
        timeout = remaining_timeout(deadline, maximum)
        row = bounds.run_step(output, name, command, environment or env, timeout=timeout)
        result["steps"].append(row)
        reader.validate_step(output, row, name, maximum)
        check_deadline()
        return row

    def source(name):
        filename = name + ".json"
        step(name, [sys.executable, str(root / "scripts/ci/verify_ci_source.py"),
                    "--kind", "head", "--expected-head", args.head,
                    "--output", str(output / filename)], 60)
        value, _ = reader.read(output / filename)
        reader.source_identity(value, args.head, args.tree)
        return value

    def resources(name):
        value = bounds.resource_observation()
        bounds.write_new(output / (name + ".json"), value)
        bounds.validate_resources(value, 10)
        reader.require(not value["cgroup"].startswith("/trnmponpublic.slice"),
                       "outer controller stays outside the fixed quarter-CPU verifier parent")
        check_deadline()
        return value

    def check_binary():
        reader.require(binary is not None and reader.hash_file(binary) == binary_sha256,
                       "retained exact release ELF changed")
        check_deadline()

    try:
        reader.require(platform.machine() == "x86_64" and sys.platform.startswith("linux"),
                       "this explicit native control lane requires Linux x64")
        bounds.validate_build_environment(os.environ)
        result["source_before"] = source("source-before")
        outer_resources = resources("resource-before")
        binary, record = reader.baseline_binary(campaign, args.head, args.tree)
        binary_sha256 = record["sha256_before"]
        result["binary"] = {
            "path": str(binary), "bytes": record["bytes"], "sha256_before": binary_sha256,
            "sha256_after": None, "actual_compiler_artifact_profile": record["actual_compiler_artifact_profile"],
            "retained_bytes_executed_directly": True, "cargo_rebuild": False,
        }
        check_binary()
        listed = step("list-small", [str(binary), reader.SMALL_PREFIX, "--list"], 10)
        ignored = step("list-small-ignored",
                       [str(binary), reader.SMALL_PREFIX, "--list", "--ignored"], 10)
        reader.validate_roster(reader.text_file(output / listed["stdout"]),
                               reader.text_file(output / ignored["stdout"]))
        small_raw = output / "small-raw"
        small_raw.mkdir()
        small_env = dict(env, TRNM_HISTORY_LIFELINE_EVIDENCE_DIR=str(small_raw))
        small = step("small-controls", [str(binary), reader.SMALL_PREFIX,
                                       "--show-output", "--test-threads=1"],
                     reader.SMALL_SECONDS, small_env)
        result["small_controls"] = reader.validate_small(
            small_raw, reader.text_file(output / small["stdout"]))
        source("source-after-small")
        resources("resource-after-small")
        check_binary()
        for number, (stage, selector) in enumerate(reader.CASES, 1):
            name = f"native-{number}"
            case_path = output / (name + "-raw")
            reader.absent(case_path)  # The actual Rust parent creates it exclusively.
            attempt = {"stage": stage, "selector": reader.NATIVE_PREFIX + selector,
                       "complete_success": False, "failure": None}
            result["cases"].append(attempt)
            try:
                check_binary()
                resources(name + "-resource-before")
                case_env = dict(env, TRNM_HISTORY_VERIFIER_LIFELINE_OUTPUT=str(case_path))
                command = [str(binary), attempt["selector"], "--exact", "--ignored",
                           "--nocapture", "--test-threads=1"]
                observation = step(name, command, reader.CASE_SECONDS, case_env)
                attempt["step"] = observation
                reader.test_terminal(reader.text_file(output / observation["stdout"]),
                                     [attempt["selector"]], [])
                attempt["readback"] = reader.validate_case(
                    case_path, stage, binary_sha256, outer_resources["cgroup"])
                attempt["complete_success"] = True
            except (OSError, ValueError, KeyError, TypeError, TimeoutError) as error:
                attempt["failure"] = f"{type(error).__name__}: {error}"
            bounds.write_new(output / (name + "-readback.json"), attempt)
            source(name + "-source-after")
            resources(name + "-resource-after")
            check_binary()
            # A failed planned case is retained. Any later case is distinct;
            # no replacement retry or relaxed budget is used to improve the cohort.
        result["complete_success"] = (
            len(result["cases"]) == 3 and all(row["complete_success"] for row in result["cases"]))
        if not result["complete_success"]:
            result["failure"] = "one or more original native owner-death controls failed"
    except (OSError, ValueError, KeyError, TypeError, TimeoutError) as error:
        result["failure"] = f"{type(error).__name__}: {error}"
    finally:
        for name, action in (
                ("source_after", lambda: source("source-after")),
                ("resources_after", lambda: resources("resource-after"))):
            try:
                result[name] = action()
            except Exception as error:
                result["finalization_failures"].append(f"{name}: {type(error).__name__}: {error}")
        if binary is not None:
            try:
                check_binary()
                result["binary"]["sha256_after"] = reader.hash_file(binary)
            except Exception as error:
                result["finalization_failures"].append(f"binary: {type(error).__name__}: {error}")
        files = []
        try:
            files = capture_inventory(output)
            check_deadline()
        except Exception as error:
            result["finalization_failures"].append(f"inventory: {type(error).__name__}: {error}")
        result["elapsed_ns"] = int((time.monotonic() - started) * 1_000_000_000)
        result["complete_success"] = (
            result["complete_success"] and not result["finalization_failures"]
            and result["elapsed_ns"] <= reader.TOTAL_SECONDS * 1_000_000_000)
        result["completed_utc"] = datetime.now(timezone.utc).isoformat()
        bounds.write_new(output / "results.json", result)
        files.append({"path": "results.json", "bytes": (output / "results.json").stat().st_size,
                      "sha256": reader.hash_file(output / "results.json")})
        bounds.write_new(output / "artifact-files.json", {
            "scope": "all retained partial or complete observations, not a separate PASS claim", "files": files})
    print(__import__("json").dumps({
        "output": str(output), "head": args.head, "tree": args.tree,
        "complete_success": result["complete_success"], "failure": result["failure"],
        "finalization_failures": result["finalization_failures"]}, sort_keys=True))
    return 0 if result["complete_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
