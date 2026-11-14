#!/usr/bin/env python3
"""Retain the fixed zero-paired/lazy grid on a complete committed source.

Reuse the original V5 source guard, sole wait4 reaper and 300-second shard
limit. A passing observation is an implementation cost, never a lower bound.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import time

from run_w1_rank_batch_v5 import (
    ARCHITECTURES, COST_BUILD_TIMEOUT_SECONDS, COST_CAMPAIGN_TIMEOUT_SECONDS,
    COST_IDENTITY_TIMEOUT_SECONDS, COST_TERMINATION_GRACE_SECONDS, ROOT,
    build_environment_overrides, capture, cargo_configuration_snapshot,
    checked_source, digest, discover_tool, elf_machine, host,
    require_cargo_configuration, write_json,
)

sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import pon_w1_zero_paired_lazy_v1 as reader

EXAMPLE = "pon_w1_zero_paired_lazy_v1"
GRID = ((0, 1), (0, 8), (1, 1), (1, 8), (2, 1), (3, 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT.resolve()):
        parser.error("output must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=False)
    spec = ARCHITECTURES[args.arch]
    started = time.monotonic_ns()
    parent_start = resource.getrusage(resource.RUSAGE_SELF)
    report = {"schema": "pon-w1-zero-paired-lazy-execution-v1", "result": "HOLD",
              "expected_commit": args.expected_commit, "architecture": args.arch,
              "grid": GRID, "observations": [], "shards": [],
              "consensus_credit": 0, "production_activation": False,
              "cheapest_strategy_proven": False, "security_qualified": False,
              "original_public_service_resource_contract_used": False,
              "independent_execution_authenticated": False,
              "process_usage_scope": "wait4; unreaped-descendant costs may be missing",
              "rss_scope": "kernel-ru_maxrss; not sum or global simultaneous peak"}

    def guarded(command, stem, timeout):
        before = checked_source(args.expected_commit)
        observation = capture(command, output, stem, timeout=timeout)
        observation["source_before"] = before
        report["observations"].append(observation)
        # Preserve the process outcome before any subsequent guard/read failure.
        with (output / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(observation, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        after = checked_source(args.expected_commit)
        observation["source_after"] = after
        if before != after:
            raise ValueError("ZERO_LAZY_SOURCE_CHANGED_DURING_COMMAND")
        return observation

    def required(command, stem, timeout):
        observation = guarded(command, stem, timeout)
        if observation["exit_code"] != 0 or observation["timed_out"]:
            raise ValueError("ZERO_LAZY_COMMAND_FAILED:" + stem)
        return observation

    try:
        if platform.system() != "Linux" or platform.machine() != spec["machine"]:
            raise ValueError("ZERO_LAZY_NATIVE_LINUX_ARCHITECTURE_REQUIRED")
        if any(not hasattr(os, name) for name in ("wait4", "waitid", "WNOWAIT", "killpg")):
            raise ValueError("ZERO_LAZY_SOLE_REAPER_PLATFORM_REQUIRED")
        report["source_before"] = checked_source(args.expected_commit)
        report["host"] = host(output)
        overrides = build_environment_overrides(dict(os.environ))
        report["build_environment_overrides"] = overrides
        if overrides:
            raise ValueError("ZERO_LAZY_ORIGINAL_RELEASE_BUILD_OVERRIDES_FORBIDDEN")
        report["cargo_configuration_before"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report["cargo_configuration_before"])
        tools = {name: discover_tool(name) for name in ("cargo", "rustc")}
        report["toolchain"] = {
            name: {"path": str(path), "resolved_launcher": str(path.resolve(strict=True)),
                   "launcher_sha256": digest(path)} for name, path in tools.items()}
        write_json(output / "declaration.json", {
            "schema": "pon-w1-zero-paired-lazy-declaration-v1",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": report["source_before"], "grid": GRID,
            "samples": 8, "arms": reader.ARMS, "limit": 4096,
            "control_limit": 3, "horizons_correlated": True,
            "command_timeout_seconds": COST_CAMPAIGN_TIMEOUT_SECONDS,
            "termination_grace_seconds": COST_TERMINATION_GRACE_SECONDS,
            "no_retry_or_result_selection": True, "host": report["host"],
            "toolchain": report["toolchain"], "production_activation": False,
            "cheapest_strategy_proven": False})
        required([str(tools["rustc"]), "-vV"], "rustc", COST_IDENTITY_TIMEOUT_SECONDS)
        required([str(tools["cargo"]), "--version"], "cargo", COST_IDENTITY_TIMEOUT_SECONDS)
        compiler = (output / "rustc.stdout").read_text()
        if "\nrelease: 1.95.0\n" not in compiler or "\nhost: " + spec["target"] + "\n" not in compiler:
            raise ValueError("ZERO_LAZY_ORIGINAL_RUST_1_95_0_CONTRACT")
        required([str(tools["cargo"]), "build", "--locked", "--offline", "--release",
                  "--manifest-path", "trillionnium/Cargo.toml", "--target", spec["target"],
                  "-p", "trnm-crypto-primitives", "--example", EXAMPLE],
                 "build", COST_BUILD_TIMEOUT_SECONDS)
        binary = Path(os.environ["CARGO_TARGET_DIR"]) / spec["target"] / "release/examples" / EXAMPLE
        if elf_machine(binary) != spec["elf_machine"]:
            raise ValueError("ZERO_LAZY_ACTUAL_ELF_ARCHITECTURE")
        retained = output / EXAMPLE
        shutil.copyfile(binary, retained)
        retained.chmod(0o755)
        expected_binary = digest(binary)
        report["binary_sha256"] = expected_binary
        reports = []
        for number, (target, horizon) in enumerate(GRID):
            if digest(binary) != expected_binary or digest(retained) != expected_binary:
                raise ValueError("ZERO_LAZY_BINARY_CHANGED")
            stem = f"campaign-{number:02d}"
            observation = guarded([str(retained), "--zero-paired-lazy-v1",
                                   "--target-index", str(target), "--reuse-searches", str(horizon)],
                                  stem, COST_CAMPAIGN_TIMEOUT_SECONDS)
            item = {"target_index": target, "horizon": horizon, "observation": observation}
            report["shards"].append(item)
            # Nonzero/unknown exits cannot borrow a syntactically complete footer.
            item["reader"] = reader.analyze(output / observation["stdout"],
                                            process_exit_code=observation["exit_code"])
            reports.append(item["reader"])
            write_json(output / (stem + ".json"), item)
            print(json.dumps({"shard": number + 1, "planned": len(GRID),
                              "status": item["reader"]["status"]}), flush=True)
        report["reader"] = reader.campaign(reports)
        if report["reader"]["status"] != "COMPONENT_OBSERVATION":
            raise ValueError("ZERO_LAZY_COMPLETE_GRID_REQUIRED")
        if digest(binary) != expected_binary or digest(retained) != expected_binary:
            raise ValueError("ZERO_LAZY_BINARY_CHANGED")
        report["retained_binary_sha256"] = digest(retained)
        report["result"] = "COMPLETE_COMPONENT_OBSERVATION"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        try:
            report["source_after"] = checked_source(args.expected_commit)
            report["cargo_configuration_after"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
            require_cargo_configuration(report["cargo_configuration_after"])
            if (report.get("source_before") != report["source_after"]
                    or report.get("cargo_configuration_before") != report["cargo_configuration_after"]):
                raise ValueError("ZERO_LAZY_FINAL_SOURCE_OR_CONFIGURATION_CHANGED")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            report["final_check_error"] = str(error)
            report["result"] = "HOLD"
        parent_end = resource.getrusage(resource.RUSAGE_SELF)
        report["observer_cpu_ns"] = round(((parent_end.ru_utime + parent_end.ru_stime)
                                          - (parent_start.ru_utime + parent_start.ru_stime)) * 1e9)
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["failed_commands"] = sum(o["exit_code"] != 0 or o["timed_out"] for o in report["observations"])
        report["artifact_sha256"] = {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
        write_json(output / "manifest.json", report)
    print(json.dumps({"result": report["result"], "receipt": str(output)}, sort_keys=True))
    return 0 if report["result"] == "COMPLETE_COMPONENT_OBSERVATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
