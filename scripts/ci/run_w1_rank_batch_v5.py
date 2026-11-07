#!/usr/bin/env python3
"""Run the declared local V5 experiment on one exact committed joint source.

Every command retains stdout/stderr, wait4 CPU/RSS, timeout and process status.
This is component research under the observed host, never the quarter-CPU
public-service contract, a proof of cheapest work, or hardware independence.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys
import time

from ci_observation import ROOT, digest, source, _wait_without_reaping
from check_cross_arch_cost import (ARCHITECTURES, COST_BUILD_TIMEOUT_SECONDS,
    COST_CAMPAIGN_TIMEOUT_SECONDS, COST_IDENTITY_TIMEOUT_SECONDS,
    COST_TERMINATION_GRACE_SECONDS, elf_machine)
from run_cross_arch_cost import (build_environment_overrides,
    cargo_configuration_snapshot, require_cargo_configuration)

sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import pon_w1_rank_batch_reader_v5 as reader

EXAMPLE = "pon_w1_rank_batch_v5"


def discover_tool(name):
    location = shutil.which(name)
    if location is None:
        raise ValueError("V5_REQUIRED_TOOL_MISSING:" + name)
    # rustup is a multi-call executable: resolving a rustc/cargo symlink before
    # invocation changes argv[0] and asks rustup itself to handle those flags.
    # Preserve the invoked name; hash/record its resolved launcher separately.
    return Path(location).absolute()


def capture(command, output, stem, *, timeout, cwd=ROOT):
    """Sole wait4 reaper; keep leader identity until the final group signal.

    The native sampler creates threads only, so its wait4 usage includes them.
    For build/failed process trees the kernel may omit unreaped descendants;
    ru_maxrss is not a sum or aggregate simultaneous global memory peak.
    """
    started = time.monotonic_ns()
    result = {"command": command, "cwd": str(cwd), "stdout": stem + ".stdout",
        "stderr": stem + ".stderr", "timeout_seconds": timeout,
        "termination_grace_seconds": COST_TERMINATION_GRACE_SECONDS,
        "executed": False, "exit_code": None, "process_exit_code": None,
        "timed_out": False, "wait4_user_ns": None, "wait4_system_ns": None,
        "wait4_cpu_ns": None, "wait4_maxrss_kib": None,
        "global_cpu_complete": False, "global_memory_peak_observed": False}
    with (output / result["stdout"]).open("xb") as stdout, (output / result["stderr"]).open("xb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr, start_new_session=True)
        except OSError as error:
            result["launch_error"] = type(error).__name__
        else:
            result["executed"] = True
            try:
                try:
                    code = _wait_without_reaping(process, time.monotonic() + timeout)
                except ValueError as error:
                    if str(error) != "NATIVE_EXECUTOR_TIMEOUT":
                        raise
                    result["timed_out"] = True
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        _wait_without_reaping(process, time.monotonic() + COST_TERMINATION_GRACE_SECONDS)
                    except ValueError as error:
                        if str(error) != "NATIVE_EXECUTOR_TIMEOUT":
                            raise
                    code = 124
            finally:
                # Only the just-created process group is signalled. Keep the
                # leader unreaped through this signal to avoid PID/PGID reuse.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                result.update(process_exit_code=process.returncode,
                    wait4_user_ns=round(usage.ru_utime * 1_000_000_000),
                    wait4_system_ns=round(usage.ru_stime * 1_000_000_000),
                    wait4_cpu_ns=round((usage.ru_utime + usage.ru_stime) * 1_000_000_000),
                    wait4_maxrss_kib=usage.ru_maxrss)
            result["exit_code"] = code
    result["elapsed_ns"] = time.monotonic_ns() - started
    for key in ("stdout", "stderr"):
        path = output / result[key]
        result[key + "_bytes"] = path.stat().st_size
        result[key + "_sha256"] = digest(path)
    return result


def checked_source(expected):
    observed = source()
    if (observed.get("commit") != expected or observed.get("source_state") != "committed-clean"
            or observed.get("tracked_worktree_verified") is not True):
        raise ValueError("V5_EXACT_COMMITTED_SOURCE_REQUIRED")
    return observed


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def host(output):
    result = {"machine": platform.machine(), "system": platform.system(),
        "uname": list(platform.uname()), "logical_cpus": os.cpu_count(),
        "allowed_cpus": sorted(os.sched_getaffinity(0)), "cgroup": {}}
    for name in ("cpuinfo", "meminfo"):
        shutil.copyfile("/proc/" + name, output / (name + ".txt"))
    for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max", "cpuset.cpus.effective"):
        path = Path("/sys/fs/cgroup") / name
        try:
            result["cgroup"][name] = path.read_text().strip()
        except OSError as error:
            result["cgroup"][name] = {"unavailable": type(error).__name__}
    return result


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
    observations, reports, shards = [], [], []
    report = {"schema": "pon-w1-rank-batch-execution-v5", "result": "HOLD",
        "execution_context": "local-component-research", "expected_commit": args.expected_commit,
        "architecture": args.arch, "target": spec["target"], "observations": observations,
        "shards": shards, "planned_shards": reader.grid(),
        "native_process_rusage_scope": "wait4-process-all-threads-and-reaped-descendants",
        "rss_scope": "kernel-wait4-ru-maxrss-kib-not-sum-or-global-simultaneous-peak",
        "failed_or_unreaped_descendants_may_be_missing": True,
        "original_public_service_resource_contract_used": False,
        **reader.FALSE_FLAGS}

    def guarded(command, stem, timeout):
        before = checked_source(args.expected_commit)
        item = capture(command, output, stem, timeout=timeout)
        item["source_before"] = before
        observations.append(item)
        # Append the original process outcome before a source/readback error.
        with (output / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(item, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        after = checked_source(args.expected_commit)
        item["source_after"] = after
        if before != after:
            raise ValueError("V5_SOURCE_CHANGED_DURING_COMMAND")
        return item

    def checked(command, stem, timeout):
        item = guarded(command, stem, timeout)
        if item["exit_code"] != 0 or item["timed_out"]:
            raise ValueError("V5_COMMAND_FAILED:" + stem)
        return item

    try:
        if platform.system() != "Linux" or platform.machine() != spec["machine"]:
            raise ValueError("V5_NATIVE_LINUX_ARCHITECTURE_REQUIRED")
        if any(not hasattr(os, name) for name in ("wait4", "waitid", "WNOWAIT", "killpg")):
            raise ValueError("V5_SOLE_REAPER_PLATFORM_REQUIRED")
        report["source_before"] = checked_source(args.expected_commit)
        report["host"] = host(output)
        overrides = build_environment_overrides(dict(os.environ))
        report["build_environment_overrides"] = overrides
        if overrides:
            raise ValueError("V5_ORIGINAL_RELEASE_BUILD_OVERRIDES_FORBIDDEN")
        report["cargo_configuration_before"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report["cargo_configuration_before"])
        tools = {name: discover_tool(name) for name in ("cargo", "rustc")}
        report["toolchain"] = {name: {"path": str(path), "resolved_launcher": str(path.resolve(strict=True)),
            "launcher_sha256": digest(path)} for name, path in tools.items()}
        write_json(output / "declaration.json", {"schema": "pon-w1-rank-batch-declaration-v5",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": report["source_before"], "grid": reader.grid(), "strategies": reader.STRATEGIES,
            "samples": reader.SAMPLES, "limit": reader.LIMIT, "batch_workers": reader.BATCH,
            "rank_bound": 8, "command_timeout_seconds": COST_CAMPAIGN_TIMEOUT_SECONDS,
            "termination_grace_seconds": COST_TERMINATION_GRACE_SECONDS,
            "horizons_correlated": True, "no_retry_or_result_selection": True,
            "host": report["host"], "toolchain": report["toolchain"], **reader.FALSE_FLAGS})
        checked([str(tools["rustc"]), "-vV"], "rustc", COST_IDENTITY_TIMEOUT_SECONDS)
        checked([str(tools["cargo"]), "--version"], "cargo", COST_IDENTITY_TIMEOUT_SECONDS)
        compiler = (output / "rustc.stdout").read_text()
        if "\nrelease: 1.95.0\n" not in compiler or "\nhost: " + spec["target"] + "\n" not in compiler:
            raise ValueError("V5_ORIGINAL_RUST_1_95_0_CONTRACT")
        checked([str(tools["cargo"]), "build", "--locked", "--offline", "--release", "--manifest-path",
            "trillionnium/Cargo.toml", "--target", spec["target"], "-p", "trnm-crypto-primitives", "--example", EXAMPLE],
            "build", COST_BUILD_TIMEOUT_SECONDS)
        binary = Path(os.environ["CARGO_TARGET_DIR"]) / spec["target"] / "release/examples" / EXAMPLE
        if elf_machine(binary) != spec["elf_machine"]:
            raise ValueError("V5_ACTUAL_ELF_ARCHITECTURE")
        retained = output / EXAMPLE
        shutil.copyfile(binary, retained)
        retained.chmod(0o755)
        report["binary_sha256_before"] = digest(binary)
        report["retained_binary_sha256_before"] = digest(retained)
        if report["binary_sha256_before"] != report["retained_binary_sha256_before"]:
            raise ValueError("V5_RETAINED_BINARY_MISMATCH")
        for number, (name, target, horizon) in enumerate(reader.grid()):
            stem = f"campaign-{number:02d}"
            item = {"configuration": {"class": name, "target_index": target, "horizon": horizon}, "result": "HOLD"}
            shards.append(item)
            if digest(binary) != report["binary_sha256_before"] or digest(retained) != report["retained_binary_sha256_before"]:
                raise ValueError("V5_BINARY_CHANGED")
            item["observation"] = guarded([str(retained), reader.SELECTOR, "--class", name,
                "--target-index", str(target), "--reuse-winners", str(horizon)], stem, COST_CAMPAIGN_TIMEOUT_SECONDS)
            try:
                if item["observation"]["exit_code"] != 0 or item["observation"]["timed_out"]:
                    raise ValueError("native process failed; all partial stdout/stderr and CPU retained")
                item["reader"] = reader.analyze(output / item["observation"]["stdout"])
                reports.append(item["reader"])
                item["result"] = "COMPLETE_COMPONENT_OBSERVATION"
            except (OSError, ValueError, KeyError, TypeError) as error:
                item["error"] = str(error)
            write_json(output / (stem + ".json"), item)
            print(json.dumps({"shard": number + 1, "planned": len(reader.grid()), "result": item["result"]}), flush=True)
        report["reader"] = reader.campaign(reports)
        report["binary_sha256_after"] = digest(binary)
        report["retained_binary_sha256_after"] = digest(retained)
        if report["binary_sha256_before"] != report["binary_sha256_after"] or report["retained_binary_sha256_before"] != report["retained_binary_sha256_after"]:
            raise ValueError("V5_BINARY_CHANGED")
        report["result"] = "COMPLETE_COMPONENT_OBSERVATION"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        try:
            report["source_after"] = checked_source(args.expected_commit)
            report["cargo_configuration_after"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
            require_cargo_configuration(report["cargo_configuration_after"])
            if report.get("source_before") != report["source_after"] or report.get("cargo_configuration_before") != report["cargo_configuration_after"]:
                raise ValueError("V5_SOURCE_OR_BUILD_CONFIGURATION_CHANGED")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report["final_check_error"] = str(error)
            report["result"] = "HOLD"
        parent_end = resource.getrusage(resource.RUSAGE_SELF)
        report["observer_user_ns"] = round((parent_end.ru_utime - parent_start.ru_utime) * 1_000_000_000)
        report["observer_system_ns"] = round((parent_end.ru_stime - parent_start.ru_stime) * 1_000_000_000)
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["observed_wait4_cpu_ns_sum"] = sum(o["wait4_cpu_ns"] for o in observations if o["wait4_cpu_ns"] is not None)
        report["commands_without_wait4_usage"] = sum(o["wait4_cpu_ns"] is None for o in observations)
        report["failed_commands"] = sum(o["exit_code"] != 0 or o["timed_out"] for o in observations)
        report["artifact_sha256"] = {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.iterdir()) if p.is_file()}
        write_json(output / "manifest.json", report)
    print(json.dumps({"result": report["result"], "receipt": str(output)}, sort_keys=True))
    return 0 if report["result"] == "COMPLETE_COMPONENT_OBSERVATION" else 1


if __name__ == "__main__":
    sys.exit(main())
