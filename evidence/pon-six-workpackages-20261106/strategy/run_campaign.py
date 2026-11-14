#!/usr/bin/env python3
"""Capture the frozen V4 grid and separate controls without hiding failures.

The native binary is supplied explicitly. This driver records its hash and the
relevant example/crypto/protocol sources; it is not a reproducible-build or
independent-hardware attestation. Every planned command has a retained outcome.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import pon_w1_preparation_strategy_reader_v4 as reader

PER_SHARD_SECONDS = 300
TERMINATION_GRACE_SECONDS = 5
FREE_DISK_FLOOR_BYTES = 512 * 1024 * 1024


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".temporary")
    with temporary.open("w") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def source_snapshot():
    paths = {
        ROOT / "trillionnium/Cargo.toml", ROOT / "trillionnium/Cargo.lock",
        ROOT / "trillionnium/crates/trnm-pon-node/Cargo.toml",
        ROOT / "trillionnium/crates/trnm-pon-node/examples/pon_w1_preparation_strategy_v4.rs",
        ROOT / "trillionnium/crates/trnm-pon-node/examples/support/w1_cost_producers.rs",
        ROOT / "scripts/pon_w1_preparation_strategy_reader_v4.py",
        ROOT / "scripts/pon_w1_cost_matrix_reader.py",
        ROOT / "scripts/ci/test_pon_w1_preparation_strategy_reader_v4.py",
        ROOT / "config/pon/work-security-acceptance-v1.json", Path(__file__).resolve(),
    }
    for name in ("trnm-crypto-primitives", "trnm-protocol"):
        directory = ROOT / "trillionnium/crates" / name
        paths.add(directory / "Cargo.toml")
        paths.update(directory.rglob("*.rs"))
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def observed_host():
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return None

    return dict(machine=platform.machine(), platform=platform.platform(),
        affinity_cpu_ids=sorted(os.sched_getaffinity(0)),
        cgroup_cpu_max=read("/sys/fs/cgroup/cpu.max"),
        cgroup_memory_max=read("/sys/fs/cgroup/memory.max"),
        cgroup_membership=read("/proc/self/cgroup"),
        clock_source="native thread CPU plus monotonic wall; outer Linux wait4",
        independent_hardware_qualified=False,
        gpu_measurement="NOT_RUN", arm_measurement="NOT_RUN",
        public_service_contract_exercised=False)


def signal_group(process, selected):
    try:
        os.killpg(process.pid, selected)
    except ProcessLookupError:
        pass


def capture(argv, directory):
    directory.mkdir()
    started = time.monotonic()
    receipt = dict(argv=argv, started_unix_ns=time.time_ns(),
        timeout_seconds=PER_SHARD_SECONDS, cleanup_grace_seconds=TERMINATION_GRACE_SECONDS,
        cleanup_extends_accepted_budget=False, timed_out=False,
        observer_interrupted=False, resource_failure=None, returncode=None,
        cpu_user_seconds=None, cpu_system_seconds=None, peak_rss_bytes=None)
    with (directory / "stdout.jsonl").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
        child = None
        reaped = False
        try:
            child = subprocess.Popen(argv, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
            stop_at = None
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    reaped = True
                    child.returncode = os.waitstatus_to_exitcode(status)
                    receipt.update(returncode=child.returncode, cpu_user_seconds=usage.ru_utime,
                        cpu_system_seconds=usage.ru_stime, peak_rss_bytes=usage.ru_maxrss * 1024)
                    break
                now = time.monotonic()
                if stop_at is None:
                    if now - started >= PER_SHARD_SECONDS:
                        receipt["timed_out"] = True
                    elif shutil.disk_usage(directory).free < FREE_DISK_FLOOR_BYTES:
                        receipt["resource_failure"] = "disk-free-floor"
                    elif stdout.tell() > reader.MAX_BYTES:
                        receipt["resource_failure"] = "raw-output-bound"
                    if receipt["timed_out"] or receipt["resource_failure"]:
                        stop_at = now
                        signal_group(child, signal.SIGTERM)
                elif now - stop_at >= TERMINATION_GRACE_SECONDS:
                    signal_group(child, signal.SIGKILL)
                time.sleep(0.02)
        except BaseException as error:
            receipt["observer_interrupted"] = True
            receipt["observer_error"] = repr(error)
            raise
        finally:
            if child is not None and not reaped:
                signal_group(child, signal.SIGKILL)
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
                receipt.update(returncode=child.returncode, cpu_user_seconds=usage.ru_utime,
                    cpu_system_seconds=usage.ru_stime, peak_rss_bytes=usage.ru_maxrss * 1024)
            stdout.flush()
            stderr.flush()
            receipt["elapsed_wall_seconds"] = time.monotonic() - started
            receipt["stdout_sha256"] = sha(directory / "stdout.jsonl")
            receipt["stderr_sha256"] = sha(directory / "stderr.log")
            receipt["resource_scope"] = "direct native process wait4; not whole-host or process-tree resource qualification"
            receipt["process_complete"] = (receipt["returncode"] == 0 and not receipt["timed_out"]
                and not receipt["observer_interrupted"] and receipt["resource_failure"] is None)
            write(directory / "process.json", receipt)
    return receipt


def lossless_archive(path):
    original_sha = sha(path)
    target = path.with_name(path.name + ".gz")
    with path.open("rb") as source, target.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=6) as encoded:
            shutil.copyfileobj(source, encoded)
    digest = hashlib.sha256()
    with gzip.open(target, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != original_sha:
        raise ValueError("lossless archive did not preserve the original observation")
    result = dict(file=target.name, sha256=sha(target), bytes=target.stat().st_size,
                  raw_sha256=original_sha, raw_bytes=path.stat().st_size)
    path.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--new-output", type=Path, required=True)
    args = parser.parse_args()
    build_binary = args.binary.resolve(strict=True)
    output = args.new_output.resolve()
    output.mkdir()
    preflight = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    (output / "preflight.log").write_bytes(preflight.stdout)
    if preflight.returncode:
        raise RuntimeError("project preflight failed")
    # Concurrent workspace builds may replace Cargo's output path. Execute a
    # checked immutable copy so later compiles cannot silently change a cohort.
    original_binary_sha = sha(build_binary)
    binary = output / "pinned-native"
    shutil.copy2(build_binary, binary)
    if sha(binary) != original_binary_sha or sha(build_binary) != original_binary_sha:
        raise RuntimeError("native binary changed during snapshot")
    planned = [dict(name=f"{name}-t{target}-h{horizon}", material=name,
        target_index=target, reuse_winners=horizon, purpose=reader.PURPOSES[target])
        for name in reader.CLASSES for target in reader.COST_TARGET_INDICES for horizon in reader.HORIZONS]
    planned.extend(dict(name=f"{name}-control-t{target}", material=name,
        target_index=target, reuse_winners=1, purpose=reader.PURPOSES[target])
        for name in reader.CLASSES for target in (2, 3))
    for slot in planned:
        slot["argv"] = [str(binary), reader.SELECTOR, "--class", slot["material"],
            "--target-index", str(slot["target_index"]), "--reuse-winners", str(slot["reuse_winners"])]
    original_source = source_snapshot()
    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT))
    source = dict(base_commit=git_head, source_sha256=original_source,
        tracked_or_untracked_working_changes=dirty,
        source_scope="explicit sampler/reader and complete crypto/protocol Rust sources plus manifests/lock; no whole-workspace build attestation",
        binary_path=str(binary), build_binary_path=str(build_binary),
        binary_sha256=original_binary_sha, host=observed_host(),
        reproducible_build_attestation=False, planned_commands=planned,
        per_command_seconds=PER_SHARD_SECONDS, free_disk_floor_bytes=FREE_DISK_FLOOR_BYTES)
    write(output / "declaration.json", source)
    results = []
    manifest = dict(schema="pon-w1-preparation-campaign-capture-v4", planned=len(planned),
                    commands=results, complete=False, qualification_status="HOLD")
    try:
        for slot in planned:
            directory = output / slot["name"]
            receipt = capture(slot["argv"], directory)
            archives = {name: lossless_archive(directory / name) for name in ("stdout.jsonl", "stderr.log")}
            result = dict(name=slot["name"], purpose=slot["purpose"], process=receipt, archives=archives)
            results.append(result)
            write(output / "manifest.json", manifest)
            print(json.dumps(dict(name=slot["name"], returncode=receipt["returncode"],
                timed_out=receipt["timed_out"], wall_seconds=receipt["elapsed_wall_seconds"])), flush=True)
        all_valid = True
        for result in results:
            path = output / result["name"] / "stdout.jsonl.gz"
            try:
                report = reader.analyze_shard(path)
                write(output / result["name"] / "readback.json", report)
                result["readback_consistent"] = (not report["semantic_alerts"]
                    and report.get("control_expected_outcome_observed") is not False)
            except (ValueError, OSError, EOFError, OverflowError) as error:
                result["readback_consistent"] = False
                result["readback_error"] = str(error)
            all_valid &= result["readback_consistent"] and result["process"]["process_complete"]
        try:
            grid = reader.analyze([output / result["name"] / "stdout.jsonl.gz"
                for result in results if result["purpose"] == "search-cost"])
            write(output / "grid-readback.json", grid)
            manifest["complete_cost_grid_consistent"] = not grid["semantic_alerts"]
        except (ValueError, OSError, EOFError, OverflowError) as error:
            manifest["complete_cost_grid_consistent"] = False
            manifest["cost_grid_error"] = str(error)
        manifest["complete"] = all_valid and manifest["complete_cost_grid_consistent"]
    finally:
        # Even an interrupted capture has a finally-written process receipt.
        # Recover that observed slot before labelling later commands NOT_RUN.
        known = {result["name"] for result in results}
        for slot in planned:
            receipt_path = output / slot["name"] / "process.json"
            if slot["name"] not in known and receipt_path.exists():
                results.append(dict(name=slot["name"], purpose=slot["purpose"],
                    process=json.loads(receipt_path.read_text()), archives={},
                    readback_consistent=False, observation_interrupted=True))
        manifest["observed_commands"] = len(results)
        observed = {result["name"] for result in results}
        manifest["unobserved_planned_commands"] = [slot["name"] for slot in planned if slot["name"] not in observed]
        manifest["source_unchanged"] = source_snapshot() == original_source
        manifest["binary_unchanged"] = sha(binary) == original_binary_sha
        manifest["complete"] &= manifest["source_unchanged"] and manifest["binary_unchanged"]
        write(output / "manifest.json", manifest)
    return 0 if manifest["complete"] else 2


if __name__ == "__main__":
    sys.exit(main())
