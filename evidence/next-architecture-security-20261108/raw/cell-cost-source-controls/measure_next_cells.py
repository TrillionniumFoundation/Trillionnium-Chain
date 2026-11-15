#!/usr/bin/env python3
"""Observe each already-built Cell release example ONCE; never build or retry.

Linux only. --target-dir is Cargo's target root (containing release/examples).
The output directory must not exist. Emitted stdout/stderr bytes and failure
records are retained; Rust rows not yet printed cannot be recovered. wait4
measures the actual child tree, including timeout and optional
GNU time overhead, input generation and native cache work. Linux ru_maxrss is KiB
of the largest process, not a sum of simultaneous process RSS or a global delta.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from functools import lru_cache

TIMEOUT_SECONDS = 600
KILL_GRACE_SECONDS = 5
ROOT = Path("trillionnium/crates/trnm-data-availability")
CASES = {
    "cell_bep52_cost_v1": {
        "schema": "trnm.cell-bep52-cost.v1", "profile": "cell-bep52-binding-v1",
        "implementation": "bep52.rs", "source_field": "binding_source_sha256",
        "workloads": [(n, 16_384) for n in (3, 16_384, 16_385, 1_048_576, 1_048_577)],
        "factor": 17,
    },
    "cell_rs46_cost_v1": {
        "schema": "trnm.cell-rs46-cost.v1", "profile": "cell-rs46-chunk-v1",
        "implementation": "erasure.rs", "source_field": "implementation_source_sha256",
        "workloads": [(16_384, 16_384), (16_385, 16_384),
                      (1_048_577, 16_384), (1_048_577, 4_194_304)],
        "factor": 19,
    },
}
SCOPE = {
    "qualification": "HOLD_NO_GO", "production_qualified": False,
    "performance_or_economics_qualified": False,
    "workload": "deterministic synthetic bytes, not models or tensors",
    "whole_run_scope": "example plus timeout/optional GNU time overhead; includes generation, file IO, cache open/write/read, validation and cleanup",
    "phase_scope": "example-reported monotonic wall nanoseconds only; no phase CPU or RSS attribution",
    "not_measured": ["model loading", "WAN", "DHT", "GPU", "independent custody", "rewards", "cost-benefit"],
    "repeat_policy": "one invocation per example; three internal repeats; no automatic retry",
    "statistics": "min/median/max of three complete repeat totals; no p95/p99",
    "raw_output_retention": "only bytes already emitted are retained; examples print after their loops, so unprinted intermediate Rust rows cannot be recovered after panic/kill/timeout",
    "failed_run_resource_usage": "observed counters retained, but CPU/RSS completeness is false for every unsuccessful or invalid observation; a killed timeout supervisor may not reap the example",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def integer(value, name: str) -> int:
    require(type(value) is int and value >= 0, "invalid nonnegative integer: " + name)
    return value


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def load_raw(path: Path):
    require(path.stat().st_size <= 8 * 1024 * 1024, "raw JSON exceeds 8 MiB parse bound")
    def reject_constant(value):
        raise ValueError("nonfinite JSON constant: " + value)
    return json.loads(path.read_text(), object_pairs_hook=pairs_unique,
                      parse_constant=reject_constant)


@lru_cache(maxsize=16)
def synthetic_sha256(size: int, factor: int) -> str:
    return hashlib.sha256(bytes((i * factor + i // 16_384) % 251
                                for i in range(size))).hexdigest()


def validate_and_summarize(document, name: str, sources: dict) -> dict:
    """Validate the COMPLETE fixed denominator before reporting any phase stats."""
    case = CASES[name]
    bep = name == "cell_bep52_cost_v1"
    require(isinstance(document, dict), "top-level JSON is not an object")
    for key in ("schema", "profile"):
        require(document.get(key) == case[key], "wrong " + key)
    require(document.get("qualification") == "HOLD_NO_GO", "qualification changed")
    require(document.get("production_consensus_activation") is False, "activation claim")
    require(integer(document.get("network_requests"), "network_requests") == 0, "network claim")
    require(integer(document.get("failed_observations"), "failed_observations") == 0, "failed observations retained in raw output")
    for key, expected in sources.items():
        require(document.get(key) == expected, "compiled source hash mismatch: " + key)
    flags = ("rewards_observed",) if bep else (
        "independent_provider_custody_qualified", "reward_sustainability_qualified")
    require(all(document.get(key) is False for key in flags), "unsupported qualification flag")
    if bep:
        require(integer(document.get("gpu_operations"), "gpu_operations") == 0, "GPU claim")
    expected = {(size, chunk, repeat) for size, chunk in case["workloads"] for repeat in range(3)}
    rows = document.get("observations")
    require(type(rows) is list and len(rows) == len(expected), "wrong workload denominator")
    observed, groups, identities = set(), {}, {}
    for row in rows:
        require(type(row) is dict, "observation is not an object")
        size = integer(row.get("payload_bytes"), "payload_bytes")
        chunk = 16_384 if bep else integer(row.get("chunk_bytes"), "chunk_bytes")
        repeat = integer(row.get("repeat"), "repeat")
        identity = (size, chunk, repeat)
        require(identity in expected and identity not in observed, "unexpected or duplicated workload/repeat")
        observed.add(identity)
        require(row.get("status") == "PASS_LOCAL_OBSERVATION", "nonpassing workload")
        complete = "complete_payload_verified" if bep else "complete_tcm1_payload_verified"
        require(row.get(complete) is True, "whole-payload verification missing")
        digest = synthetic_sha256(size, case["factor"])
        require(row.get("payload_sha256") == digest, "wrong deterministic payload SHA256")
        hash_keys = ("manifest_id", "infohash", "pieces_root") if bep else ("manifest_id",)
        for key in hash_keys:
            require(type(row.get(key)) is str and re.fullmatch(r"[0-9a-f]{64}", row[key]) is not None, "invalid " + key)
        fingerprints = tuple(row[key] for key in hash_keys)
        group_key = (size, chunk)
        require(identities.setdefault(group_key, fingerprints) == fingerprints, "identity changed across repeats")
        count = (size + chunk - 1) // chunk
        chunks = row.get("chunk_observations")
        require(type(chunks) is list and len(chunks) == count, "incomplete chunk denominator")
        if bep:
            require(row.get("fresh_temporary_cache") is True, "fresh-cache flag missing")
            require(integer(row.get("chunk_count"), "chunk_count") == count, "wrong chunk_count")
            for key in ("pack_file_wall_ns", "binding_wall_ns", "descriptor_roundtrip_wall_ns", "complete_cached_payload_verify_wall_ns"):
                integer(row.get(key), key)
            totals = {"binding": row["binding_wall_ns"], "valid_check_all_chunks": 0}
        else:
            require(row.get("retained_shard_indices") == [2, 3, 4, 5], "wrong retained shards")
            require(row.get("omitted_shard_indices") == [0, 1] and
                    all(type(i) is int for i in row["omitted_shard_indices"]), "wrong omitted shards")
            require(row.get("materialized_sha256") == digest, "materialized payload mismatch")
            for key in ("native_pack_file_wall_ns", "complete_tcm1_verify_wall_ns"):
                integer(row.get(key), key)
            totals = {"encode_all_chunks": 0, "recover_all_chunks": 0}
        for index, item in enumerate(chunks):
            require(type(item) is dict and integer(item.get("index"), "chunk index") == index, "chunk order/index mismatch")
            source_bytes = min(chunk, size - index * chunk)
            length_key = "chunk_bytes" if bep else "source_bytes"
            require(integer(item.get(length_key), length_key) == source_bytes, "wrong chunk length")
            require(item.get("valid_accepted" if bep else "matches_source") is True, "valid/recovered chunk not accepted")
            require(item.get("corrupt_rejected") is True, "corrupt chunk not rejected")
            require(type(item.get("corrupt_error")) is str and item["corrupt_error"], "missing corrupt rejection detail")
            timings = (("proof_construction_wall_ns", "proof_decode_wall_ns", "valid_verify_wall_ns", "corrupt_verify_wall_ns") if bep else
                       ("binding_wall_ns", "encode_wall_ns", "selected_wire_roundtrip_wall_ns", "recover_wall_ns", "corrupt_reject_wall_ns"))
            for key in timings:
                integer(item.get(key), key)
            if bep:
                require(integer(item.get("proof_bytes"), "proof_bytes") == 77 + 32 * (count - 1).bit_length(), "wrong proof size")
                totals["valid_check_all_chunks"] += item["valid_verify_wall_ns"]
            else:
                shard = (source_bytes + 3) // 4
                for key, value in {"shard_payload_bytes": shard, "all_six_payload_bytes": 6 * shard,
                                   "retained_four_payload_bytes": 4 * shard, "all_six_wire_bytes": 6 * (81 + shard)}.items():
                    require(integer(item.get(key), key) == value, "wrong shard denominator: " + key)
                totals["encode_all_chunks"] += item["encode_wall_ns"]
                totals["recover_all_chunks"] += item["recover_wall_ns"]
        groups.setdefault(group_key, {})[repeat] = totals
    require(observed == expected, "missing workload/repeat")
    summary = []
    for (size, chunk), repeats in sorted(groups.items()):
        metrics = {}
        for metric in repeats[0]:
            samples = [repeats[r][metric] for r in range(3)]
            ordered = sorted(samples)
            metrics[metric] = {"repeat_0_1_2_ns": samples, "n": 3,
                               "min_ns": ordered[0], "median_ns": ordered[1], "max_ns": ordered[2]}
        summary.append({"payload_bytes": size, "chunk_bytes": chunk,
                        "chunks_per_repeat": (size + chunk - 1) // chunk, "phase_wall": metrics})
    return {"workloads_verified": len(rows), "expected_workloads": len(expected),
            "all_payload_and_chunk_checks_verified": True,
            "statistical_unit": "one complete workload repeat; chunk metrics are SUMS over every chunk before three-repeat statistics",
            "workload_summaries": summary}


def write_json(path: Path, value) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def classify_exit(code: int) -> dict:
    """137 and wait4's -9 report KILL; neither alone proves its trigger."""
    if code == 0:
        kind = "success"
    elif code == 124:
        kind = "timeout_reported"
    elif code in (137, -9):
        kind = "killed_or_timeout_supervisor_killed"
    else:
        kind = "failed_exit"
    return {"exit_code": code, "exit_class": kind,
            "timeout_exit_reported": code in (124, 137, -9)}


def run_once(repo: Path, target: Path, output: Path, name: str, timeout: str) -> dict:
    result = {"example": name, "command_invocations_planned": 1, "command_invocations_started": 0,
              "validation_passed": False, "cpu_rss_complete_for_example": False, "errors": []}
    case = CASES[name]
    binary = target / "release/examples" / name
    try:
        require(binary.is_file() and os.access(binary, os.X_OK), "missing built executable: " + str(binary))
        sources = {"example_source_sha256": sha256(repo / ROOT / "examples" / (name + ".rs")),
                   case["source_field"]: sha256(repo / ROOT / "src/cell" / case["implementation"])}
        before = sha256(binary)
        result.update(binary=str(binary.resolve()), binary_sha256_before=before, source_hashes=sources)
        command = [timeout, "--signal=TERM", "--kill-after=" + str(KILL_GRACE_SECONDS) + "s",
                   str(TIMEOUT_SECONDS), str(binary)]
        gnu_time = Path("/usr/bin/time")
        if gnu_time.is_file() and os.access(gnu_time, os.X_OK):
            command = [str(gnu_time), "-o", str(output / (name + ".gnu-time.txt")),
                       "-f", "wall_seconds=%e\nuser_cpu_seconds=%U\nsystem_cpu_seconds=%S\npeak_rss_kib=%M\nexit_code=%x", "--"] + command
        result.update(command=command, gnu_time_enabled=command[0] == str(gnu_time))
        with (output / (name + ".raw.json")).open("xb") as stdout, (output / (name + ".stderr.log")).open("xb") as stderr:
            started = time.monotonic_ns()
            child = subprocess.Popen(command, cwd=repo, stdout=stdout, stderr=stderr,
                                     env={**os.environ, "LC_ALL": "C"})
            result["command_invocations_started"] = 1
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            result["whole_run"] = {"wall_ns": time.monotonic_ns() - started,
                "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                "peak_rss_kib": usage.ru_maxrss, "rss_unit_bytes": 1024,
                "usage_method": "Linux wait4 on this invocation's child; no global resource counter subtraction",
                "rss_scope": "largest process in reaped child tree, not simultaneous summed RSS",
                "includes_supervisor_overhead": True}
            result.update(classify_exit(child.returncode))
        result["binary_sha256_after"] = sha256(binary)
        result["raw_json_sha256"] = sha256(output / (name + ".raw.json"))
        result["stderr_sha256"] = sha256(output / (name + ".stderr.log"))
        require(result["binary_sha256_after"] == before, "binary changed during observation")
        if result["exit_code"] != 0:
            result["errors"].append("nonzero process exit; raw output retained")
        result["validation"] = validate_and_summarize(load_raw(output / (name + ".raw.json")), name, sources)
        result["validation_passed"] = result["exit_code"] == 0
        result["cpu_rss_complete_for_example"] = result["validation_passed"]
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    write_json(output / (name + ".result.json"), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("repo", "target-dir", "output-dir"):
        parser.add_argument("--" + argument, type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and hasattr(os, "wait4"), "Linux wait4 required")
    timeout = shutil.which("timeout")
    require(timeout is not None, "existing coreutils timeout required; nothing installed")
    repo, target = args.repo.resolve(strict=True), args.target_dir.resolve(strict=True)
    require(repo.is_dir() and target.is_dir(), "repo and target-dir must be directories")
    output = args.output_dir.absolute()
    output.mkdir()  # Atomic refusal if ANY output already occupies this path.
    write_json(output / "scope.json", SCOPE)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True,
                          capture_output=True, check=False)
    results = [run_once(repo, target, output, name, timeout) for name in CASES]
    passed = all(result["validation_passed"] for result in results)
    write_json(output / "summary.json", {"schema": "trnm.cell-cost-wrapper.v1", **SCOPE,
        "repo": str(repo), "repo_head": head.stdout.strip() if head.returncode == 0 else None,
        "target_dir": str(target), "wrapper_sha256": sha256(Path(__file__)),
        "timeout_seconds_per_example": TIMEOUT_SECONDS, "kill_grace_seconds": KILL_GRACE_SECONDS,
        "all_complete_observations_passed": passed, "results": results})
    print(json.dumps({"output_dir": str(output), "all_complete_observations_passed": passed,
                      "qualification": "HOLD_NO_GO"}))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print("measure_next_cells: " + str(error), file=sys.stderr)
        raise SystemExit(2)
