#!/usr/bin/env python3
"""Read the complete, fixed repeated-sender experiment without inventing TPS."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics


RAW_SCHEMA = "pon-repeated-sender-whole-block-cost-v1"
REPORT_SCHEMA = "pon-repeated-sender-whole-block-readback-v1"
ARMS = ("full-speculation-reference", "account-conflict-hint")
SENDERS = (2, 64, 256)
TEST_NAME = "pon_executor::repeated_sender_tests::repeated_sender_complete_block_cost_observation"
MAX_STDOUT_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
PROCESS_FIELDS = {
    "name", "argv", "cwd", "exit_code", "waited_pid", "wall_ns", "disk_before", "disk_after",
    "extra_env", "rusage", "rusage_maxrss_unit", "stdout_sha256", "stderr_sha256",
}
RUSAGE_FIELDS = {
    "ru_utime", "ru_stime", "ru_maxrss", "ru_ixrss", "ru_idrss", "ru_isrss", "ru_minflt",
    "ru_majflt", "ru_nswap", "ru_inblock", "ru_oublock", "ru_msgsnd", "ru_msgrcv",
    "ru_nsignals", "ru_nvcsw", "ru_nivcsw",
}
FIELDS = {
    "schema", "senders", "transactions", "workers", "pair", "warmup",
    "implementation", "wall_ns", "signature_verifications", "speculative",
    "reexecuted", "root", "cpu_ns", "public_confirmation", "production_activation",
}


class InvalidObservation(ValueError):
    """The original, fixed experiment cannot be reconstructed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidObservation(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_stdout(raw: bytes) -> list[dict]:
    """Retain every JSON record; do not filter failed or inconvenient samples."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STDOUT_BYTES,
            "bounded original stdout bytes required")
    require(raw.endswith(b"\n"), "original stdout is truncated before its terminal newline")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise InvalidObservation("stdout is not UTF-8") from error
    lines = [line for line in text.splitlines() if line.strip()]
    require(len(lines) == 87 and lines[0] == "running 1 test",
            "require the complete one-test stdout envelope and 84 observation records")
    require(re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
        r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s", lines[-1]) is not None,
        "require the complete successful original libtest footer")
    require(lines[-2] == "ok", "require the original test terminal result")
    prefix = f"test {TEST_NAME} ... "
    require(lines[1].startswith(prefix), "original native test identity required")
    candidates = [lines[1][len(prefix):], *lines[2:-2]]
    rows = []
    for candidate in candidates:
        require(candidate.startswith("{"), "unexpected output inside original observation roster")
        try:
            row = json.loads(candidate, object_pairs_hook=unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(
                                 InvalidObservation("non-finite JSON number")))
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise InvalidObservation("invalid observation JSON") from error
        require(isinstance(row, dict), "observation must be an object")
        rows.append(row)
    return rows


def summarize(rows: list[dict], *, original_stdout_sha256: str) -> dict:
    require(re.fullmatch(r"[0-9a-f]{64}", original_stdout_sha256) is not None,
            "original stdout digest required")
    require(len(rows) == 84, "complete 84-record census required, including warmups")
    offset = 0
    cohorts = []
    for senders in SENDERS:
        cohort_rows = []
        root = None
        for pair in range(14):
            order = ARMS if pair % 2 == 0 else ARMS[::-1]
            for arm in order:
                row = rows[offset]
                offset += 1
                require(set(row) == FIELDS, "exact original v1 fields required")
                require(row["schema"] == RAW_SCHEMA, "wrong observation schema")
                for key, expected in (("senders", senders), ("pair", pair),
                                      ("transactions", 256), ("workers", 4),
                                      ("signature_verifications", 256)):
                    require(type(row[key]) is int and row[key] == expected,
                            f"original cohort/order/coverage changed: {key}")
                require(row["implementation"] == arm, "original AB/BA order changed")
                require(row["warmup"] is (pair < 2), "original warmup membership changed")
                require(type(row["wall_ns"]) is int and 0 < row["wall_ns"] < 1 << 128,
                        "positive original u128 measured wall time required")
                require(row["cpu_ns"] is None, "v1 did not observe per-arm CPU")
                require(row["public_confirmation"] is False and
                        row["production_activation"] is False,
                        "component observation cannot grant business qualification")
                expected_counts = (256, 255) if arm == ARMS[0] else (1, 0)
                for key, expected in zip(("speculative", "reexecuted"), expected_counts):
                    require(type(row[key]) is int and row[key] == expected,
                            "original complete execution control changed")
                require(isinstance(row["root"], str) and
                        re.fullmatch(r"[0-9a-f]{64}", row["root"]) is not None,
                        "complete canonical root required")
                if root is None:
                    root = row["root"]
                require(row["root"] == root, "roots disagree within original cohort")
                cohort_rows.append(row)
        pairs = []
        for pair in range(2, 14):
            measurements = {row["implementation"]: row["wall_ns"]
                            for row in cohort_rows if row["pair"] == pair}
            reference, candidate = (measurements[arm] for arm in ARMS)
            pairs.append({"pair": pair, "reference_wall_ns": reference,
                          "candidate_wall_ns": candidate,
                          "candidate_over_reference_wall_ratio": candidate / reference})
        reference_median = statistics.median(p["reference_wall_ns"] for p in pairs)
        candidate_median = statistics.median(p["candidate_wall_ns"] for p in pairs)
        cohorts.append({
            "senders": senders, "transactions_per_block": 256, "workers": 4,
            "original_records": len(cohort_rows), "warmup_records": 4,
            "retained_pairs": len(pairs), "canonical_root": root,
            "reference_wall_median_ns": reference_median,
            "candidate_wall_median_ns": candidate_median,
            "ratio_of_wall_medians": candidate_median / reference_median,
            "wall_reduction_percent_from_medians": 100 * (1 - candidate_median / reference_median),
            "paired_wall_ratio_median": statistics.median(
                p["candidate_over_reference_wall_ratio"] for p in pairs),
            "candidate_faster_pairs": sum(p["candidate_wall_ns"] < p["reference_wall_ns"]
                                          for p in pairs),
            "pairs": pairs,
            "reference_cpu_ns": None, "candidate_cpu_ns": None,
            "cpu_reduction_percent": None, "qualified_confirmed_tps": None,
        })
    return {
        "schema": REPORT_SCHEMA,
        "raw_schema": RAW_SCHEMA,
        "original_stdout_sha256": original_stdout_sha256,
        "readback_status": "COMPLETE_COMPONENT_OBSERVATION",
        "reported_native_test_name": TEST_NAME,
        "reported_libtest_result": {"passed": 1, "failed": 0, "ignored": 0},
        "native_process_exit_code": None,
        "native_process_success": None,
        "process_outcome_unknown_reason": "STDOUT_IS_NOT_A_BOUND_PROCESS_EXIT_RECEIPT",
        "scope": "one native M06 full-block execution experiment on a shared host",
        "observed_records": 84, "recorded_warmup_records": 12,
        "retained_measurement_records": 72, "retained_pairs": 36,
        "cohorts": cohorts,
        "measurement_includes": ["decode_and_signature_verification", "canonical_state_execution",
                                  "final_state_commitment", "worker_spawn_and_join"],
        "measurement_excludes": ["fixture_generation_and_signing", "post_call_parity_assertions",
                                  "process_startup", "node_ingress", "proof_generation",
                                  "consensus_confirmation", "sqlite_commit_and_fsync",
                                  "network_transport", "cold_recovery"],
        "per_arm_cpu_observed": False,
        "whole_process_cpu_is_per_arm_cpu": False,
        "independent_training_or_business_trials": False,
        "resource_contract_enforcement_observed_by_this_reader": False,
        "native_origin_authenticated": False,
        "source_execution_authenticated": False,
        "qualified_confirmed_tps": None,
        "independently_accepted_useful_tasks_per_second": None,
        "production_activation": False,
        "qualification": "HOLD_NO_GO",
    }


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "original record exceeds fixed experiment bound")
    return raw


def process_receipt(raw: bytes, expected_sha256: str, *, stdout: bytes, stderr: bytes, rows: list[dict]) -> dict:
    """Bind the existing runner's wait4 receipt; it is not host authentication."""
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None and
            hashlib.sha256(raw).hexdigest() == expected_sha256, "process receipt SHA-256 mismatch")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(
                                 InvalidObservation("non-finite process receipt number")))
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise InvalidObservation("invalid process receipt JSON") from error
    require(type(receipt) is dict and set(receipt) == PROCESS_FIELDS,
            "exact original process receipt fields required")
    require(receipt["name"] == "complete-block" and type(receipt["exit_code"]) is int and
            receipt["exit_code"] == 0, "original complete-block process did not report exit zero")
    require(type(receipt["waited_pid"]) is int and 0 < receipt["waited_pid"] < 1 << 32,
            "original waited process identity required")
    require(type(receipt["wall_ns"]) is int and 0 < receipt["wall_ns"] < 1 << 128 and
            sum(row["wall_ns"] for row in rows) <= receipt["wall_ns"],
            "original whole-process wall must enclose every measured arm")
    argv = receipt["argv"]
    require(type(argv) is list and len(argv) == 6 and all(type(arg) is str for arg in argv) and
            argv[1:] == [TEST_NAME, "--ignored", "--exact", "--nocapture", "--test-threads=1"],
            "exact native selector and original ignored-only single-test command required")
    for path in (argv[0], receipt["cwd"]):
        require(type(path) is str and 0 < len(path) <= 4096 and
                all(ord(character) >= 32 for character in path) and PurePosixPath(path).is_absolute() and
                str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts,
                "original absolute binary and working-directory paths required")
    require(type(receipt["extra_env"]) is dict and not receipt["extra_env"],
            "original complete-block command has no per-command environment override")
    require(receipt["rusage_maxrss_unit"] == "KiB (Linux)", "original Linux rusage unit required")
    usage = receipt["rusage"]
    require(type(usage) is dict and set(usage) == RUSAGE_FIELDS, "complete original wait4 rusage required")
    for name, value in usage.items():
        if name in ("ru_utime", "ru_stime"):
            require(type(value) in (int, float) and 0 <= value < 1 << 128 and math.isfinite(value),
                    "finite nonnegative process CPU observation required")
        else:
            require(type(value) is int and 0 <= value < 1 << 128,
                    "nonnegative original rusage counter required")
    for name in ("disk_before", "disk_after"):
        value = receipt[name]
        require(type(value) is dict and set(value) == {"total_bytes", "used_bytes", "free_bytes"} and
                all(type(count) is int and 0 <= count < 1 << 128 for count in value.values()) and
                value["used_bytes"] <= value["total_bytes"] and value["free_bytes"] <= value["total_bytes"],
                "original disk observation required")
    require(receipt["stdout_sha256"] == hashlib.sha256(stdout).hexdigest() and
            receipt["stderr_sha256"] == hashlib.sha256(stderr).hexdigest(),
            "original process stdout/stderr byte binding mismatch")
    require(stderr == b"", "original isolated complete-block benchmark must retain empty stderr")
    return receipt


def read(path: Path, expected_sha256: str, *, receipt_path: Path,
         expected_receipt_sha256: str, stderr_path: Path) -> dict:
    raw = read_bounded(path, MAX_STDOUT_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == expected_sha256, "original stdout SHA-256 mismatch")
    rows = parse_stdout(raw)
    report = summarize(rows, original_stdout_sha256=digest)
    receipt_raw = read_bounded(receipt_path, MAX_RECEIPT_BYTES)
    stderr = read_bounded(stderr_path, MAX_STDOUT_BYTES)
    receipt = process_receipt(receipt_raw, expected_receipt_sha256, stdout=raw, stderr=stderr, rows=rows)
    report.update(native_process_exit_code=receipt["exit_code"], native_process_success=True,
                  process_outcome_unknown_reason=None,
                  process_outcome_scope="supplied byte-bound wait4 receipt; not native-origin or source-execution authentication",
                  original_process_receipt_sha256=expected_receipt_sha256,
                  original_stderr_sha256=receipt["stderr_sha256"], original_stderr_bytes=len(stderr),
                  original_process_receipt=receipt,
                  whole_process_rusage_scope="complete test process including fixture generation, signing, all arms, assertions and output; never per-arm CPU")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--process-receipt", type=Path, required=True)
    parser.add_argument("--expected-receipt-sha256", required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = read(args.stdout, args.expected_sha256, receipt_path=args.process_receipt,
                      expected_receipt_sha256=args.expected_receipt_sha256, stderr_path=args.stderr)
    except (InvalidObservation, OSError) as error:
        print(json.dumps({"schema": REPORT_SCHEMA, "readback_status": "INVALID_OBSERVATION",
                          "error": str(error), "qualified_confirmed_tps": None,
                          "qualification": "HOLD_NO_GO"}, sort_keys=True))
        return 2
    raw = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is not None:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(raw)
    print(raw, end="")
    return 0  # Readback completed; the explicit qualification remains HOLD_NO_GO.


if __name__ == "__main__":
    raise SystemExit(main())
