#!/usr/bin/env python3
"""Independently check every raw observation in pq_parameter_bench JSONL.

Usage: python3 recompute_benchmark.py pq-parameter-bench.jsonl
This validates local measurements and coverage; it is not a production gate.
Hardware, exact source/diff, toolchain, target, flags and load are separate evidence.
"""

import itertools
import json
import sys
from pathlib import Path


PARAMETERS = {"ML-DSA-65": (1952, 3309, 3), "ML-DSA-87": (2592, 4627, 5)}
MESSAGE_LENGTHS = (0, 176, 4096, 65536)
SIGNER_COUNTS = (1, 2, 4, 8)
OPERATIONS = (
    "keygen_with_candidate_verifier_and_zeroizing_drop",
    "pinned_raw_key_import_and_drop",
    "sign_encode_self_verify_and_drop",
    "valid_verify_with_preexpanded_key",
    "late_invalid_verify_with_preexpanded_key",
    "early_signature_size_rejection",
    "candidate_observation_frame_encode_and_drop",
    "candidate_observation_frame_preflight",
    "candidate_observation_frame_preflight_and_verify",
)
ARITHMETIC = {
    "sign_encode_self_verify_and_drop",
    "valid_verify_with_preexpanded_key",
    "late_invalid_verify_with_preexpanded_key",
    "candidate_observation_frame_preflight_and_verify",
}
REJECTIONS = {
    "late_invalid_verify_with_preexpanded_key",
    "early_signature_size_rejection",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate(records):
    require(len(records) == 290, "need run header + 288 measurements + completion sentinel")
    meta, *rows, completion = records
    require(meta.get("kind") == "run", "missing run header")
    require(meta.get("schema") == "trnm.pq-candidate-bench.v1", "unknown benchmark schema")
    samples = meta.get("samples_per_stage_case")
    require(type(samples) is int and 64 <= samples <= 4096, "invalid sample count")
    require(meta.get("algorithms") == list(PARAMETERS), "algorithm inventory changed")
    require(meta.get("message_lengths") == list(MESSAGE_LENGTHS), "message inventory changed")
    require(meta.get("signer_counts") == list(SIGNER_COUNTS), "signer inventory changed")
    require(meta.get("signature_mode") == "FIPS204-Pure", "signature mode changed")
    require(meta.get("fips_context_hex") == "", "FIPS context changed")
    require(meta.get("signing_variant") == "deterministic", "signing mode changed")
    require(meta.get("implicit_randomness") is False, "implicit randomness is not this fixture")
    require(meta.get("warmup_groups_per_stage_case") == 1, "warm-up accounting changed")
    require(meta.get("fixture_repeated_each_sample") is True, "fixture scope changed")
    require(meta.get("frame_is_PNQ_or_NPQ") is False, "candidate frame must not claim PNQ/NPQ")
    require(meta.get("network_or_production_p99") is False, "local benchmark must not claim production p99")
    require(meta.get("activation_performed") is False, "benchmark must not activate a profile")
    require(meta.get("caller_run_context_required") is True, "missing external run-context requirement")

    expected = set(itertools.product(PARAMETERS, MESSAGE_LENGTHS, SIGNER_COUNTS, OPERATIONS))
    seen = set()
    for row_number, row in enumerate(rows, 2):
        require(row.get("kind") == "measurement", f"unexpected record at line {row_number}")
        key = (
            row.get("algorithm"),
            row.get("message_bytes"),
            row.get("signer_count"),
            row.get("operation"),
        )
        require(key in expected, f"unexpected measurement: {key}")
        require(key not in seen, f"duplicate measurement: {key}")
        seen.add(key)
        algorithm, message_bytes, signer_count, operation = key
        public_key_bytes, signature_bytes, category = PARAMETERS[algorithm]
        raw = row.get("sample_ns")
        require(type(raw) is list and len(raw) == samples, f"raw population missing: {key}")
        require(all(type(value) is int and value >= 0 for value in raw), f"invalid duration: {key}")
        ordered = sorted(raw)
        expected_values = {
            "samples": samples,
            "min_ns": min(raw),
            "mean_ns": sum(raw) // samples,
            "p50_ns": ordered[(samples * 50 + 99) // 100 - 1],
            "p95_ns": ordered[(samples * 95 + 99) // 100 - 1],
            "p99_ns": ordered[(samples * 99 + 99) // 100 - 1],
            "max_ns": max(raw),
            "total_ns": sum(raw),
            "nist_category": category,
            "public_key_bytes_each": public_key_bytes,
            "signature_bytes_each": signature_bytes,
            "actual_framing_bytes": 15 + 4 * signer_count,
            "actual_candidate_frame_bytes": 15 + message_bytes
            + signer_count * (4 + public_key_bytes + signature_bytes),
            "arithmetic_verify_calls_per_sample": signer_count if operation in ARITHMETIC else 0,
            "expected_rejections_per_sample": signer_count if operation in REJECTIONS else 0,
        }
        for field, expected_value in expected_values.items():
            require(type(row.get(field)) is int, f"non-integer {field}: {key}")
            require(row[field] == expected_value, f"incorrect {field}: {key}")
        require(row.get("latency_unit") == "ns_per_signer_group", f"latency unit changed: {key}")
        require("production_message_budget_pass" in row, f"missing production scope: {key}")
        require(row["production_message_budget_pass"] is None, f"unmeasured production budget claimed: {key}")

    require(seen == expected, "missing parameter/message/signer/operation combination")
    require(completion.get("kind") == "complete", "missing completion sentinel; incomplete run")
    for field, value in {
        "cases": 32,
        "measurement_rows": 288,
        "samples_per_stage_case": samples,
        "raw_sample_values": samples * 288,
    }.items():
        require(type(completion.get(field)) is int and completion[field] == value, f"incorrect completion {field}")
    require(completion.get("all_expected_outcomes_checked") is True, "incomplete outcome checking")
    return {
        "result": "PASS",
        "scope": "local candidate observations only",
        "unique_cases": 32,
        "unique_measurements": 288,
        "samples_per_measurement": samples,
        "raw_sample_values_recomputed": samples * 288,
        "wire_layout": "TRNMCPB1, not CPQ1/PNQ/NPQ",
        "production_or_activation_claim": False,
    }


def main():
    require(len(sys.argv) == 2, "usage: recompute_benchmark.py benchmark.jsonl")
    records = []
    with Path(sys.argv[1]).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            require(line.strip(), f"blank record at line {line_number}")
            records.append(json.loads(line, object_pairs_hook=unique_object))
    print(json.dumps(validate(records), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
