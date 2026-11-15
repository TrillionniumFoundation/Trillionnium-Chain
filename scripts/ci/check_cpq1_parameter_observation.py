#!/usr/bin/env python3
"""Independently validate bounded pq_profile_bench JSONL observations.

The reader recomputes descriptor and fixture identities, the complete CPQ1
byte layout, every planned case/stage, observed counters and raw statistics.
It does NOT run ML-DSA, attest execution, authenticate a host or qualify a
production profile. An unchanged exact-source binary, terminal command receipt
and host/toolchain record are separate required evidence. Synthetic reader
fixtures exercise this reader only and never count as native execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys


SCHEMA = "trnm.cpq1-parameter-observation.v1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1
ENVELOPE_DOMAIN = b"TRNM/CryptoProfile/Envelope/v1\0"
COMMITMENT_DOMAIN = b"TRNM/CryptoProfile/Commitment/v1\0"
CONFIGURATION_DOMAIN = b"TRNM/CryptoProfile/Configuration/v1\0"
HEADER_BYTES = len(ENVELOPE_DOMAIN) + 176
WORK_DIGEST = (
    "6da47a17baafdcf3748010f4fc5a9291a31ed0a8fd3ac26e41df98cd5f7685bc8f8d"
    "80325c21105bb21b1b1c24da723e4345306c1f8e579cb8f5d5c6dc0c0632"
)
# Fixed binding from the pre-existing independent Python profile oracle:
# network=01*32, parameters=02*32, genesis=03*32, WholeSystemCandidate/v1,
# activation=10, exclusive retirement=100. Changes require a new observation
# schema; a message's own configuration bytes cannot nominate a weaker profile.
PARAMETERS = {
    "ML-DSA-65": {
        "public_key_bytes": 1952, "signature_bytes": 3309, "category": 3,
        "profile_id": "8f572de360c4ffa4681d027b3c2ef0499e159ad3de2e5eccaedcffb8149e88fd"
        "fec814ae4523e25fbbe402d05b5eed54b3287c40aca16b006d504b4832dcd3ba",
    },
    "ML-DSA-87": {
        "public_key_bytes": 2592, "signature_bytes": 4627, "category": 5,
        "profile_id": "3d95c89d2e8ffe72d936476106fba9583d7f93a0c984fd6881d9475c3f5fa7a8"
        "47e723340e0c33688310e75697221f2ac3fd58f8d08f75097a04ae5a8bfa83a5",
    },
}
SIGNER_COUNTS = (1, 2, 4, 8)
PAYLOAD_LABELS = ("empty", "176", "4096", "maximum")
OPERATIONS = (
    "cpq1_encode_with_existing_signatures",
    "cpq1_sign_self_verify_and_encode",
    "cpq1_cold_pin_and_verify",
    "cpq1_hot_verify",
    "cpq1_late_invalid_last_signature",
    "cpq1_wrong_profile",
    "cpq1_wrong_purpose",
    "cpq1_short_wire",
    "cpq1_trailing_byte",
    "cpq1_message_length_mismatch",
    "cpq1_shared_budget_exhaustion",
)
OUTCOME_FIELDS = (
    "encoded_frames", "sign_and_self_verify_calls", "verification_api_calls",
    "accepted_authentications", "returned_verified_signatures",
    "policy_encoding_rejections", "policy_size_rejections",
    "policy_budget_rejections", "signature_arithmetic_rejections",
    "reserved_verification_attempts", "reserved_wire_bytes",
    "sticky_budget_checks", "input_wire_bytes",
)
RUN_FIXED = {
    "schema": SCHEMA, "kind": "run", "wire_format": "CPQ1",
    "scope": "actual CPQ1 candidate APIs; local repeated public fixtures only",
    "algorithms": list(PARAMETERS), "signer_counts": list(SIGNER_COUNTS),
    "payload_labels": list(PAYLOAD_LABELS), "operations": list(OPERATIONS),
    "warmup_groups_per_operation_case": 1, "fixture_repeated_each_sample": True,
    "signature_mode": "FIPS204-Pure", "fips_context_hex": "",
    "signing_variant": "deterministic",
    "seed_fixture": "32 bytes 0x42; last eight bytes replaced by signer index as u64be",
    "payload_fixture": "byte[i] = (i * 29 + 17) mod 256",
    "binding": {
        "network_hex": "01" * 32, "parameters_hex": "02" * 32,
        "genesis_hex": "03" * 32, "scope": "WholeSystemCandidate",
        "protocol_version": 1, "activation_height": 10,
        "retirement_height_exclusive": 100,
    },
    "envelope": {
        "purpose": "FinalUse", "purpose_code": 9, "owner_generation": 7,
        "key_epoch": 3, "sequence": 11, "valid_from_height": 10,
        "valid_until_height_inclusive": 99,
    },
    "work_configuration_digest": WORK_DIGEST,
    "limits": {
        "signed_message_bytes": 65536, "wire_bytes": 131072, "signers": 8,
        "reserved_verification_attempts": 64, "reserved_wire_bytes": 8388608,
        "signed_header_bytes": HEADER_BYTES,
    },
    "clock": "std::time::Instant",
    "quantiles": "nearest-rank; integer mean; raw samples retained",
    "tail_note": "64-sample p99 is the observed maximum, not a production population tail",
    "timing_scope": "inclusive operation, outcome checks and owned temporary drops; fixture key generation and initial signatures outside samples; output IO outside samples",
    "budget_scope": "each independent timing sample and warmup creates a new budget; shared_budget_exhaustion never resets its one budget within a sample",
    "hardware_scope": "single process on caller-recorded host; wall time includes scheduling; CPU, RSS, WAL, WAN and business confirmation are not measured",
    "caller_run_context_required": True,
    "caller_run_context": "record exact source and diff, binary hash, locked graph, rustc -Vv, cargo -V, target, flags, CPU, memory, kernel, load, command and terminal exit beside this output",
    "frame_is_PNQ_or_NPQ": False,
    "network_or_business_confirmation_measured": False,
    "production_tail_established": False, "activation_performed": False,
}
CASE_KEYS = {
    "schema", "kind", "case_id", "algorithm", "nist_category", "signer_count",
    "payload_label", "payload_bytes", "maximum_legal_payload_bytes",
    "crypto_profile_id", "wrong_profile_id", "signer_ids",
    "signer_seed_indices_in_wire_order", "signed_message_bytes", "cpq1_wire_bytes",
    "signed_metadata_bytes", "outer_framing_bytes", "public_key_bytes_each",
    "signature_bytes_each", "signed_message_hex", "cpq1_wire_hex",
    "signed_message_sha512", "cpq1_wire_sha512", "late_invalid_byte_offset",
    "late_invalid_xor", "setup_wall_ns", "setup_outcomes", "current_authorization_refused",
}
MEASUREMENT_KEYS = {
    "schema", "kind", "case_id", "operation", "samples", "checked_samples",
    "warmup_groups", "latency_unit", "sample_ns", "min_ns", "mean_ns",
    "p50_ns", "p95_ns", "p99_ns", "max_ns", "total_ns", "outcomes_per_sample",
    "warmup_outcomes", "measured_outcome_totals", "production_p99_ns",
    "performance_acceptance_gate",
}
COMPLETION_KEYS = {
    "schema", "kind", "cases", "measurement_rows", "samples_per_operation_case",
    "raw_sample_values", "warmup_groups", "all_expected_outcomes_checked",
    "measured_outcome_totals", "production_qualified", "activation_performed",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def same(actual, expected, field):
    """Exact shape AND type: JSON booleans must not impersonate integers."""
    require(type(actual) is type(expected), f"incorrect type: {field}")
    if type(expected) is dict:
        require(actual.keys() == expected.keys(), f"incorrect object shape: {field}")
        for key in expected:
            same(actual[key], expected[key], f"{field}.{key}")
    elif type(expected) is list:
        require(len(actual) == len(expected), f"incorrect list length: {field}")
        for index, (left, right) in enumerate(zip(actual, expected)):
            same(left, right, f"{field}[{index}]")
    else:
        require(actual == expected, f"incorrect value: {field}")


def uint(value, field):
    require(type(value) is int and 0 <= value <= MAX_U64, f"invalid unsigned integer: {field}")
    return value


def exact_keys(row, keys, name):
    require(type(row) is dict and row.keys() == keys, f"incorrect {name} fields")


def hex_bytes(value, maximum, name):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= 2 * maximum
            and re.fullmatch(r"[0-9a-f]*", value) is not None, f"invalid hex: {name}")
    return bytes.fromhex(value)


def sha512(raw):
    return hashlib.sha512(raw).hexdigest()


def foreign_profile_id(configuration):
    """Independently change only network in the fixed known descriptor grammar."""
    require(configuration.startswith(CONFIGURATION_DOMAIN), "configuration domain")
    at = len(CONFIGURATION_DOMAIN) + 1
    for _ in range(4):
        require(at + 4 <= len(configuration), "configuration field prefix")
        length = int.from_bytes(configuration[at:at + 4], "big")
        at += 4 + length
        require(at <= len(configuration), "configuration field length")
    at += 8  # public-key and signature lengths
    require(configuration[at:at + 32] == b"\x01" * 32, "fixture descriptor network")
    return sha512(configuration[:at] + b"\x04" * 32 + configuration[at + 32:])


def validate_header(meta):
    exact_keys(meta, RUN_FIXED.keys() | {"samples_per_operation_case", "profiles", "execution_context"}, "run")
    for field, expected in RUN_FIXED.items():
        same(meta[field], expected, f"run.{field}")
    samples = uint(meta["samples_per_operation_case"], "sample count")
    require(64 <= samples <= 4096, "sample count outside 64..4096")
    context = meta["execution_context"]
    exact_keys(context, {"arch", "os", "debug_assertions", "crate_version"}, "execution context")
    for field in ("arch", "os", "crate_version"):
        require(type(context[field]) is str and 1 <= len(context[field]) <= 128
                and re.fullmatch(r"[A-Za-z0-9_.+-]+", context[field]) is not None,
                "invalid execution context")
    require(type(context["debug_assertions"]) is bool, "debug assertions field is not boolean")
    profiles = meta["profiles"]
    require(type(profiles) is list and len(profiles) == 2, "profile inventory")
    foreign = {}
    for entry, algorithm in zip(profiles, PARAMETERS):
        exact_keys(entry, {"algorithm", "crypto_profile_id", "canonical_configuration_bytes",
                           "canonical_configuration_hex", "wrong_network_profile_id"}, "profile")
        same(entry["algorithm"], algorithm, "profile.algorithm")
        expected_id = PARAMETERS[algorithm]["profile_id"]
        same(entry["crypto_profile_id"], expected_id, "profile.id")
        configuration = hex_bytes(entry["canonical_configuration_hex"], 16384, "configuration")
        same(entry["canonical_configuration_bytes"], len(configuration), "configuration byte count")
        require(sha512(configuration) == expected_id, "configuration digest does not match frozen profile")
        foreign[algorithm] = foreign_profile_id(configuration)
        same(entry["wrong_network_profile_id"], foreign[algorithm], "foreign profile.id")
    return samples, foreign


def blank_outcomes():
    return dict.fromkeys(OUTCOME_FIELDS, 0)


def expected_outcomes(operation, signers, wire_bytes):
    result = blank_outcomes()
    if operation in OPERATIONS[:2]:
        result["encoded_frames"] = 1
        result["sign_and_self_verify_calls"] = signers if operation == OPERATIONS[1] else 0
        return result
    result.update(verification_api_calls=1, reserved_verification_attempts=signers,
                  reserved_wire_bytes=wire_bytes, input_wire_bytes=wire_bytes)
    if operation in (OPERATIONS[2], OPERATIONS[3]):
        result.update(accepted_authentications=1, returned_verified_signatures=signers)
    elif operation == OPERATIONS[4]:
        result["signature_arithmetic_rejections"] = 1
    elif operation in (OPERATIONS[5], OPERATIONS[6], OPERATIONS[8]):
        result["policy_encoding_rejections"] = 1
        if operation == OPERATIONS[8]:
            result["reserved_wire_bytes"] += 1
            result["input_wire_bytes"] += 1
    elif operation in (OPERATIONS[7], OPERATIONS[9]):
        result["policy_size_rejections"] = 1
        if operation == OPERATIONS[7]:
            result.update(reserved_wire_bytes=7, input_wire_bytes=7)
    elif operation == OPERATIONS[10]:
        groups = 64 // signers
        result.update(verification_api_calls=groups + 2,
                      accepted_authentications=1, returned_verified_signatures=signers,
                      policy_encoding_rejections=groups - 1, policy_budget_rejections=2,
                      reserved_verification_attempts=64 + signers,
                      reserved_wire_bytes=(groups + 1) * wire_bytes,
                      sticky_budget_checks=1, input_wire_bytes=(groups + 1) * wire_bytes + 7)
    else:
        raise ValueError("unregistered operation")
    return result


def validate_case(row, foreign, fixture_keys):
    exact_keys(row, CASE_KEYS, "case")
    same(row["schema"], SCHEMA, "case.schema")
    same(row["kind"], "case", "case.kind")
    algorithm, signers, label = row["algorithm"], row["signer_count"], row["payload_label"]
    require(type(algorithm) is str and algorithm in PARAMETERS, "unknown case algorithm")
    require(type(signers) is int and signers in SIGNER_COUNTS, "unknown signer count")
    require(type(label) is str and label in PAYLOAD_LABELS, "unknown payload label")
    parameters = PARAMETERS[algorithm]
    max_payload = 65536 - HEADER_BYTES - 64 * signers
    length = {"empty": 0, "176": 176, "4096": 4096, "maximum": max_payload}[label]
    pk_bytes, sig_bytes = parameters["public_key_bytes"], parameters["signature_bytes"]
    message_bytes = HEADER_BYTES + 64 * signers + length
    wire_bytes = 8 + message_bytes + signers * (8 + pk_bytes + sig_bytes)
    case_id = f"{algorithm}/{signers}/{label}"
    for field, expected in {
        "case_id": case_id, "nist_category": parameters["category"],
        "payload_bytes": length, "maximum_legal_payload_bytes": max_payload,
        "crypto_profile_id": parameters["profile_id"], "wrong_profile_id": foreign[algorithm],
        "signed_message_bytes": message_bytes, "cpq1_wire_bytes": wire_bytes,
        "signed_metadata_bytes": HEADER_BYTES + 64 * signers,
        "outer_framing_bytes": 8 + 8 * signers, "public_key_bytes_each": pk_bytes,
        "signature_bytes_each": sig_bytes, "late_invalid_byte_offset": wire_bytes - sig_bytes,
        "late_invalid_xor": 1, "current_authorization_refused": True,
    }.items():
        same(row[field], expected, f"{case_id}.{field}")
    uint(row["setup_wall_ns"], "setup wall time")
    setup = expected_outcomes(OPERATIONS[3], signers, wire_bytes)
    setup.update(encoded_frames=1, sign_and_self_verify_calls=signers)
    same(row["setup_outcomes"], setup, "setup outcomes")
    message = hex_bytes(row["signed_message_hex"], 65536, "signed message")
    wire = hex_bytes(row["cpq1_wire_hex"], 131072, "CPQ1 wire")
    require(len(message) == message_bytes and len(wire) == wire_bytes, "complete fixture byte count")
    same(row["signed_message_sha512"], sha512(message), "signed message digest")
    same(row["cpq1_wire_sha512"], sha512(wire), "wire digest")
    require(wire[:8] == b"CPQ1" + struct.pack(">I", len(message))
            and wire[8:8 + len(message)] == message, "CPQ1 actual wire/message boundary")
    indices = row["signer_seed_indices_in_wire_order"]
    require(type(indices) is list and len(indices) == signers
            and all(type(index) is int for index in indices)
            and sorted(indices) == list(range(signers)), "seed-index permutation")
    at, key_ids = 8 + len(message), []
    for index in indices:
        require(wire[at:at + 4] == struct.pack(">I", pk_bytes), "actual CPQ1 key length")
        at += 4
        public_key = wire[at:at + pk_bytes]
        require(len(public_key) == pk_bytes, "truncated CPQ1 key")
        at += pk_bytes
        require(wire[at:at + 4] == struct.pack(">I", sig_bytes), "actual CPQ1 signature length")
        at += 4 + sig_bytes
        require(at <= len(wire), "truncated CPQ1 signature")
        key_id = hashlib.sha512(COMMITMENT_DOMAIN + bytes.fromhex(parameters["profile_id"])
                                + b"\1" + struct.pack(">Q", pk_bytes) + public_key).digest()
        key_ids.append(key_id)
        identity = algorithm, index
        if identity in fixture_keys:
            require(fixture_keys[identity] == public_key, "public fixture key changed between cases")
        else:
            fixture_keys[identity] = public_key
    require(at == len(wire), "CPQ1 trailing bytes")
    require(key_ids == sorted(set(key_ids)) and bytes(64) not in key_ids,
            "noncanonical CPQ1 signer set")
    same(row["signer_ids"], [key.hex() for key in key_ids], "profile-bound signer IDs")
    body = bytes((index * 29 + 17) % 256 for index in range(length))
    expected_message = ENVELOPE_DOMAIN + bytes.fromhex(parameters["profile_id"]) + bytes.fromhex(WORK_DIGEST)
    expected_message += struct.pack(">HQQQQQH", 9, 7, 3, 11, 10, 99, signers)
    expected_message += b"".join(key_ids) + struct.pack(">I", len(body)) + body
    require(message == expected_message, "actual signed message differs from complete fixed context")
    return case_id, signers, wire_bytes


def validate_measurement(row, case_id, signers, wire_bytes, samples, operation):
    exact_keys(row, MEASUREMENT_KEYS, "measurement")
    for field, expected in {
        "schema": SCHEMA, "kind": "measurement", "case_id": case_id,
        "operation": operation, "samples": samples, "checked_samples": samples,
        "warmup_groups": 1, "latency_unit": "ns_per_independent_operation_group",
        "production_p99_ns": None, "performance_acceptance_gate": False,
    }.items():
        same(row[field], expected, f"measurement.{field}")
    raw = row["sample_ns"]
    require(type(raw) is list and len(raw) == samples, "missing raw sample population")
    for duration in raw:
        uint(duration, "sample duration")
    ordered, total = sorted(raw), sum(raw)
    uint(total, "sample duration sum")
    expected_stats = {
        "min_ns": min(raw), "max_ns": max(raw), "mean_ns": total // samples,
        "p50_ns": ordered[(samples * 50 + 99) // 100 - 1],
        "p95_ns": ordered[(samples * 95 + 99) // 100 - 1],
        "p99_ns": ordered[(samples * 99 + 99) // 100 - 1], "total_ns": total,
    }
    for field, expected in expected_stats.items():
        same(row[field], expected, f"measurement.{field}")
    expected = expected_outcomes(operation, signers, wire_bytes)
    same(row["outcomes_per_sample"], expected, "per-sample checked outcomes")
    same(row["warmup_outcomes"], expected, "warmup checked outcomes")
    totals = {field: number * samples for field, number in expected.items()}
    same(row["measured_outcome_totals"], totals, "measured outcome totals")
    return totals


def validate(records):
    require(type(records) is list and len(records) == 386,
            "need run header, 32 cases, 352 measurements and completion sentinel")
    samples, foreign = validate_header(records[0])
    expected_cases = {f"{algorithm}/{signers}/{label}" for algorithm in PARAMETERS
                      for signers in SIGNER_COUNTS for label in PAYLOAD_LABELS}
    seen, fixture_keys, totals = set(), {}, blank_outcomes()
    for at in range(1, 385, 12):
        case_id, signers, wire_bytes = validate_case(records[at], foreign, fixture_keys)
        require(case_id in expected_cases and case_id not in seen, "unexpected or duplicate case")
        seen.add(case_id)
        for index, operation in enumerate(OPERATIONS, 1):
            actual = validate_measurement(records[at + index], case_id, signers, wire_bytes, samples, operation)
            for field, number in actual.items():
                totals[field] += number
    require(seen == expected_cases, "missing algorithm/signer/payload coverage")
    require(len(fixture_keys) == 16, "incomplete public fixture key inventory")
    completion = records[-1]
    exact_keys(completion, COMPLETION_KEYS, "completion")
    for field, expected in {
        "schema": SCHEMA, "kind": "complete", "cases": 32, "measurement_rows": 352,
        "samples_per_operation_case": samples, "raw_sample_values": 352 * samples,
        "warmup_groups": 352, "all_expected_outcomes_checked": True,
        "measured_outcome_totals": totals, "production_qualified": False,
        "activation_performed": False,
    }.items():
        same(completion[field], expected, f"completion.{field}")
    return {
        "result": "PASS", "schema": SCHEMA,
        "scope": "local CPQ1 observation consistency only; external execution/source/host receipt required",
        "cases": 32, "measurement_rows": 352, "samples_per_measurement": samples,
        "raw_sample_values_recomputed": 352 * samples, "warmup_groups": 352,
        "measured_outcome_totals": totals, "wire_format": "CPQ1",
        "native_execution_attested": False, "signature_math_independently_verified": False,
        "production_or_activation_claim": False,
        "reservations_are_not_mathematical_verification_counts": True,
    }


def unique_object(pairs):
    output = {}
    for key, value in pairs:
        require(key not in output, "duplicate JSON key")
        output[key] = value
    return output


def forbidden_number(value):
    raise ValueError("floating point or nonfinite JSON is not allowed: " + value)


def read_records(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES,
                "observation must be a bounded regular file")
        raw = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(fingerprint(before) == fingerprint(after), "observation changed during read")
        require(len(raw) == before.st_size and raw.endswith(b"\n"), "incomplete observation file")
    rows = []
    for line in raw.splitlines():
        require(0 < len(line) <= MAX_LINE_BYTES, "blank or oversized observation line")
        row = json.loads(line, object_pairs_hook=unique_object,
                         parse_constant=forbidden_number, parse_float=forbidden_number)
        require(type(row) is dict, "observation record is not an object")
        rows.append(row)
    return rows, {"file": Path(path).name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def check(path):
    records, identity = read_records(path)
    return {**validate(records), "observation_file": identity}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.observation), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, OverflowError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
