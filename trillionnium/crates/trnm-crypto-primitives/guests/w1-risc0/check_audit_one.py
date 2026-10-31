#!/usr/bin/env python3
"""Bind one real-host case record to actual bytes/source; never reverify a STARK.

This independently reconstructs claimed journals, the bounded receipt layout,
and the exact seal/parameter mutation positions. Seal validity, SDK dispatch,
and timings remain source-bound native observations, not independently verified.
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct

from check_observations import bounded_raw, decode_json, require
from receipt_layout import parse_receipt_layout

ROOT = Path(__file__).resolve().parents[5]
PREFIX = "trillionnium/crates/trnm-crypto-primitives/"
SOURCE_PATHS = {PREFIX + p for p in (
    "src/pon_work/full_relation.rs", "guests/w1-risc0/host/src/main.rs",
    "guests/w1-risc0/host/src/claimed_context.rs", "guests/w1-risc0/host/src/audit_one.rs",
    "guests/w1-risc0/host/src/receipt_bounds.rs", "guests/w1-risc0/host/src/phase_journal.rs",
    "guests/w1-risc0/relation/src/lib.rs", "guests/w1-risc0/relation/src/parameters.rs",
    "guests/w1-risc0/guest/src/main.rs", "guests/w1-risc0/backend-manifest.json",
    "guests/w1-risc0/Cargo.toml", "guests/w1-risc0/Cargo.lock",
    "guests/w1-risc0/host/Cargo.toml", "guests/w1-risc0/relation/Cargo.toml",
    "guests/w1-risc0/guest/Cargo.toml",
)}
CAPS = {"receipt_bytes": 128 * 1024 * 1024, "segments": 2048, "seal_words": 262144,
        "padded_cycles": 256 * 1024 * 1024, "journal_bytes": 228,
        "elf_bytes": 16 * 1024 * 1024, "input_bytes": 49640}
CASES = {"valid", "first_seal_tamper", "last_seal_tamper", "wrong_verifier_parameters",
         "wrong_statement_miner", "truncated_receipt", "trailing_receipt_bytes",
         "seal_length_allocation_bomb"}
FALSE_FLAGS = {"native_w1_recomputed", "new_proof_generated", "minimum_work_cost_proved",
               "public_ingress_qualified", "pq_128_security_qualified", "consensus_authority"}
EXCLUDED = ["file-io", "positive-prerequisite", "case-construction", "source-and-byte-hashes",
            "error-formatting", "json-output", "process-startup"]
FIELDS = {"schema", "operation", "case", "real_proof_positive_control",
          "positive_prerequisite_warms_verifier", "positive_prerequisite_wall_ns",
          "case_construction_wall_ns", "receiver", "receiver_scope",
          "excluded_from_receiver_timing", "original_input", "original_receipt", "case_input",
          "case_receipt", "input_mutation", "receipt_mutation", "original_shape",
          "original_statement_id", "case_expected_journal_sha256", "image_id",
          "source_inputs", "resource_caps"} | FALSE_FLAGS


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unsigned(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def domain(tag, *parts):
    h = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


def claimed_journal(raw):
    require(len(raw) == 49640 and raw[:6] == b"PWG1\x01\0", "fixed statement encoding")
    require(raw[6:38] == domain(b"w1-complete-profile-v1", b"pon-complete-w1-relation-v1"),
            "complete relation profile")
    statement, witness = raw[:452], raw[452:]
    header = statement[38:356]
    task, target, commitment = statement[356:388], statement[388:420], statement[420:452]
    require(header[:6] == b"PNH1\x01\0" and header[278:310] == task
            and header[118:150] == target and target != bytes(32), "header/task/target context")
    require(domain(b"w1-complete-witness-v1", witness) == commitment, "full witness commitment")
    statement_id = domain(b"w1-complete-statement-v1", statement)
    challenge = domain(b"challenge", header)
    trace = witness[-32:]
    product = witness[4 + 2 * 64 * 64 * 4:4 + 3 * 64 * 64 * 4]
    journal = b"PWJ1" + b"".join((statement_id, challenge, task,
                                  domain(b"ticket", challenge, trace), trace,
                                  domain(b"block", header, trace),
                                  domain(b"w1-complete-product-v1", product)))
    return statement_id.hex(), journal


def bind(row, raw, label):
    require(type(row) is dict and set(row) == {"bytes", "sha256"}, label + " binding shape")
    require(unsigned(row["bytes"]) and row["bytes"] == len(raw)
            and row["sha256"] == sha(raw), label + " exact bytes/hash")


def apply_mutation(row, raw, suffix=b"", truncate=False):
    require(type(row) is dict and set(row) == {"byte_changes", "before_bytes", "after_bytes"},
            "mutation schema")
    require(unsigned(row["before_bytes"]) and row["before_bytes"] == len(raw), "mutation input size")
    changed = bytearray(raw[:-1] if truncate else raw + suffix)
    require(unsigned(row["after_bytes"]) and row["after_bytes"] == len(changed), "mutation output size")
    entries = row["byte_changes"]
    require(type(entries) is list and len(entries) <= 32, "mutation count budget")
    previous = -1
    for item in entries:
        require(type(item) is dict and set(item) == {"offset", "before", "after"}, "byte mutation schema")
        offset, old, new = item["offset"], item["before"], item["after"]
        require(unsigned(offset) and previous < offset < min(len(raw), len(changed)), "ordered byte offset")
        require(type(old) is int and type(new) is int and 0 <= new <= 255
                and old == raw[offset] and old != new, "byte mutation values")
        changed[offset] = new
        previous = offset
    return bytes(changed)


def validate(record, input_bytes, receipt_bytes, root=ROOT):
    require(type(record) is dict and set(record) == FIELDS, "exact case record schema")
    require(record["schema"] == "pon-w1-receiver-case-v1"
            and record["operation"] == "audit-one" and record["case"] in CASES, "case namespace")
    require(all(record[key] is False for key in FALSE_FLAGS), "unearned proof/work/ingress authority")
    require(record["real_proof_positive_control"] is True
            and record["positive_prerequisite_warms_verifier"] is True, "actual positive prerequisite scope")
    require(record["receiver_scope"] == "bounded-preflight/sdk-decode/strict-verify/decoded-drop"
            and record["excluded_from_receiver_timing"] == EXCLUDED, "uniform receiver timing scope")
    require(type(record["resource_caps"]) is dict and record["resource_caps"] == CAPS
            and all(type(value) is int for value in record["resource_caps"].values()), "original fixed resource caps")
    for key in ("positive_prerequisite_wall_ns", "case_construction_wall_ns"):
        require(unsigned(record[key]), "nonnegative integer timing " + key)
    require(len(input_bytes) == CAPS["input_bytes"] and 20 <= len(receipt_bytes) <= CAPS["receipt_bytes"],
            "supplied input/receipt budgets")
    bind(record["original_input"], input_bytes, "original input")
    bind(record["original_receipt"], receipt_bytes, "original receipt")
    layout = parse_receipt_layout(receipt_bytes, CAPS)
    original_id, original_journal = claimed_journal(input_bytes)
    require(record["original_statement_id"] == original_id, "independently bound original statement")
    journal_start = layout["journal_offset"]
    require(receipt_bytes[journal_start:journal_start + CAPS["journal_bytes"]] == original_journal,
            "original receipt journal matches claimed input")
    case = record["case"]
    changed_input = apply_mutation(record["input_mutation"], input_bytes)
    changed_receipt = apply_mutation(record["receipt_mutation"], receipt_bytes,
                                     b"\0" if case == "trailing_receipt_bytes" else b"",
                                     case == "truncated_receipt")
    input_changes = record["input_mutation"]["byte_changes"]
    changes = record["receipt_mutation"]["byte_changes"]
    if case == "wrong_statement_miner":
        require(input_changes == [{"offset":188,"before":input_bytes[188],"after":input_bytes[188] ^ 1}],
                "exact miner mutation")
    else:
        require(not input_changes, "unexpected statement mutation")
    if case in {"valid", "wrong_statement_miner", "truncated_receipt", "trailing_receipt_bytes"}:
        require(not changes, "unexpected receipt byte mutation")
    elif case == "seal_length_allocation_bomb":
        expected = bytearray(receipt_bytes)
        expected[12:20] = b"\xff" * 8
        require(changed_receipt == expected, "exact first seal length mutation")
    elif case in {"first_seal_tamper", "last_seal_tamper"}:
        require(len(changes) == 1 and changes[0]["after"] == changes[0]["before"] ^ 1, "single seal bit mutation")
        if case == "first_seal_tamper":
            require(changes[0]["offset"] == layout["first_seal_word_100_offset"], "exact first seal word offset")
        else:
            require(changes[0]["offset"] == layout["last_seal_word_offset"], "exact last seal word offset")
    elif case == "wrong_verifier_parameters":
        start = layout["first_segment_parameters_offset"]
        expected_changes = [{"offset": offset, "before": receipt_bytes[offset], "after": 0}
                            for offset in range(start, start + 32) if receipt_bytes[offset] != 0]
        require(changes and changes == expected_changes, "exact first segment parameter-digest mutation")
    bind(record["case_input"], changed_input, "case input")
    bind(record["case_receipt"], changed_receipt, "case receipt")
    _, expected_journal = claimed_journal(changed_input)
    require(record["case_expected_journal_sha256"] == sha(expected_journal), "independent case journal")
    receiver = record["receiver"]
    require(type(receiver) is dict and set(receiver) == {"accepted", "outcome", "reason", "last_stage",
            "bounded_preflight_and_sdk_decode_wall_ns", "strict_verify_wall_ns",
            "decoded_receipt_drop_wall_ns", "receiver_total_wall_ns"}, "receiver fields")
    require(receiver["accepted"] is (case == "valid"), "fixed positive/negative outcome")
    early = case in {"truncated_receipt", "trailing_receipt_bytes", "seal_length_allocation_bomb"}
    expected_outcome = ("verified" if case == "valid" else "refused_not_evaluated"
                        if case == "seal_length_allocation_bomb" else "malformed_encoding"
                        if early else "verification_failed")
    require(receiver["outcome"] == expected_outcome and receiver["last_stage"] ==
            ("bounded_preflight_or_sdk_decode" if early else "strict_verify"), "expected failure stage")
    require(receiver["reason"] is None if case == "valid" else
            type(receiver["reason"]) is str and 0 < len(receiver["reason"]) <= 4096, "outcome reason")
    timings = [receiver["bounded_preflight_and_sdk_decode_wall_ns"]]
    for key in ("strict_verify_wall_ns", "decoded_receipt_drop_wall_ns"):
        require(receiver[key] is None if early else unsigned(receiver[key]), "executed timing stage")
        if not early:
            timings.append(receiver[key])
    require(all(unsigned(value) for value in timings) and unsigned(receiver["receiver_total_wall_ns"])
            and receiver["receiver_total_wall_ns"] >= sum(timings), "receiver time accounting")
    shape = record["original_shape"]
    require(type(shape) is dict and set(shape) == {"segments", "padded_cycles", "maximum_po2"}
            and all(unsigned(value) for value in shape.values())
            and 1 <= shape["segments"] <= CAPS["segments"] and 13 <= shape["maximum_po2"] <= 20
            and shape["segments"] * (1 << 13) <= shape["padded_cycles"] <= CAPS["padded_cycles"],
            "bounded declared original shape")
    require(shape == layout["shape"], "declared original shape matches receipt bytes")
    inputs = record["source_inputs"]
    require(type(inputs) is list and len(inputs) == len(SOURCE_PATHS), "complete direct source input set")
    seen = set()
    for row in inputs:
        require(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
                and row["path"] in SOURCE_PATHS and row["path"] not in seen, "exact unique source path")
        seen.add(row["path"])
        actual = bounded_raw(root / row["path"], 2 * 1024 * 1024)
        bind({"bytes":row["bytes"],"sha256":row["sha256"]}, actual, row["path"])
    manifest = decode_json((root / (PREFIX + "guests/w1-risc0/backend-manifest.json")).read_bytes())
    require(re.fullmatch(r"[0-9a-f]{64}", record["image_id"]) is not None
            and record["image_id"] == manifest["guest_image_id"], "pinned original image")
    return {"schema":"pon-w1-receiver-case-binding-v2", "case":case, "metadata_and_byte_bindings_pass":True,
            "source_files_checked":len(seen), "receiver_total_wall_ns":receiver["receiver_total_wall_ns"],
            "receipt_layout_independently_reconstructed":True,
            "mutation_offsets_independently_reconstructed":True,
            "original_receipt_journal_bound_to_claimed_input":True,
            "receipt_layout":layout,
            "proof_reverified_by_reader":False, "proof_shape_independently_reconstructed":False,
            "sdk_mutation_dispatch_independently_reexecuted":False,
            "timings_independently_remeasured":False, "consensus_authority":False}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = validate(decode_json(bounded_raw(args.record, 512 * 1024)),
                      bounded_raw(args.input, CAPS["input_bytes"]),
                      bounded_raw(args.receipt, CAPS["receipt_bytes"]))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
