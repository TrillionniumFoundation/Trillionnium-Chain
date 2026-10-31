#!/usr/bin/env python3
"""Read fixed claim-cost observations; do not authenticate proofs or timings."""
import argparse
import json
from pathlib import Path
import re

import check_audit_one as original

CASES = ("valid", "outer_journal_rebound", "late_link_tamper", "late_nonfinal_exit",
         "matching_claims_corrupt_seal", "coordinated_public_claim_forgery")
CONSISTENT = {"valid", "matching_claims_corrupt_seal", "coordinated_public_claim_forgery"}
FALSE_FLAGS = {"new_proof_generated", "minimum_work_cost_proved", "public_ingress_qualified",
               "pq_128_security_qualified", "worst_case_rejection_cost_closed", "consensus_authority"}
SCOPE = "optional-context-setup/bounded-decode/strict-profile/public-claims-if-selected/full-sdk-if-reached/owned-drop"
EXCLUDED = ["file-io", "statement-binding", "positive-prerequisite", "case-construction",
            "source-and-byte-hashes", "error-formatting", "json-output", "process-startup"]
FIELDS = {"schema", "operation", "prepared_context_setup_wall_ns", "positive_prerequisite_wall_ns",
          "real_proof_positive_control", "prerequisite_warms_runtime", "fresh_context_does_not_mean_cold_hardware",
          "exclusive_host", "receiver_scope", "excluded_from_receiver_timing", "original_input_sha256",
          "original_receipt_sha256", "original_receipt_bytes", "original_statement_id", "image_id",
          "source_inputs", "resource_caps", "cases"} | FALSE_FLAGS
ROW_FIELDS = {"route", "context", "accepted", "public_claims_entered", "sdk_entered",
              "context_setup_wall_ns", "bounded_decode_wall_ns", "verification_wall_ns",
              "owned_objects_drop_wall_ns", "receiver_total_wall_ns", "reason"}
require = original.require


def validate(record, input_bytes, receipt_bytes, root=original.ROOT):
    require(type(record) is dict and set(record) == FIELDS, "exact claim-audit schema")
    require(record["schema"] == "pon-w1-public-claim-cost-audit-v1" and record["operation"] == "audit-claims",
            "claim-audit namespace")
    require(all(record[key] is False for key in FALSE_FLAGS) and record["exclusive_host"] is False,
            "unsupported claim-audit authority or exclusive host")
    for key in ("real_proof_positive_control", "prerequisite_warms_runtime", "fresh_context_does_not_mean_cold_hardware"):
        require(record[key] is True, "positive prerequisite and context scope")
    require(record["receiver_scope"] == SCOPE and record["excluded_from_receiver_timing"] == EXCLUDED,
            "receiver timing scope")
    require(record["resource_caps"] == original.CAPS and all(type(v) is int for v in record["resource_caps"].values()),
            "unchanged resource caps")
    for key in ("prepared_context_setup_wall_ns", "positive_prerequisite_wall_ns"):
        require(original.unsigned(record[key]), "context/prerequisite time")
    require(len(input_bytes) == original.CAPS["input_bytes"] and 20 <= len(receipt_bytes) <= original.CAPS["receipt_bytes"],
            "original input byte bounds")
    require(record["original_input_sha256"] == original.sha(input_bytes)
            and record["original_receipt_sha256"] == original.sha(receipt_bytes)
            and type(record["original_receipt_bytes"]) is int and record["original_receipt_bytes"] == len(receipt_bytes),
            "original bytes")
    statement_id, _ = original.claimed_journal(input_bytes)
    require(record["original_statement_id"] == statement_id, "original complete statement")
    inputs = record["source_inputs"]
    require(type(inputs) is list and len(inputs) == len(original.SOURCE_PATHS), "complete source input set")
    seen = set()
    for row in inputs:
        require(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
                and row["path"] in original.SOURCE_PATHS and row["path"] not in seen, "unique source input")
        seen.add(row["path"])
        raw = original.bounded_raw(root / row["path"], 2 * 1024 * 1024)
        original.bind({"bytes":row["bytes"], "sha256":row["sha256"]}, raw, row["path"])
    manifest = original.decode_json((root / (original.PREFIX + "guests/w1-risc0/backend-manifest.json")).read_bytes())
    require(record["image_id"] == manifest["guest_image_id"], "original image pin")
    cases = record["cases"]
    require(type(cases) is list and [c.get("case") for c in cases if type(c) is dict] == list(CASES),
            "complete ordered case set")
    summary = []
    for case in cases:
        require(set(case) == {"case", "input_sha256", "receipt_sha256", "receipt_bytes",
                              "expected_journal_sha256", "public_claims_consistent", "observations"}, "case fields")
        name = case["case"]
        changed = bytearray(input_bytes)
        if name in {"outer_journal_rebound", "coordinated_public_claim_forgery"}:
            changed[188] ^= 1
        _, journal = original.claimed_journal(changed)
        require(case["input_sha256"] == original.sha(changed) and case["expected_journal_sha256"] == original.sha(journal),
                "independent complete-statement rebinding")
        require(type(case["receipt_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", case["receipt_sha256"])
                and original.unsigned(case["receipt_bytes"]) and 20 <= case["receipt_bytes"] <= original.CAPS["receipt_bytes"],
                "reported mutated receipt identity")
        if name == "valid":
            require(case["receipt_sha256"] == original.sha(receipt_bytes) and case["receipt_bytes"] == len(receipt_bytes),
                    "unchanged positive receipt")
        require(case["public_claims_consistent"] is (name in CONSISTENT), "fixed public-claim boundary")
        rows = case["observations"]
        require(type(rows) is list and len(rows) == 4, "all paired reference/new and fresh/reused observations")
        pairs = set()
        for row in rows:
            require(type(row) is dict and set(row) == ROW_FIELDS, "observation fields")
            pair = (row["route"], row["context"])
            require(pair in {(a,b) for a in ("original_sdk_order", "public_claims_first") for b in ("fresh", "reused")}
                    and pair not in pairs, "unique original/new context pair")
            pairs.add(pair)
            reference = row["route"] == "original_sdk_order"
            require(row["accepted"] is (name == "valid") and row["public_claims_entered"] is (not reference)
                    and row["sdk_entered"] is (reference or name in CONSISTENT), "actual expected SDK frontier")
            require(row["reason"] is None if name == "valid" else
                    type(row["reason"]) is str and 0 < len(row["reason"]) <= 4096, "outcome reason")
            require(row["context_setup_wall_ns"] is None if row["context"] == "reused" else
                    original.unsigned(row["context_setup_wall_ns"]), "observed/omitted context setup")
            times = [row[k] for k in ("bounded_decode_wall_ns", "verification_wall_ns", "owned_objects_drop_wall_ns")]
            if row["context"] == "fresh":
                times.append(row["context_setup_wall_ns"])
            require(all(original.unsigned(t) for t in times) and original.unsigned(row["receiver_total_wall_ns"])
                    and row["receiver_total_wall_ns"] >= sum(times), "complete receiver time accounting")
        summary.append({"case":name, "accepted":name == "valid", "public_claims_consistent":name in CONSISTENT,
                        "observations":rows})
    return {"schema":"pon-w1-public-claim-cost-readback-v1", "metadata_bindings_pass":True,
            "source_files_checked":len(seen), "cases":summary, "proof_reverified_by_reader":False,
            "sdk_mutations_independently_reconstructed":False, "timings_independently_remeasured":False,
            "worst_case_rejection_cost_closed":False, "consensus_authority":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    result = validate(original.decode_json(original.bounded_raw(args.record, 512 * 1024)),
                      original.bounded_raw(args.input, original.CAPS["input_bytes"]),
                      original.bounded_raw(args.receipt, original.CAPS["receipt_bytes"]))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
