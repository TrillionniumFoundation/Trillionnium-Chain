#!/usr/bin/env python3
"""Decompose the pinned full W1 v2 observation without inventing a winner clock.

The existing retained-proof reader authenticates the historical byte closure.
This reader adds disjoint supervisor intervals and separately labelled nested
prover clocks. It generates no proof, executes no verifier and authorizes no
block or reward. Its counterfactuals are arithmetic on the old schedule only.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import read_w1_full_v2_disposition as retained

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "trnm-w1-historical-latency-readback-v1"
SEGMENTS = 43
UNMEASURED = (
    "post_find_publish_seconds", "real_network_propagation_seconds",
    "node_admission_seconds", "confirmation_seconds", "stale_block_rate",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def seconds(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            "nonnegative finite clock required")
    return value


def nanoseconds(value):
    require(type(value) is int and 0 <= value < 2**63, "canonical nanoseconds required")
    return value


def events(raw, label):
    rows = [retained.strict_json(line) for line in raw[label + "/stdout.log"].splitlines()
            if line.strip()]
    require(all(type(row) is dict for row in rows), "nonobject runner event")
    nested = [row["event"] for row in rows if "event" in row]
    require(all(type(row) is dict for row in nested), "nonobject nested runner event")
    return nested


def selected(rows, stage):
    return [row for row in rows if row.get("stage") == stage]


def decompose(report, raw):
    """Internal structural check; the public analyze() also checks fixed hashes."""
    expected = ["prepare-full-execution", "reverify-existing-prefix"] + [
        f"prove-{i:04}" for i in range(SEGMENTS)] + [
        "complete-recursive-compression", "fresh-process-strict-verification",
        "serialize-local-payloads", "observe-local-transfer-transparent",
        "observe-local-transfer-native", "fixed-receipt-verifier-cost",
        "native-full-verifier-cost"]
    require([row["stage"] for row in report["stages"]] == expected,
            "original ordered stages required")
    require(all(report[key] is None for key in UNMEASURED),
            "historical missing winner/WAN/admission clocks cannot be relabelled")
    require(report["prover_p99_established"] is False and
            report["consensus_admission"] is False,
            "historical observation promoted to latency or consensus qualification")
    require(report["fresh_preparation_included"] is True and
            report["prior_runs"] == [] and report["prior_bounded_wall_seconds"] == 0,
            "fresh schedule replaced with a resumed or partial pipeline")
    start = seconds(report["started_monotonic"])
    pipeline = seconds(report["fresh_proof_pipeline_seconds"])
    complete = seconds(report["new_controller_wall_seconds"])
    require(pipeline == report["fresh_verified_receipt_observed_seconds_from_start"]
            and 0 < pipeline <= complete, "pipeline endpoint differs")
    deadline = seconds(report["deadline_monotonic"])
    require(start + complete <= deadline, "historical completion exceeded budget")
    spans, previous_end = [], start
    for row in report["stages"]:
        label, result = row["stage"], row["result"]
        require(result == retained.strict_json(raw[label + "/result.json"]),
                "stage differs from raw supervisor result")
        for stream in ("stdout", "stderr"):
            require(result[stream + "_sha256"] == retained.sha(raw[label + "/" + stream + ".log"]),
                    "stage output digest differs")
        require(type(result["returncode"]) is int and result["returncode"] == 0 and
                result["stage_process_complete"] is True and result["timed_out"] is False,
                "incomplete stage cannot become completed latency")
        begin = seconds(result["started_monotonic"])
        elapsed = seconds(result["wall_seconds"])
        end = begin + elapsed
        require(begin >= previous_end and end <= start + complete,
                "overlapping, reversed or out-of-window supervisor interval")
        require(result["completion_observed_before_deadline"] is True and
                end <= seconds(result["effective_deadline_monotonic"]),
                "stage completion missed its original deadline")
        spans.append({"stage": label, "start_seconds_from_controller": begin - start,
                      "end_seconds_from_controller": end - start,
                      "supervisor_wall_seconds": elapsed,
                      "preceding_controller_gap_seconds": begin - previous_end})
        previous_end = end
    verified_index = expected.index("fresh-process-strict-verification")
    require(spans[verified_index]["end_seconds_from_controller"] <= pipeline <=
            spans[verified_index + 1]["start_seconds_from_controller"],
            "verified receipt endpoint outside its actual stage boundary")
    pipeline_spans = spans[:verified_index + 1]
    segment_spans = [row for row in spans if row["stage"].startswith("prove-")]
    by_name = {row["stage"]: row for row in spans}
    segment_wall = math.fsum(row["supervisor_wall_seconds"] for row in segment_spans)
    compression_wall = by_name["complete-recursive-compression"]["supervisor_wall_seconds"]
    stage_wall = math.fsum(row["supervisor_wall_seconds"] for row in pipeline_spans)
    gap = pipeline - stage_wall
    require(gap >= 0, "stage sum exceeds enclosing pipeline")

    initial_prefix = events(raw, "reverify-existing-prefix")
    initial_budget = selected(initial_prefix, "SEGMENT_BUDGET_EXHAUSTED")
    require(len(initial_budget) == 1 and type(initial_budget[0]["verified_prefix"]) is int and
            initial_budget[0]["verified_prefix"] == 0 and
            not selected(initial_prefix, "CHECKPOINT_CRYPTOGRAPHICALLY_REVERIFIED"),
            "initial empty-prefix stage cannot become old-receipt verification")

    segment_prover_ns = segment_verifier_ns = prefix_verifier_ns = prefix_count = 0
    for index in range(SEGMENTS):
        rows = events(raw, f"prove-{index:04}")
        saved = selected(rows, "REAL_SEGMENT_STARK_SAVED_VERIFIED")
        require(len(saved) == 1 and type(saved[0]["index"]) is int and
                saved[0]["index"] == index and saved[0]["cryptographic_proof_complete"] is False,
                "missing, duplicate or mislabelled segment operation")
        prefix = selected(rows, "CHECKPOINT_CRYPTOGRAPHICALLY_REVERIFIED")
        require([row["index"] for row in prefix] == list(range(index)) and
                all(type(row["index"]) is int for row in prefix),
                "reverified prefix omitted, duplicated or reordered")
        prover = nanoseconds(saved[0]["prover_ns"])
        verifier = nanoseconds(saved[0]["verifier_ns"])
        prefix_ns = sum(nanoseconds(row["elapsed_ns"]) for row in prefix)
        require((prover + verifier + prefix_ns) / 1e9 <=
                segment_spans[index]["supervisor_wall_seconds"],
                "nested segment clocks exceed containing process")
        segment_prover_ns += prover
        segment_verifier_ns += verifier
        prefix_verifier_ns += prefix_ns
        prefix_count += len(prefix)

    compression_events = events(raw, "complete-recursive-compression")
    recursion = selected(compression_events, "REAL_RECURSIVE_STARK_SAVED_VERIFIED")
    expected_operations = [("lift", "lift-0000")]
    for index in range(1, SEGMENTS):
        expected_operations += [("lift", f"lift-{index:04}"),
                                ("join", f"join-through-{index:04}")]
    require([(row["operation"], row["name"]) for row in recursion] == expected_operations,
            "historical lift/left-fold join chain changed")
    require(all(row["eligible_as_final"] is False for row in recursion),
            "intermediate recursion receipt promoted to full proof")
    completed = selected(compression_events, "FULL_SUCCINCT_STARK_SAVED_VERIFIED")
    require(len(completed) == 1 and completed[0]["receipt_sha256"] == report["identity"]["receipt_sha256"]
            and completed[0]["work_id"] == report["identity"]["work_id"] and
            completed[0]["consensus_admission"] is False and
            type(completed[0]["proof_randomness_tickets"]) is int and
            completed[0]["proof_randomness_tickets"] == 0,
            "final recursive operation does not bind the observed full statement")
    recursive_loop = nanoseconds(completed[0]["compression_prover_ns"]) / 1e9
    operations = {}
    for operation in ("lift", "join"):
        rows = [row for row in recursion if row["operation"] == operation]
        operations[operation] = {
            "operations": len(rows),
            "prover_seconds": sum(nanoseconds(row["prover_ns"]) for row in rows) / 1e9,
            "verifier_seconds": sum(nanoseconds(row["verifier_ns"]) for row in rows) / 1e9,
        }
    nested_recursive = math.fsum(row["prover_seconds"] + row["verifier_seconds"]
                                 for row in operations.values())
    require(nested_recursive <= recursive_loop <= compression_wall,
            "recursive child clocks exceed enclosing clocks")
    exclusive = {
        "prepare_full_execution_seconds": by_name["prepare-full-execution"]["supervisor_wall_seconds"],
        "reverify_existing_prefix_seconds": by_name["reverify-existing-prefix"]["supervisor_wall_seconds"],
        "segment_stages_seconds": segment_wall,
        "recursive_compression_stage_seconds": compression_wall,
        "fresh_verifier_stage_seconds": by_name["fresh-process-strict-verification"]["supervisor_wall_seconds"],
        "controller_and_interstage_gaps_seconds": gap,
    }
    require(math.isclose(math.fsum(exclusive.values()), pipeline, rel_tol=1e-14),
            "exclusive phase ledger does not reconcile")
    return {
        "fresh_pipeline_seconds": pipeline,
        "fresh_pipeline_scope": report["fresh_proof_pipeline_scope"],
        "complete_controller_seconds": complete,
        "exclusive_pipeline_ledger": exclusive,
        "segment_share_of_pipeline": segment_wall / pipeline,
        "compression_share_of_pipeline": compression_wall / pipeline,
        "supervisor_spans": spans,
        "nested_clocks_not_additive_to_pipeline": {
            "scope": "Nested wall clocks within the exclusive ledger, not additional CPU or work trials.",
            "initial_prefix_stage_verified_receipts": 0,
            "segment_prover_seconds": segment_prover_ns / 1e9,
            "segment_verifier_seconds": segment_verifier_ns / 1e9,
            "repeated_prefix_verifications": prefix_count,
            "repeated_prefix_verifier_seconds": prefix_verifier_ns / 1e9,
            "segment_unattributed_remainder_seconds": segment_wall -
                (segment_prover_ns + segment_verifier_ns + prefix_verifier_ns) / 1e9,
            "recursive_operations": operations,
            "recursive_enclosing_clock_scope": "Starts before API client initialization; includes recursive loop, final claim check and Receipt construction. Not a pure cryptographic kernel clock.",
            "recursive_loop_seconds": recursive_loop,
            "recursive_loop_other_seconds": recursive_loop - nested_recursive,
            "compression_outside_recursive_loop_seconds": compression_wall - recursive_loop,
        },
        "fixed_other_stage_counterfactuals": {
            "scope": "Arithmetic only: set named observed intervals to zero and retain every other interval. Not a measured speedup, parallel schedule, hardware forecast or algorithmic lower bound.",
            "segment_stages_zero_remaining_seconds": pipeline - segment_wall,
            "compression_stage_zero_remaining_seconds": pipeline - compression_wall,
            "both_zero_remaining_seconds": pipeline - segment_wall - compression_wall,
        },
        "unmeasured": {key: None for key in UNMEASURED},
        "winner_to_receiver_complete_seconds": None,
        "prover_p99_seconds": None,
        "measured_stale_probability": None,
    }


def analyze(root=ROOT):
    disposition = retained.analyze(root)
    _, values = retained.pinned_inputs(root)
    report = retained.strict_json(values[retained.PROOF + "proof-result.json"])
    raw = retained.observation_files(values[retained.PROOF + "observation-3.tar.gz"],
                                    retained.strict_json(values[retained.PROOF + "raw-index.json"]))
    require(raw["result.json"] == values[retained.PROOF + "proof-result.json"],
            "raw report differs from retained report")
    return {
        "schema": SCHEMA,
        "disposition": "HOLD_NO_GO",
        "scope": "Exact-byte historical readback; zero new proof or mining trials.",
        "input_declaration_sha256": retained.MANIFEST_SHA256,
        "historical_prover_source_commit": disposition["historical_prover_source_commit"],
        "reader_sha256": retained.sha(Path(__file__).read_bytes()),
        "retained_disposition_reader_sha256": disposition["reader_sha256"],
        "historical_identity": disposition["identity"],
        "historical_attempts": disposition["retained_attempts"],
        "historical_cost_vetoes": {key: disposition[key] for key in (
            "native_median_ns", "transparent_median_ns", "transparent_to_native_median_ratio",
            "native_local_envelope_bytes", "transparent_local_envelope_bytes", "local_envelope_ratio")},
        "timing": decompose(report, raw),
        "gates": {
            "historical_fresh_on_demand_pipeline_four_second_necessary_screen": "FAIL",
            "winner_to_receiver_complete_latency": "INSUFFICIENT_DIRECT_EVIDENCE",
            "independent_prover_tail_distribution": "INSUFFICIENT_DIRECT_EVIDENCE",
            "async_task_proof_adapter": "NOT_IMPLEMENTED",
        },
        "original_confirmation_deadline_seconds": 4,
        "consensus_block_interval_changed": False,
        "new_proofs_generated": 0,
        "cryptographic_verification_performed_by_reader": False,
        "consensus_admission": False,
        "production_activation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.source_root)
        output = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.out:
            with args.out.open("x", encoding="utf-8") as target:
                target.write(output)
        else:
            print(output, end="")
    except (OSError, ValueError, KeyError, TypeError, retained.tarfile.TarError) as error:
        print(json.dumps({"schema": SCHEMA, "disposition": "INVALID_EVIDENCE",
                          "error": str(error), "production_activation": False}, allow_nan=False))
        return 2
    # Successful readback of a failed gate is not a successful performance gate.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
