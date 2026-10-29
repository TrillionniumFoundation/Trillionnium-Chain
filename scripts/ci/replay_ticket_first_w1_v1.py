#!/usr/bin/env python3
"""Fully replay retained ticket-first W1 statements with the existing Python oracle.

This optional offline entry leaves the original cost reader and its summaries
unchanged. Its input manifest names complete native captures and their original
source receipts. Every unique (task, challenge, full canonical prefix) is replayed
once, including all target misses and exhausted searches. Repeated observations
and identical input sets across captures share arithmetic, never host authority.
The offline deadline is cooperative: it does not preempt a blocking file read or
one in-progress scalar evaluation. An incomplete/failed receipt retains the
completed journal prefix and observed identities; it does not claim after-binding.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
import work_oracle
from check_ticket_first_cost_v1 import bound_capture, material, parsed, read_rows, require

SCHEMA = "pon-ticket-first-independent-w1-replay-v1"
INPUT_SCHEMA = "pon-ticket-first-independent-w1-input-v1"
DEADLINE_SECONDS = 300
MAX_DATASETS = 8
MAX_JOURNAL_LINE_BYTES = 16 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
REPETITIONS = 12  # Six original arms, each with fresh and reused setup.
UNIQUE_PARTITION = {"winning_trials": 655, "misses_before_winner": 688,
                    "exhausted_search_trials": 24}
OBSERVED_PARTITION = {key: count * REPETITIONS for key, count in UNIQUE_PARTITION.items()}
UNIQUE_INPUTS = sum(UNIQUE_PARTITION.values())
SOURCE_PATHS = (
    "scripts/ci/replay_ticket_first_w1_v1.py",
    "scripts/ci/check_ticket_first_cost_v1.py",
    "scripts/ci/check_legal_ticket_cost_v5.py",
    "scripts/ci/capture_pure_pon_campaign.py",
    "scripts/pon_w1_cost_matrix_reader.py",
    "scripts/read_original_native_campaign.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "config/pon/devnet-v1.json", "config/pon/ledger-v1.json",
    "config/pon/work-profile-v1.json", "config/pon/model-family-v1.json",
    "config/pon/evaluation-round-v1.json",
)


def identity(path, limit=None):
    require(path.is_file(), "input is not a regular file")
    size = path.stat().st_size
    require(limit is None or size <= limit, "input byte bound")
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            require(limit is None or count <= limit, "input grew beyond byte bound")
            digest.update(chunk)
    require(count == size == path.stat().st_size, "input size changed while hashing")
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


def source_identity():
    return {name: identity(ROOT / name)["sha256"] for name in SOURCE_PATHS}


def within(deadline):
    require(time.monotonic() < deadline, "independent replay deadline")


def decode_prefix(task, prefix):
    require(type(task) is bytes and len(task) == 32, "task length/type")
    require(type(prefix) is bytes and len(prefix) == work_oracle.PROOF_BYTES - 32
            and prefix[:4] == b"PNW1", "canonical full prefix framing")
    values = struct.unpack("<" + "I" * (3 * work_oracle.CELLS), prefix[4:])
    a, b, product = (list(values[i * work_oracle.CELLS:(i + 1) * work_oracle.CELLS])
                     for i in range(3))
    for matrix in (a, b, product):
        work_oracle.check(matrix)
    require(work_oracle.task_id(a, b) == task, "prefix task mismatch")
    return a, b, product


def input_key(task, challenge, prefix):
    require(type(task) is bytes and len(task) == 32 and
            type(challenge) is bytes and len(challenge) == 32, "exact W1 input identity")
    require(type(prefix) is bytes, "prefix bytes required")
    # Full bytes are part of the dictionary key, not just challenge or a digest.
    return task, challenge, prefix


def key_id(key):
    digest = hashlib.sha256(b"TRNM-TICKET-FIRST-INDEPENDENT-W1-INPUT-V1\0")
    for part in key:
        digest.update(len(part).to_bytes(4, "little"))
        digest.update(part)
    return digest.hexdigest()


def retain(records, key, trace, category, count=1):
    require(type(trace) is bytes and len(trace) == 32, "trace length/type")
    require(category in UNIQUE_PARTITION and type(count) is int and count > 0,
            "observation category/count")
    if key in records:
        require(records[key]["trace"] == trace and records[key]["category"] == category,
                "conflicting observation for exact task/challenge/prefix")
        records[key]["observations"] += count
    else:
        records[key] = {"trace": trace, "category": category, "observations": count}


def coverage(records):
    unique = Counter(row["category"] for row in records.values())
    observed = Counter()
    for row in records.values():
        require(row["observations"] == REPETITIONS, "each unique input needs all twelve paired observations")
        observed[row["category"]] += row["observations"]
    require(len(records) == UNIQUE_INPUTS and dict(unique) == UNIQUE_PARTITION and
            dict(observed) == OBSERVED_PARTITION, "complete frozen unique/miss/exhaustion coverage")
    return {"unique_inputs": len(records), "unique_partition": dict(unique),
            "observations": sum(observed.values()), "observed_partition": dict(observed),
            "repetitions_per_unique_input": REPETITIONS}


def parse_manifest(path):
    identity(path, 1024 * 1024)
    value = parsed(path.read_bytes())
    require(type(value) is dict and set(value) == {"schema", "datasets"}
            and value["schema"] == INPUT_SCHEMA, "input manifest schema/fields")
    datasets = value["datasets"]
    require(type(datasets) is list and 1 <= len(datasets) <= MAX_DATASETS, "bounded dataset roster")
    labels, captures, output = set(), set(), []
    for row in datasets:
        require(type(row) is dict and set(row) == {
            "label", "capture", "source_before", "source_after", "expected_head"}, "dataset fields")
        require(type(row["label"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", row["label"])
                and row["label"] not in labels, "unique bounded dataset label")
        require(type(row["expected_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", row["expected_head"]),
                "expected measured-source commit")
        labels.add(row["label"])
        spec = dict(row)
        for name in ("capture", "source_before", "source_after"):
            require(type(row[name]) is str and row[name], "input path")
            spec[name] = (path.parent / row[name]).resolve(strict=True)
        require(spec["capture"] not in captures, "same capture listed more than once")
        captures.add(spec["capture"])
        output.append(spec)
    return output


def dataset_identities(spec):
    return {name: identity(path, limit) for name, path, limit in (
        ("capture", spec["capture"], 1024 * 1024),
        ("source_before", spec["source_before"], 1024 * 1024),
        ("source_after", spec["source_after"], 1024 * 1024),
        ("raw_gzip", spec["capture"].parent / "stdout.jsonl.gz", 64 * 1024 * 1024),
        ("journal", spec["capture"].parent / "stderr.log", 64 * 1024 * 1024))}


def collect_dataset(spec, before):
    # The original acceptance path still checks all source/capture/nonce/ticket/
    # full-stream/cold-packet/journal fields before this additional arithmetic.
    summary = bound_capture(spec["capture"], spec["expected_head"],
                            spec["source_before"], spec["source_after"])
    rows, _, raw_sha = read_rows(spec["capture"].parent / "stdout.jsonl.gz")
    require(raw_sha == summary["raw_uncompressed_sha256"], "raw changed between validation and replay indexing")
    _, _, task, prefix = material("continuity-maintenance-v1")
    decode_prefix(task, prefix)
    prefix_sha = hashlib.sha256(prefix).hexdigest()
    records = {}
    for row in rows[1:-1]:
        require(bytes.fromhex(row["task"]) == task and row["proof_prefix_sha256"] == prefix_sha,
                "every cohort uses the canonical complete maintenance prefix")
        for search in row["searches"]:
            for trial in search["trials"]:
                category = ("winning_trials" if trial["target_hit"] else
                            "misses_before_winner" if search["won"] else "exhausted_search_trials")
                retain(records, input_key(task, bytes.fromhex(trial["challenge"]), prefix),
                       bytes.fromhex(trial["trace"]), category)
    counts = coverage(records)
    require(summary["attempts_including_paired_repetitions"] == counts["observations"] and
            summary["first_admission_calls"] == counts["observed_partition"]["winning_trials"] and
            sum(row["exhausted"] for row in summary["groups"]) == 36,
            "complete native denominators retained")
    return records, {"label": spec["label"], "measured_source": summary["source"],
        "machine_claim": summary["native_capture"]["machine"], "input_files_before": before,
        "raw_uncompressed_sha256": raw_sha, "old_reader_complete_validation_passed": True,
        "journal_events": summary["journal"]["events"], **counts}


def replay_inputs(records, observe, state, deadline):
    decoded = {}
    for ordinal, (key, row) in enumerate(records.items()):
        within(deadline)
        task, challenge, prefix = key
        current = {"ordinal": ordinal, "input_id": key_id(key), "task": task.hex(),
                   "challenge": challenge.hex(), "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                   "expected_trace": row["trace"].hex(), "category": row["category"]}
        state["inflight_input"] = current
        observe({"kind": "input-start", **current})
        preparation_key = (task, prefix)
        if preparation_key not in decoded:
            decoded[preparation_key] = decode_prefix(task, prefix)
        a, b, expected_product = decoded[preparation_key]
        start = time.monotonic_ns()
        state["arithmetic_evaluations_started"] += 1
        # Do NOT call verify(): its target precheck would reject every miss
        # before evaluating W1. evaluate() replays all noise, 512 tiles and the
        # product correction for both hits and misses, without changing it.
        product, trace = work_oracle.evaluate(challenge, a, b)
        elapsed = time.monotonic_ns() - start
        state["arithmetic_evaluations_returned"] += 1
        result = {"kind": "input-result", **current, "actual_trace": trace.hex(),
                  "trace_matches": trace == row["trace"], "product_matches": product == expected_product,
                  "offline_replay_elapsed_ns": elapsed,
                  "canonical_proof_sha256": hashlib.sha256(prefix + trace).hexdigest()}
        observe(result)
        require(result["trace_matches"], "independent W1 TRACE_MISMATCH: " + current["input_id"])
        require(result["product_matches"], "independent W1 PRODUCT_MISMATCH: " + current["input_id"])
        state["inputs_verified"] += 1
        state["verified_partition"][row["category"]] += 1
        state["inflight_input"] = None
    within(deadline)


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    require(len(raw) <= MAX_RECEIPT_BYTES, "offline receipt output byte bound")
    path.write_bytes(raw)


def journal_record(stream, value, used):
    raw = (json.dumps({**value, "schema": SCHEMA}, sort_keys=True) + "\n").encode("utf-8")
    require(len(raw) <= MAX_JOURNAL_LINE_BYTES, "offline journal line byte bound")
    # A nonterminal observation cannot consume the final failure-record reserve.
    limit = MAX_JOURNAL_BYTES if value.get("kind") == "terminal" else MAX_JOURNAL_BYTES - MAX_JOURNAL_LINE_BYTES
    require(used + len(raw) <= limit, "offline journal total byte bound")
    stream.write(raw)
    stream.flush()
    return used + len(raw)


def run(manifest_path, output):
    # Never replace evidence from an earlier pass, failure or interruption.
    output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    deadline = time.monotonic() + DEADLINE_SECONDS
    state = {"arithmetic_evaluations_started": 0, "arithmetic_evaluations_returned": 0,
             "inputs_verified": 0, "verified_partition": dict.fromkeys(UNIQUE_PARTITION, 0),
             "inflight_input": None}
    result = {"schema": SCHEMA, "status": "incomplete", "complete": False,
        "frozen_unique_inputs_per_dataset": UNIQUE_INPUTS, "frozen_unique_partition": UNIQUE_PARTITION,
        "repetition_policy": "full task + challenge + full canonical prefix bytes; each input computed once",
        "offline_deadline_seconds": DEADLINE_SECONDS, "deadline_is_cooperative": True,
        "output_byte_limits": {"journal_line": MAX_JOURNAL_LINE_BYTES,
            "journal_total": MAX_JOURNAL_BYTES, "receipt": MAX_RECEIPT_BYTES},
        "blocking_io_or_one_evaluation_preempted": False,
        "source_and_input_after_binding_complete": False, "datasets": [], "replay": state,
        "boundaries": {"native_cost_summary_changed": False, "fresh_native_execution": False,
            "independent_host_executions": False, "physical_execution_authenticated": False,
            "native_miner_cost_remeasured": False, "work_hardness_qualified": False,
            "global_minimum_proved": False, "public_fairness_qualified": False,
            "throughput_qualified": False, "quantum_cost_bound": False, "production_qualified": False},
        "scope": "Independent existing scalar Python arithmetic over recorded complete W1 inputs, including misses. Trace equality is mathematical statement evidence, not evidence of when/how recorded native work was executed. Offline timings are not mining costs."}
    write_json(output / "receipt.json", result)
    success = False
    with (output / "replay.jsonl").open("xb") as journal:
        journal_bytes = 0
        def observe(value):
            nonlocal journal_bytes
            journal_bytes = journal_record(journal, value, journal_bytes)
        try:
            require(os.environ.get("TRNM_PON_EVALUATION_POLICY", "legacy-first-two-v3") == "legacy-first-two-v3",
                    "original offline wire context required")
            within(deadline)
            source_before = source_identity()
            result["reader_and_oracle_source_sha256_before"] = source_before
            within(deadline)
            manifest_before = identity(manifest_path, 1024 * 1024)
            result["input_manifest_before"] = manifest_before
            specs = parse_manifest(manifest_path)
            within(deadline)
            all_files = []
            for spec in specs:
                within(deadline)
                all_files.append(dataset_identities(spec))
                within(deadline)
            raw_ids, records, key_set = set(), {}, None
            for spec, files in zip(specs, all_files):
                within(deadline)
                require(files["raw_gzip"]["sha256"] not in raw_ids, "duplicate raw capture bytes in dataset roster")
                raw_ids.add(files["raw_gzip"]["sha256"])
                local, report = collect_dataset(spec, files)
                within(deadline)
                require(key_set is None or key_set == set(local), "captures do not share the exact complete input set")
                key_set = set(local)
                for key, row in local.items():
                    retain(records, key, row["trace"], row["category"], row["observations"])
                result["datasets"].append(report)
                observe({"kind": "dataset-validated", "label": spec["label"],
                         "unique_inputs": len(local), "observations": report["observations"]})
                within(deadline)
            result["datasets_share_one_complete_input_set"] = True
            result["arithmetic_evaluations_planned"] = len(records)
            result["raw_observations_covered_if_complete"] = sum(row["observations"] for row in records.values())
            result["duplicate_arithmetic_evaluations_avoided"] = result["raw_observations_covered_if_complete"] - len(records)
            replay_inputs(records, observe, state, deadline)
            require(state["inputs_verified"] == UNIQUE_INPUTS and state["verified_partition"] == UNIQUE_PARTITION,
                    "complete independent replay coverage")
            after_files = []
            for spec in specs:
                within(deadline)
                after_files.append(dataset_identities(spec))
                within(deadline)
            source_after = source_identity()
            within(deadline)
            manifest_after = identity(manifest_path, 1024 * 1024)
            within(deadline)
            result.update(reader_and_oracle_source_sha256_after=source_after,
                          input_manifest_after=manifest_after)
            for report, after in zip(result["datasets"], after_files):
                report["input_files_after"] = after
            require(all_files == after_files and manifest_before == manifest_after,
                    "input evidence changed during offline replay")
            require(source_before == source_after, "reader/oracle source changed during replay")
            within(deadline)
            result.update(status="complete", complete=True, all_observed_w1_statements_replayed=True,
                          source_and_input_after_binding_complete=True)
            success = True
        except Exception as error:
            result.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
            print("independent W1 replay failed: " + str(error), file=sys.stderr)
        result["offline_processing_elapsed_ns"] = time.monotonic_ns() - start
        observe({"kind": "terminal", "status": result["status"], "complete": result["complete"],
                 "replay": state, "error": result.get("error")})
    result["replay_journal"] = identity(output / "replay.jsonl")
    write_json(output / "receipt.json", result)
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new directory; existing evidence is never replaced")
    args = parser.parse_args()
    return run(args.input_manifest.resolve(), args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
