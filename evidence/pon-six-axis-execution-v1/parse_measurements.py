#!/usr/bin/env python3
"""Create-only analysis of the pre-registered local six-axis observations.

This helper never runs Rust or a benchmark. Raw logs/journals remain authoritative;
missing, failed, duplicate and malformed attempts make completeness fail closed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys


PLAN_SHA256 = "e2714a9b9976bfb83658af5e8aab7efa2d16017c7a726d68042ed1cc8342efeb"
DEFAULT_REPO = Path(__file__).resolve().parents[2]
PREFIX_SCHEMA = "account-prefix-parser-cost-v1"
PREFIX_COHORTS = [(8, 0), (8, 64), (8, 4096), (8, 65528), (4096, 64)]
ARMS = ["original_full_scan", "account_prefix_range", "account_prefix_range", "original_full_scan"]
GROWTH_COHORTS = [(a, h) for a in (64, 1024, 16384) for h in (0, 16, 128)]
GROWTH_EVENTS = {
    "run_started", "run_completed", "cohort_started", "warmup_started", "warmup_completed",
    "measurement_started", "measurement_completed", "native_stage_returned",
    "atomic_cancellation_started", "atomic_cancellation_completed", "cold_reopen_started",
    "cohort_completed",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key: " + key)
        out[key] = value
    return out


def strict_json(text):
    def reject_constant(value):
        raise ValueError("non-finite JSON number: " + value)
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def digest(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


class Analysis:
    def __init__(self, args):
        self.args = args
        self.issues = []
        self.inputs = {}
        self.plan = self.json_file(args.plan, "plan")
        self.check(self.inputs.get("plan", {}).get("sha256") == PLAN_SHA256, "plan_hash", "plan")
        self.check(self.plan.get("schema") == "pon-six-axis-local-measurement-plan-v1", "plan_schema", "plan")
        self.receipt = self.json_file(args.receipt, "runner_receipt")
        self.log = self.read(args.log, "runner_log")
        self.log_text = self.decode(self.log, "runner_log")
        self.check(self.receipt.get("returncode") == 0 and type(self.receipt.get("returncode")) is int,
                   "runner_did_not_return_success", "runner_receipt")
        self.check(self.receipt.get("timed_out") is False, "runner_timeout_or_unfinished", "runner_receipt")
        self.check(self.receipt.get("log_sha256") == sha256(self.log), "runner_log_hash", "runner_receipt")
        recorded_log = self.receipt.get("log")
        self.check(isinstance(recorded_log, str) and Path(recorded_log).resolve() == args.log.resolve(),
                   "runner_log_path", "runner_receipt")
        self.check(len(re.findall(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", self.log_text)) == 1,
                   "single_successful_rust_test_summary_missing_or_duplicated", "runner_log")
        source = args.repo / "trillionnium/crates/trnm-pon-node/src/account_archive_prototype.rs"
        candidate = self.read(source, "current_candidate_parser")
        component = self.plan.get("parser_component")
        self.check(isinstance(component, dict), "parser_component_plan_object", "plan")
        component = component if isinstance(component, dict) else {}
        self.check(sha256(candidate) == component.get("candidate_source_sha256"),
                   "current_candidate_source_differs_from_registered_plan", str(source))

    def check(self, condition, code, where, **detail):
        if not condition:
            self.issues.append({"code": code, "where": str(where), **detail})
        return bool(condition)

    def read(self, path, label):
        try:
            data = Path(path).read_bytes()
        except OSError as error:
            self.check(False, "input_unreadable", path, error=str(error))
            self.inputs[label] = {"path": str(Path(path).resolve()), "readable": False}
            return b""
        self.inputs[label] = {"path": str(Path(path).resolve()), "readable": True,
                              "bytes": len(data), "sha256": sha256(data)}
        return data

    def decode(self, data, where):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as error:
            self.check(False, "invalid_utf8", where, error=str(error))
            return data.decode("utf-8", errors="replace")

    def json_file(self, path, label):
        try:
            value = strict_json(self.decode(self.read(path, label), path))
            if not isinstance(value, dict):
                raise ValueError("expected JSON object")
            return value
        except ValueError as error:
            self.check(False, "invalid_json_document", path, error=str(error))
            return {}

    def jsonl(self, path, label):
        rows = []
        for number, line in enumerate(self.decode(self.read(path, label), path).splitlines(), 1):
            try:
                row = strict_json(line)
                if not isinstance(row, dict):
                    raise ValueError("expected JSON object")
                rows.append(row)
            except ValueError as error:
                self.check(False, "invalid_jsonl_record", f"{path}:{number}", error=str(error))
        return rows

    def log_rows(self, kind):
        rows = []
        for number, line in enumerate(self.log_text.splitlines(), 1):
            at = line.find("{")
            if at < 0:
                continue
            try:
                row = strict_json(line[at:])
            except ValueError as error:
                if (kind == "prefix" and PREFIX_SCHEMA in line) or (
                    kind == "growth" and any('"' + event + '"' in line for event in GROWTH_EVENTS)
                ):
                    self.check(False, "malformed_target_log_record", f"log:{number}", error=str(error))
                continue
            if not isinstance(row, dict):
                continue
            if (kind == "prefix" and row.get("schema") == PREFIX_SCHEMA) or (
                kind == "growth" and row.get("event") in GROWTH_EVENTS
            ):
                rows.append((number, row))
        return rows

    def one(self, rows, event, where):
        found = [row for row in rows if row.get("event") == event]
        self.check(len(found) == 1, "expected_one_event", where, event=event, actual=len(found))
        return found[0] if len(found) == 1 else None

    def base(self, kind):
        return {
            "schema": "pon-six-axis-local-analysis-v1", "measurement": kind,
            "registered_plan_sha256": PLAN_SHA256, "inputs": self.inputs,
            "runner_returncode": self.receipt.get("returncode"),
            "runner_recorded_source_paths_sha256": self.receipt.get("source_paths_sha256"),
            "binary_build_provenance_verified_by_this_helper": False,
            "raw_inputs_retained": True, "discarded_attempts": 0,
            "outlier_exclusion": False, "fastest_arm_selection": False,
            "p99_ns": None, "p99_qualified": False, "public_service_qualified": False,
            "whole_request_speedup_claim": False, "production_activation": False,
        }


def fixture_digest(accounts, working):
    state = {f"account:{i:064x}": {"balance": i, "nonce": (1 << 64) - 1 - i} for i in range(accounts)}
    state.update({f"{'a:' if i % 2 == 0 else 'z:'}{i:08}": None for i in range(working)})
    data = json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    tag = b"account-prefix-cost-input-v1"
    framed = b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag + len(data).to_bytes(4, "little") + data
    return sha256(framed)


def prefix(a):
    a.read(a.args.repo / "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/account_prefix_tests.rs",
           "current_prefix_measurement_test")
    spec = a.plan.get("parser_component", {})
    a.check(spec.get("cohorts_account_rows_working_rows") == [list(c) for c in PREFIX_COHORTS]
            and spec.get("rounds_per_cohort") == 16 and spec.get("calls_per_sample") == 8
            and spec.get("arm_order") == "ABBA" and spec.get("planned_completed_samples") == 320,
            "registered_prefix_shape", "plan")
    rows = a.log_rows("prefix")
    counts = Counter(row.get("event") for _, row in rows)
    campaign = a.one([row for _, row in rows], "campaign_started", "prefix campaign")
    if campaign is not None:
        a.check(campaign.get("cohorts") == [list(c) for c in PREFIX_COHORTS]
                and campaign.get("rounds") == 16 and campaign.get("iterations_per_sample") == 8
                and campaign.get("order") == "ABBA" and campaign.get("public_service_qualified") is False,
                "campaign_shape_or_scope", "campaign_started")
    expected_digests = {cohort: fixture_digest(*cohort) for cohort in PREFIX_COHORTS}
    by_event = {"sample_started": {}, "sample_completed": {}}
    observed_order = []
    for line, row in rows:
        event = row.get("event")
        if event == "campaign_started":
            observed_order.append((event,))
            continue
        if not a.check(event in by_event, "unknown_prefix_event", f"log:{line}", event=event):
            continue
        values = [row.get(field) for field in ("account_rows", "working_rows", "round", "position")]
        if not a.check(all(integer(v) for v in values), "sample_identity_types", f"log:{line}"):
            continue
        key = tuple(values)
        accounts, working, round_number, position = key
        observed_order.append((event, *key))
        by_event[event].setdefault(key, []).append((line, row))
        if not a.check((accounts, working) in PREFIX_COHORTS and round_number < 16 and position < 4,
                       "unplanned_sample", f"log:{line}", identity=values):
            continue
        a.check(row.get("arm") == ARMS[position], "abba_arm", f"log:{line}")
        a.check(row.get("input_digest") == expected_digests[(accounts, working)],
                "independently_rebuilt_fixture_digest", f"log:{line}")
        if event == "sample_completed":
            a.check(type(row.get("iterations")) is int and row["iterations"] == 8
                    and type(row.get("parser_calls")) is int and row["parser_calls"] == 8,
                    "iterations_or_parser_calls", f"log:{line}")
            expected_rows = 8 * (accounts + working if position in (0, 3) else accounts)
            a.check(type(row.get("visited_rows")) is int and row["visited_rows"] == expected_rows,
                    "visited_rows", f"log:{line}", expected=expected_rows, actual=row.get("visited_rows"))
            a.check(integer(row.get("elapsed_ns"), 1), "positive_elapsed_ns", f"log:{line}")
    expected_order = [("campaign_started",)]
    for accounts, working in PREFIX_COHORTS:
        for r in range(16):
            for p in range(4):
                expected_order.extend([(event, accounts, working, r, p) for event in by_event])
    a.check(observed_order == expected_order, "exact_campaign_and_abba_event_order", "runner_log",
            actual_events=len(observed_order), expected_events=len(expected_order))
    cohort_rows, missing, ratios = [], [], {}
    for accounts, working in PREFIX_COHORTS:
        round_ratios = []
        started_count = completed_count = calls = 0
        for r in range(16):
            elapsed = []
            for p in range(4):
                key = (accounts, working, r, p)
                starts = by_event["sample_started"].get(key, [])
                ends = by_event["sample_completed"].get(key, [])
                started_count += len(starts)
                completed_count += len(ends)
                calls += sum(row.get("parser_calls", 0) for _, row in ends if integer(row.get("parser_calls")))
                if len(starts) != 1 or len(ends) != 1:
                    missing.append({"identity": list(key), "started": len(starts), "completed": len(ends)})
                    a.check(False, "missing_or_duplicate_sample", str(key), started=len(starts), completed=len(ends))
                    elapsed.append(None)
                    continue
                start, end = starts[0][1], ends[0][1]
                identity = ("account_rows", "working_rows", "round", "position", "arm", "input_digest")
                a.check(all(start.get(field) == end.get(field) for field in identity), "start_return_identity", str(key))
                elapsed.append(end.get("elapsed_ns") if integer(end.get("elapsed_ns"), 1) else None)
            round_ratios.append(Fraction(elapsed[1] + elapsed[2], elapsed[0] + elapsed[3])
                                if all(value is not None for value in elapsed) else None)
        median = statistics.median(round_ratios) if all(ratio is not None for ratio in round_ratios) else None
        ratios[(accounts, working)] = median
        cohort_rows.append({
            "account_rows": accounts, "working_rows": working, "input_digest": expected_digests[(accounts, working)],
            "samples_started": started_count, "samples_completed": completed_count, "recorded_parser_calls": calls,
            "round_ratios_B_mean_over_A_mean": [float(ratio) if ratio is not None else None for ratio in round_ratios],
            "median_of_16_round_ratios": float(median) if median is not None else None,
            "maximum_allowed_median_ratio": 0.5 if (accounts, working) == (8, 65528) else 1.1,
            "ratio_gate_pass": median is not None and median <= (Fraction(1, 2) if (accounts, working) == (8, 65528) else Fraction(11, 10)),
        })
    integrity = not a.issues
    ratio_gate = all(row["ratio_gate_pass"] for row in cohort_rows)
    out = a.base("account_prefix_parser_component")
    out.update({
        "expected": {"cohorts": 5, "rounds_per_cohort": 16, "samples_started": 320, "samples_completed": 320,
                     "calls_per_sample": 8, "total_parser_calls": 2560},
        "retained_event_counts": dict(counts), "cohorts": cohort_rows,
        "missing_or_duplicate_sample_identities": missing,
        "data_integrity_complete": integrity, "ratio_gate_pass": ratio_gate,
        "component_gate_pass": integrity and ratio_gate,
        "calculation": "For every registered round, (B1+B2)/(A1+A2); median of all 16 ratios. Exact rational comparisons against 11/10 and 1/2. No exclusions.",
        "scope": "Instrumented parser plus returned-map drop; not Node, ordinary-binary CPU, RSS, full W1, roots, durable commit, response, client import or independent confirmation.",
        "separate_correctness_suite_required_for_malformed_inputs": True,
        "issues": a.issues,
    })
    return out, out["component_gate_pass"]


def stage_contract(a, row, where, parent_height=None):
    stage = row.get("native_stage")
    if not a.check(isinstance(stage, dict), "native_stage_object", where):
        return
    a.check(integer(stage.get("wall_ns"), 1), "stage_wall_ns", where)
    a.check(stage.get("thread_cpu_ns") is None and stage.get("process_cpu_ns") is None,
            "wall_only_stage_scope", where)
    a.check(integer(row.get("sql_total_changes")), "sql_total_changes", where)
    if parent_height is not None:
        counters = stage.get("checkpoints", {})
        a.check(counters.get("header_ancestors") == 3 * min(parent_height, 16), "bounded_header_window", where)
    before, commit, wall = (stage.get(name) for name in ("before_persistence_offset_ns", "before_commit_offset_ns", "wall_ns"))
    if before is not None:
        a.check(integer(before, 1) and integer(commit, 1) and before <= commit <= wall,
                "persistence_offsets_order", where)
        if all(integer(value) for value in (before, commit, wall)):
            a.check(stage.get("persistence_and_readback_wall_ns") == commit - before,
                    "persistence_nested_interval", where)
    if commit is not None and integer(commit, 1) and integer(wall):
        a.check(commit <= wall and stage.get("before_commit_to_return_wall_ns") == wall - commit,
                "commit_to_return_nested_interval", where)


def distribution(values):
    return {"count": len(values), "minimum_ns": min(values) if values else None,
            "median_ns": statistics.median(values) if values else None,
            "maximum_ns": max(values) if values else None, "p99_ns": None}


def growth(a):
    a.read(a.args.repo / "trillionnium/crates/trnm-pon-node/src/store/growth/tests/scale_observation.rs",
           "current_growth_measurement_test")
    spec = a.plan.get("fixed_touched_set_native_matrix", {})
    a.check(spec.get("account_counts") == [64, 1024, 16384] and spec.get("warmup_history_blocks") == [0, 16, 128]
            and spec.get("measured_blocks_per_cohort") == 8 and spec.get("workers") == 1,
            "registered_growth_shape", "plan")
    directory = a.args.directory
    run_rows = a.jsonl(directory / "run.jsonl", "growth_run")
    start = a.one(run_rows, "run_started", "run.jsonl")
    end = a.one(run_rows, "run_completed", "run.jsonl")
    a.check([row.get("event") for row in run_rows] == ["run_started", "run_completed"], "run_event_order", "run.jsonl")
    if start:
        a.check(start.get("schema") == "native-growth-fixed-owner-scale-observation-v3"
                and start.get("accounts") == [64, 1024, 16384] and start.get("warmup_history_blocks") == [0, 16, 128]
                and start.get("measured_blocks_per_cohort") == 8 and start.get("workers") == 1
                and start.get("work_search_attempt_limit") == 4096
                and start.get("p99_ns") is None and start.get("wall_time_acceptance_gate") is False,
                "run_shape_or_scope", "run_started")
    expected_names = {f"cohort-a{accounts}-h{history}.jsonl" for accounts, history in GROWTH_COHORTS}
    actual_names = {path.name for path in directory.glob("cohort-*.jsonl")}
    a.check(actual_names == expected_names, "cohort_files", directory,
            missing=sorted(expected_names - actual_names), unexpected=sorted(actual_names - expected_names))
    unexpected_journals = {}
    for name in sorted(actual_names - expected_names):
        records = a.jsonl(directory / name, "unexpected:" + name)
        unexpected_journals[name] = {"retained_records": len(records), "records": records}
    aggregate = Counter()
    cohorts, failed_returns, owner_sets = [], [], set()
    journal_sequence = [start] if start else []
    for accounts, history in GROWTH_COHORTS:
        name = f"cohort-a{accounts}-h{history}.jsonl"
        rows = a.jsonl(directory / name, name)
        journal_sequence.extend(rows)
        counts = Counter(row.get("event") for row in rows)
        aggregate.update(counts)
        for index, row in enumerate(rows):
            for field in ("accounts", "warmup_history_blocks", "planned_measurements", "index", "sample",
                          "history_blocks_before", "history_blocks_after", "measured_blocks", "returned_native_stages"):
                if field in row and not (field == "sample" and row[field] is None):
                    a.check(integer(row[field]), "nonnegative_integer_field", f"{name}:record={index}", field=field)
        cstart = a.one(rows, "cohort_started", name)
        warm = a.one(rows, "warmup_completed", name)
        cend = a.one(rows, "cohort_completed", name)
        if cstart:
            a.check(cstart.get("accounts") == accounts and cstart.get("warmup_history_blocks") == history
                    and cstart.get("planned_measurements") == 8, "cohort_identity", name)
        expected_events = ["cohort_started"] + ["warmup_started"] * history + ["warmup_completed"]
        expected_events += [event for _ in range(8) for event in ("measurement_started", "native_stage_returned", "native_stage_returned", "measurement_completed")]
        expected_events += ["atomic_cancellation_started", "native_stage_returned", "atomic_cancellation_completed", "cold_reopen_started", "cohort_completed"]
        a.check([row.get("event") for row in rows] == expected_events, "cohort_event_order_or_missing_attempt", name)
        a.check([row.get("index") for row in rows if row.get("event") == "warmup_started"] == list(range(history)),
                "warmup_attempt_indices", name)
        admission, activation, construction = [], [], []
        prior = warm.get("genesis") if warm and history == 0 else None
        for sample in range(8):
            selected = [row for row in rows if row.get("sample") == sample]
            began = a.one(selected, "measurement_started", f"{name}:sample={sample}")
            completed = a.one(selected, "measurement_completed", f"{name}:sample={sample}")
            stages = [row for row in selected if row.get("event") == "native_stage_returned"]
            a.check([row.get("operation") for row in stages] == ["admission", "activation"], "measurement_stage_order", f"{name}:sample={sample}")
            if began:
                a.check(digest(began.get("parent")) and began.get("history_blocks_before") == history + sample,
                        "measurement_start_identity", f"{name}:sample={sample}")
                if prior is not None:
                    a.check(began.get("parent") == prior, "measured_parent_chain", f"{name}:sample={sample}")
            for stage in stages:
                where = f"{name}:sample={sample}:{stage.get('operation')}"
                stage_contract(a, stage, where, history + sample if stage.get("operation") == "admission" else None)
                a.check(stage.get("schema") == "native-growth-stage-return-v1" and stage.get("purpose") == "measurement"
                        and stage.get("accepted") is True and stage.get("error") is None and stage.get("error_code") is None
                        and digest(stage.get("block")) and stage.get("returned_block") == stage.get("block"), "successful_stage_identity", where)
                if began:
                    a.check(stage.get("parent") == began.get("parent"), "stage_parent_identity", where)
                if completed:
                    op = stage.get("operation")
                    a.check(stage.get("block") == completed.get("block")
                            and stage.get("native_stage") == completed.get("native_" + str(op))
                            and stage.get("sql_total_changes") == completed.get(str(op) + "_sql_total_changes"),
                            "stage_return_matches_completed_measurement", where)
            if completed:
                a.check(completed.get("accounts") == accounts and completed.get("history_blocks_before") == history + sample
                        and completed.get("history_blocks_after") == history + sample + 1
                        and completed.get("complete_state_reference_equal") is True and completed.get("p99_ns") is None,
                        "completed_measurement_identity_or_reference", f"{name}:sample={sample}")
                owners = completed.get("actual_witness_owners")
                if a.check(isinstance(owners, list) and all(digest(owner) for owner in owners), "witness_owners", name):
                    a.check(owners == sorted(set(owners)) and completed.get("actual_witness_accounts") == len(owners), "witness_owner_count", name)
                    owner_sets.add(tuple(owners))
                before, after = completed.get("sql_rows_before", {}), completed.get("sql_rows_after", {})
                for table in ("blocks", "growth_states", "events"):
                    a.check(integer(before.get(table)) and integer(after.get(table)) and after[table] == before[table] + 1,
                            "successful_sql_row_delta", f"{name}:sample={sample}", table=table)
                for dest, value in ((admission, completed.get("native_admission", {}).get("wall_ns")),
                                    (activation, completed.get("native_activation", {}).get("wall_ns")),
                                    (construction, completed.get("make_signed_packet_and_full_work_wall_ns"))):
                    if a.check(integer(value, 1), "completed_wall_ns", f"{name}:sample={sample}"):
                        dest.append(value)
                prior = completed.get("block")
        cancelled_start = a.one(rows, "atomic_cancellation_started", name)
        cancelled_end = a.one(rows, "atomic_cancellation_completed", name)
        cancelled = [row for row in rows if row.get("event") == "native_stage_returned" and row.get("purpose") == "atomic_cancellation"]
        a.check(len(cancelled) == 1, "one_cancelled_return_per_cohort", name, actual=len(cancelled))
        if len(cancelled) == 1:
            record = cancelled[0]
            stage_contract(a, record, name + ":cancelled", history + 8)
            a.check(record.get("schema") == "native-growth-stage-return-v1" and record.get("sample") is None
                    and record.get("operation") == "admission" and record.get("accepted") is False
                    and record.get("returned_block") is None and record.get("error") == "SCALE_OBSERVATION_BEFORE_COMMIT_CANCEL",
                    "expected_cancelled_return", name)
            if cancelled_start:
                a.check(record.get("parent") == cancelled_start.get("parent") == prior, "cancellation_parent", name)
            if cancelled_end:
                a.check(cancelled_end.get("all_sql_rows_equal") is True and cancelled_end.get("active_generation_equal") is True
                        and cancelled_end.get("error") == record.get("error")
                        and cancelled_end.get("native_admission") == record.get("native_stage")
                        and cancelled_end.get("admission_sql_total_changes") == record.get("sql_total_changes"), "cancelled_return_and_rollback", name)
        for record in rows:
            if record.get("event") == "native_stage_returned" and record.get("accepted") is not True:
                failed_returns.append({"cohort": [accounts, history], "record": record})
        if cend:
            a.check(cend.get("accounts") == accounts and cend.get("warmup_history_blocks") == history
                    and cend.get("measured_blocks") == 8 and cend.get("successful_native_admissions") == history + 8
                    and cend.get("returned_native_stages") == 17 and cend.get("deliberately_cancelled_admissions") == 1
                    and cend.get("failed_unexpected_admissions") == 0 and cend.get("cold_reopens") == 1
                    and cend.get("cold_complete_reference_equal") is True and cend.get("production_qualified") is False
                    and cend.get("p99_ns") is None, "cohort_completion_contract", name)
            if len(admission) == 8:
                ordered = sorted(admission)
                a.check(cend.get("admission_median_interval_ns") == ordered[3:5]
                        and cend.get("admission_max_ns") == ordered[-1], "reported_median_interval_and_max", name)
            journal = cend.get("separate_post_open_journal_differential", {})
            a.check(journal.get("typed_events") == history + 8 and journal.get("semantic_events") == history + 8,
                    "cold_journal_counts", name)
        cohorts.append({"accounts": accounts, "warmup_history_blocks": history, "retained_event_counts": dict(counts),
                        "admission_wall": distribution(admission), "activation_wall": distribution(activation),
                        "packet_and_full_work_wall": distribution(construction),
                        "cancelled_admission_wall_ns": cancelled[0].get("native_stage", {}).get("wall_ns") if len(cancelled) == 1 else None,
                        "cold_reopen_wall_ns": cend.get("cold_reopen_wall_ns") if cend else None})
    if end:
        journal_sequence.append(end)
        a.check(end.get("completed_cohorts") == 9 and end.get("completed_measurements") == 72
                and end.get("returned_native_stages") == 153 and end.get("fixed_witness_owner_set_observed") is True
                and end.get("p99_ns") is None and end.get("throughput_claim") is False and end.get("production_qualified") is False,
                "run_completion_contract", "run_completed")
        a.check(end.get("actual_distinct_witness_owner_sets") == [list(owners) for owners in sorted(owner_sets)],
                "run_witness_owner_sets", "run_completed")
    a.check(len(owner_sets) == 1, "fixed_actual_witness_owner_set", "all cohorts", actual=len(owner_sets))
    log_records = [row for _, row in a.log_rows("growth")]
    a.check(log_records == journal_sequence, "stdout_matches_all_flushed_journal_records_in_order", "runner_log",
            log_records=len(log_records), journal_records=len(journal_sequence))
    expected_counts = {"cohort_started": 9, "cohort_completed": 9, "measurement_started": 72,
                       "measurement_completed": 72, "atomic_cancellation_started": 9,
                       "atomic_cancellation_completed": 9, "native_stage_returned": 153,
                       "cold_reopen_started": 9, "warmup_started": 432, "warmup_completed": 9}
    for event, expected in expected_counts.items():
        a.check(aggregate[event] == expected, "total_event_count", event, expected=expected, actual=aggregate[event])
    out = a.base("fixed_touched_set_native_account_history_matrix")
    out.update({"expected_retained_event_counts": expected_counts, "retained_event_counts": dict(aggregate),
                "cohorts": cohorts, "retained_failed_or_cancelled_native_returns": failed_returns,
                "unexpected_journals_retained": unexpected_journals,
                "actual_distinct_witness_owner_sets": [list(owners) for owners in sorted(owner_sets)],
                "correctness_observation_complete": not a.issues, "latency_acceptance_gate": False,
                "original_4105_history_gate_substitution": False,
                "scope": "Current-source direct Node wall observations, 8 completed blocks per cohort; descriptive scaling only. Inclusive intervals are not summed. SQL total_changes includes rolled-back writes. No CPU, RSS, p99, WAN, confirmation, throughput or production claim.",
                "issues": a.issues})
    return out, out["correctness_observation_complete"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("prefix", "growth"))
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--plan", type=Path, default=DEFAULT_REPO / "evidence/pon-six-axis-execution-v1/measurement-plan.json")
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--directory", type=Path, help="Growth run directory containing run.jsonl and all cohort journals")
    parser.add_argument("--output", type=Path, required=True, help="New JSON output path; existing output is never overwritten")
    args = parser.parse_args()
    if args.kind == "growth" and args.directory is None:
        parser.error("growth requires --directory")
    if args.output.exists():
        parser.error("create-only output already exists")
    analysis = Analysis(args)
    try:
        result, passed = prefix(analysis) if args.kind == "prefix" else growth(analysis)
    except Exception as error:
        analysis.check(False, "analysis_could_not_complete", args.kind, error=repr(error))
        result = analysis.base(args.kind)
        result.update({"component_gate_pass": False, "correctness_observation_complete": False,
                       "analysis_complete": False, "issues": analysis.issues})
        passed = False
    result["helper_sha256"] = sha256(Path(__file__).read_bytes())
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"output": str(args.output.resolve()), "output_sha256": sha256(args.output.read_bytes()),
                      "measurement": args.kind, "passed": passed, "issues": len(analysis.issues)}))
    return 0 if passed else 2


if __name__ == "__main__":
    sys.exit(main())
