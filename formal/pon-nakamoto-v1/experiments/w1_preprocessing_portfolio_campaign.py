#!/usr/bin/env python3
"""Source-bound CPU observations of four complete legal W1 producers.

The frozen stream is the original 16 native-fixture candidates followed by 12
labelled relation-only controls.  Every strategy/capacity has one full run and
one separate four-second run in a fresh Python process.  Observed deadline
censoring is non-preemptive at stage boundaries.  All overruns, startup, failed
stages and unstarted planned attempts remain visible; no sample is replaced.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import subprocess
import sys
import time

sys.dont_write_bytecode = True
FORMAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FORMAL))
from quantum_oracle_resources import integer
from w1_preprocessing_portfolio import (
    ATTEMPT_STAGES, CAPACITIES, STRATEGIES, CLAIMS as MODEL_CLAIMS, run_cell, source_hashes, verify_cell,
)
from w1_quantum_oracle import FixedTemplate, ROOT, canonical, h_bytes, template_from_spec
from w1_preprocessing_cache import _field
from w1_preprocessing_cache_campaign import _peak_rss, native_plan

SCHEMA = "trnm-w1-preprocessing-portfolio-cpu-observation-v1"
PLAN_SCHEMA = "trnm-w1-preprocessing-portfolio-workload-v1"
MATRIX_SCHEMA = "trnm-w1-preprocessing-portfolio-cpu-matrix-v1"
INPUT_SCHEMA = "trnm-w1-preprocessing-portfolio-portable-input-v1"
DEADLINE_NS = 4_000_000_000
MODES = ("full", "budgeted")
ATTEMPT_COUNT = 28
NATIVE_ATTEMPT_COUNT = 16
MAX_REPORT_BYTES = 16 * 1024 * 1024
CLAIMS = {**MODEL_CLAIMS, "GPU_executed": False,
    "timings_independently_attested": False, "unbiased_statistical_speedup_proved": False,
    "hard_wall_deadline_guaranteed": False, "exclusive_host_resources_measured": False,
    "per_cache_capacity_is_total_process_memory": False,
    "derived_contexts_native_admitted": False,
    "same_total_physical_resource_budget_proved": False}


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _sources():
    names = ("formal/pon-nakamoto-v1/experiments/w1_preprocessing_portfolio_campaign.py",
             "formal/pon-nakamoto-v1/experiments/w1_preprocessing_cache_campaign.py",
             "formal/pon-nakamoto-v1/experiments/w1_native_bridge.py",
             "config/pon/ledger-v1.json", "config/pon/work-profile-v1.json",
             "config/pon/model-family-v1.json", "config/pon/devnet-v1.json",
             "config/pon/evaluation-round-v1.json")
    return {**source_hashes(), **{name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in names}}


def _changed(template, *, offset=None, value=None, a=None, b=None):
    base = 4 if template.profile == "PGH2" else 0
    header = bytearray(template.header)
    if offset is not None:
        header[base + offset:base + offset + len(value)] = value
    a = template.a if a is None else tuple(a)
    b = template.b if b is None else tuple(b)
    header[base + 278:base + 310] = hashlib.sha256(h_bytes(b"task", _field(a), _field(b))).digest()
    return FixedTemplate.from_header(bytes(header), a, b, template.nonce_bits, template.shape)


def portfolio_plan(fixture):
    """Preserve the original 16 candidates, never select from their verdicts."""
    originals, original_schedule = native_plan(fixture)
    if len(originals) != 2 or len(original_schedule) != NATIVE_ATTEMPT_COUNT:
        raise ValueError("PORTFOLIO_FROZEN_ORIGINAL_16_REQUIRED")
    p = originals[0]
    n, q = p.shape.n, p.shape.q
    base = 4 if p.profile == "PGH2" else 0
    parent = bytearray(p.header[base + 70:base + 102])
    parent[0] ^= 1
    hard_target = (1 if p.target != 1 else 2).to_bytes(32, "big")
    dense_a = tuple((value + 17 + i * i) % q for i, value in enumerate(p.a))
    dense_b = tuple((value + 29 + 3 * i * i) % q for i, value in enumerate(p.b))
    diagonal_a = tuple((i + 2) % q if i == j else 0 for i in range(n) for j in range(n))
    diagonal_b = tuple((i + 3) % q if i == j else 0 for i in range(n) for j in range(n))
    rank_a = tuple(((i + 1) * (j + 2)) % q for i in range(n) for j in range(n))
    rank_b = tuple(((i + 3) * (j + 4)) % q for i in range(n) for j in range(n))
    templates = originals + (
        _changed(p, offset=70, value=bytes(parent)),
        _changed(p, offset=118, value=hard_target),
        _changed(p, a=dense_a, b=dense_b),
        _changed(p, a=(0,) * (n * n)),
        _changed(p, a=diagonal_a, b=diagonal_b),
        _changed(p, a=rank_a, b=rank_b),
    )
    extension = ((0, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0),
                 (0, 1), (2, 1), (4, 1), (5, 1), (0, 0))
    schedule = original_schedule + extension
    contexts = ["native-fixture-0", "native-fixture-1", "parent-field-change",
                "target-field-change", "dense-task-change", "zero-left-task",
                "diagonal-task", "rank-one-task"]
    labels = [{"attempt_index": index, "context_index": context, "nonce": nonce,
               "phase": "original-native-16" if index < NATIVE_ATTEMPT_COUNT else "extended-relation-only-12",
               "context": contexts[context], "fresh_native_admission_claimed": False}
              for index, (context, nonce) in enumerate(schedule)]
    result = {"schema": PLAN_SCHEMA, "original_native_attempt_count": NATIVE_ATTEMPT_COUNT,
        "extended_relation_attempt_count": 12, "attempt_count": ATTEMPT_COUNT,
        "templates": [template.spec() for template in templates],
        "schedule": [list(action) for action in schedule], "attempt_labels": labels,
        "repeated_attempts_are_independent_queries": False,
        "whole_proof_replay_cache_enumerated": False,
        "derived_task_supply_or_eligibility_established": False}
    result["plan_sha256"] = _hash(result)
    return templates, schedule, result


def native_equivalence(cell, fixture, plan):
    """Only verified original attempts get retained native proof comparisons."""
    templates, original_schedule = native_plan(fixture)
    tables = []
    for template, context in zip(templates, fixture["contexts"]):
        table = {}
        rows = context["all_nonce_outcomes"]
        if type(rows) is not list or len(rows) != 1 << template.nonce_bits:
            raise ValueError("PORTFOLIO_NATIVE_CENSUS_COUNT")
        for row in rows:
            nonce = row["nonce"]
            integer(nonce, "PORTFOLIO_NATIVE_NONCE", 0, (1 << template.nonce_bits) - 1)
            if (nonce in table or row["header_hex"] != template.header_for(nonce).hex()
                    or row["complete_native_proof_generated"] is not True
                    or type(row["native_winner"]) is not bool):
                raise ValueError("PORTFOLIO_NATIVE_CENSUS_IDENTITY")
            table[nonce] = row
        tables.append(table)
    if len(cell["attempts"]) != ATTEMPT_COUNT or plan["attempt_count"] != ATTEMPT_COUNT:
        raise ValueError("PORTFOLIO_NATIVE_PLANNED_DENOMINATOR")
    compared = []
    for index, (context, nonce) in enumerate(original_schedule):
        attempt = cell["attempts"][index]
        if (attempt["attempt_index"], attempt["context_index"], attempt["nonce"]) != (index, context, nonce):
            raise ValueError("PORTFOLIO_NATIVE_ATTEMPT_BINDING")
        if attempt["status"] != "VERIFIED":
            continue
        original = tables[context][nonce]
        if (attempt["proof_sha256"] != original["proof_sha256"]
                or attempt["proof_bytes"] != original["proof_bytes"]
                or attempt["trace"] != original["trace"]
                or attempt["outcome"] not in ("TARGET_HIT", "TARGET_MISS")
                or (attempt["outcome"] == "TARGET_HIT") != original["native_winner"]):
            raise ValueError("PORTFOLIO_NATIVE_PROOF_MISMATCH")
        compared.append(index)
    return {"original_native_attempts_planned": NATIVE_ATTEMPT_COUNT,
            "verified_original_native_proof_identities_checked": len(compared),
            "compared_attempt_indices": compared, "same_packets_new_node_execution_claimed": False,
            "extended_attempts_native_admitted": False}


def _runtime():
    result = {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
              "machine": platform.machine(), "logical_cpus_reported": os.cpu_count()}
    if hasattr(os, "sched_getaffinity"):
        result["cpu_affinity_count"] = len(os.sched_getaffinity(0))
    for name, path in (("cpu_quota", "/sys/fs/cgroup/cpu.max"),
                       ("memory_limit", "/sys/fs/cgroup/memory.max")):
        p = Path(path)
        result[name] = p.read_text().strip() if p.is_file() else None
    return result


def export_portable_input(native_directory, output):
    """Run the unchanged full native fixture loader on its complete Git checkout.

    The portable consumer inherits this explicit evidence binding.  It does not
    pretend to rerun that full checkout/native admission on a small source pack.
    """
    from w1_native_bridge import load_fixture
    if output.exists():
        raise ValueError("PORTFOLIO_PORTABLE_OUTPUT_EXISTS")
    start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
    source_before = _sources()
    fixture, fixture_sha, checked_packets = load_fixture(native_directory)
    _, _, plan = portfolio_plan(fixture)
    fields = ("nonce", "header_hex", "native_winner", "complete_native_proof_generated",
              "proof_sha256", "proof_bytes", "trace")
    projection = {"contexts": [{"template_spec": row["template_spec"],
        "all_nonce_outcomes": [{key: item[key] for key in fields} for item in row["all_nonce_outcomes"]]}
        for row in fixture["contexts"]]}
    # Validate every projected identity before creating the delegated input.
    for context, template in zip(projection["contexts"], plan["templates"][:2]):
        if context["template_spec"] != template:
            raise ValueError("PORTFOLIO_PORTABLE_PROJECTION")
    native = fixture["native_source"]
    source_after = _sources()
    if source_before != source_after:
        raise ValueError("PORTFOLIO_PORTABLE_EXPORT_SOURCE_CHANGED")
    end_cpu, end_wall = time.process_time_ns(), time.perf_counter_ns()
    record = {"schema": INPUT_SCHEMA, "source_sha256": source_before,
        "native_fixture_sha256": fixture_sha, "fixture_projection": projection, "plan": plan,
        "native_provenance": {"frozen_implementation_commit": native["git_head"],
            "native_binary_sha256": native["binary_sha256"],
            "full_native_inventory_sha256": _hash(native["source_sha256"]),
            "full_native_inventory_files": len(native["source_sha256"]),
            "inventory_digest_encoding": "sha256 of canonical JSON path-to-SHA256 map",
            "independently_checked_native_packet_records": checked_packets,
            "fixture_claims": fixture["claims"],
            "full_native_fixture_loader_executed_on_export_host": True,
            "native_node_executed_by_exporter": False,
            "portable_consumer_reexecutes_native_admission": False},
        "preparation_observation": {"cpu_ns": end_cpu - start_cpu, "wall_ns": end_wall - start_wall,
            "runtime": _runtime(), "shared_input_preparations": 1,
            "scope": "one actual export-function execution including full Git/source/fixture/packet validation and plan preparation; interpreter startup and final serialization are in the separate outer process receipt",
            "outer_process_receipt_embedded": False,
            "different_hosts_CPU_seconds_are_economic_equivalents": False},
        "claims": dict(CLAIMS)}
    record["record_sha256"] = _hash(record)
    with output.open("xb") as stream:
        stream.write(canonical(record) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "EXPORTED", "file_bytes": output.stat().st_size,
            "file_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "record_sha256": record["record_sha256"], "plan_sha256": plan["plan_sha256"],
            "frozen_implementation_commit": native["git_head"],
            "native_fixture_sha256": fixture_sha,
            "preparation_observation": record["preparation_observation"]}


def load_portable_input(path, expected_sha256):
    from w1_quantum_oracle_campaign import strict_load
    from w1_native_bridge import FIXTURE_CLAIMS
    if (type(expected_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES):
        raise ValueError("PORTFOLIO_PORTABLE_EXTERNAL_BYTE_PIN")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("PORTFOLIO_PORTABLE_BYTE_PIN_MISMATCH")
    record = strict_load(raw)
    if (type(record) is not dict or record.get("schema") != INPUT_SCHEMA
            or record.get("claims") != CLAIMS or record.get("source_sha256") != _sources()
            or record.get("record_sha256") != _hash({key: value for key, value in record.items() if key != "record_sha256"})):
        raise ValueError("PORTFOLIO_PORTABLE_SOURCE_OR_RECORD")
    native = record["native_provenance"]
    if (re.fullmatch(r"[0-9a-f]{40}", native["frozen_implementation_commit"]) is None
            or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (
                native["native_binary_sha256"], native["full_native_inventory_sha256"], record["native_fixture_sha256"]))
            or native["full_native_fixture_loader_executed_on_export_host"] is not True
            or native["native_node_executed_by_exporter"] is not False
            or native["portable_consumer_reexecutes_native_admission"] is not False
            or native["fixture_claims"] != FIXTURE_CLAIMS):
        raise ValueError("PORTFOLIO_PORTABLE_PROVENANCE")
    integer(native["full_native_inventory_files"], "PORTFOLIO_NATIVE_INVENTORY_COUNT", 1, 100000)
    integer(native["independently_checked_native_packet_records"], "PORTFOLIO_NATIVE_PACKET_COUNT", 32, 32)
    preparation = record["preparation_observation"]
    for key in ("cpu_ns", "wall_ns"):
        integer(preparation[key], "PORTFOLIO_PREPARATION_CLOCK", 0, 1 << 63)
    if (preparation["shared_input_preparations"] != 1 or type(preparation["shared_input_preparations"]) is not int
            or preparation["outer_process_receipt_embedded"] is not False
            or preparation["different_hosts_CPU_seconds_are_economic_equivalents"] is not False):
        raise ValueError("PORTFOLIO_PREPARATION_SCOPE")
    _, _, plan = portfolio_plan(record["fixture_projection"])
    if canonical(record["plan"]) != canonical(plan):
        raise ValueError("PORTFOLIO_PORTABLE_PLAN_CHANGED")
    return record


def _inputs(native_directory, input_plan, input_plan_sha256):
    if input_plan is not None:
        if native_directory is not None:
            raise ValueError("PORTFOLIO_EXACTLY_ONE_INPUT_CHANNEL")
        record = load_portable_input(input_plan, input_plan_sha256)
        binding = {"kind": "SHA-pinned-portable-delegation", "input_file_sha256": input_plan_sha256,
            "portable_record_sha256": record["record_sha256"], "native_provenance": record["native_provenance"],
            "shared_preparation_observation": record["preparation_observation"],
            "full_native_inventory_checked_in_this_process": False,
            "native_fixture_loader_executed_in_this_process": False}
        return record["fixture_projection"], record["native_fixture_sha256"], binding
    if native_directory is None or input_plan_sha256 is not None:
        raise ValueError("PORTFOLIO_EXACTLY_ONE_INPUT_CHANNEL")
    from w1_native_bridge import load_fixture
    fixture, fixture_sha, _ = load_fixture(native_directory)
    return fixture, fixture_sha, {"kind": "full-checkout-native-fixture-replay",
        "input_file_sha256": fixture_sha, "shared_preparation_observation": None,
        "full_native_inventory_checked_in_this_process": True,
        "native_fixture_loader_executed_in_this_process": True}


def observe(native_directory, strategy, capacity, mode, *, origin_wall_ns=None, progress=None,
            input_plan=None, input_plan_sha256=None):
    if (type(strategy) is not str or strategy not in STRATEGIES
            or type(capacity) is not int or capacity not in CAPACITIES
            or type(mode) is not str or mode not in MODES):
        raise ValueError("PORTFOLIO_FROZEN_CELL")
    entry_wall, entry_cpu, rss_before = time.perf_counter_ns(), time.process_time_ns(), _peak_rss()
    origin = entry_wall if origin_wall_ns is None else origin_wall_ns
    integer(origin, "PORTFOLIO_CLOCK_ORIGIN", 0, entry_wall)
    if entry_wall - origin > 120_000_000_000:
        raise ValueError("PORTFOLIO_CLOCK_ORIGIN_STALE")
    emit = (lambda event: None) if progress is None else progress
    timings, admissions = [], []
    status, failure, cell, plan, equivalence, fixture_sha, binding = "FAILED", None, None, None, None, None, None
    sources = _sources()
    emit({"event": "run_started", "strategy": strategy, "capacity_payload_bytes": capacity,
          "mode": mode, "deadline_ns": DEADLINE_NS if mode == "budgeted" else None,
          "source_sha256": sources})

    def admit(identity):
        elapsed = time.perf_counter_ns() - origin
        allowed = mode == "full" or elapsed < DEADLINE_NS
        row = {"identity": list(identity), "wall_elapsed_ns": elapsed, "allowed": allowed}
        admissions.append(row)
        emit({"event": "stage_admission", **row})
        return allowed

    def timed(identity, call):
        start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
        emit({"event": "stage_started", "identity": list(identity),
              "wall_elapsed_ns": start_wall - origin, "process_cpu_ns": start_cpu})
        stage_status, error = "FAILED", None
        try:
            result = call()
            stage_status = "COMPLETED"
            return result
        except Exception as caught:
            error = {"type": type(caught).__name__, "message": str(caught)}
            raise
        finally:
            end_cpu, end_wall = time.process_time_ns(), time.perf_counter_ns()
            row = {"identity": list(identity), "status": stage_status, "error": error,
                "start_wall_elapsed_ns": start_wall - origin, "end_wall_elapsed_ns": end_wall - origin,
                "start_process_cpu_ns": start_cpu, "end_process_cpu_ns": end_cpu,
                "cpu_ns": end_cpu - start_cpu, "wall_ns": end_wall - start_wall}
            timings.append(row)
            emit({"event": "stage_terminal", **row})
    try:
        fixture, fixture_sha, binding = _inputs(native_directory, input_plan, input_plan_sha256)
        templates, schedule, plan = portfolio_plan(fixture)
        emit({"event": "plan_bound", "plan_sha256": plan["plan_sha256"],
              "native_fixture_sha256": fixture_sha, "planned_attempt_count": ATTEMPT_COUNT})
        cell = run_cell(templates, schedule, strategy, capacity, observer=timed, admit=admit)
        if cell["status"] == "FAILED":
            raise ValueError("PORTFOLIO_PRODUCER_OR_VERIFIER_FAILURE:" + str(cell["failure"]))
        equivalence = native_equivalence(cell, fixture, plan)
        input_path = input_plan if input_plan is not None else native_directory / "native-fixture.json"
        if hashlib.sha256(input_path.read_bytes()).hexdigest() != binding["input_file_sha256"]:
            raise ValueError("PORTFOLIO_NATIVE_FIXTURE_CHANGED")
        if _sources() != sources:
            raise ValueError("PORTFOLIO_SOURCE_CHANGED")
        status = "COMPLETE_OBSERVATION"
    except Exception as caught:
        failure = {"type": type(caught).__name__, "message": str(caught)}
    emit({"event": "run_terminal", "status": status, "failure": failure})
    end_cpu, end_wall = time.process_time_ns(), time.perf_counter_ns()
    stage_cpu = sum(row["cpu_ns"] for row in timings)
    stage_wall = sum(row["wall_ns"] for row in timings)
    verified_rows = [row for row in timings if row["status"] == "COMPLETED"
                     and row["identity"][1] == "independent_full_relation_check"]
    timely = [row["identity"][0] for row in verified_rows
              if mode == "full" or row["end_wall_elapsed_ns"] <= DEADLINE_NS]
    report = {"schema": SCHEMA, "status": status, "failure": failure,
        "strategy": strategy, "capacity_payload_bytes": capacity, "mode": mode,
        "deadline_ns": DEADLINE_NS if mode == "budgeted" else None,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_sha256_before": sources, "source_sha256_after": _sources(),
        "native_fixture_sha256": fixture_sha, "input_binding": binding, "plan": plan, "cell": cell,
        "native_fixture_equivalence": equivalence, "admissions": admissions, "timings": timings,
        "runtime": _runtime(), "timely_verified_attempt_indices": timely,
        "completed_verifications_after_deadline": [row["identity"][0] for row in verified_rows
            if mode == "budgeted" and row["end_wall_elapsed_ns"] > DEADLINE_NS],
        "process_observation": {
            "origin_scope": "observation-entry" if origin_wall_ns is None else "parent-subprocess-launch",
            "origin_wall_ns": origin, "entry_wall_elapsed_ns": entry_wall - origin,
            "end_wall_elapsed_ns": end_wall - origin, "observation_wall_ns": end_wall - entry_wall,
            "process_cpu_ns_at_entry": entry_cpu, "process_cpu_ns_at_end": end_cpu,
            "observation_cpu_ns": end_cpu - entry_cpu,
            "accounted_stage_cpu_ns": stage_cpu, "accounted_stage_wall_ns": stage_wall,
            "other_observation_cpu_ns": end_cpu - entry_cpu - stage_cpu,
            "other_observation_wall_ns": end_wall - entry_wall - stage_wall,
            "process_high_water_rss_bytes_before": rss_before,
            "process_high_water_rss_bytes_after": _peak_rss(),
            "overrun_after_deadline_ns": max(0, end_wall - origin - DEADLINE_NS) if mode == "budgeted" else 0,
            "scope": "actual observation including input/source checks, cache initialization, all completed/failed stages and journal emission; child startup precedes entry; final report serialization follows end and is retained in the separate subprocess receipt"},
        "claims": dict(CLAIMS)}
    report["report_sha256"] = _hash(report)
    return report


def validate_timing_ledger(report):
    cell, timings, admissions = report["cell"], report["timings"], report["admissions"]
    if report["status"] != "COMPLETE_OBSERVATION" or cell["status"] not in ("COMPLETE", "CENSORED"):
        raise ValueError("PORTFOLIO_TIMING_NEEDS_COMPLETE_OBSERVATION")
    expected = cell["completed_stages"]
    if (len(timings) != len(expected) or len(admissions) != len(expected) + (cell["status"] == "CENSORED")
            or [row["identity"] for row in timings] != expected):
        raise ValueError("PORTFOLIO_TIMING_BIJECTION")
    whole = report["process_observation"]
    for key in ("origin_wall_ns", "entry_wall_elapsed_ns", "end_wall_elapsed_ns", "observation_wall_ns",
                "process_cpu_ns_at_entry", "process_cpu_ns_at_end", "observation_cpu_ns",
                "accounted_stage_cpu_ns", "accounted_stage_wall_ns", "other_observation_cpu_ns",
                "other_observation_wall_ns", "process_high_water_rss_bytes_before",
                "process_high_water_rss_bytes_after", "overrun_after_deadline_ns"):
        integer(whole[key], "PORTFOLIO_OBSERVED_CLOCK_OR_RSS", 0, 1 << 63)
    last_wall, last_cpu = whole["entry_wall_elapsed_ns"], whole["process_cpu_ns_at_entry"]
    for index, (row, identity) in enumerate(zip(timings, expected)):
        admission = admissions[index]
        for pair in (identity, row["identity"], admission["identity"]):
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("PORTFOLIO_STAGE_IDENTITY")
            integer(pair[0], "PORTFOLIO_STAGE_INDEX", -1, ATTEMPT_COUNT - 1)
            if ((pair[0] == -1 and pair[1] != "initialize_cache")
                    or (pair[0] != -1 and pair[1] not in ATTEMPT_STAGES)):
                raise ValueError("PORTFOLIO_STAGE_IDENTITY")
        if set(admission) != {"identity", "wall_elapsed_ns", "allowed"}:
            raise ValueError("PORTFOLIO_ADMISSION_FIELDS")
        integer(admission["wall_elapsed_ns"], "PORTFOLIO_ADMISSION_CLOCK", 0, 1 << 63)
        if canonical(admission["identity"]) != canonical(identity) or admission["allowed"] is not True:
            raise ValueError("PORTFOLIO_ADMISSION_BINDING")
        if report["mode"] == "budgeted" and admission["wall_elapsed_ns"] >= DEADLINE_NS:
            raise ValueError("PORTFOLIO_STAGE_ADMITTED_AFTER_DEADLINE")
        for key in ("start_wall_elapsed_ns", "end_wall_elapsed_ns", "start_process_cpu_ns",
                    "end_process_cpu_ns", "cpu_ns", "wall_ns"):
            integer(row[key], "PORTFOLIO_STAGE_CLOCK", 0, 1 << 63)
        if (row["status"] != "COMPLETED" or row["error"] is not None
                or not last_wall <= admission["wall_elapsed_ns"] <= row["start_wall_elapsed_ns"] <= row["end_wall_elapsed_ns"]
                or not last_cpu <= row["start_process_cpu_ns"] <= row["end_process_cpu_ns"]
                or row["wall_ns"] != row["end_wall_elapsed_ns"] - row["start_wall_elapsed_ns"]
                or row["cpu_ns"] != row["end_process_cpu_ns"] - row["start_process_cpu_ns"]):
            raise ValueError("PORTFOLIO_STAGE_CLOCK_ORDER_OR_COST")
        last_wall, last_cpu = row["end_wall_elapsed_ns"], row["end_process_cpu_ns"]
    if cell["status"] == "CENSORED":
        final = admissions[-1]
        integer(final["wall_elapsed_ns"], "PORTFOLIO_FINAL_ADMISSION_CLOCK", 0, 1 << 63)
        if (report["mode"] != "budgeted" or final["identity"] != cell["stopped_before"]
                or final["allowed"] is not False or final["wall_elapsed_ns"] < max(DEADLINE_NS, last_wall)):
            raise ValueError("PORTFOLIO_CENSORING_REASON")
        last_wall = final["wall_elapsed_ns"]
    if (whole["end_wall_elapsed_ns"] < last_wall or whole["process_cpu_ns_at_end"] < last_cpu
            or whole["observation_wall_ns"] != whole["end_wall_elapsed_ns"] - whole["entry_wall_elapsed_ns"]
            or whole["observation_cpu_ns"] != whole["process_cpu_ns_at_end"] - whole["process_cpu_ns_at_entry"]
            or whole["process_high_water_rss_bytes_after"] < whole["process_high_water_rss_bytes_before"]):
        raise ValueError("PORTFOLIO_PROCESS_CLOCK_OR_RSS")
    for clock in ("cpu", "wall"):
        total = sum(row[clock + "_ns"] for row in timings)
        if (whole["accounted_stage_" + clock + "_ns"] != total
                or whole["observation_" + clock + "_ns"] != total + whole["other_observation_" + clock + "_ns"]):
            raise ValueError("PORTFOLIO_UNACCOUNTED_OBSERVATION_COST")
    verify_rows = [row for row in timings if row["identity"][1] == "independent_full_relation_check"]
    timely = [row["identity"][0] for row in verify_rows if report["mode"] == "full" or row["end_wall_elapsed_ns"] <= DEADLINE_NS]
    late = [row["identity"][0] for row in verify_rows if report["mode"] == "budgeted" and row["end_wall_elapsed_ns"] > DEADLINE_NS]
    expected_overrun = max(0, whole["end_wall_elapsed_ns"] - DEADLINE_NS) if report["mode"] == "budgeted" else 0
    if (report["timely_verified_attempt_indices"] != timely
            or report["completed_verifications_after_deadline"] != late
            or whole["overrun_after_deadline_ns"] != expected_overrun):
        raise ValueError("PORTFOLIO_DEADLINE_DELIVERY_OR_OVERRUN")


def verify_observation(report, native_directory, *, replay=True, input_plan=None, input_plan_sha256=None):
    if (type(report) is not dict or report.get("schema") != SCHEMA
            or report.get("status") != "COMPLETE_OBSERVATION" or report.get("failure") is not None
            or report.get("claims") != CLAIMS or type(report.get("strategy")) is not str
            or report.get("strategy") not in STRATEGIES
            or type(report.get("capacity_payload_bytes")) is not int
            or report.get("capacity_payload_bytes") not in CAPACITIES
            or type(report.get("mode")) is not str or report.get("mode") not in MODES
            or report.get("deadline_ns") != (DEADLINE_NS if report["mode"] == "budgeted" else None)
            or report.get("report_sha256") != _hash({k: v for k, v in report.items() if k != "report_sha256"})):
        raise ValueError("PORTFOLIO_OBSERVATION_RECORD")
    if report["source_sha256_before"] != _sources() or report["source_sha256_after"] != _sources():
        raise ValueError("PORTFOLIO_OBSERVATION_SOURCE_BINDING")
    fixture, fixture_sha, binding = _inputs(native_directory, input_plan, input_plan_sha256)
    templates, schedule, plan = portfolio_plan(fixture)
    if report["plan"] != plan or report["native_fixture_sha256"] != fixture_sha or report["input_binding"] != binding:
        raise ValueError("PORTFOLIO_OBSERVATION_PLAN_BINDING")
    if (report["cell"].get("claims") != MODEL_CLAIMS
            or report["cell"].get("record_sha256") != _hash({k: v for k, v in report["cell"].items() if k != "record_sha256"})):
        raise ValueError("PORTFOLIO_CELL_HASH_OR_CLAIMS")
    cell = verify_cell(report["cell"], templates, schedule) if replay else report["cell"]
    if (cell["strategy"] != report["strategy"] or cell["capacity_payload_bytes"] != report["capacity_payload_bytes"]
            or native_equivalence(cell, fixture, plan) != report["native_fixture_equivalence"]):
        raise ValueError("PORTFOLIO_OBSERVATION_CELL_BINDING")
    validate_timing_ledger(report)
    return {"status": "PASS", "report_sha256": report["report_sha256"],
            "complete_relations_and_cache_counts_reexecuted": replay,
            "observed_clocks_independently_attested": False, "quantum_mining_qualified": False}


def validate_journal(report, raw):
    from w1_quantum_oracle_campaign import strict_load
    if report.get("status") != "COMPLETE_OBSERVATION" or not isinstance(report.get("plan"), dict):
        raise ValueError("PORTFOLIO_JOURNAL_RETAINS_FAILED_OBSERVATION")
    if type(raw) is not bytes or not raw.endswith(b"\n") or len(raw) > MAX_REPORT_BYTES:
        raise ValueError("PORTFOLIO_JOURNAL_BYTES")
    events = [strict_load(line) for line in raw.splitlines()]
    expected = [{"event": "run_started", "strategy": report["strategy"],
        "capacity_payload_bytes": report["capacity_payload_bytes"], "mode": report["mode"],
        "deadline_ns": report["deadline_ns"], "source_sha256": report["source_sha256_before"]},
        {"event": "plan_bound", "plan_sha256": report["plan"]["plan_sha256"],
         "native_fixture_sha256": report["native_fixture_sha256"], "planned_attempt_count": ATTEMPT_COUNT}]
    for index, admission in enumerate(report["admissions"]):
        expected.append({"event": "stage_admission", **admission})
        if admission["allowed"]:
            row = report["timings"][index]
            expected.append({"event": "stage_started", "identity": row["identity"],
                             "wall_elapsed_ns": row["start_wall_elapsed_ns"],
                             "process_cpu_ns": row["start_process_cpu_ns"]})
            expected.append({"event": "stage_terminal", **row})
    expected.append({"event": "run_terminal", "status": report["status"], "failure": report["failure"]})
    if canonical(events) != canonical(expected):
        raise ValueError("PORTFOLIO_JOURNAL_MISMATCH")


def _load_report(path):
    from w1_quantum_oracle_campaign import strict_load
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("PORTFOLIO_REPORT_BYTES_BUDGET")
    return strict_load(path.read_bytes())


def _matrix_contract():
    return [{"index": index, "mode": mode, "strategy": strategy, "capacity_payload_bytes": capacity,
             "file": f"{index:02d}-{mode}-{strategy}-{capacity}.json"}
            for index, (mode, strategy, capacity) in enumerate(
                (mode, strategy, capacity) for mode in MODES for strategy in STRATEGIES for capacity in CAPACITIES)]


def summarize_matrix(directory, native_directory, *, replay=False, input_plan=None, input_plan_sha256=None):
    manifest = _load_report(directory / "matrix.json")
    declaration = _load_report(directory / "declaration.json")
    if declaration != {key: value for key, value in manifest.items() if key != "runs"}:
        raise ValueError("PORTFOLIO_MATRIX_DECLARATION_CHANGED")
    if (manifest.get("schema") != MATRIX_SCHEMA or manifest.get("contract") != _matrix_contract()
            or manifest.get("deadline_ns") != DEADLINE_NS or manifest.get("planned_runs") != 32
            or manifest.get("planned_attempts_per_run") != ATTEMPT_COUNT
            or len(manifest.get("runs", [])) != 32):
        raise ValueError("PORTFOLIO_MATRIX_DENOMINATOR")
    rows = []
    for expected, receipt in zip(_matrix_contract(), manifest["runs"]):
        if receipt["identity"] != expected:
            raise ValueError("PORTFOLIO_MATRIX_RUN_IDENTITY")
        path = directory / expected["file"]
        if _load_report(path.with_name(path.name + ".process.json")) != receipt:
            raise ValueError("PORTFOLIO_MATRIX_SUBPROCESS_RECEIPT")
        if receipt["exit_code"] != 0 or not path.is_file():
            raise ValueError("PORTFOLIO_MATRIX_INCOMPLETE_RUN_RETAINED")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt["report_file_sha256"]:
            raise ValueError("PORTFOLIO_MATRIX_FILE_BINDING")
        report = _load_report(path)
        if any(report[key] != expected[key] for key in ("mode", "strategy", "capacity_payload_bytes")):
            raise ValueError("PORTFOLIO_MATRIX_CELL_BINDING")
        verify_observation(report, native_directory, replay=replay,
                           input_plan=input_plan, input_plan_sha256=input_plan_sha256)
        journal_path = path.with_name(path.name + ".stages.jsonl")
        raw_journal = journal_path.read_bytes()
        if report.get("journal") != {"file": journal_path.name, "bytes": len(raw_journal),
                                     "sha256": hashlib.sha256(raw_journal).hexdigest()}:
            raise ValueError("PORTFOLIO_MATRIX_JOURNAL_BINDING")
        validate_journal(report, raw_journal)
        for key in ("origin_wall_ns", "end_wall_ns", "wall_ns", "child_user_cpu_ns", "child_system_cpu_ns"):
            integer(receipt[key], "PORTFOLIO_SUBPROCESS_CLOCK", 0, 1 << 63)
        if report["process_observation"]["origin_scope"] != "parent-subprocess-launch":
            raise ValueError("PORTFOLIO_MATRIX_STARTUP_SCOPE")
        whole = report["process_observation"]
        if (receipt["origin_wall_ns"] != whole["origin_wall_ns"]
                or receipt["wall_ns"] != receipt["end_wall_ns"] - receipt["origin_wall_ns"]
                or receipt["wall_ns"] < whole["end_wall_elapsed_ns"]
                # getrusage reports floating-point seconds.  Its rounding and
                # platform resolution do not provide nanosecond attestation.
                or receipt["child_user_cpu_ns"] + receipt["child_system_cpu_ns"] + 1_000_000
                   < whole["process_cpu_ns_at_end"]):
            raise ValueError("PORTFOLIO_MATRIX_WHOLE_PROCESS_COST")
        for stream in ("stdout", "stderr"):
            if hashlib.sha256(path.with_name(path.name + "." + stream).read_bytes()).hexdigest() != receipt[stream + "_sha256"]:
                raise ValueError("PORTFOLIO_MATRIX_RAW_OUTPUT_CHANGED")
        if _load_report(path.with_name(path.name + ".started.json")) != {
                "identity": expected, "argv": receipt["argv"], "origin_wall_ns": receipt["origin_wall_ns"]}:
            raise ValueError("PORTFOLIO_MATRIX_START_RECEIPT")
        rows.append({"identity": expected, "report_sha256": report["report_sha256"],
            "cell_status": report["cell"]["status"], "planned_attempts": ATTEMPT_COUNT,
            "verified_attempts": report["cell"]["attempts_verified"],
            "partial_attempts": report["cell"]["attempts_partial"],
            "not_started_attempts": report["cell"]["attempts_not_started"],
            "timely_verified_attempts": len(report["timely_verified_attempt_indices"]),
            "verified_after_deadline": len(report["completed_verifications_after_deadline"]),
            "target_hits": report["cell"]["verified_target_hits"],
            "target_misses": report["cell"]["verified_target_misses"],
            "noise_exhaustions": report["cell"]["verified_noise_exhaustions"],
            "observed_process": report["process_observation"],
            "whole_child_cpu_ns": receipt["child_user_cpu_ns"] + receipt["child_system_cpu_ns"],
            "whole_child_wall_ns": receipt["wall_ns"],
            "work_units_total": report["cell"]["work_units_total"],
            "cache": report["cell"]["cache"], "native_equivalence": report["native_fixture_equivalence"]})
    full = [row for row in rows if row["identity"]["mode"] == "full"]
    if any(row["cell_status"] != "COMPLETE" or row["verified_attempts"] != ATTEMPT_COUNT for row in full):
        raise ValueError("PORTFOLIO_FULL_RUN_INCOMPLETE")
    controller = _load_report(directory / "controller-observation.json")
    if (controller.get("schema") != "trnm-w1-portfolio-matrix-controller-observation-v1"
            or type(controller.get("completed_subprocess_receipts")) is not int
            or controller.get("completed_subprocess_receipts") != 32
            or controller.get("child_cpu_separately_recorded") is not True):
        raise ValueError("PORTFOLIO_CONTROLLER_RECEIPT")
    for key in ("cpu_ns", "wall_ns"):
        integer(controller[key], "PORTFOLIO_CONTROLLER_CLOCK", 0, 1 << 63)
    if controller["wall_ns"] < sum(row["whole_child_wall_ns"] for row in rows):
        raise ValueError("PORTFOLIO_CONTROLLER_WALL_COST_OMITTED")
    minima = []
    for capacity in CAPACITIES:
        choices = [row for row in full if row["identity"]["capacity_payload_bytes"] == capacity]
        winner = min(choices, key=lambda row: (row["whole_child_cpu_ns"], row["identity"]["strategy"]))
        minima.append({"capacity_payload_bytes": capacity, "strategy": winner["identity"]["strategy"],
                       "whole_child_cpu_ns": winner["whole_child_cpu_ns"],
                       "scope": "lowest single observed full-run CPU among these four legal implementations; includes checker/startup/serialization; not an unbiased estimate or all-algorithm lower bound"})
    result = {"schema": MATRIX_SCHEMA, "status": "PASS", "planned_runs": 32,
        "planned_attempts_per_run": ATTEMPT_COUNT, "planned_attempt_slots": 32 * ATTEMPT_COUNT,
        "original_native_attempt_slots": 32 * NATIVE_ATTEMPT_COUNT,
        "extended_relation_attempt_slots": 32 * 12, "deadline_ns": DEADLINE_NS,
        "rows": rows, "lowest_observed_full_run_cpu_by_capacity": minima,
        "fixed_order_single_full_and_single_budgeted_run_per_cell": True,
        "partial_and_unstarted_attempts_retained": True,
        "complete_relations_reexecuted_by_this_summary": replay,
        "input_binding": report["input_binding"],
        "controller_observation": controller,
        "shared_preparation_counted_once_and_host_separate": report["input_binding"]["shared_preparation_observation"] is not None,
        "claims": dict(CLAIMS)}
    result["summary_sha256"] = _hash(result)
    return result


def observe_matrix(directory, native_directory, *, input_plan=None, input_plan_sha256=None):
    controller_wall, controller_cpu = time.perf_counter_ns(), time.process_time_ns()
    directory.mkdir(exist_ok=False)
    contract = _matrix_contract()
    manifest = {"schema": MATRIX_SCHEMA, "contract": contract, "planned_runs": 32,
        "planned_attempts_per_run": ATTEMPT_COUNT, "deadline_ns": DEADLINE_NS,
        "fixed_order": True, "replacement_runs_permitted": False, "runs": []}
    (directory / "declaration.json").write_bytes(canonical({key: value for key, value in manifest.items() if key != "runs"}) + b"\n")
    (directory / "matrix.json").write_bytes(canonical(manifest) + b"\n")
    for identity in contract:
        path = directory / identity["file"]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter_ns()
        channel = (["--input-plan", str(input_plan), "--input-plan-sha256", input_plan_sha256]
                   if input_plan is not None else ["--native-directory", str(native_directory)])
        args = [sys.executable, "-B", str(Path(__file__).resolve()), *channel,
            "--observe", str(path), "--strategy", identity["strategy"], "--capacity", str(identity["capacity_payload_bytes"]),
            "--mode", identity["mode"], "--origin-wall-ns", str(started)]
        with path.with_name(path.name + ".started.json").open("xb") as stream:
            stream.write(canonical({"identity": identity, "argv": args, "origin_wall_ns": started}) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        timed_out = False
        try:
            process = subprocess.run(args, capture_output=True, timeout=120)
            stdout, stderr, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code = error.stdout or b"", error.stderr or b"", None
            timed_out = True
        ended = time.perf_counter_ns()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        (path.with_name(path.name + ".stdout")).write_bytes(stdout)
        (path.with_name(path.name + ".stderr")).write_bytes(stderr)
        receipt = {"identity": identity, "argv": args, "exit_code": code,
            "watchdog_timed_out": timed_out, "origin_wall_ns": started, "end_wall_ns": ended,
            "wall_ns": ended - started,
            "child_user_cpu_ns": round((after.ru_utime - before.ru_utime) * 1e9),
            "child_system_cpu_ns": round((after.ru_stime - before.ru_stime) * 1e9),
            "report_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        with path.with_name(path.name + ".process.json").open("xb") as stream:
            stream.write(canonical(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        manifest["runs"].append(receipt)
        (directory / "matrix.json").write_bytes(canonical(manifest) + b"\n")
    controller = {"schema": "trnm-w1-portfolio-matrix-controller-observation-v1",
        "cpu_ns": time.process_time_ns() - controller_cpu,
        "wall_ns": time.perf_counter_ns() - controller_wall,
        "runtime": _runtime(), "completed_subprocess_receipts": len(manifest["runs"]),
        "scope": "parent execution from matrix preparation through all 32 subprocess receipts; excludes later summary/replay and final serialization covered by outer command receipts",
        "child_cpu_separately_recorded": True}
    (directory / "controller-observation.json").write_bytes(canonical(controller) + b"\n")
    summary = summarize_matrix(directory, native_directory, input_plan=input_plan, input_plan_sha256=input_plan_sha256)
    (directory / "summary.json").write_bytes(canonical(summary) + b"\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    channel = parser.add_mutually_exclusive_group(required=True)
    channel.add_argument("--native-directory", type=Path)
    channel.add_argument("--input-plan", type=Path)
    parser.add_argument("--input-plan-sha256")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--observe", type=Path)
    action.add_argument("--verify", type=Path)
    action.add_argument("--observe-matrix", type=Path)
    action.add_argument("--verify-matrix", type=Path)
    action.add_argument("--export-plan", type=Path)
    parser.add_argument("--strategy", choices=STRATEGIES)
    parser.add_argument("--capacity", type=int, choices=CAPACITIES)
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument("--origin-wall-ns", type=int)
    args = parser.parse_args()
    if args.export_plan is not None:
        if args.native_directory is None or args.input_plan is not None or args.input_plan_sha256 is not None:
            raise ValueError("PORTFOLIO_EXPORT_REQUIRES_FULL_NATIVE_DIRECTORY")
        print(json.dumps(export_portable_input(args.native_directory, args.export_plan)))
        return 0
    if (args.input_plan is None) != (args.input_plan_sha256 is None):
        raise ValueError("PORTFOLIO_PORTABLE_INPUT_NEEDS_EXTERNAL_SHA256")
    if args.observe_matrix is not None:
        report = observe_matrix(args.observe_matrix, args.native_directory,
                                input_plan=args.input_plan, input_plan_sha256=args.input_plan_sha256)
        print(json.dumps({"status": report["status"], "summary_sha256": report["summary_sha256"]}))
        return 0
    if args.verify_matrix is not None:
        report = summarize_matrix(args.verify_matrix, args.native_directory, replay=True,
                                  input_plan=args.input_plan, input_plan_sha256=args.input_plan_sha256)
        print(json.dumps({"status": report["status"], "summary_sha256": report["summary_sha256"],
                          "observed_clocks_independently_attested": False}))
        return 0
    if args.observe is not None:
        if args.strategy is None or args.capacity is None or args.mode is None:
            raise ValueError("PORTFOLIO_OBSERVE_CELL_REQUIRED")
        journal_path = args.observe.with_name(args.observe.name + ".stages.jsonl")
        if args.observe.exists() or journal_path.exists():
            raise ValueError("PORTFOLIO_OUTPUT_EXISTS")
        with journal_path.open("x") as journal:
            def emit(value):
                journal.write(canonical(value).decode() + "\n")
                journal.flush()
                os.fsync(journal.fileno())
            report = observe(args.native_directory, args.strategy, args.capacity, args.mode,
                             origin_wall_ns=args.origin_wall_ns, progress=emit,
                             input_plan=args.input_plan, input_plan_sha256=args.input_plan_sha256)
        raw = journal_path.read_bytes()
        report["journal"] = {"file": journal_path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        del report["report_sha256"]
        report["report_sha256"] = _hash(report)
        with args.observe.open("xb") as output:
            output.write(canonical(report) + b"\n")
        print(json.dumps({"status": report["status"], "report_sha256": report["report_sha256"],
                          "failure": report["failure"]}))
        return 0 if report["status"] == "COMPLETE_OBSERVATION" else 1
    report = _load_report(args.verify)
    raw = args.verify.with_name(args.verify.name + ".stages.jsonl").read_bytes()
    journal_path = args.verify.with_name(args.verify.name + ".stages.jsonl")
    if report.get("journal") != {"file": journal_path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
        raise ValueError("PORTFOLIO_JOURNAL_BINDING")
    validate_journal(report, raw)
    print(json.dumps(verify_observation(report, args.native_directory,
                                      input_plan=args.input_plan, input_plan_sha256=args.input_plan_sha256)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
