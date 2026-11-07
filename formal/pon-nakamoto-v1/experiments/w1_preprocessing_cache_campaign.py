#!/usr/bin/env python3
"""Fresh CPU observations of complete proofs with bounded preprocessing caches.

The fixed nonce-major schedule uses every native fixture context and candidate.
Every capacity starts empty. Complete proof hashes must equal the corresponding
actual native producer/verifier fixture, including target misses. CPU timings
include actual producer calls and separate independent complete-relation checks;
they are observations, not deadline guarantees or quantum-machine calibration.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time

sys.dont_write_bytecode = True
FORMAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FORMAL))
from quantum_oracle_resources import integer
from w1_preprocessing_cache import (MAX_ATTEMPTS, MAX_CONTEXTS, SOURCES, execute_cache_comparison,
                                     verify_cache_comparison)
from w1_quantum_oracle import ROOT, canonical, template_from_spec

SCHEMA = "trnm-w1-native-preprocessing-cache-cpu-observation-v1"
CAPACITIES = (0, 4096, 262144)
CLAIMS = {
    "native_node_executed_by_this_reader": False,
    "QPU_or_GPU_executed": False,
    "exclusive_host_cpu_calibration": False,
    "CPU_sample_maximum_is_runtime_upper_bound": False,
    "complete_energy_capital_or_network_cost": False,
    "same_total_resource_advantage_proved": False,
    "minimum_legal_attacker_cost_proved": False,
    "quantum_mining_qualified": False,
    "production_activation": False,
}


def _sources():
    names = SOURCES + ("formal/pon-nakamoto-v1/experiments/w1_preprocessing_cache_campaign.py",)
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def native_plan(fixture):
    if (type(fixture) is not dict or type(fixture.get("contexts")) is not list
            or not 1 <= len(fixture["contexts"]) <= MAX_CONTEXTS):
        raise ValueError("CACHE_CAMPAIGN_CONTEXTS")
    contexts = fixture["contexts"]
    templates = tuple(template_from_spec(row["template_spec"]) for row in contexts)
    if not templates or not all(value.shape.native for value in templates):
        raise ValueError("CACHE_CAMPAIGN_NATIVE_SHAPE")
    sizes = {1 << value.nonce_bits for value in templates}
    if len(sizes) != 1:
        raise ValueError("CACHE_CAMPAIGN_INCOMPATIBLE_NONCE_WINDOWS")
    count = next(iter(sizes))
    if count * len(templates) > MAX_ATTEMPTS:
        raise ValueError("CACHE_CAMPAIGN_ATTEMPT_BUDGET")
    return templates, tuple((context, nonce) for nonce in range(count) for context in range(len(templates)))


def compare_native_proofs(model, fixture):
    templates, schedule = native_plan(fixture)
    if (model["templates"] != [value.spec() for value in templates]
            or model["schedule"] != [list(value) for value in schedule]
            or model["capacities_payload_bytes"] != list(CAPACITIES)):
        raise ValueError("CACHE_CAMPAIGN_NATIVE_PLAN_BINDING")
    indexed = []
    for template, context in zip(templates, fixture["contexts"]):
        rows = context["all_nonce_outcomes"]
        if type(rows) is not list or len(rows) != 1 << template.nonce_bits:
            raise ValueError("CACHE_CAMPAIGN_NATIVE_CENSUS")
        table = {}
        for row in rows:
            nonce = row["nonce"]
            integer(nonce, "CACHE_CAMPAIGN_NATIVE_NONCE", 0, (1 << template.nonce_bits) - 1)
            if nonce in table or row["header_hex"] != template.header_for(nonce).hex():
                raise ValueError("CACHE_CAMPAIGN_NATIVE_CENSUS_IDENTITY")
            if type(row["native_winner"]) is not bool or row["complete_native_proof_generated"] is not True:
                raise ValueError("CACHE_CAMPAIGN_NATIVE_CENSUS_COMPLETION")
            table[nonce] = row
        indexed.append(table)
    checked = 0
    for cell in model["cells"]:
        if len(cell["attempts"]) != len(schedule):
            raise ValueError("CACHE_CAMPAIGN_MISSING_ATTEMPT")
        for index, attempt in enumerate(cell["attempts"]):
            context, nonce = schedule[index]
            if (attempt["attempt_index"] != index or attempt["context_index"] != context
                    or attempt["nonce"] != nonce):
                raise ValueError("CACHE_CAMPAIGN_ATTEMPT_IDENTITY")
            native = indexed[context][nonce]
            if (attempt["proof_sha256"] != native["proof_sha256"]
                    or attempt["proof_bytes"] != native["proof_bytes"]
                    or attempt["trace"] != native["trace"]
                    or (attempt["outcome"] == "TARGET_HIT") != native["native_winner"]
                    or attempt["outcome"] not in ("TARGET_HIT", "TARGET_MISS")):
                raise ValueError("CACHE_CAMPAIGN_NATIVE_PROOF_MISMATCH")
            checked += 1
    return {"actual_native_fixture_proof_identities_checked": checked,
            "full_proofs_match_retained_native_packets": True,
            "same_packet_new_node_execution_claimed": False}


def _peak_rss():
    amount = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return int(amount)
    if sys.platform.startswith("linux"):
        return int(amount * 1024)
    raise ValueError("CACHE_CAMPAIGN_RSS_UNITS_UNSUPPORTED")


def observe(native_directory, *, progress=None):
    from w1_native_bridge import load_fixture
    start_wall, start_cpu, initial_rss = time.perf_counter_ns(), time.process_time_ns(), _peak_rss()
    sources = _sources()
    timings = []
    status, failure, model, equivalence, fixture_sha = "FAILED", None, None, None, None
    emit = (lambda value: None) if progress is None else progress
    def timed(identity, call):
        emit({"event": "stage_started", "capacity_payload_bytes": identity[0],
              "attempt_index": identity[1], "stage": identity[2]})
        before_wall, before_cpu = time.perf_counter_ns(), time.process_time_ns()
        outcome, error = "FAILED", None
        try:
            value = call()
            outcome = "COMPLETED"
            return value
        except Exception as caught:
            error = type(caught).__name__ + ":" + str(caught)
            raise
        finally:
            row = {"capacity_payload_bytes": identity[0], "attempt_index": identity[1],
                "stage": identity[2], "status": outcome, "error": error,
                "cpu_ns": time.process_time_ns() - before_cpu,
                "wall_ns": time.perf_counter_ns() - before_wall}
            timings.append(row)
            emit({"event": "stage_terminal", **row})
    try:
        fixture, fixture_sha, _ = load_fixture(native_directory)
        templates, schedule = native_plan(fixture)
        emit({"event": "declared", "source_sha256": sources, "native_fixture_sha256": fixture_sha,
              "schedule": [list(value) for value in schedule], "capacities_payload_bytes": list(CAPACITIES)})
        model = execute_cache_comparison(templates, schedule, CAPACITIES, observe=timed)
        equivalence = compare_native_proofs(model, fixture)
        if hashlib.sha256((native_directory / "native-fixture.json").read_bytes()).hexdigest() != fixture_sha:
            raise ValueError("CACHE_CAMPAIGN_NATIVE_FIXTURE_CHANGED")
        if _sources() != sources:
            raise ValueError("CACHE_CAMPAIGN_SOURCE_CHANGED")
        status = "PASS"
    except Exception as caught:
        failure = {"type": type(caught).__name__, "message": str(caught)}
    emit({"event": "observation_terminal", "status": status, "failure": failure})
    total_cpu, total_wall = time.process_time_ns() - start_cpu, time.perf_counter_ns() - start_wall
    report = {
        "schema": SCHEMA, "status": status, "failure": failure,
        "source_sha256_before": sources, "source_sha256_after": _sources(),
        "native_fixture_sha256": fixture_sha, "capacities_payload_bytes": list(CAPACITIES),
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": {"python": sys.version, "executable": sys.executable,
                    "platform": platform.platform(), "logical_cpus_reported": os.cpu_count()},
        "process_observation": {"cpu_ns": total_cpu, "wall_ns": total_wall,
            "accounted_stage_cpu_ns": sum(row["cpu_ns"] for row in timings),
            "accounted_stage_wall_ns": sum(row["wall_ns"] for row in timings),
            "other_observation_cpu_ns": total_cpu - sum(row["cpu_ns"] for row in timings),
            "other_observation_wall_ns": total_wall - sum(row["wall_ns"] for row in timings),
            "process_high_water_rss_bytes_before": initial_rss,
            "process_high_water_rss_bytes_after": _peak_rss(),
            "scope": "this observation function including source/fixture checks and all capacities; excludes interpreter startup, imports and final report serialization; RSS is process-wide high-water, not isolated cache usage"},
        "timings": timings, "comparison": model, "native_fixture_equivalence": equivalence,
        "claims": dict(CLAIMS),
    }
    report["report_sha256"] = _hash(report)
    return report


def validate_progress_journal(report, raw):
    """Bind the flushed start/terminal journal to every retained completed stage.

    An interrupted CLI can leave a started stage without a terminal event; that
    journal is preserved but cannot pass this successful-observation checker.
    """
    from w1_quantum_oracle_campaign import strict_load
    if (type(report) is not dict or report.get("status") != "PASS"
            or type(report.get("comparison")) is not dict or type(report.get("timings")) is not list):
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_NEEDS_COMPLETE_OBSERVATION")
    if type(raw) is not bytes or not raw or len(raw) > 4 * 1024 * 1024 or not raw.endswith(b"\n"):
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_BYTES")
    lines = raw.splitlines()
    if len(lines) > 4 * MAX_ATTEMPTS * len(CAPACITIES) + 2:
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_EVENT_BUDGET")
    events = [strict_load(line) for line in lines]
    expected = [{"event": "declared", "source_sha256": report["source_sha256_before"],
        "native_fixture_sha256": report["native_fixture_sha256"],
        "schedule": report["comparison"]["schedule"], "capacities_payload_bytes": list(CAPACITIES)}]
    for row in report["timings"]:
        expected.append({"event": "stage_started", "capacity_payload_bytes": row["capacity_payload_bytes"],
                         "attempt_index": row["attempt_index"], "stage": row["stage"]})
        expected.append({"event": "stage_terminal", **row})
    expected.append({"event": "observation_terminal", "status": report["status"], "failure": report["failure"]})
    if canonical(events) != canonical(expected):
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_MISMATCH")


def validate_timing_ledger(timings, whole, attempt_count):
    """Every completed producer and separate verifier has one paid timing row."""
    integer(attempt_count, "CACHE_CAMPAIGN_ATTEMPT_COUNT", 1, MAX_ATTEMPTS)
    expected = [(capacity, index, stage) for capacity in CAPACITIES
                for index in range(attempt_count)
                for stage in ("producer", "independent_full_relation_check")]
    if type(timings) is not list or len(timings) != len(expected):
        raise ValueError("CACHE_CAMPAIGN_TIMING_BIJECTION")
    for row, identity in zip(timings, expected):
        if (type(row) is not dict or set(row) != {"capacity_payload_bytes", "attempt_index", "stage",
                "status", "error", "cpu_ns", "wall_ns"}
                or (row["capacity_payload_bytes"], row["attempt_index"], row["stage"]) != identity
                or row["status"] != "COMPLETED" or row["error"] is not None):
            raise ValueError("CACHE_CAMPAIGN_TIMING_BIJECTION")
        for key in ("capacity_payload_bytes", "attempt_index", "cpu_ns", "wall_ns"):
            integer(row[key], "CACHE_CAMPAIGN_TIMING_INTEGER", 0, 1 << 63)
    if type(whole) is not dict:
        raise ValueError("CACHE_CAMPAIGN_PROCESS_OBSERVATION")
    for clock in ("cpu", "wall"):
        for key in (clock + "_ns", "accounted_stage_" + clock + "_ns", "other_observation_" + clock + "_ns"):
            integer(whole[key], "CACHE_CAMPAIGN_TOTAL_CLOCK", 0, 1 << 63)
        total = sum(row[clock + "_ns"] for row in timings)
        if (whole["accounted_stage_" + clock + "_ns"] != total
                or whole[clock + "_ns"] != total + whole["other_observation_" + clock + "_ns"]):
            raise ValueError("CACHE_CAMPAIGN_TIMING_TOTAL")
    for key in ("process_high_water_rss_bytes_before", "process_high_water_rss_bytes_after"):
        integer(whole[key], "CACHE_CAMPAIGN_RSS", 0, 1 << 63)
    if whole["process_high_water_rss_bytes_after"] < whole["process_high_water_rss_bytes_before"]:
        raise ValueError("CACHE_CAMPAIGN_RSS_REWOUND")


def verify_observation(report, native_directory):
    """Re-execute relations and exact ledger counts; timings remain observed data."""
    from w1_native_bridge import load_fixture
    if (type(report) is not dict or report.get("schema") != SCHEMA or report.get("status") != "PASS"
            or report.get("failure") is not None or report.get("claims") != CLAIMS
            or report.get("capacities_payload_bytes") != list(CAPACITIES)
            or report.get("report_sha256") != _hash({k: v for k, v in report.items() if k != "report_sha256"})):
        raise ValueError("CACHE_CAMPAIGN_REPORT")
    if report["source_sha256_before"] != _sources() or report["source_sha256_after"] != _sources():
        raise ValueError("CACHE_CAMPAIGN_SOURCE_BINDING")
    fixture, fixture_sha, _ = load_fixture(native_directory)
    if fixture_sha != report["native_fixture_sha256"]:
        raise ValueError("CACHE_CAMPAIGN_FIXTURE_BINDING")
    model = verify_cache_comparison(report["comparison"])
    if compare_native_proofs(model, fixture) != report["native_fixture_equivalence"]:
        raise ValueError("CACHE_CAMPAIGN_NATIVE_EQUIVALENCE")
    validate_timing_ledger(report["timings"], report["process_observation"], len(model["schedule"]))
    return {"schema": "trnm-w1-cache-cpu-observation-replay-v1", "status": "PASS",
        "report_sha256": report["report_sha256"], "complete_proofs_and_cache_counts_reexecuted": True,
        "observed_timing_values_reproduced_or_attested": False,
        "native_node_executed_by_verifier": False, "quantum_mining_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-directory", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--observe", type=Path)
    action.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.observe is not None:
        journal_path = args.observe.with_name(args.observe.name + ".stages.jsonl")
        if args.observe.exists() or journal_path.exists():
            raise ValueError("CACHE_CAMPAIGN_OUTPUT_ALREADY_EXISTS")
        with journal_path.open("x") as journal:
            def progress(value):
                journal.write(canonical(value).decode() + "\n")
                journal.flush()
                os.fsync(journal.fileno())
            report = observe(args.native_directory, progress=progress)
        raw_journal = journal_path.read_bytes()
        report["progress_journal"] = {"file": journal_path.name, "bytes": len(raw_journal),
                                     "sha256": hashlib.sha256(raw_journal).hexdigest()}
        del report["report_sha256"]
        report["report_sha256"] = _hash(report)
        with args.observe.open("x") as stream:
            json.dump(report, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
        print(json.dumps({"status": report["status"], "report_sha256": report["report_sha256"],
                          "failure": report["failure"]}, sort_keys=True))
        return 0 if report["status"] == "PASS" else 1
    from w1_quantum_oracle_campaign import strict_load
    if args.verify.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("CACHE_CAMPAIGN_RECORD_BYTES_BUDGET")
    report = strict_load(args.verify.read_bytes())
    journal_path = args.verify.with_name(args.verify.name + ".stages.jsonl")
    if journal_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_BYTES_BUDGET")
    journal = journal_path.read_bytes()
    if report.get("progress_journal") != {"file": journal_path.name, "bytes": len(journal),
                                         "sha256": hashlib.sha256(journal).hexdigest()}:
        raise ValueError("CACHE_CAMPAIGN_JOURNAL_BINDING")
    validate_progress_journal(report, journal)
    print(json.dumps(verify_observation(report, args.native_directory), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
