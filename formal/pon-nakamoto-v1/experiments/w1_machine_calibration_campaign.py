#!/usr/bin/env python3
"""Native-validated portable input and finite-calibration gap observations.

Export runs only beside the full native fixture and original source checkout.
The portable reader checks a caller-pinned input digest, current required source
bytes, the literal domain and complete architecture reconstruction. It does not
rerun the native Node or authenticate a QPU. No physical observation is supplied
by this campaign: its output exposes missing coverage and direct-sampling gaps.
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
from w1_machine_architecture import build_service_architecture, declared_architectures
from w1_machine_calibration import (
    SOURCES as CALIBRATION_SOURCES, review_machine_calibration,
    strict_load, verify_machine_calibration,
)
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import ROOT, canonical, template_from_spec

INPUT_SCHEMA = "trnm-w1-native-calibration-portable-input-v1"
SCHEMA = "trnm-w1-calibration-gap-cpu-observation-v1"
SOURCES = CALIBRATION_SOURCES + (
    "formal/pon-nakamoto-v1/experiments/w1_native_bridge.py",
    "formal/pon-nakamoto-v1/experiments/w1_machine_calibration_campaign.py",
)
PROFILE = "declared-fast-service-p1-q1-two-trial-calibration-gap-v1"
OBSERVATION_SCOPE = "input/source checks and exact scalar domain, allocation and calibration-gap reconstruction; excludes interpreter startup/imports and final serialization"
CLAIMS = {"native_node_executed_by_portable_reader": False,
          "QPU_executed": False, "hardware_parameters_calibrated": False,
          "sample_maximum_is_runtime_upper_bound": False,
          "exclusive_host_measurement": False, "complete_machine_energy_measured": False,
          "minimum_legal_attacker_cost_proved": False, "quantum_mining_qualified": False,
          "production_activation": False}


def sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def export_input(native_directory):
    from w1_native_bridge import declared_models, load_fixture
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    before = sources()
    fixture, fixture_sha, packets = load_fixture(native_directory)
    context = next(row for row in fixture["contexts"] if row["context_id"] == fixture["root_context_id"])
    domain = enumerate_domain(template_from_spec(context["template_spec"]))
    classical, physical, lifecycle = declared_models()
    architecture = build_service_architecture((domain,), ((0, 1), (0, 1)), 1,
        (classical,), physical, lifecycle, declared_architectures()[2], 10**16, "4",
        predicate="full", reserved_maximum_winners=1)
    source = fixture["native_source"]
    plan = {"schema": INPUT_SCHEMA, "profile": PROFILE, "source_sha256": before,
        "native_fixture_sha256": fixture_sha, "native_packets_checked_at_export": packets,
        "native_source": {"git_head": source["git_head"], "binary_sha256": source["binary_sha256"],
                          "source_inventory_sha256": digest(source["source_sha256"])},
        "domain": domain, "architecture": architecture,
        "export_observation": {"cpu_ns": time.process_time_ns() - cpu,
            "wall_ns": time.perf_counter_ns() - wall,
            "scope": "full native fixture/source inventory and scalar domain/allocation preparation; excludes interpreter startup and final file serialization",
            "quantum_execution": False},
        "export_claims": {"full_native_fixture_checked_at_export": True,
                          "native_fixture_validation_repeated_by_portable_reader": False,
                          "physical_calibration_provided": False}}
    if sources() != before:
        raise ValueError("CALIBRATION_EXPORT_SOURCE_CHANGED")
    plan["plan_sha256"] = digest(plan)
    return plan


def load_input(path, expected_sha256):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("CALIBRATION_INPUT_DIGEST")
    plan = strict_load(raw)
    keys = {"schema", "profile", "source_sha256", "native_fixture_sha256",
            "native_packets_checked_at_export", "native_source", "domain", "architecture",
            "export_claims", "export_observation", "plan_sha256"}
    if type(plan) is not dict or set(plan) != keys or plan["schema"] != INPUT_SCHEMA or plan["profile"] != PROFILE:
        raise ValueError("CALIBRATION_INPUT_SCHEMA")
    if plan["source_sha256"] != sources() or plan["plan_sha256"] != digest({k: v for k, v in plan.items() if k != "plan_sha256"}):
        raise ValueError("CALIBRATION_INPUT_SOURCE_OR_BODY")
    if (type(plan["native_packets_checked_at_export"]) is not int or plan["native_packets_checked_at_export"] < 1
            or plan["export_claims"] != {"full_native_fixture_checked_at_export": True,
                "native_fixture_validation_repeated_by_portable_reader": False,
                "physical_calibration_provided": False}):
        raise ValueError("CALIBRATION_INPUT_NATIVE_SCOPE")
    native = plan["native_source"]
    if type(native) is not dict or set(native) != {"git_head", "binary_sha256", "source_inventory_sha256"}:
        raise ValueError("CALIBRATION_INPUT_NATIVE_IDENTITY")
    import re
    for key, width in (("git_head", 40), ("binary_sha256", 64), ("source_inventory_sha256", 64)):
        if type(native[key]) is not str or re.fullmatch(r"[0-9a-f]{" + str(width) + "}", native[key]) is None:
            raise ValueError("CALIBRATION_INPUT_NATIVE_IDENTITY")
    if type(plan["native_fixture_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", plan["native_fixture_sha256"]) is None:
        raise ValueError("CALIBRATION_INPUT_NATIVE_IDENTITY")
    preparation = plan["export_observation"]
    if (type(preparation) is not dict or set(preparation) != {"cpu_ns", "wall_ns", "scope", "quantum_execution"}
            or preparation["quantum_execution"] is not False
            or any(type(preparation[k]) is not int or preparation[k] < 0 for k in ("cpu_ns", "wall_ns"))):
        raise ValueError("CALIBRATION_INPUT_PREPARATION_RECEIPT")
    # Same declared 4 s, qubit ceiling and full two-trial q=1 allocation.
    architecture = plan["architecture"]
    p = architecture["machine_record"]["premises"]
    fixed = {"schedule": [[0, 1], [0, 1]], "processors": 1, "predicate": "full",
             "physical_qubit_budget": 10**16, "horizon_seconds": "4", "reserved_maximum_winners": 1}
    if (canonical({k: p[k] for k in fixed}) != canonical(fixed)
            or architecture["architecture"]["name"] != declared_architectures()[2].name
            or plan["domain"].get("native_shape") is not True):
        raise ValueError("CALIBRATION_INPUT_FROZEN_ALLOCATION")
    return plan


def gap(plan, checked_at):
    return review_machine_calibration(plan["architecture"], (plan["domain"],), {},
        hardware_id="unprovided-matched-physical-quantum-hardware",
        hardware_epoch="unprovided-physical-calibration-epoch",
        instrument_sha256=plan["source_sha256"]["formal/pon-nakamoto-v1/experiments/w1_machine_calibration_campaign.py"],
        now_unix_seconds=checked_at, maximum_age_seconds=24 * 3600)


def observe(input_path, input_sha256):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    before = sources()
    plan = load_input(input_path, input_sha256)
    checked_at = int(time.time())
    analysis = gap(plan, checked_at)
    elapsed_cpu, elapsed_wall = time.process_time_ns() - cpu, time.perf_counter_ns() - wall
    if sources() != before:
        raise ValueError("CALIBRATION_CAMPAIGN_SOURCE_CHANGED")
    report = {"schema": SCHEMA, "status": "OBSERVED_HOLD", "source_sha256": before,
        "input_file_sha256": input_sha256, "input_plan_sha256": plan["plan_sha256"],
        "native_source": plan["native_source"], "native_fixture_sha256": plan["native_fixture_sha256"],
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": {"python": sys.version, "platform": platform.platform(), "logical_cpus_reported": os.cpu_count()},
        "process_observation": {"cpu_ns": elapsed_cpu, "wall_ns": elapsed_wall,
            "high_water_rss_native_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "rss_units": "bytes" if sys.platform == "darwin" else "KiB" if sys.platform.startswith("linux") else "unknown",
            "scope": OBSERVATION_SCOPE,
            "native_execution_performed": False, "measurement_authenticity_established_by_reader": False},
        "analysis": analysis, "claims": dict(CLAIMS)}
    report["report_sha256"] = digest(report)
    return report


def verify(input_path, input_sha256, report_path, report_file_sha256):
    plan = load_input(input_path, input_sha256)
    raw = Path(report_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != report_file_sha256:
        raise ValueError("CALIBRATION_REPORT_DIGEST")
    report = strict_load(raw)
    keys = {"schema", "status", "source_sha256", "input_file_sha256", "input_plan_sha256", "native_source",
            "native_fixture_sha256", "observed_at_utc", "runtime", "process_observation", "analysis", "claims", "report_sha256"}
    if (type(report) is not dict or set(report) != keys or report.get("schema") != SCHEMA or report.get("status") != "OBSERVED_HOLD"
            or report.get("source_sha256") != sources() or report.get("claims") != CLAIMS
            or report.get("input_file_sha256") != input_sha256
            or report.get("input_plan_sha256") != plan["plan_sha256"]
            or report.get("native_source") != plan["native_source"]
            or report.get("native_fixture_sha256") != plan["native_fixture_sha256"]
            or report.get("report_sha256") != digest({k: v for k, v in report.items() if k != "report_sha256"})):
        raise ValueError("CALIBRATION_CAMPAIGN_REPORT_BINDING")
    verify_machine_calibration(report["analysis"], plan["architecture"], (plan["domain"],), {})
    if report["analysis"] != gap(plan, report["analysis"]["checked_at_unix_seconds"]):
        raise ValueError("CALIBRATION_CAMPAIGN_ANALYSIS_REPLAY")
    observation = report["process_observation"]
    if (type(observation) is not dict or set(observation) != {"cpu_ns", "wall_ns", "high_water_rss_native_units", "rss_units", "scope", "native_execution_performed", "measurement_authenticity_established_by_reader"}
            or observation["scope"] != OBSERVATION_SCOPE
            or observation["native_execution_performed"] is not False
            or observation["measurement_authenticity_established_by_reader"] is not False
            or observation["rss_units"] not in ("bytes", "KiB", "unknown")):
        raise ValueError("CALIBRATION_CAMPAIGN_OBSERVATION_SCOPE")
    for name in ("cpu_ns", "wall_ns", "high_water_rss_native_units"):
        value = report["process_observation"][name]
        if type(value) is not int or value < 0:
            raise ValueError("CALIBRATION_CAMPAIGN_OBSERVATION_COUNT")
    return {"schema": "trnm-w1-calibration-gap-portable-verification-v1", "status": "VERIFIED_HOLD",
        "input_file_sha256": input_sha256, "report_file_sha256": report_file_sha256,
        "native_node_executed": False, "QPU_executed": False,
        "physical_calibration_established": False, "quantum_mining_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-directory", type=Path)
    parser.add_argument("--input-plan", type=Path)
    parser.add_argument("--input-plan-sha256")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--export-input", type=Path)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify-report", type=Path)
    parser.add_argument("--report-sha256")
    args = parser.parse_args()
    if args.export_input:
        if args.native_directory is None or args.input_plan is not None:
            parser.error("--export-input requires --native-directory only")
        result = export_input(args.native_directory)
        write_new(args.export_input, result)
        print(json.dumps({"status": "NATIVE_VALIDATED_PORTABLE_INPUT_EXPORTED",
            "path": str(args.export_input), "sha256": hashlib.sha256(args.export_input.read_bytes()).hexdigest()}))
    else:
        if args.input_plan is None or args.input_plan_sha256 is None or args.native_directory is not None:
            parser.error("portable operations require --input-plan and --input-plan-sha256")
        if args.output:
            result = observe(args.input_plan, args.input_plan_sha256)
            write_new(args.output, result)
            print(json.dumps({"status": result["status"], "path": str(args.output),
                "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))
        else:
            if args.report_sha256 is None:
                parser.error("verification requires caller-pinned --report-sha256")
            print(json.dumps(verify(args.input_plan, args.input_plan_sha256, args.verify_report, args.report_sha256)))


if __name__ == "__main__":
    main()
