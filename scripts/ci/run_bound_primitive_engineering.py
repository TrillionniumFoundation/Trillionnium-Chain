#!/usr/bin/env python3
"""Observe four default-feature engineering tests without changing research gates."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import time

from ci_observation import run as run_observed
from run_pq_root_native_v3 import checked_result
from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "circuit_evaluation::bound_identity_versions_select_exact_request_and_delivery_namespaces"
NOISE = tuple("pon_work::noise_frame::tests::" + name for name in (
    "framing_matches_original_domain_and_all_part_lengths",
    "words_callbacks_and_fixed_noise_budget_match_reference",
    "each_cancelled_noise_boundary_stops_and_retry_has_fresh_framing",
))
COMMAND_SECONDS = 120
MAX_LOG_BYTES = 16 * 1024 * 1024


def suites():
    base = ["cargo", "test", "--offline", "--locked", "--manifest-path", "trillionnium/Cargo.toml"]
    serial = ["--", "--test-threads=1", "--color", "never"]
    return (
        ("bound-identity-selector", base + ["-p", "trnm-pon-node", "--test",
         "native_task_operation_v2", NAMESPACE] + serial + ["--exact"], (NAMESPACE,)),
        ("noise-frame-controls", base + ["-p", "trnm-crypto-primitives", "--lib",
         "pon_work::noise_frame::tests::"] + serial, NOISE),
    )


def cpu_sample():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"owner_user_seconds": own.ru_utime, "owner_system_seconds": own.ru_stime,
            "reaped_children_user_seconds": children.ru_utime,
            "reaped_children_system_seconds": children.ru_stime}


def difference(after, before):
    return {key: after[key] - before[key] for key in before}


def command_record(output, source, name, argv, expected):
    log = output / (name + ".log")
    started, cpu = time.monotonic_ns(), cpu_sample()
    row = {"name": name, "argv": argv, "expected_tests": list(expected),
           "execution": None, "observation": None, "error": None}
    try:
        row["execution"] = run_observed(argv, log, cwd=ROOT, timeout=COMMAND_SECONDS,
                                        expected_source=source)
        with log.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise ValueError("ENGINEERING_LOG_BOUND")
        row["observation"] = checked_result(raw.decode("utf-8"), expected,
                                             row["execution"]["exit_code"])
    except (OSError, ValueError) as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        row["elapsed_ns"] = time.monotonic_ns() - started
        row["cpu"] = difference(cpu_sample(), cpu)
        if log.is_file():
            hasher = hashlib.sha256()
            with log.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(block)
            row.update(log=log.name, log_bytes=log.stat().st_size,
                       log_sha256=hasher.hexdigest())
    return row


def execute(output, source):
    if not output.is_absolute() or output.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("engineering output must be outside source")
    output.mkdir(parents=True, exist_ok=False)
    started, cpu = time.monotonic_ns(), cpu_sample()
    report = {"schema": "trnm-bound-primitive-engineering-v1", "result": "FAIL",
              "scope": "default-feature engineering tests only; no E1-E6, pressure, learning or production qualification",
              "source_expected": source, "commands": [], "command_timeout_seconds": COMMAND_SECONDS,
              "run": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
              "cpu_scope": "observed owner and reaped children, including command compilation and source checks; not whole-host CPU",
              "command_costs_nested_in_inclusive_total": True,
              "pressure_qualified": False, "original_research_budget_changed": False}
    def retain():
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    retain()  # An interrupted owner retains a failing incomplete observation.
    try:
        report["source_before"] = verify("head", source, root=ROOT)
        report["lock_sha256_before"] = hashlib.sha256((ROOT / "trillionnium/Cargo.lock").read_bytes()).hexdigest()
        for name, argv, expected in suites():
            report["commands"].append(command_record(output, source, name, argv, expected))
            retain()
        report["source_after"] = verify("head", source, root=ROOT)
        report["lock_sha256_after"] = hashlib.sha256((ROOT / "trillionnium/Cargo.lock").read_bytes()).hexdigest()
        passed = (report["source_before"] == report["source_after"]
                  and report["lock_sha256_before"] == report["lock_sha256_after"]
                  and len(report["commands"]) == len(suites())
                  and all(row["error"] is None for row in report["commands"]))
        report["result"] = "PASS" if passed else "FAIL"
    except (OSError, ValueError) as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["elapsed_ns"] = time.monotonic_ns() - started
        report["cpu"] = difference(cpu_sample(), cpu)
        retain()
    print(json.dumps({"result": report["result"], "summary": str(output / "summary.json")}))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.output, args.expected_source))
