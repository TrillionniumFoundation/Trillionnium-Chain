#!/usr/bin/env python3
"""Replayable, bounded observations of literal W1 nonce domains.

Native runs keep the 64x64 / rank-8 / 32-bit W1 relation and restrict only the
searched nonce subspace. Reduced controls are separately identified. Runtime
samples measure this classical observer, including independent proof checking;
they are neither per-oracle quantum clocks nor a mining cost lower bound.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

import w1_quantum_oracle_campaign as retained
from quantum_adversarial_search import TrialCosts
from w1_marked_domain import (
    MAX_NATIVE_NONCE_BITS, MAX_REDUCED_NONCE_BITS, compare_domains,
    enumerate_domain, simulate_measurements,
)
from w1_quantum_oracle import FixedTemplate, canonical

SCHEMA = "trnm-w1-literal-domain-campaign-v1"
# One bounded I/O policy covers the accepted maximum of three 4096-nonce
# reduced censuses plus three 64-nonce native censuses and their controls.
# Default runs remain below one MiB. This is a hard cap, never a retry/fallback.
MAX_REPORT_BYTES = 16 * 1024 * 1024
FILES = tuple(sorted(set(retained.FILES + (
    "formal/pon-nakamoto-v1/w1_marked_domain.py",
    "formal/pon-nakamoto-v1/test_w1_marked_domain.py",
    "formal/pon-nakamoto-v1/experiments/w1_marked_domain_campaign.py",
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
))))
ASSERTIONS = {
    "native_relation_not_reduced_for_native_cases": True,
    "native_winners_have_complete_independent_scalar_PNW1_checks": True,
    "all_reported_domains_recomputed_from_literal_header_and_matrices": True,
    "domain_counts_not_sampled_from_a_uniform_ticket_prior": True,
    "measurement_schedule_is_predeclared_and_count_blind": True,
    "observer_timing_is_not_a_quantum_clock": True,
    "native_node_admission_executed": False,
    "quantum_hardware_executed": False,
    "ticket_independence_or_full_nonce64_distribution_proved": False,
    "physical_clock_calibrated": False,
    "attacker_minimum_cost_proved": False,
    "consensus_security_theorem": False,
    "production_consensus_activation": False,
}
# Deliberate integer toy clocks, not hardware measurements. Their distinct
# values make omitted candidate checks/setup/proof charges easy to detect.
ASSUMED_COSTS = TrialCosts(1, 2, 3, 5, 7, 11, "upward")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_load(raw):
    if type(raw) is not bytes or len(raw) > MAX_REPORT_BYTES:
        raise ValueError("JSON_BOUND")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("NONFINITE_JSON:" + value)
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            reject(value)
        return result
    def integer(value):
        if len(value) > 1300:
            raise ValueError("JSON_INTEGER_BOUND")
        result = int(value)
        if result.bit_length() > 4096:
            raise ValueError("JSON_INTEGER_BOUND")
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject,
                      parse_float=finite, parse_int=integer)


def read_report(path):
    return retained.read(path, MAX_REPORT_BYTES)


def write_report(path, raw):
    if type(raw) is not bytes or len(raw) > MAX_REPORT_BYTES:
        raise ValueError("OUTPUT_BOUND")
    if path.exists() or path.is_symlink():
        raise ValueError("OUTPUT_ALREADY_EXISTS")
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # A competing writer must not turn a checked-absent output into replacement.
    # The temporary is in the same directory, so link is an atomic no-clobber
    # publication. Failure retains the partial file for inspection.
    os.link(temporary, path)
    temporary.unlink()


def committed_inventory(head, hashes):
    if type(head) is not str or not re.fullmatch("[0-9a-f]{40}", head):
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT,
                          capture_output=True, text=True)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    uncommitted = []
    for name in FILES:
        observed = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT, capture_output=True)
        if observed.returncode or digest(observed.stdout) != hashes[name]:
            uncommitted.append(name)
    return uncommitted


def source_record():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    hashes = {name: digest((ROOT / name).read_bytes()) for name in FILES}
    uncommitted = committed_inventory(head, hashes)
    return {"git_head": head, "source_sha256": hashes,
            "uncommitted_source_files": uncommitted, "all_sources_committed_at_head": not uncommitted}


def validate_source(record):
    if type(record) is not dict or set(record) != {
            "git_head", "source_sha256", "uncommitted_source_files", "all_sources_committed_at_head"}:
        raise ValueError("SOURCE_SCHEMA")
    hashes = {name: digest((ROOT / name).read_bytes()) for name in FILES}
    if record["source_sha256"] != hashes:
        raise ValueError("SOURCE_HASH")
    expected = committed_inventory(record["git_head"], hashes)
    if (record["uncommitted_source_files"] != expected
            or record["all_sources_committed_at_head"] is not (not expected)):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def with_parameters(template, nonce_bits, target=None, profile=None):
    header = template.header
    if profile is not None and profile != template.profile:
        if template.profile == "PNH1" and profile == "PGH2":
            header = b"PGH2" + header + bytes([71]) * 32
        else:
            raise ValueError("PROFILE_CONVERSION")
    base = 4 if header[:4] == b"PGH2" else 0
    if target is not None:
        if type(target) is not int or not 1 <= target < (1 << 256):
            raise ValueError("TARGET")
        start = base + 118
        header = header[:start] + target.to_bytes(32, "big") + header[start + 32:]
    return FixedTemplate.from_header(header, template.a, template.b, nonce_bits, template.shape)


def case_definitions(native_nonce_bits=4, reduced_nonce_bits=8):
    for value, bound in ((native_nonce_bits, MAX_NATIVE_NONCE_BITS),
                         (reduced_nonce_bits, MAX_REDUCED_NONCE_BITS)):
        if type(value) is not int or not 1 <= value <= bound:
            raise ValueError("CAMPAIGN_NONCE_BITS")
    native, reduced = retained.retained_template(), retained.reduced_template()
    return [
        ("native-pnh1", with_parameters(native, native_nonce_bits)),
        ("native-pgh2", with_parameters(native, native_nonce_bits, profile="PGH2")),
        ("native-pnh1-target-one", with_parameters(native, native_nonce_bits, target=1)),
        ("reduced-pnh1", with_parameters(reduced, reduced_nonce_bits)),
        ("reduced-pnh1-target-one", with_parameters(reduced, reduced_nonce_bits, target=1)),
        ("reduced-pgh2-target-one", with_parameters(reduced, reduced_nonce_bits, target=1, profile="PGH2")),
    ]


def observe(native_nonce_bits=4, reduced_nonce_bits=8):
    cases, timings = [], []
    for name, template in case_definitions(native_nonce_bits, reduced_nonce_bits):
        wall, cpu = time.perf_counter(), time.process_time()
        census = enumerate_domain(template)
        timings.append({"case": name, "wall_seconds": time.perf_counter() - wall,
                        "process_cpu_seconds": time.process_time() - cpu})
        cases.append({"case": name, "census": census})
    by_name = {row["case"]: row["census"] for row in cases}
    comparisons = [compare_domains(by_name[left], by_name[right]) for left, right in (
        ("native-pnh1", "native-pnh1"),
        ("native-pnh1", "native-pgh2"),
        ("native-pnh1", "native-pnh1-target-one"),
        ("reduced-pnh1", "reduced-pnh1-target-one"),
    )]
    # The counts remain outcomes. Do not manufacture M=0 if a real nonce wins.
    # Target-one fixtures observed otherwise would make the explicit control fail.
    for name in ("native-pnh1-target-one", "reduced-pnh1-target-one", "reduced-pgh2-target-one"):
        if not by_name[name]["no_solution"]:
            raise ValueError("DECLARED_EMPTY_DOMAIN_CONTROL_NOT_EMPTY:" + name)
    controls = {
        "native-empty-domain-retries": simulate_measurements(
            (by_name["native-pnh1-target-one"],), ((0, 0), (0, 1), (0, 3), (0, 7)),
            4, 23, ASSUMED_COSTS),
        "reduced-empty-domain-refresh": simulate_measurements(
            (by_name["reduced-pnh1-target-one"], by_name["reduced-pgh2-target-one"]),
            ((0, 0), (0, 1), (1, 3), (1, 7), (0, 9)), 3, 29, ASSUMED_COSTS),
        "reduced-actual-candidate-measurement": simulate_measurements(
            (by_name["reduced-pnh1"],), ((0, 0), (0, 1), (0, 3)),
            4, 31, ASSUMED_COSTS),
    }
    return {"parameters": {"native_nonce_bits": native_nonce_bits, "reduced_nonce_bits": reduced_nonce_bits},
            "cases": cases, "comparisons": comparisons, "search_controls": controls}, timings


def run_campaign(native_nonce_bits=4, reduced_nonce_bits=8):
    source = source_record()
    body, timings = observe(native_nonce_bits, reduced_nonce_bits)
    if source_record() != source:
        raise ValueError("SOURCE_CHANGED_DURING_RUN")
    return {"schema": SCHEMA, "source": source, **body, "observer_timings": timings,
            "observer_scope": "classical public AB, scalar nonce census and independent winning PNW1 checks",
            "environment": {"python": platform.python_version(), "platform": platform.platform()},
            "assertions": dict(ASSERTIONS)}


def replay_campaign(record):
    fields = {"schema", "source", "parameters", "cases", "comparisons", "search_controls",
              "observer_timings", "observer_scope", "environment", "assertions"}
    if type(record) is not dict or set(record) != fields or record["schema"] != SCHEMA:
        raise ValueError("CAMPAIGN_SCHEMA")
    validate_source(record["source"])
    if record["assertions"] != ASSERTIONS or canonical(record["assertions"]) != canonical(ASSERTIONS):
        raise ValueError("CAMPAIGN_ASSERTIONS")
    params = record["parameters"]
    if type(params) is not dict or set(params) != {"native_nonce_bits", "reduced_nonce_bits"}:
        raise ValueError("CAMPAIGN_PARAMETERS")
    definitions = case_definitions(**params)
    timings = record["observer_timings"]
    if type(timings) is not list or len(timings) != len(definitions):
        raise ValueError("OBSERVER_TIMINGS")
    for row, (name, _) in zip(timings, definitions):
        if type(row) is not dict or set(row) != {"case", "wall_seconds", "process_cpu_seconds"} or row["case"] != name:
            raise ValueError("OBSERVER_TIMING_ROW")
        for key in ("wall_seconds", "process_cpu_seconds"):
            value = row[key]
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1e7:
                raise ValueError("OBSERVER_TIME_BOUND")
    if record["observer_scope"] != "classical public AB, scalar nonce census and independent winning PNW1 checks":
        raise ValueError("OBSERVER_SCOPE")
    if (type(record["environment"]) is not dict or set(record["environment"]) != {"python", "platform"}
            or any(type(x) is not str or not 1 <= len(x) <= 1024 for x in record["environment"].values())):
        raise ValueError("OBSERVER_ENVIRONMENT")
    before = source_record()
    rebuilt, _ = observe(**params)
    for key, value in rebuilt.items():
        if canonical(record[key]) != canonical(value):
            raise ValueError("CAMPAIGN_REPLAY_MISMATCH:" + key)
    if source_record() != before:
        raise ValueError("SOURCE_CHANGED_DURING_REPLAY")
    return {
        "schema": "trnm-w1-literal-domain-replay-v1",
        "campaign_sha256": digest(canonical(record)),
        "literal_cases_replayed": len(record["cases"]),
        "native_nonces_replayed": sum(row["census"]["domain_size"] for row in record["cases"] if row["census"]["native_shape"]),
        "reduced_nonces_replayed": sum(row["census"]["domain_size"] for row in record["cases"] if not row["census"]["native_shape"]),
        "native_winning_proofs_scalar_verified": sum(row["census"]["native_winning_proofs_verified"] for row in record["cases"]),
        "search_controls_replayed": len(record["search_controls"]),
        "recorded_timings_reexecuted_or_attested": False,
        "security_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    run = sub.add_parser("run")
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--native-nonce-bits", type=int, default=4)
    run.add_argument("--reduced-nonce-bits", type=int, default=8)
    replay = sub.add_parser("replay")
    replay.add_argument("--input", required=True, type=Path)
    replay.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.operation == "run":
        record = run_campaign(args.native_nonce_bits, args.reduced_nonce_bits)
        write_report(args.output, canonical(record) + b"\n")
        print(json.dumps({"written": str(args.output), "cases": len(record["cases"]),
                          "native_winning_proofs_scalar_verified": sum(
                              row["census"]["native_winning_proofs_verified"] for row in record["cases"]),
                          "all_sources_committed_at_head": record["source"]["all_sources_committed_at_head"]}))
    else:
        record = strict_load(read_report(args.input))
        result = replay_campaign(record)
        write_report(args.output, canonical(result) + b"\n")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
