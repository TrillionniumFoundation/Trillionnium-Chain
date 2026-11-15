#!/usr/bin/env python3
"""Literal-domain differential of a sound restricted W1 phase construction.

Native-size cases execute hierarchical macro semantics, with separate scalar
PNW1 verification. Actual leaf gates execute only on two reduced controls.
Resource ratios compare two explicit constructions, never minimal hardware
costs. Sampling the original nonce subspace is retained; no filtered quantum
state preparation is silently provided for free.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from experiments.w1_quantum_oracle_campaign import (  # noqa: E402
    read, reduced_template, retained_template, write_atomic,
)
from w1_marked_domain import enumerate_domain  # noqa: E402
from w1_quantum_oracle import FixedTemplate, OracleProgram, canonical  # noqa: E402
from w1_quantum_restricted_oracle import (  # noqa: E402
    PrefixRestrictedProgram, RESTRICTED_SOURCE_FILES, conditional_prefix_retention,
)

SCHEMA = "trnm-w1-prefix-restricted-campaign-v1"
FILES = tuple(dict.fromkeys((*RESTRICTED_SOURCE_FILES,
    "formal/pon-nakamoto-v1/test_w1_quantum_oracle.py",
    "formal/pon-nakamoto-v1/test_w1_quantum_restricted_oracle.py",
    "formal/pon-nakamoto-v1/w1_marked_domain.py",
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
    "formal/pon-nakamoto-v1/quantum_oracle_resources.py",
    "formal/pon-nakamoto-v1/experiments/w1_quantum_oracle_campaign.py",
    "formal/pon-nakamoto-v1/experiments/w1_restricted_oracle_campaign.py",
    "formal/pon-nakamoto-v1/vectors/header.bin",
    "formal/pon-nakamoto-v1/vectors/work.bin",
)))
CLAIMS = {
    "full_relation_checked_for_every_native_shape_winner": True,
    "native_node_or_quantum_hardware_executed": False,
    "native_macro_execution_is_not_leaf_gate_execution": True,
    "unfiltered_low_nonce_superposition_dimension_retained": True,
    "subset_may_discard_full_legal_winners": True,
    "uniform_tickets_or_prefix_ticket_independence_proved": False,
    "cost_ratios_are_constructive_census_ratios_only": True,
    "matched_classical_quantum_speedup_measured": False,
    "attacker_minimum_cost_or_consensus_security_proved": False,
    "production_activation": False,
}


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def committed_inventory(head, source):
    if type(head) is not str or not re.fullmatch("[0-9a-f]{40}", head):
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, capture_output=True, text=True)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    dirty = []
    for name, wanted in source.items():
        blob = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT, capture_output=True)
        if blob.returncode or hashlib.sha256(blob.stdout).hexdigest() != wanted:
            dirty.append(name)
    return dirty


def strict_load(raw):
    # Inclusive probability denominators legitimately contain exactly 2**256.
    # The older standalone circuit receipt parser has a smaller integer bound.
    if type(raw) is not bytes or len(raw) > 2_000_000:
        raise ValueError("JSON_BOUND")
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[name] = value
        return result
    def reject(value):
        raise ValueError("NONFINITE_JSON:" + value)
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            reject(value)
        return result
    def integer(value):
        result = int(value)
        if abs(result) > (1 << 256):
            raise ValueError("JSON_INTEGER_BOUND")
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject,
                      parse_float=finite, parse_int=integer)


def source_record():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source = hashes()
    dirty = committed_inventory(head, source)
    return {"git_head": head, "source_sha256": source,
            "all_sources_committed_at_head": not dirty, "uncommitted_source_files": dirty}


def validate_source(source):
    if type(source) is not dict or set(source) != {
        "git_head", "source_sha256", "all_sources_committed_at_head", "uncommitted_source_files"
    }:
        raise ValueError("SOURCE_FIELDS")
    current = hashes()
    if source["source_sha256"] != current:
        raise ValueError("SOURCE_DIGEST")
    dirty = committed_inventory(source["git_head"], current)
    if source["uncommitted_source_files"] != dirty or source["all_sources_committed_at_head"] is not (not dirty):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def narrow(template, nonce_bits, target=None):
    header = bytearray(template.header)
    if target is not None:
        offset = 118 if template.profile == "PNH1" else 122
        header[offset:offset + 32] = target.to_bytes(32, "big")
    return FixedTemplate.from_header(bytes(header), template.a, template.b, nonce_bits, template.shape)


def definitions():
    native = retained_template()
    return (
        ("native_pnh1", narrow(native, 2)),
        ("native_pnh1_changed_target", narrow(native, 2, max(1, native.target // 4))),
        ("native_pgh2", narrow(retained_template("PGH2"), 2)),
        ("reduced_prefix_losses", narrow(reduced_template(), 5)),
        ("reduced_zero_marked", narrow(reduced_template(), 4, 1)),
    )


def compare(name, template):
    domain = enumerate_domain(template)
    program = PrefixRestrictedProgram(template)
    macro_rows = []
    for scalar in domain["outcomes"]:
        observed = program.execute(scalar["nonce"])
        if observed["challenge"] != scalar["challenge"] or observed["prefix_all_accepted"] is not scalar["prefix_all_accepted"]:
            raise ValueError("PREFIX_DOMAIN_DIFFERENTIAL")
        if observed["winner"] is not (scalar["winner"] and scalar["prefix_all_accepted"]):
            raise ValueError("RESTRICTED_WINNER_DIFFERENTIAL")
        if scalar["prefix_all_accepted"] and any(observed[key] != scalar[key] for key in ("trace", "ticket")):
            raise ValueError("FULL_TRACE_DIFFERENTIAL")
        macro_rows.append(observed)
    gate_rows = []
    if name == "reduced_prefix_losses":
        for validity in (True, False):
            nonce = next(row["nonce"] for row in domain["outcomes"]
                         if row["prefix_all_accepted"] is validity)
            observed = program.execute(nonce, mode="gates")
            wanted = macro_rows[nonce]
            for key in ("winner", "challenge", "trace", "ticket", "prefix_all_accepted", "clean_ancillas"):
                if observed[key] != wanted[key]:
                    raise ValueError("LEAF_GATE_DIFFERENTIAL")
            if observed["leaf_gates_executed"] + observed["outer_X_Z_gates_executed"] != program.resources()["phase_oracle_gate_count"]:
                raise ValueError("EXECUTED_GATE_CENSUS")
            gate_rows.append(observed)
    full, restricted = OracleProgram(template).resources(), program.resources()
    ratios = {}
    for key in ("logical_qubits", "phase_oracle_gate_count", "phase_oracle_depth_upper_bound"):
        ratio = Fraction(restricted[key], full[key])
        ratios[key] = {"restricted": restricted[key], "full": full[key],
                       "ratio_numerator": ratio.numerator, "ratio_denominator": ratio.denominator}
    retention = conditional_prefix_retention(template.shape)
    return {"name": name, "domain": domain, "macro_observations": macro_rows,
            "reduced_actual_gate_observations": gate_rows,
            "restricted_resources": restricted, "comparison": ratios,
            "conditional_iid_raw_word_retention_approx": float(retention),
            "retention_scope": "iid uniform raw words only; no assertion of independence from ticket success",
            "Grover_domain_size": domain["domain_size"],
            "full_marked_count": domain["marked_count"],
            "restricted_marked_count": domain["prefix_restricted_marked_count"],
            "discarded_full_winners": domain["marked_count"] - domain["prefix_restricted_marked_count"]}


def measure():
    rows = [compare(name, template) for name, template in definitions()]
    full64 = []
    for profile in ("PNH1", "PGH2"):
        template = retained_template(profile)
        original, restricted = OracleProgram(template).resources(), PrefixRestrictedProgram(template).resources()
        keys = ("logical_qubits", "phase_oracle_gate_count", "phase_oracle_depth_upper_bound", "forward_gate_count")
        full64.append({"profile": profile, "nonce_bits": 64,
                       "full": {key: original[key] for key in keys},
                       "restricted": {key: restricted[key] for key in keys},
                       "native_full_nonce64_executed": False,
                       "restricted_construction_sha256": restricted["construction_sha256"]})
    return {"cases": rows, "full_nonce64_resource_census_only": full64}


def run(out):
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    wall, cpu = time.perf_counter(), time.process_time()
    records = measure()
    if source["source_sha256"] != hashes():
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    report = {"schema": SCHEMA, "source": source, "assertions": CLAIMS, "records": records,
              "observer_process": {"wall_seconds": time.perf_counter() - wall,
                                   "cpu_seconds": time.process_time() - cpu,
                                   "python": sys.version, "platform": platform.platform(),
                                   "scope": "classical Python census/verification; not mining hardware"}}
    raw = canonical(report) + b"\n"
    write_atomic(out / "report.json", raw)
    write_atomic(out / "manifest.json", canonical({"schema": SCHEMA + "-manifest",
                 "report_sha256": hashlib.sha256(raw).hexdigest()}) + b"\n")
    return summary(report, "RESTRICTED_W1_DIFFERENTIAL_OBSERVED")


def summary(report, result):
    cases = report["records"]["cases"]
    return {"result": result, "cases": len(cases),
            "literal_nonces": sum(row["domain"]["domain_size"] for row in cases),
            "native_PNW1_winners_verified": sum(row["domain"]["native_winning_proofs_verified"] for row in cases),
            "actual_reduced_gate_controls": sum(len(row["reduced_actual_gate_observations"]) for row in cases),
            "discarded_full_winners": sum(row["discarded_full_winners"] for row in cases),
            "security_qualified": False, "production_activation": False}


def verify(out):
    if out.is_symlink() or not out.is_dir() or {path.name for path in out.iterdir()} != {"report.json", "manifest.json"}:
        raise ValueError("ARTIFACT_INVENTORY")
    raw = read(out / "report.json")
    report, manifest = strict_load(raw), strict_load(read(out / "manifest.json"))
    if (type(report) is not dict or type(manifest) is not dict
            or report.get("schema") != SCHEMA or manifest != {
                "schema": SCHEMA + "-manifest", "report_sha256": hashlib.sha256(raw).hexdigest()}):
        raise ValueError("CAMPAIGN_SCHEMA_OR_DIGEST")
    if set(report) != {"schema", "source", "assertions", "records", "observer_process"}:
        raise ValueError("REPORT_FIELDS")
    if report.get("assertions") != CLAIMS:
        raise ValueError("CLAIMS_SUBSTITUTION")
    validate_source(report.get("source"))
    if canonical(report.get("records")) != canonical(measure()):
        raise ValueError("RESTRICTED_CAMPAIGN_REPLAY_MISMATCH")
    return summary(report, "RESTRICTED_W1_DIFFERENTIAL_REPLAY_PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.verify) if args.verify else run(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
