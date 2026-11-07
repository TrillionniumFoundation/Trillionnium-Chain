#!/usr/bin/env python3
"""Retain literal W1, constructed resources and finite-horizon search together.

Every physical/classical clock is an explicitly illustrative premise. The four
second analysis horizon is not native service acceptance and no packet is
submitted. Original consensus, resource limits and qualification flags remain.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import subprocess
import sys

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

import w1_marked_domain_campaign as literal
from quantum_oracle_resources import example
from w1_constructed_search import SOURCES, run_constructed_search
from w1_marked_domain import enumerate_domain
from w1_quantum_oracle import canonical

SCHEMA = "trnm-w1-constructed-bounded-campaign-v1"
FILES = tuple(sorted(set(SOURCES + literal.FILES + (
    "formal/pon-nakamoto-v1/test_w1_bounded_search.py",
    "formal/pon-nakamoto-v1/test_w1_constructed_search.py",
    "formal/pon-nakamoto-v1/experiments/w1_bounded_search_campaign.py",
    "formal/pon-nakamoto-v1/experiments/test_w1_bounded_search_campaign.py",
))))


def source_record():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    hashes = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in FILES}
    uncommitted = []
    for path, expected in hashes.items():
        old = subprocess.run(["git", "show", head + ":" + path], cwd=ROOT, capture_output=True)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != expected:
            uncommitted.append(path)
    return {"git_head": head, "source_sha256": hashes,
            "uncommitted_source_files": uncommitted,
            "all_sources_committed_at_head": not uncommitted}


def cases(scope):
    if scope not in ("all", "native", "reduced"):
        raise ValueError("CAMPAIGN_SCOPE")
    names = ("native", "reduced") if scope == "all" else (scope,)
    for name in names:
        template = (literal.retained.retained_template() if name == "native" else
                    literal.retained.reduced_template())
        bits = 2 if name == "native" else 4
        yield name, (
            literal.with_parameters(template, bits),
            literal.with_parameters(template, bits, target=(1 << 254) - 1),
            literal.with_parameters(template, bits, profile="PGH2"),
            literal.with_parameters(template, bits, target=1),
            literal.with_parameters(template, bits, target=1, profile="PGH2"),
        )


def scenarios(group):
    # All choices, including q=0 random measurement, precede the census. The
    # iteration-one case keeps a censored expensive trial visible even if an
    # earlier zero-iteration strategy delivers. No adaptive best-seed selection.
    for predicate in ("full", "prefix-restricted"):
        for processors in (1, 4):
            yield {"name": f"{group}-{predicate}-p{processors}-mixed",
                   "predicate": predicate, "processors": processors,
                   "schedule": ((0, 0), (0, 1), (1, 0), (2, 1)),
                   "seed": 9, "horizon_seconds": "4"}
        yield {"name": f"{group}-{predicate}-p1-iteration-one",
               "predicate": predicate, "processors": 1,
               "schedule": ((0, 1), (1, 1), (2, 2)),
               "seed": 9, "horizon_seconds": "4"}
        yield {"name": f"{group}-{predicate}-p4-empty-reuse",
               "predicate": predicate, "processors": 4,
               "schedule": ((3, 0), (3, 0), (4, 0), (3, 0)),
               "seed": 9, "horizon_seconds": "4"}


def observe(scope="all"):
    before = source_record()
    baseline = example()
    # Deliberately hypothetical residual T-state error, not an achieved factory.
    physical = replace(baseline.physical_models[1], name="illustrative-w1-bounded-schedule",
                       magic_state_error="1e-30")
    budget = 10**16
    groups = []
    for group, templates in cases(scope):
        plan = tuple(scenarios(group))
        domains = tuple(enumerate_domain(template) for template in templates)
        classical = (baseline.classical,) * len(domains)
        runs = []
        for item in plan:
            result = run_constructed_search(
                domains, item["schedule"], item["processors"], item["seed"],
                classical, physical, budget, item["horizon_seconds"], predicate=item["predicate"])
            runs.append({"name": item["name"], "result": result})
        groups.append({"name": group, "domains": list(domains), "runs": runs})
    if source_record() != before:
        raise ValueError("CAMPAIGN_SOURCE_CHANGED")
    return {"schema": SCHEMA, "scope": scope, "source": before, "groups": groups,
            "illustrative_physical_model": asdict(physical),
            "illustrative_classical_costs_ns": asdict(baseline.classical),
            "physical_qubit_cap": budget,
            "finite_horizon_is_native_acceptance_profile": False,
            "all_clocks_are_measurements": False,
            "fixed_contexts_are_native_eligible": False,
            "quantum_hardware_executed": False, "native_blocks_admitted": 0,
            "profitable_consensus_attack_demonstrated": False,
            "quantum_mining_qualified": False, "production_activation": False}


def verify(record):
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("CAMPAIGN_SCHEMA")
    # Re-executing this fixed campaign also checks its complete scenario and
    # source inventories; deleting a losing/censored run cannot pass replay.
    rebuilt = observe(record.get("scope"))
    # A later evidence-only commit may have a different HEAD but the source
    # bytes must still be exactly the original committed bytes.
    old = record.get("source")
    if type(old) is not dict or set(old) != set(rebuilt["source"]):
        raise ValueError("CAMPAIGN_SOURCE_SCHEMA")
    if old["source_sha256"] != rebuilt["source"]["source_sha256"]:
        raise ValueError("CAMPAIGN_SOURCE_HASH")
    head = old["git_head"]
    if type(head) is not str or len(head) != 40 or any(x not in "0123456789abcdef" for x in head):
        raise ValueError("CAMPAIGN_SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, capture_output=True, text=True)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("CAMPAIGN_SOURCE_HEAD")
    uncommitted = []
    for path, expected in old["source_sha256"].items():
        original = subprocess.run(["git", "show", head + ":" + path], cwd=ROOT, capture_output=True)
        if original.returncode or hashlib.sha256(original.stdout).hexdigest() != expected:
            uncommitted.append(path)
    if old["uncommitted_source_files"] != uncommitted or old["all_sources_committed_at_head"] is not (not uncommitted):
        raise ValueError("CAMPAIGN_SOURCE_COMMITMENT")
    rebuilt["source"] = old
    if canonical(rebuilt) != canonical(record):
        raise ValueError("CAMPAIGN_REPLAY_MISMATCH")
    return {"schema": SCHEMA, "replay": "PASS", "groups": len(record["groups"]),
            "runs": sum(len(group["runs"]) for group in record["groups"]),
            "native_blocks_admitted": 0, "quantum_mining_qualified": False,
            "production_activation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--observe", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--scope", choices=("all", "native", "reduced"), default="all")
    args = parser.parse_args()
    if args.observe:
        report = observe(args.scope)
        literal.write_report(args.observe, canonical(report))
        print(canonical({"output": str(args.observe), "groups": len(report["groups"]),
                         "quantum_mining_qualified": False}).decode())
    else:
        print(canonical(verify(literal.strict_load(literal.read_report(args.verify)))).decode())


if __name__ == "__main__":
    main()
