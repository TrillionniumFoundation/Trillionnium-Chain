#!/usr/bin/env python3
"""Compare a declared finite family on one native W1 root context.

All cells share the literal domain, deadline, host costs, error budget and
physical-qubit ceiling. Each pays its complete two-trial lifecycle including
all processors. These are conditional constructions, not calibrated prices,
actual concurrent hardware, or the least-cost legal implementation. Interval
dominance is deliberately conservative: an uncertain probability cannot be
rounded into evidence that one strategy is better.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
FORMAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FORMAL))
from w1_machine_envelope import build_machine_envelope
from w1_marked_domain import enumerate_domain, replay_domain
from w1_quantum_oracle import canonical, template_from_spec

SCHEMA = "trnm-w1-constructed-machine-frontier-v1"
PREDICATES = ("full", "prefix-restricted")
PROCESSORS = (1, 2, 4)
ITERATIONS = (0, 1, 2)
TRIALS = 2
HORIZON = "4"
QUBIT_BUDGET = 10**16
RESOURCE_FIELDS = ("physical_qubits", "planned_t_states", "planned_input_bytes",
                   "initialized_patches", "controller_commands")


def rational(value):
    return Fraction(**value)


def dominates(left, right):
    """Prove weak improvement in all listed dimensions, one strict change."""
    if left["status"] != "CONSTRUCTED" or right["status"] != "CONSTRUCTED":
        return False
    a, b = left["resources"], right["resources"]
    lo = rational(left["conditional_delivery_probability"]["lower"])
    hi = rational(right["conditional_delivery_probability"]["upper"])
    return (all(a[key] <= b[key] for key in RESOURCE_FIELDS) and lo >= hi
            and (any(a[key] < b[key] for key in RESOURCE_FIELDS) or lo > hi))


def compare(domain, classical, physical, lifecycle):
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    domain = replay_domain(domain)
    for model in (classical, physical, lifecycle):
        model.validate()
    cells = []
    plan = [(predicate, processors, iterations) for predicate in PREDICATES
            for processors in PROCESSORS for iterations in ITERATIONS]
    for predicate, processors, iterations in plan:
        identity = {"predicate": predicate, "processors": processors, "iterations": iterations}
        name = f"{predicate}-p{processors}-q{iterations}"
        try:
            record = build_machine_envelope((domain,), ((0, iterations),) * TRIALS,
                processors, (classical,), physical, lifecycle, QUBIT_BUDGET, HORIZON,
                predicate=predicate)
        except ValueError as error:
            # A refused cell remains in the denominator. No alternative budget,
            # horizon, processor count or error rate is silently substituted.
            cells.append({"name": name, **identity, "status": "REFUSED", "reason": str(error)})
            continue
        envelope = record["envelope"]
        events = envelope["events_all_processors"]
        cells.append({"name": name, **identity, "status": "CONSTRUCTED",
            "resources": {"physical_qubits": envelope["physical_qubits_all_processors"],
                "planned_t_states": events["magic_state_services"],
                "planned_input_bytes": sum(row["input_bytes_all_processors"] for row in record["planned_rounds"]),
                "initialized_patches": events["initialization_patches"],
                "controller_commands": events["controller_commands"]},
            "code_distance": envelope["code_distance_for_whole_schedule"],
            "ideal_delivery_probability": record["ideal_schedule_probability"]["delivery_probability"],
            "conditional_delivery_probability": record["conditional_machine_delivery_probability"],
            "whole_plan_failure_union_upper": envelope["whole_plan_failure_union_upper"],
            "machine_record": record})
    frontier = [row["name"] for row in cells if row["status"] == "CONSTRUCTED"
                and not any(dominates(other, row) for other in cells)]
    report = {"schema": SCHEMA, "domain_sha256": domain["domain_sha256"],
        "native_shape": domain["native_shape"], "comparison_source_sha256": source_digest,
        "common_model_premises": {"classical_costs_ns": asdict(classical),
            "physical_model": asdict(physical), "lifecycle_model": asdict(lifecycle)},
        "declared_grid": {"predicates": list(PREDICATES), "processors": list(PROCESSORS),
            "iterations": list(ITERATIONS), "trials": TRIALS, "horizon_seconds": HORIZON,
            "physical_qubit_budget": QUBIT_BUDGET},
        "planned_cells": len(plan), "observed_model_cells": len(cells), "cells": cells,
        "undominated_with_certified_interval_order": frontier,
        "comparison_scope": {"domain": ("one native-shape template, no parent switching"
            if domain["native_shape"] else "one explicitly reduced-shape control template, no parent switching"),
            "candidate_check": "full legal W1 even when phase predicate is restricted",
            "resources": list(RESOURCE_FIELDS), "probability": "conditional full-lifecycle delivery interval",
            "parallelism": "independent ideal processor measurements and declared shared service costs",
            "dominance": "left lower success endpoint >= right upper endpoint and no larger listed resource",
            "early_stop_does_not_refund_provisioned_envelope": True,
            "census_tuned_online_policy_executed": False,
            "all_legal_algorithms_or_caches_enumerated": False,
            "ordinary_random_nonce_classical_baseline_has_no_QPU_requirement": True},
        "claims": {"physical_parameters_calibrated": False, "parallel_hardware_measured": False,
            "energy_or_capital_prices_calibrated": False, "same_total_economic_budget_proved": False,
            "minimum_attacker_cost_proved": False, "native_blocks_admitted_by_this_comparison": 0,
            "quantum_hardware_executed": False, "quantum_mining_qualified": False,
            "production_activation": False}}
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != source_digest:
        raise ValueError("FRONTIER_SOURCE_CHANGED")
    report["report_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from w1_native_bridge import declared_models, load_fixture
    fixture, fixture_sha, _ = load_fixture(args.native_directory)
    context = next(row for row in fixture["contexts"] if row["context_id"] == fixture["root_context_id"])
    domain = enumerate_domain(template_from_spec(context["template_spec"]))
    report = compare(domain, *declared_models())
    report["native_fixture_sha256"] = fixture_sha
    del report["report_sha256"]
    report["report_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
    with args.output.open("x") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
        output.write("\n")


if __name__ == "__main__":
    main()
