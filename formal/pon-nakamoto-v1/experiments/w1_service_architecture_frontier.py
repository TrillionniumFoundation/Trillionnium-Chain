#!/usr/bin/env python3
"""Retain a predeclared 54-cell service-architecture comparison.

The existing 18-cell serial comparison remains separate. Every cell here pays
auxiliary patches, reset/readout ports and controller reservations. No cell
receives changed noise, factory throughput, failure budget, deadline or qubit
ceiling because its original construction missed the deadline.
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
from w1_machine_architecture import (SOURCES, build_service_architecture,
                                     declared_architectures)
from w1_marked_domain import enumerate_domain, replay_domain
from w1_quantum_oracle import ROOT, canonical, template_from_spec

SCHEMA = "trnm-w1-service-architecture-frontier-v1"
PREDICATES = ("full", "prefix-restricted")
PROCESSORS = (1, 2, 4)
ITERATIONS = (0, 1, 2)
TRIALS = 2
HORIZON = "4"
QUBIT_BUDGET = 10**16
RESOURCE_FIELDS = (
    "physical_qubits", "service_logical_patches", "initialization_service_ports",
    "readout_service_ports", "classical_controller_cores_reserved",
    "classical_controller_memory_bytes_reserved", "initialized_patches",
    "controller_commands", "planned_t_states", "planned_transfer_bytes",
    "planned_host_calls_including_proofs", "initialization_port_code_cycles_reserved",
    "readout_port_code_cycles_reserved", "complete_plan_seconds_reserved",
    "physical_qubit_seconds_reserved", "initialization_port_seconds_reserved",
    "readout_port_seconds_reserved", "controller_core_seconds_reserved",
    "controller_memory_byte_seconds_reserved",
)


def _sources():
    names = SOURCES + ("formal/pon-nakamoto-v1/experiments/w1_service_architecture_frontier.py",)
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def _number(value):
    return Fraction(value) if type(value) is int else Fraction(**value)


def dominates(left, right):
    """Only certified interval order across every listed resource dimension."""
    if left["status"] != "CONSTRUCTED_CONDITIONAL_MODEL" or right["status"] != "CONSTRUCTED_CONDITIONAL_MODEL":
        return False
    a, b = left["resources"], right["resources"]
    lo = Fraction(**left["conditional_delivery_probability"]["lower"])
    hi = Fraction(**right["conditional_delivery_probability"]["upper"])
    return (lo >= hi and all(_number(a[key]) <= _number(b[key]) for key in RESOURCE_FIELDS)
            and (lo > hi or any(_number(a[key]) < _number(b[key]) for key in RESOURCE_FIELDS)))


def compare(domain, classical, physical, lifecycle):
    sources = _sources()
    domain = replay_domain(domain)
    for model in (classical, physical, lifecycle):
        model.validate()
    architectures = declared_architectures()
    cells = []
    for architecture in architectures:
        for predicate in PREDICATES:
            for processors in PROCESSORS:
                for iterations in ITERATIONS:
                    identity = {"architecture": architecture.name, "predicate": predicate,
                                "processors": processors, "iterations": iterations}
                    name = f"{architecture.name}-{predicate}-p{processors}-q{iterations}"
                    try:
                        record = build_service_architecture((domain,), ((0, iterations),) * TRIALS,
                            processors, (classical,), physical, lifecycle, architecture,
                            QUBIT_BUDGET, HORIZON, predicate=predicate)
                    except ValueError as error:
                        cells.append({"name": name, **identity, "status": "REFUSED", "reason": str(error)})
                        continue
                    machine = record["machine_record"]
                    cells.append({"name": name, **identity, "status": "CONSTRUCTED_CONDITIONAL_MODEL",
                        "resources": record["resources"],
                        "code_distance": machine["envelope"]["code_distance_for_whole_schedule"],
                        "ideal_delivery_probability": machine["ideal_schedule_probability"]["delivery_probability"],
                        "conditional_delivery_probability": machine["conditional_machine_delivery_probability"],
                        "architecture_record": record})
    frontier = [row["name"] for row in cells if row["status"] == "CONSTRUCTED_CONDITIONAL_MODEL"
                and not any(dominates(other, row) for other in cells)]
    report = {
        "schema": SCHEMA, "source_sha256": sources, "domain_sha256": domain["domain_sha256"],
        "native_shape": domain["native_shape"],
        "common_models": {"classical_costs_ns": asdict(classical), "physical_model": asdict(physical),
                          "original_lifecycle_model": asdict(lifecycle)},
        "declared_grid": {"architectures": [asdict(value) for value in architectures],
            "predicates": list(PREDICATES), "processors": list(PROCESSORS), "iterations": list(ITERATIONS),
            "trials": TRIALS, "horizon_seconds": HORIZON, "physical_qubit_budget": QUBIT_BUDGET},
        "planned_cells": len(architectures) * len(PREDICATES) * len(PROCESSORS) * len(ITERATIONS),
        "retained_cells": len(cells), "cells": cells,
        "undominated_with_certified_interval_order": frontier,
        "compared_resource_dimensions": list(RESOURCE_FIELDS),
        "scope": {
            "same_literal_domain_and_no_parent_switching": True,
            "full_candidate_check_also_for_restricted_predicate": True,
            "all_processors_and_service_auxiliaries_charged": True,
            "fixed_controller_reservation_is_not_verified_peak_usage": True,
            "factory_throughput_noise_and_failure_budget_unchanged": True,
            "fixed_budget_is_physical_qubits_and_horizon_not_complete_economics": True,
            "all_legal_architectures_algorithms_or_caches_enumerated": False,
        },
        "claims": {"physical_parameters_calibrated": False, "compiled_physical_layout": False,
            "complete_energy_or_capital_cost": False, "same_total_economic_budget_proved": False,
            "minimum_attacker_cost_proved": False, "quantum_hardware_executed": False,
            "quantum_mining_qualified": False, "production_activation": False},
    }
    if _sources() != sources:
        raise ValueError("ARCHITECTURE_FRONTIER_SOURCE_CHANGED")
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
    with args.output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
