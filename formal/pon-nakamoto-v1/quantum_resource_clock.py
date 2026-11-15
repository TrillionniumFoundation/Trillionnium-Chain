#!/usr/bin/env python3
"""Bind conditional circuit resources to a bounded event experiment.

This adapter pays for every independent processor and chooses one code distance
against an upper envelope of the *whole campaign*. It never calibrates hardware,
certifies a caller's predicate, or turns an upper-bound construction into the
cheapest possible miner. Only the explicitly serialized magic-state schedule is
used as an event clock; the ideal-overlap bound is never used as an achievable
speed. Classical preprocessing/setup is conservatively repeated on every trial.
This is an allowed, deliberately unoptimized strategy, not a lower bound.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from decimal import Decimal, ROUND_CEILING, localcontext
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from quantum_network_sim import NetworkScenario, run_network_scenario
from quantum_oracle_resources import (
    Circuit, PhysicalModel, Request, bounded, integer,
)

SCHEMA = "trnm-quantum-resource-clock-v1"
COUNTS = ("gate_count", "gate_depth", "toffoli_count", "toffoli_depth",
          "direct_t_count", "direct_t_depth")
ROOT = Path(__file__).resolve().parent
SOURCE_FILES = ("quantum_resource_clock.py", "quantum_oracle_resources.py",
                "quantum_network_sim.py", "quantum_adversarial_search.py",
                "quantum_daa_model.py", "reference.py")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def source_fingerprint() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCE_FILES}


def rational(value: str) -> Fraction:
    return Fraction(Decimal(value))


def decimal_upper(value: Fraction) -> str:
    """Printable conservative rounding; comparisons use the exact fraction."""
    with localcontext() as ctx:
        ctx.prec = 50
        ctx.rounding = ROUND_CEILING
        return str(Decimal(value.numerator) / Decimal(value.denominator))


def float_upper(value: Fraction, *, positive: bool = False) -> float:
    """No downward binary-float rounding can give the miner a cheaper clock."""
    if value < 0 or (positive and not value):
        raise ValueError("NONPOSITIVE_RESOURCE_CLOCK")
    result = float(value)
    if not math.isfinite(result) or result > 1e30:
        raise ValueError("RESOURCE_CLOCK_OUTSIDE_EVENT_RANGE")
    if Fraction.from_float(result) < value:
        result = math.nextafter(result, math.inf)
    # Event-engine positive quantum clocks have a declared nanosecond floor.
    if positive and result < 1e-9:
        result = 1e-9
    return result


def stage_units(stage: Circuit, model: PhysicalModel) -> dict[str, int]:
    """Per-distance units for a conditional serialized stage schedule.

    The declared per-T service must cover production, delivery, injection and
    feedforward, with a live service/buffer patch included in factory footprint.
    This is a premise, not a verified layout of a fault-tolerant machine.
    """
    states = bounded(stage.direct_t_count + stage.toffoli_count * model.t_per_toffoli)
    depth = bounded(max(stage.gate_depth * model.toffoli_decomposition_depth,
                        stage.direct_t_depth + stage.toffoli_depth * model.t_depth_per_toffoli))
    data = bounded(depth * model.logical_gate_cycles_per_distance)
    delivery = bounded(states * model.factory_t_cycles_per_distance)
    return {"t_states": states, "data_cycles_per_distance": data,
            "serial_cycles_per_distance": bounded(data + delivery)}


@dataclass(frozen=True)
class ClockBinding:
    scenario: NetworkScenario
    certificate: dict[str, Any]


def bind_resource_clock(case: NetworkScenario, request: Request, model_name: str,
                        physical_qubit_budget: int) -> ClockBinding:
    """Derive all quantum clocks; original caller workload is not a run bound.

    A single event may deliver many competing tips and restart honest mining
    for each. Thus max_events+1 is NOT a safe preparation count. There is at
    most one initial start and at most max_blocks starts per handled event,
    giving 1 + max_events*max_blocks. Each start is charged a full preparation
    and the largest permitted iteration count even when it is interrupted.
    Both error and qubit checks use this conservative envelope and all P copies.
    """
    case.validate()
    request.validate()
    integer(physical_qubit_budget, "PHYSICAL_QUBIT_BUDGET", 1, 2**256 - 1)
    if any(stage is None for stage in request.circuits.values()):
        raise ValueError("UNKNOWN_COMPLETE_ORACLE_COST")
    if request.workload.independent_instances != case.quantum_processors:
        raise ValueError("PROCESSOR_COUNT_MISMATCH")
    if case.quantum_initial_factor not in (0, 1) or any(
            shock.quantum_factor not in (0, 1) for shock in case.shocks):
        raise ValueError("UNBUDGETED_QUANTUM_SPEED_FACTOR")
    choices = [model for model in request.physical_models if model.name == model_name]
    if len(choices) != 1:
        raise ValueError("PHYSICAL_MODEL_NOT_FOUND")
    model = choices[0]
    c = request.classical
    if not c.per_trial_reset_readout_ns:
        raise ValueError("POSITIVE_RESET_READOUT_REQUIRED")
    # One network model has a common propagation baseline. Reject a different
    # resource premise instead of silently charging it only in a prose ledger.
    if abs(case.propagation_seconds - c.per_winner_propagation_ns / 10**9) > 1e-12:
        raise ValueError("PROPAGATION_PREMISE_MISMATCH")
    circuits = request.circuits
    assert all(isinstance(stage, Circuit) for stage in circuits.values())
    units = {name: stage_units(stage, model) for name, stage in circuits.items()}
    prep = units["prepare"]
    iteration = {key: bounded(2 * units["winner_compute"][key]
                              + units["phase_marker"][key] + units["diffusion"][key])
                 for key in prep}
    if not iteration["serial_cycles_per_distance"]:
        raise ValueError("EMPTY_ITERATION_SCHEDULE")
    if case.quantum_fixed_iterations is not None:
        q_max = case.quantum_fixed_iterations
    elif getattr(case, "quantum_trial_policy", "first-peak") == "bounded-throughput":
        q_max = max(case.quantum_iteration_candidates)
    else:
        q_max = case.quantum_max_iterations
    trials = bounded(1 + case.max_events * case.max_blocks)
    iterations = bounded(trials * q_max)
    processors = case.quantum_processors
    peak = max(stage.logical_qubits for stage in circuits.values())
    cycle_units = bounded(prep["serial_cycles_per_distance"] * trials
                          + iteration["serial_cycles_per_distance"] * iterations)
    states = bounded(prep["t_states"] * trials + iteration["t_states"] * iterations)
    magic_failure = bounded(states * processors) * rational(model.magic_state_error)
    failure_budget = rational(model.total_failure_budget)
    if magic_failure >= failure_budget:
        raise ValueError("UNSATISFIED_CAMPAIGN_MAGIC_STATE_ERROR_BUDGET")
    ratio = rational(model.physical_error) / rational(model.threshold)
    prefactor = rational(model.logical_error_prefactor)
    distance, failure = None, None
    for candidate in range(3, model.maximum_distance + 1, 2):
        error_per_cycle = prefactor * ratio ** ((candidate + 1) // 2)
        current = bounded(peak * cycle_units * candidate * processors) * error_per_cycle + magic_failure
        if current <= failure_budget:
            distance, failure = candidate, current
            break
    if distance is None:
        raise ValueError("NO_DISTANCE_FOR_CAMPAIGN_ENVELOPE")
    data_qubits = bounded(model.data_physical_qubits_per_d2 * distance**2 * peak)
    factory_qubits = bounded(model.factory_physical_qubits_per_d2 * distance**2
                             * model.factories_per_instance)
    total_qubits = bounded((data_qubits + factory_qubits) * processors)
    if total_qubits > physical_qubit_budget:
        raise ValueError("INSUFFICIENT_PHYSICAL_QUBITS")
    seconds_per_unit = rational(model.cycle_ns) * distance / 10**9
    # Paid before each preparation. This deliberately gives no free reusable
    # preprocessing or setup; optimized reuse is a separately modelled strategy.
    setup = Fraction(c.task_preprocessing_ns + c.per_search_setup_ns, 10**9)
    clock_exact = {
        "quantum_prepare_seconds": prep["serial_cycles_per_distance"] * seconds_per_unit + setup,
        "quantum_iteration_seconds": iteration["serial_cycles_per_distance"] * seconds_per_unit,
        "quantum_measure_seconds": Fraction(c.per_trial_reset_readout_ns, 10**9),
        "quantum_candidate_check_seconds": Fraction(c.per_completed_trial_candidate_check_ns, 10**9),
        "quantum_proof_seconds": Fraction(c.per_winner_proof_ns, 10**9),
    }
    clocks = {name: float_upper(value, positive=name in (
        "quantum_iteration_seconds", "quantum_measure_seconds", "quantum_candidate_check_seconds"))
              for name, value in clock_exact.items()}
    # Domain setup was already conservatively paid in *every* preparation.
    if "quantum_domain_setup_seconds" in case.__dataclass_fields__:
        clocks["quantum_domain_setup_seconds"] = 0.0
        clock_exact["quantum_domain_setup_seconds"] = Fraction(0)
    bound_case = replace(case, quantum_clock_rounding="upward", **clocks)
    bound_case.validate()
    certificate = {
        "schema": SCHEMA,
        "source_sha256": source_fingerprint(),
        "requested_scenario_sha256": digest(asdict(case)),
        "resource_request_sha256": digest(asdict(request)),
        "bound_scenario": asdict(bound_case),
        "model": asdict(model),
        "physical_qubit_budget": physical_qubit_budget,
        "code_distance_for_whole_campaign": distance,
        "physical_qubits_all_processors": total_qubits,
        "logical_qubits_per_processor": peak,
        "processors": processors,
        "envelope": {
            "trial_starts_per_processor": trials,
            "maximum_iterations_per_trial": q_max,
            "iterations_per_processor": iterations,
            "serial_cycles_per_processor": bounded(cycle_units * distance),
            "t_states_all_processors": bounded(states * processors),
            "trial_bound_reason": "one initial start plus at most max_blocks per handled event",
            "interruptions_charged_as_full_planned_trials": True,
        },
        "stage_cycle_units": units,
        "iteration_cycle_units": iteration,
        "whole_campaign_failure_union_upper_rounded": decimal_upper(failure),
        "whole_campaign_magic_error_upper_rounded": decimal_upper(magic_failure),
        "clock_seconds_exact": {name: {"numerator": value.numerator, "denominator": value.denominator}
                                for name, value in clock_exact.items()},
        "clock_seconds_float_upper": clocks,
        "event_deadline_rounding": "quantum search and proof deadlines rounded upward from exact sums of float inputs",
        "classical_setup_policy": "repeat task preprocessing and search setup before every trial",
        "quantum_schedule": "serial stage execution and serial magic delivery; includes inverse compute",
        "magic_service_premise": "per-T service includes production, delivery, immediate injection and feedforward; factory footprint pays at least one service/buffer patch",
        "fault_tolerant_schedule_verified": False,
        "coherent_state_during_classical_waits": False,
        "failure_budget_scope": "coherent stage cycles and declared T-service errors only; initialization/reset/readout and classical controller assumed ideal or outside scope",
        "end_to_end_machine_failure_bound": False,
        "original_workload_replaced_by_event_envelope": True,
        "gate_counts_need_independent_predicate_verification": True,
        "simulated_success_probabilities_bound_to_constructed_predicate": False,
        "physical_model_is_calibration": False,
        "cheapest_miner_or_lower_bound": False,
        "security_theorem": False,
        "production_activation": False,
    }
    certificate["binding_sha256"] = digest(certificate)
    return ClockBinding(bound_case, certificate)


def verify_binding(binding: ClockBinding, case: NetworkScenario, request: Request) -> None:
    """Rebuild the binding; forged timing, model, budgets or source are rejected."""
    data = binding.certificate
    rebuilt = bind_resource_clock(case, request, data["model"]["name"], data["physical_qubit_budget"])
    if data != rebuilt.certificate or asdict(binding.scenario) != asdict(rebuilt.scenario):
        raise ValueError("RESOURCE_CLOCK_BINDING_MISMATCH")


def audit_execution(binding: ClockBinding, summary: dict, trace: list[dict]) -> dict:
    """Check the run against its prior bound; resource evidence is not consensus evidence."""
    case, certificate = binding.scenario, binding.certificate
    if certificate["source_sha256"] != source_fingerprint():
        raise ValueError("STALE_RESOURCE_CLOCK_SOURCE")
    unsigned = {key: value for key, value in certificate.items() if key != "binding_sha256"}
    if digest(unsigned) != certificate["binding_sha256"] or asdict(case) != certificate["bound_scenario"]:
        raise ValueError("RESOURCE_CLOCK_BINDING_MISMATCH")
    q = summary["miners"]["q"]
    bound = certificate["envelope"]
    starts = integer(q["searches_started"], "OBSERVED_TRIALS", 0, bound["trial_starts_per_processor"])
    integer(q["logical_iterations_completed"], "OBSERVED_ITERATIONS", 0,
            bound["iterations_per_processor"] * case.quantum_processors)
    integer(q["candidate_checks_started"], "OBSERVED_CANDIDATE_CHECKS", 0,
            starts * case.quantum_processors)
    integer(q["proofs_started"], "OBSERVED_PROOFS", 0, starts)
    integer(summary["events_processed"], "OBSERVED_EVENTS", 0, case.max_events)
    integer(summary["blocks_created"], "OBSERVED_BLOCKS", 0, case.max_blocks)
    rows = [row for row in trace if row.get("kind") == "search-start" and row.get("miner") == "q"]
    if not summary["trace_limit_reached"] and len(rows) != starts:
        raise ValueError("TRIAL_TRACE_COUNT_MISMATCH")
    for row in rows:
        integer(row["iterations"], "OBSERVED_PLANNED_ITERATIONS", 0, bound["maximum_iterations_per_trial"])
    complete = summary["termination"] == "horizon" and not summary["trace_limit_reached"]
    return {
        "status": "CONDITIONAL_RESOURCE_BOUND_OBSERVATION" if complete else "INCOMPLETE_OBSERVATION",
        "binding_sha256": certificate["binding_sha256"],
        "observed_trial_starts": starts,
        "observed_iterations_all_processors": q["logical_iterations_completed"],
        "whole_campaign_envelope_respected": True,
        "code_distance_not_reoptimized_after_observation": True,
        "security_theorem": False, "native_w1_verified": False,
        "quantum_hardware_executed": False, "release_ready": False,
    }


def run_resource_bound(case: NetworkScenario, request: Request, model_name: str,
                       physical_qubit_budget: int) -> tuple[dict, list[dict], dict]:
    binding = bind_resource_clock(case, request, model_name, physical_qubit_budget)
    verify_binding(binding, case, request)
    summary, trace = run_network_scenario(binding.scenario)
    report = audit_execution(binding, summary, trace)
    return summary, trace, {"binding": binding.certificate, "execution": report}
