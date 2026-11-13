#!/usr/bin/env python3
"""Conditional accounting of a winner predicate, never a W1 resource certificate.

No existing SHA/multiply component is multiplied into an invented complete W1
oracle. A missing stage keeps complete costs unknown. A supplied stage is a
caller assertion, not evidence that its circuit implements the W1 relation.

Current pon_work.rs separates evaluate_transcript from finish_product. For a
fixed public task, A B may be prepared classically; the winner ticket depends
on challenge and trace, so corrected-product/proof production is not silently
charged to each query. This observation does not implement a coherent trace
oracle or prove a shortcut correct for arbitrary task/search freedoms.

The surface-code equation is an explicit phenomenological *assumption*, not a
fit or a compiled machine. Counts include every independent processor; parallel
speed is never free work. This module grants no mining or activation authority.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
from typing import Any

SCHEMA = "trnm-quantum-oracle-resource-v1"
MAX_INPUT_BYTES = 131072
MAX_COUNT = 2**64 - 1
MAX_DERIVED = 2**256 - 1
MAX_MODELS = 16
STAGES = ("prepare", "winner_compute", "phase_marker", "diffusion")
# These are dependency obligations, not asserted minimum gate counts.
W1_OBLIGATIONS = (
    "search_domain_and_header_challenge_binding",
    "bounded_noise_expansion_and_rejection",
    "low_rank_factors_and_challenge_matrices",
    "ordered_tiled_prefix_transcript",
    "ticket_domain_and_inclusive_target_comparison",
    "phase_marking_and_complete_garbage_uncomputation",
    "data_access_and_persistent_register_schedule",
)


def integer(value: Any, name: str, low: int = 0, high: int = MAX_COUNT) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(name)
    return value


def bounded(value: int) -> int:
    return integer(value, "DERIVED_COUNT_OVERFLOW", high=MAX_DERIVED)


def dec(value: Any, name: str, *, positive: bool = False) -> Decimal:
    if type(value) is not str or len(value) > 100:
        raise ValueError(name)
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(name) from error
    if not number.is_finite() or not 0 <= number <= Decimal("1e100"):
        raise ValueError(name)
    if number and number.adjusted() < -100:
        raise ValueError(name)
    if positive and not number:
        raise ValueError(name)
    return number


def exact(obj: Any, keys: set[str], label: str) -> dict:
    if type(obj) is not dict or set(obj) != keys:
        raise ValueError(label)
    return obj


def label(value: Any, name: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,200}", value):
        raise ValueError(name)
    return value


def fraction(value: Fraction) -> dict:
    return {"numerator": value.numerator, "denominator": value.denominator}


def decimal_text(value: Decimal) -> str:
    return format(value, ".30g")


@dataclass(frozen=True)
class Circuit:
    """One stage; qubits count *all live registers*, including persistent memory.

    Counts describe a caller-supplied X/CNOT/Toffoli/T abstraction. winner_compute
    is the forward computation of the winner predicate, including any garbage.
    Its inverse is charged independently with identical count/depth. An already
    compute-copy-uncompute component may be used inside it, but is not a phase
    oracle by itself. Stage transitions assume compatible register allocations.
    """
    logical_qubits: int
    gate_count: int
    gate_depth: int
    toffoli_count: int
    toffoli_depth: int
    direct_t_count: int
    direct_t_depth: int
    provenance: str

    def validate(self) -> None:
        for key, value in asdict(self).items():
            if key != "provenance":
                integer(value, "CIRCUIT_" + key.upper())
        label(self.provenance, "CIRCUIT_PROVENANCE")
        if not self.logical_qubits or self.gate_depth > self.gate_count:
            raise ValueError("CIRCUIT_SHAPE")
        if self.toffoli_count + self.direct_t_count > self.gate_count:
            raise ValueError("CIRCUIT_GATE_SUBTOTAL")
        for count, depth in ((self.gate_count, self.gate_depth),
                             (self.toffoli_count, self.toffoli_depth),
                             (self.direct_t_count, self.direct_t_depth)):
            if depth > count or bool(count) != bool(depth):
                raise ValueError("CIRCUIT_COUNT_DEPTH")
        if max(self.toffoli_depth, self.direct_t_depth) > self.gate_depth:
            raise ValueError("CIRCUIT_DEPENDENCY_DEPTH")


@dataclass(frozen=True)
class Workload:
    """Identical finite workload per independent processor.

    Interrupted entries stop before a completed candidate measurement, so they
    produce no candidate to recheck. Partial classical checks after a completed
    measurement are outside this workload schema. Completed winners may come
    only from measured full trials. Search-domain changes and restart policies
    are supplied by the caller.
    """
    task_count: int
    searches_per_task: int
    independent_instances: int
    full_trials_per_search_instance: int
    iterations_per_full_trial: int
    interrupted_iterations_per_search_instance: tuple[int, ...]
    completed_winners: int

    def validate(self) -> None:
        for key, value in asdict(self).items():
            if key != "interrupted_iterations_per_search_instance":
                integer(value, "WORKLOAD_" + key.upper())
        if min(self.task_count, self.searches_per_task, self.independent_instances) < 1:
            raise ValueError("EMPTY_WORKLOAD")
        items = self.interrupted_iterations_per_search_instance
        if type(items) is not tuple or len(items) > 4096:
            raise ValueError("INTERRUPTION_LIST")
        for value in items:
            integer(value, "INTERRUPTED_ITERATIONS", high=self.iterations_per_full_trial)
        full = bounded(self.task_count * self.searches_per_task * self.independent_instances
                       * self.full_trials_per_search_instance)
        if self.completed_winners > full:
            raise ValueError("WINNERS_EXCEED_MEASURED_FULL_TRIALS")
        if not self.full_trials_per_search_instance and not items:
            raise ValueError("NO_TRIALS")


@dataclass(frozen=True)
class ClassicalCosts:
    """Caller supplied nanoseconds, not measurements made by this calculator.

    Preprocessing is paid once per task and shared across its searches. Search
    setup is paid once per search *per processor*. Trial reset/readout is charged
    for aborted trials as well; this conservative uniform charge is declared.
    Each completed measurement is followed by a classical recheck of the whole
    winner predicate: the phase oracle has uncomputed its winner bit. This
    recheck is charged for failed candidates and zero-iteration trials as well;
    abandoned interruptions produce no candidate and receive no recheck charge.
    Proof construction and propagation are separate, per completed winner only.
    These are resource charges, not quantum wall time. No coherent state is
    retained through these classical waits; otherwise its idle cycles and errors
    must be supplied in the circuit schedule before using the physical estimate.
    """
    task_preprocessing_ns: int
    per_search_setup_ns: int
    per_trial_reset_readout_ns: int
    per_completed_trial_candidate_check_ns: int
    per_winner_proof_ns: int
    per_winner_propagation_ns: int

    def validate(self) -> None:
        for key, value in asdict(self).items():
            integer(value, "CLASSICAL_" + key.upper())
        integer(self.per_completed_trial_candidate_check_ns,
                "CLASSICAL_PER_COMPLETED_TRIAL_CANDIDATE_CHECK_NS", 1)


@dataclass(frozen=True)
class PhysicalModel:
    """Phenomenological model, never a physical implementation or lower bound.

    p_L(d) = prefactor * (physical_error / threshold)^((d+1)/2)
    The union estimate charges every live logical patch at every allocated code
    cycle, plus every distilled T state's caller-supplied residual error. An odd
    code distance is selected against that union estimate for the whole workload.
    These are hypothetical parameters, never measured W1 hardware results.
    """
    name: str
    physical_error: str
    threshold: str
    logical_error_prefactor: str
    cycle_ns: str
    logical_gate_cycles_per_distance: int
    toffoli_decomposition_depth: int
    t_per_toffoli: int
    t_depth_per_toffoli: int
    data_physical_qubits_per_d2: int
    factories_per_instance: int
    factory_physical_qubits_per_d2: int
    factory_t_cycles_per_distance: int
    magic_state_error: str
    total_failure_budget: str
    maximum_distance: int

    def validate(self) -> None:
        label(self.name, "PHYSICAL_MODEL_NAME")
        for key in ("physical_error", "threshold", "logical_error_prefactor", "cycle_ns",
                    "magic_state_error", "total_failure_budget"):
            dec(getattr(self, key), key.upper(), positive=key != "magic_state_error")
        if not dec(self.physical_error, "P") < dec(self.threshold, "THRESHOLD") <= 1:
            raise ValueError("PHYSICAL_ERROR_NOT_BELOW_THRESHOLD")
        if dec(self.logical_error_prefactor, "A") > 1:
            raise ValueError("LOGICAL_ERROR_PREFACTOR")
        if dec(self.total_failure_budget, "BUDGET") >= 1 or dec(self.magic_state_error, "MAGIC") >= 1:
            raise ValueError("FAILURE_PROBABILITY_RANGE")
        for key, value in asdict(self).items():
            if type(value) is int:
                integer(value, key.upper(), 1, 10**9)
        # Explicitly reject bools, which are not covered by type(value) is int.
        for key in ("logical_gate_cycles_per_distance", "toffoli_decomposition_depth",
                    "t_per_toffoli", "t_depth_per_toffoli", "data_physical_qubits_per_d2",
                    "factories_per_instance", "factory_physical_qubits_per_d2",
                    "factory_t_cycles_per_distance"):
            integer(getattr(self, key), key.upper(), 1, 10**9)
        integer(self.maximum_distance, "MAXIMUM_DISTANCE", 3, 1001)
        if self.maximum_distance % 2 != 1:
            raise ValueError("ODD_MAXIMUM_DISTANCE_REQUIRED")


@dataclass(frozen=True)
class Request:
    scope: str
    strategy: str
    data_access_assumption: str
    classical_preprocessing: tuple[str, ...]
    circuits: dict[str, Circuit | None]
    workload: Workload
    classical: ClassicalCosts
    physical_models: tuple[PhysicalModel, ...]

    def validate(self) -> None:
        if self.scope not in ("W1_INCOMPLETE", "CALLER_SUPPLIED_UNVERIFIED_PREDICATE",
                              "HYPOTHETICAL_NON_W1_EXAMPLE"):
            raise ValueError("SCOPE")
        label(self.strategy, "STRATEGY")
        label(self.data_access_assumption, "DATA_ACCESS_ASSUMPTION")
        if type(self.classical_preprocessing) is not tuple or len(self.classical_preprocessing) > 32:
            raise ValueError("PREPROCESSING_LIST")
        for item in self.classical_preprocessing:
            label(item, "PREPROCESSING_ENTRY")
        if len(set(self.classical_preprocessing)) != len(self.classical_preprocessing):
            raise ValueError("DUPLICATE_PREPROCESSING")
        exact(self.circuits, set(STAGES), "CIRCUIT_STAGES")
        for circuit in self.circuits.values():
            if circuit is not None:
                if type(circuit) is not Circuit:
                    raise ValueError("CIRCUIT_TYPE")
                circuit.validate()
        if self.scope == "W1_INCOMPLETE" and self.circuits["winner_compute"] is not None:
            raise ValueError("INCOMPLETE_W1_CANNOT_HAVE_COMPLETE_COMPUTE_BUDGET")
        if type(self.workload) is not Workload or type(self.classical) is not ClassicalCosts:
            raise ValueError("WORKLOAD_TYPE")
        self.workload.validate()
        self.classical.validate()
        if type(self.physical_models) is not tuple or len(self.physical_models) > MAX_MODELS:
            raise ValueError("PHYSICAL_MODELS")
        if any(type(item) is not PhysicalModel for item in self.physical_models):
            raise ValueError("PHYSICAL_MODEL_TYPE")
        for item in self.physical_models:
            item.validate()
        if len({item.name for item in self.physical_models}) != len(self.physical_models):
            raise ValueError("DUPLICATE_PHYSICAL_MODEL")


def _sum_circuits(circuits: list[tuple[Circuit, int]]) -> dict:
    fields = ("gate_count", "gate_depth", "toffoli_count", "toffoli_depth",
              "direct_t_count", "direct_t_depth")
    return {key: bounded(sum(getattr(item, key) * count for item, count in circuits))
            for key in fields}


def physical_estimate(counts: dict, qubits: int, instances: int,
                      model: PhysicalModel) -> dict:
    """counts are serial totals *per instance* across every task/search.

    Identical workloads run on independent processors. The allocated schedule
    adds serial delivery time for every T state to data execution time; its
    longer duration is used for the union error estimate. A separate lower
    bound assumes ideal overlap of data execution and all factory throughput.
    Qubit counts pay for both resources and every processor. Routing and
    connectivity must be included in the supplied factors. Classical waits
    retain no coherent state and are outside these quantum wall times.
    """
    model.validate()
    exact(counts, {"gate_count", "gate_depth", "toffoli_count", "toffoli_depth",
                   "direct_t_count", "direct_t_depth"}, "PHYSICAL_COUNT_SCHEMA")
    for key, value in counts.items():
        integer(value, "PHYSICAL_" + key.upper(), high=MAX_DERIVED)
    integer(qubits, "PHYSICAL_LOGICAL_QUBITS", 1)
    integer(instances, "PHYSICAL_INSTANCES", 1)
    with localcontext() as ctx:
        ctx.prec = 100
        t_count = bounded(counts["direct_t_count"] + model.t_per_toffoli * counts["toffoli_count"])
        t_depth_bound = bounded(counts["direct_t_depth"] + model.t_depth_per_toffoli * counts["toffoli_depth"])
        decomposed_depth = bounded(max(
            counts["gate_depth"] * model.toffoli_decomposition_depth, t_depth_bound))
        depth_cycles_unit = bounded(decomposed_depth * model.logical_gate_cycles_per_distance)
        factory_rounds = (t_count + model.factories_per_instance - 1) // model.factories_per_instance
        factory_cycles_unit = bounded(factory_rounds * model.factory_t_cycles_per_distance)
        ideal_cycle_unit = max(depth_cycles_unit, factory_cycles_unit)
        allocated_cycle_unit = bounded(depth_cycles_unit + t_count * model.factory_t_cycles_per_distance)
        magic_state_count = bounded(t_count * instances)
        magic_error = dec(model.magic_state_error, "MAGIC")
        magic_failure = Decimal(magic_state_count) * magic_error
        budget = dec(model.total_failure_budget, "BUDGET")
        # Decimal values retain the report's presentation. Budget decisions
        # use the exact decimal inputs, including gaps below that precision.
        magic_failure_exact = magic_state_count * Fraction(magic_error)
        budget_exact = Fraction(budget)
        common = {"name": model.name, "assumptions": asdict(model),
                  "t_count_per_instance_conditional": t_count,
                  "t_depth_upper_bound_per_instance_conditional": t_depth_bound,
                  "whole_workload_magic_error_union_estimate": decimal_text(magic_failure),
                  "model_is_physical_calibration": False}
        if magic_failure_exact >= budget_exact:
            return {**common, "status": "UNSATISFIED_MAGIC_STATE_ERROR_BUDGET", "estimate": None}
        physical_error = dec(model.physical_error, "P")
        threshold = dec(model.threshold, "THRESHOLD")
        ratio = physical_error / threshold
        ratio_exact = Fraction(physical_error) / Fraction(threshold)
        prefactor = dec(model.logical_error_prefactor, "A")
        for distance in range(3, model.maximum_distance + 1, 2):
            cycles = bounded(allocated_cycle_unit * distance)
            patch_cycles = bounded(qubits * cycles * instances)
            logical_error = prefactor * ratio ** ((distance + 1) // 2)
            failure = Decimal(patch_cycles) * logical_error + magic_failure
            failure_exact = (patch_cycles * Fraction(prefactor)
                             * ratio_exact ** ((distance + 1) // 2) + magic_failure_exact)
            if failure_exact <= budget_exact:
                data = bounded(model.data_physical_qubits_per_d2 * distance**2 * qubits)
                factories = bounded(model.factory_physical_qubits_per_d2 * distance**2
                                    * model.factories_per_instance)
                return {**common, "status": "CONDITIONAL_ESTIMATE", "estimate": {
                    "code_distance": distance,
                    "allocated_code_cycles_per_instance": cycles,
                    "data_physical_qubits_per_instance": data,
                    "factory_physical_qubits_per_instance": factories,
                    "total_physical_qubits_all_instances": bounded((data + factories) * instances),
                    "quantum_wall_seconds_serial_magic_delivery_schedule": decimal_text(
                        Decimal(cycles) * dec(model.cycle_ns, "CYCLE_NS") / 10**9),
                    "quantum_wall_seconds_ideal_overlap_lower_bound": decimal_text(
                        Decimal(ideal_cycle_unit * distance) * dec(model.cycle_ns, "CYCLE_NS") / 10**9),
                    "factory_error_includes_all_factory_faults_assumed": True,
                    "logical_error_per_patch_cycle_assumption": decimal_text(logical_error),
                    "whole_workload_failure_union_estimate": decimal_text(failure),
                    "bottleneck": "factory" if factory_cycles_unit > depth_cycles_unit else "depth",
                }}
        return {**common, "status": "NO_DISTANCE_IN_DECLARED_RANGE", "estimate": None}


def account(request: Request) -> dict:
    request.validate()
    w, c = request.workload, request.classical
    searches = bounded(w.task_count * w.searches_per_task)
    per_instance_trials = bounded(searches * (w.full_trials_per_search_instance
                                             + len(w.interrupted_iterations_per_search_instance)))
    per_instance_iterations = bounded(searches * (
        w.full_trials_per_search_instance * w.iterations_per_full_trial
        + sum(w.interrupted_iterations_per_search_instance)))
    search_instances = bounded(searches * w.independent_instances)
    total_trials = bounded(per_instance_trials * w.independent_instances)
    completed_trials = bounded(w.full_trials_per_search_instance * search_instances)
    preprocessing = bounded(c.task_preprocessing_ns * w.task_count)
    classical = {
        "task_preprocessing_ns_total": preprocessing,
        "per_search_setup_ns_total": bounded(c.per_search_setup_ns * search_instances),
        "trial_reset_readout_ns_total": bounded(c.per_trial_reset_readout_ns * total_trials),
        "completed_trial_candidate_check_ns_total": bounded(
            c.per_completed_trial_candidate_check_ns * completed_trials),
        "winner_proof_ns_total": bounded(c.per_winner_proof_ns * w.completed_winners),
        "winner_propagation_ns_sum": bounded(c.per_winner_propagation_ns * w.completed_winners),
        "amortized_preprocessing_ns_per_search_instance": fraction(Fraction(preprocessing, search_instances)),
        "per_trial_readout_also_charged_for_interruptions": True,
        "candidate_recheck_includes_failed_and_zero_iteration_full_trials": True,
        "candidate_recheck_excludes_abandoned_interruptions": True,
        "values_are_caller_supplied": True,
        "totals_are_resource_charges_not_parallel_wall_time": True,
        "no_coherent_state_retained_during_classical_waits_assumption": True,
    }
    missing = [key for key in STAGES if request.circuits[key] is None]
    result = {
        "schema": SCHEMA, "scope": request.scope,
        "strategy": request.strategy,
        "data_access_assumption": request.data_access_assumption,
        "classical_preprocessing": list(request.classical_preprocessing),
        "workload": asdict(w), "circuit_inputs": {k: asdict(v) if v else None for k, v in request.circuits.items()},
        "per_instance_total_trials": per_instance_trials,
        "all_instances_completed_measured_trials": completed_trials,
        "interrupted_trials_have_no_accepted_winner_measurement": True,
        "per_instance_total_grover_iterations_including_interrupted": per_instance_iterations,
        "classical_costs": classical, "missing_circuit_stages": missing,
        "w1_dependency_obligations": list(W1_OBLIGATIONS),
        "complete_quantum_cost": None, "physical_sensitivity": [],
        "gate_counts_are_caller_assertions_not_verified_netlists": True,
        "full_W1_oracle_constructed": False, "quantum_work_lower_bound_proved": False,
        "quantum_mining_qualified": False, "production_activation": False,
        "winner_probability_or_security_threshold_inferred": False,
    }
    if missing:
        result["status"] = "UNKNOWN_COMPLETE_ORACLE_COST"
        result["physical_sensitivity"] = [
            {"name": m.name, "status": "UNKNOWN_COMPLETE_ORACLE_COST", "estimate": None}
            for m in request.physical_models]
        return result
    prepare = request.circuits["prepare"]
    compute = request.circuits["winner_compute"]
    marker = request.circuits["phase_marker"]
    diffusion = request.circuits["diffusion"]
    iteration = _sum_circuits([(compute, 2), (marker, 1), (diffusion, 1)])
    counts = {key: bounded(value * per_instance_iterations + getattr(prepare, key) * per_instance_trials)
              for key, value in iteration.items()}
    qubits = max(stage.logical_qubits for stage in request.circuits.values())
    result["status"] = "CALLER_CONDITIONAL_ACCOUNTING_ONLY"
    result["complete_quantum_cost"] = {
        "per_grover_iteration": iteration,
        "per_instance_workload": counts,
        "all_instances_gate_counts": {k: bounded(v * w.independent_instances)
                                      for k, v in counts.items() if not k.endswith("depth")},
        "logical_qubits_peak_per_instance": qubits,
        "logical_qubits_peak_all_instances": bounded(qubits * w.independent_instances),
        "register_schedule_assumption": "each stage peak includes all persistent inputs and live memory; compatible reuse",
        "inverse_compute_charged": True,
        "post_winner_proof_in_per_iteration_cost": False,
    }
    result["physical_sensitivity"] = [physical_estimate(counts, qubits, w.independent_instances, m)
                                      for m in request.physical_models]
    return result


def parse_request(value: Any) -> Request:
    keys = {"schema", "scope", "strategy", "data_access_assumption", "classical_preprocessing",
            "circuits", "workload", "classical", "physical_models"}
    data = exact(value, keys, "REQUEST_SCHEMA")
    if data["schema"] != SCHEMA:
        raise ValueError("SCHEMA_VERSION")
    stages = exact(data["circuits"], set(STAGES), "CIRCUIT_STAGES")
    circuits = {key: None if value is None else Circuit(**exact(value, set(Circuit.__dataclass_fields__), "CIRCUIT_SCHEMA"))
                for key, value in stages.items()}
    work = dict(exact(data["workload"], set(Workload.__dataclass_fields__), "WORKLOAD_SCHEMA"))
    if type(work["interrupted_iterations_per_search_instance"]) is not list:
        raise ValueError("INTERRUPTION_ARRAY")
    work["interrupted_iterations_per_search_instance"] = tuple(work["interrupted_iterations_per_search_instance"])
    if type(data["physical_models"]) is not list or type(data["classical_preprocessing"]) is not list:
        raise ValueError("REQUEST_ARRAYS")
    models = tuple(PhysicalModel(**exact(item, set(PhysicalModel.__dataclass_fields__), "PHYSICAL_SCHEMA"))
                   for item in data["physical_models"])
    request = Request(data["scope"], data["strategy"], data["data_access_assumption"],
                      tuple(data["classical_preprocessing"]), circuits, Workload(**work),
                      ClassicalCosts(**exact(data["classical"], set(ClassicalCosts.__dataclass_fields__), "CLASSICAL_SCHEMA")), models)
    request.validate()
    return request


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def load_request(raw: bytes) -> Request:
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("INPUT_BYTE_BOUND")
    def reject_number(value):
        raise ValueError("NONFINITE_JSON_NUMBER:" + value)
    return parse_request(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                                    parse_constant=reject_number))


def example(complete_hypothesis: bool = False) -> Request:
    # These tiny counts are a deliberate arithmetic example, never W1 figures.
    stage = Circuit(100, 40, 10, 8, 3, 0, 0, "hypothetical-arithmetic-example")
    physical = tuple(PhysicalModel(
        name="illustrative-p-" + error, physical_error=error, threshold="0.01",
        logical_error_prefactor="0.1", cycle_ns="1000",
        logical_gate_cycles_per_distance=1, toffoli_decomposition_depth=10,
        t_per_toffoli=7, t_depth_per_toffoli=3, data_physical_qubits_per_d2=2,
        factories_per_instance=2, factory_physical_qubits_per_d2=100,
        factory_t_cycles_per_distance=10, magic_state_error="1e-15",
        total_failure_budget="0.01", maximum_distance=101,
    ) for error in ("0.0001", "0.001", "0.003"))
    return Request(
        "HYPOTHETICAL_NON_W1_EXAMPLE" if complete_hypothesis else "W1_INCOMPLETE",
        "fixed public task with per-challenge nonce search",
        "all coherent loading and memory must be included in supplied stages",
        ("fixed public matrices and their canonical task identity", "public AB if useful after winner"),
        {key: stage if complete_hypothesis else None for key in STAGES},
        Workload(1, 4, 2, 8, 32, (7, 11), 1),
        ClassicalCosts(1000000, 10000, 1000, 20000, 1000000000, 100000000), physical,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=Path)
    group.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    if args.demo:
        result = {"W1": account(example()), "hypothetical_arithmetic_example": account(example(True))}
    else:
        if args.input.is_symlink() or not args.input.is_file() or args.input.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("INPUT_FILE_BOUND")
        raw = args.input.read_bytes()
        result = account(load_request(raw))
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
