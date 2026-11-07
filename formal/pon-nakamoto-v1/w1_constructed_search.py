"""Bind literal W1 marked domains to one conservative constructed-circuit clock.

The complete planned schedule, including rounds never reached after a success,
pays one common code distance and all independent processors. The full and
prefix-restricted phase predicates are separately identified; final candidate
validation still uses the full literal W1 relation. This is an upper-bound
construction under declared physical premises, not a calibrated machine,
attacker minimum, native block-admission result or consensus security theorem.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from fractions import Fraction
import hashlib
from pathlib import Path

from quantum_adversarial_search import TrialCosts
from quantum_oracle_resources import ClassicalCosts, PhysicalModel, Workload, bounded, integer
from quantum_resource_clock import decimal_upper, float_upper, stage_units
from w1_marked_domain import (MAX_DOMAINS, MAX_ITERATIONS, MAX_PROCESSORS, MAX_TRIALS,
                              replay_domain)
from w1_quantum_oracle import OracleProgram, SOURCE_FILES, canonical, template_from_spec
from w1_quantum_restricted_oracle import PrefixRestrictedProgram

SCHEMA = "trnm-w1-constructed-bounded-search-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCES = SOURCE_FILES + (
    "formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py",
    "formal/pon-nakamoto-v1/w1_marked_domain.py",
    "formal/pon-nakamoto-v1/w1_bounded_search.py",
    "formal/pon-nakamoto-v1/w1_constructed_search.py",
    "formal/pon-nakamoto-v1/quantum_oracle_resources.py",
    "formal/pon-nakamoto-v1/quantum_resource_clock.py",
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
)


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def _rational(value):
    return Fraction(Decimal(value))


def _ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


@dataclass(frozen=True)
class ConstructedBinding:
    costs: tuple[TrialCosts, ...]
    propagation_seconds: tuple[float, ...]
    certificate: dict


def bind_constructed_search(domains, schedule, processors, classical_costs,
                            physical_model, physical_qubit_budget, *, predicate="full"):
    """Replay every domain and derive costs from its actual declared construction.

    Classical task preprocessing is shared once per resident template. Declared
    per-processor search setup is serialized and charged for every processor on
    first use or template change. Readout occurs on all processors in parallel;
    candidate checks are serialized by the bounded-search executor. No coherent
    state is kept across these classical phases.
    """
    if type(domains) is not tuple or not 1 <= len(domains) <= MAX_DOMAINS:
        raise ValueError("CONSTRUCTED_SEARCH_DOMAINS")
    if type(schedule) is not tuple or not 1 <= len(schedule) <= MAX_TRIALS:
        raise ValueError("CONSTRUCTED_SEARCH_SCHEDULE")
    integer(processors, "CONSTRUCTED_SEARCH_PROCESSORS", 1, MAX_PROCESSORS)
    if type(predicate) is not str or predicate not in ("full", "prefix-restricted"):
        raise ValueError("CONSTRUCTED_SEARCH_PREDICATE")
    if type(classical_costs) is not tuple or len(classical_costs) != len(domains):
        raise ValueError("CONSTRUCTED_CLASSICAL_COSTS")
    for costs in classical_costs:
        if type(costs) is not ClassicalCosts:
            raise ValueError("CONSTRUCTED_CLASSICAL_COST_TYPE")
        costs.validate()
        integer(costs.per_trial_reset_readout_ns, "POSITIVE_RESET_READOUT_REQUIRED", 1)
    if type(physical_model) is not PhysicalModel:
        raise ValueError("CONSTRUCTED_PHYSICAL_MODEL")
    physical_model.validate()
    integer(physical_qubit_budget, "PHYSICAL_QUBIT_BUDGET", 1, (1 << 256) - 1)
    for item in schedule:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("CONSTRUCTED_SCHEDULE_ENTRY")
        integer(item[0], "CONSTRUCTED_DOMAIN_INDEX", 0, len(domains) - 1)
        integer(item[1], "CONSTRUCTED_ITERATIONS", 0, MAX_ITERATIONS)
    sources = _sources()
    checked = tuple(replay_domain(record) for record in domains)
    constructor = OracleProgram if predicate == "full" else PrefixRestrictedProgram
    domain_resources, units_by_domain = [], []
    for record, classical in zip(checked, classical_costs):
        program = constructor(template_from_spec(record["template"]))
        resources = program.resources()
        request = program.resource_request(Workload(1, 1, processors, 1, 0, (), 0), classical)
        units = {name: stage_units(circuit, physical_model)
                 for name, circuit in request.circuits.items()}
        iteration = {key: bounded(2 * units["winner_compute"][key]
                                  + units["phase_marker"][key] + units["diffusion"][key])
                     for key in units["prepare"]}
        if not iteration["serial_cycles_per_distance"]:
            raise ValueError("EMPTY_CONSTRUCTED_ITERATION")
        units_by_domain.append((units["prepare"], iteration))
        phase_marked = record["marked_count"] if predicate == "full" else record["prefix_restricted_marked_count"]
        domain_resources.append({
            "domain_sha256": record["domain_sha256"],
            "template_sha256": record["template_sha256"],
            "construction_sha256": resources["construction_sha256"],
            "construction_schema": resources["schema"],
            "construction_scope": resources["scope"],
            "nonce_bits": resources["nonce_bits"],
            "logical_qubits": resources["logical_qubits"],
            "phase_predicate": predicate,
            "phase_marked_count": phase_marked,
            "full_w1_accepted_count": record["marked_count"],
            "domain_size": record["domain_size"],
            "discarded_full_w1_winners_may_pass_final_check": predicate == "prefix-restricted",
            "forward_gate_count": resources["forward_gate_count"],
            "phase_oracle_gate_count": resources["phase_oracle_gate_count"],
            "stage_cycle_units": units,
            "iteration_cycle_units": iteration,
            "classical_costs_ns": asdict(classical),
        })
    peak = max(row["logical_qubits"] for row in domain_resources)
    cycle_units = states = iterations = 0
    planned = []
    for domain_index, count in schedule:
        prep, iteration = units_by_domain[domain_index]
        cycles = bounded(prep["serial_cycles_per_distance"] + count * iteration["serial_cycles_per_distance"])
        t_states = bounded(prep["t_states"] + count * iteration["t_states"])
        cycle_units = bounded(cycle_units + cycles)
        states = bounded(states + t_states)
        iterations = bounded(iterations + count)
        planned.append({"domain_index": domain_index, "iterations": count,
                        "serial_cycle_units_per_processor": cycles,
                        "t_states_per_processor": t_states})
    model = physical_model
    magic_failure = bounded(states * processors) * _rational(model.magic_state_error)
    budget = _rational(model.total_failure_budget)
    if magic_failure >= budget:
        raise ValueError("UNSATISFIED_SCHEDULE_MAGIC_STATE_ERROR_BUDGET")
    error_ratio = _rational(model.physical_error) / _rational(model.threshold)
    prefactor = _rational(model.logical_error_prefactor)
    distance = failure = None
    for candidate in range(3, model.maximum_distance + 1, 2):
        current = (bounded(peak * cycle_units * candidate * processors)
                   * prefactor * error_ratio ** ((candidate + 1) // 2) + magic_failure)
        if current <= budget:
            distance, failure = candidate, current
            break
    if distance is None:
        raise ValueError("NO_DISTANCE_FOR_PLANNED_SCHEDULE")
    data_qubits = bounded(model.data_physical_qubits_per_d2 * distance**2 * peak)
    factory_qubits = bounded(model.factory_physical_qubits_per_d2 * distance**2
                             * model.factories_per_instance)
    total_qubits = bounded((data_qubits + factory_qubits) * processors)
    if total_qubits > physical_qubit_budget:
        raise ValueError("INSUFFICIENT_PHYSICAL_QUBITS")
    seconds_per_unit = _rational(model.cycle_ns) * distance / 10**9
    bound_costs, propagation = [], []
    for row, (prep, iteration), classical in zip(domain_resources, units_by_domain, classical_costs):
        exact = {
            "prepare_seconds": prep["serial_cycles_per_distance"] * seconds_per_unit,
            "iteration_seconds": iteration["serial_cycles_per_distance"] * seconds_per_unit,
            "measurement_seconds": Fraction(classical.per_trial_reset_readout_ns, 10**9),
            "candidate_check_seconds": Fraction(classical.per_completed_trial_candidate_check_ns, 10**9),
            "proof_seconds": Fraction(classical.per_winner_proof_ns, 10**9),
            "domain_setup_seconds": Fraction(classical.task_preprocessing_ns
                                             + processors * classical.per_search_setup_ns, 10**9),
            "propagation_seconds": Fraction(classical.per_winner_propagation_ns, 10**9),
        }
        # The search executor pays exact fractions of these represented clocks.
        # Upward conversion can only make the declared miner slower.
        rounded = {name: float_upper(value) for name, value in exact.items()}
        cost = TrialCosts(**{name: value for name, value in rounded.items()
                             if name != "propagation_seconds"}, clock_rounding="upward")
        cost.validate()
        bound_costs.append(cost)
        propagation.append(rounded["propagation_seconds"])
        row["clock_seconds_exact"] = {name: _ratio(value) for name, value in exact.items()}
        row["clock_seconds_float_upper"] = rounded
    certificate = {
        "schema": SCHEMA,
        "source_sha256": sources,
        "schedule": [list(item) for item in schedule],
        "processors": processors,
        "predicate": predicate,
        "final_candidate_check_predicate": "full-literal-W1",
        "physical_model": asdict(model),
        "physical_qubit_budget": physical_qubit_budget,
        "domain_resources": domain_resources,
        "code_distance_for_whole_schedule": distance,
        "logical_qubits_reserved_per_processor": peak,
        "data_physical_qubits_per_processor": data_qubits,
        "factory_physical_qubits_per_processor": factory_qubits,
        "physical_qubits_all_processors": total_qubits,
        "whole_schedule_failure_union_upper_rounded": decimal_upper(failure),
        "whole_schedule_failure_union_exact": _ratio(failure),
        "whole_schedule_magic_error_exact": _ratio(magic_failure),
        "envelope": {
            "planned_trials_per_processor": len(schedule),
            "planned_iterations_per_processor": iterations,
            "serial_cycles_per_processor": bounded(cycle_units * distance),
            "t_states_all_processors": bounded(states * processors),
            "planned_rounds": planned,
            "early_success_and_censoring_do_not_reduce_provisioned_envelope": True,
        },
        "classical_setup_policy": "single resident template; shared task preprocessing plus serialized setup for all processors on first use or change",
        "measurement_policy": "parallel readout and serialized full-W1 candidate checks for all processors; one proof and propagation after first accepted batch",
        "quantum_schedule": "serial stages and magic-state service, complete compute-marker-uncompute and diffusion",
        "magic_service_premise": "per-T service includes production, delivery, injection and feedforward; factory footprint includes its live service/buffer patch",
        "failure_budget_scope": "coherent stage patch-cycles plus declared T-service errors; initialization, reset, readout and controller assumed ideal or outside scope",
        "coherent_state_during_classical_waits": False,
        "census_replay_and_observer_cost_charged_to_miner": False,
        "domain_input_premise": "declared fixed public input bytes preexist; no claim that the miner can obtain them for free",
        "conditional_success_bound_to_actual_phase_and_candidate_predicates": True,
        "physical_model_is_calibration": False,
        "fault_tolerant_schedule_verified": False,
        "end_to_end_machine_failure_bound": False,
        "attacker_minimum_cost_proved": False,
        "native_node_admission_checked": False,
        "quantum_mining_qualified": False,
        "production_activation": False,
    }
    if _sources() != sources:
        raise ValueError("CONSTRUCTED_SEARCH_SOURCE_CHANGED")
    certificate["binding_sha256"] = _digest(certificate)
    return ConstructedBinding(tuple(bound_costs), tuple(propagation), certificate)


def verify_constructed_binding(binding, domains, schedule, processors, classical_costs,
                               physical_model, physical_qubit_budget, *, predicate="full"):
    """Rebuild circuit counts and literal predicates; caller-supplied digests do not certify them."""
    if type(binding) is not ConstructedBinding:
        raise ValueError("CONSTRUCTED_BINDING_TYPE")
    rebuilt = bind_constructed_search(domains, schedule, processors, classical_costs,
                                     physical_model, physical_qubit_budget, predicate=predicate)
    if canonical(asdict(binding)) != canonical(asdict(rebuilt)):
        raise ValueError("CONSTRUCTED_BINDING_MISMATCH")


def run_constructed_search(domains, schedule, processors, seed, classical_costs,
                           physical_model, physical_qubit_budget, horizon_seconds,
                           *, predicate="full"):
    """Run the bounded simulator with derived clocks and retain the prior full envelope."""
    from w1_bounded_search import horizon, simulate_bounded_measurements
    # Cheap caller-shape validation precedes expensive census/circuit replay.
    integer(seed, "SEARCH_SEED", 0, (1 << 64) - 1)
    horizon(horizon_seconds)
    binding = bind_constructed_search(domains, schedule, processors, classical_costs,
                                      physical_model, physical_qubit_budget, predicate=predicate)
    observation = simulate_bounded_measurements(
        domains, schedule, processors, seed, binding.costs, horizon_seconds,
        predicate=predicate, propagation_seconds=binding.propagation_seconds)
    if _sources() != binding.certificate["source_sha256"]:
        raise ValueError("CONSTRUCTED_SEARCH_SOURCE_CHANGED")
    return {"schema": SCHEMA, "binding": binding.certificate, "observation": observation,
            "quantum_mining_qualified": False, "production_activation": False}


def verify_constructed_search(record, domains):
    """Recompute the complete binding and seeded observation from serialized premises.

    Caller-provided circuit counts, hashes, outcomes and qualification flags are
    never accepted as authority. The domain tuple itself is independently
    replayed by ``run_constructed_search``. Return the fresh verified record.
    """
    if (type(record) is not dict or set(record) != {
            "schema", "binding", "observation", "quantum_mining_qualified", "production_activation"}
            or record["schema"] != SCHEMA):
        raise ValueError("CONSTRUCTED_SEARCH_RECORD")
    binding, observation = record["binding"], record["observation"]
    if type(binding) is not dict or type(observation) is not dict:
        raise ValueError("CONSTRUCTED_SEARCH_RECORD")
    plan = observation.get("plan")
    if type(plan) is not dict:
        raise ValueError("CONSTRUCTED_SEARCH_PLAN")
    schedule = binding.get("schedule")
    rows = binding.get("domain_resources")
    physical = binding.get("physical_model")
    if (type(schedule) is not list or not 1 <= len(schedule) <= MAX_TRIALS
            or any(type(item) is not list or len(item) != 2 for item in schedule)
            or type(rows) is not list or not 1 <= len(rows) <= MAX_DOMAINS
            or any(type(row) is not dict for row in rows)
            or type(physical) is not dict
            or set(physical) != set(PhysicalModel.__dataclass_fields__)):
        raise ValueError("CONSTRUCTED_SEARCH_PREMISES")
    costs = []
    for row in rows:
        values = row.get("classical_costs_ns")
        if type(values) is not dict or set(values) != set(ClassicalCosts.__dataclass_fields__):
            raise ValueError("CONSTRUCTED_SEARCH_CLASSICAL_PREMISES")
        costs.append(ClassicalCosts(**values))
    required = {"processors", "predicate", "physical_qubit_budget"}
    if not required <= binding.keys() or not {"seed", "horizon_seconds"} <= plan.keys():
        raise ValueError("CONSTRUCTED_SEARCH_PREMISES")
    rebuilt = run_constructed_search(
        domains, tuple(tuple(item) for item in schedule), binding["processors"], plan["seed"],
        tuple(costs), PhysicalModel(**physical), binding["physical_qubit_budget"],
        plan["horizon_seconds"], predicate=binding["predicate"])
    if canonical(record) != canonical(rebuilt):
        raise ValueError("CONSTRUCTED_SEARCH_REPLAY_MISMATCH")
    return rebuilt
