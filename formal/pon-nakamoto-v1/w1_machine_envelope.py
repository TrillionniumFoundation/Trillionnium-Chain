"""A conditional lifecycle envelope for constructed, fixed-domain W1 search.

This companion retains the original coherent-only resource namespace. It adds
derived initialization, transfer, readout, controller and finite factory-service
events to a whole predeclared schedule, then selects one code distance against
the unchanged caller failure budget. No CPU experiment calibrates these quantum
parameters. A declared error is a conditional fault-event bound with a specified
ideal-execution coupling; an infidelity or zero observed failures is insufficient.

The modeled machine deliberately serializes gates/services/control stalls and
the shared transfer bus. Independent quantum processors run each trial together.
The fixed allocation for each magic state includes every allowed attempt and
its discard/reset slot, even after an early successful attempt. This padding
makes the no-fault clock independent of the factory's heralded outcomes.

Primary-source boundaries: Beverland et al., arXiv:2211.07629v1 Appendix G,
explicitly lists classical/control and noise assumptions in a full-stack
estimate. Litinski, arXiv:1905.06903v3 Eqs. (2)-(4), distinguishes heralded
distillation rejection from conditional accepted-output infidelity; its mean
service time is not a deadline guarantee. Paler/Fowler/Wille,
arXiv:1711.01385v1, treats heralded failures as a scheduling concern. The event
contract and finite-slot union bound here are our conditional model, not a
hardware theorem imported from those papers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
from pathlib import Path

from quantum_oracle_resources import (ClassicalCosts, PhysicalModel, Workload,
                                       bounded, dec, integer, label)
from quantum_resource_clock import stage_units
from w1_bounded_search import horizon, ratio
from w1_constructed_search import SOURCES as CONSTRUCTED_SOURCES
from w1_marked_domain import MAX_DOMAINS, MAX_ITERATIONS, MAX_PROCESSORS, MAX_TRIALS, replay_domain
from w1_quantum_oracle import OracleProgram, canonical, template_from_spec
from w1_quantum_restricted_oracle import PrefixRestrictedProgram
from w1_search_probability import (ProbabilityInterval, ProbabilityTrial,
                                    coupled_success_bounds, probability_power_bounds,
                                    schedule_success_bounds)

SCHEMA = "trnm-w1-machine-lifecycle-envelope-v1"
RESERVED_SERVICE_SCHEMA = "trnm-w1-machine-reserved-service-envelope-v2"
NOISE_CONTRACT = "history-conditional-fault-events-and-ideal-no-fault-coupling-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCES = CONSTRUCTED_SOURCES + (
    "formal/pon-nakamoto-v1/w1_search_probability.py",
    "formal/pon-nakamoto-v1/w1_machine_envelope.py",
)


def _sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def _fraction(value):
    return Fraction(dec(value, "MACHINE_DECIMAL"))


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _ceil_div(left, right):
    return (left + right - 1) // right


@dataclass(frozen=True)
class LifecycleModel:
    """Explicit service premises, never a fit to physical hardware.

    Initialization and terminal nonce readout operate in bounded parallel
    batches per processor. Command latency is additional to logical gate and
    T-service time, including decoding/feedforward waits. Transfer uses one
    shared serialized bus with a fixed message charge plus a per-byte charge.
    ``host_call_failure_bound`` covers incorrect results or clock overruns of
    classical preprocessing, per-processor setup/turnaround/checks and each
    explicitly reserved proof.
    The separate propagation bound covers delivery failure or its clock overrun.

    Each probability is an upper bound conditional on the entire prior history
    before that event. Controller faults include corruption of cached templates
    or commands. Factory rejection bounds also hold after earlier rejections;
    marginal rejection rates cannot justify exponentiating them. Accepted magic
    state service faults use PhysicalModel.magic_state_error, including accepted
    output storage, transport, injection and factory internals. These broad
    premises need independent hardware/implementation evidence to become useful
    physical claims. They do not follow from sample maxima or zero failures.
    """
    name: str
    noise_contract: str
    initialization_cycles_per_distance: int
    initialization_parallel_patches: int
    readout_cycles_per_distance: int
    readout_parallel_bits: int
    controller_cycles_per_command: int
    transfer_fixed_ns: int
    transfer_ns_per_byte: int
    factory_startup_cycles_per_distance: int
    factory_attempts_per_state: int
    factory_discard_reset_cycles_per_distance: int
    factory_reject_probability_bound: str
    initialization_failure_bound: str
    readout_failure_bound: str
    transfer_byte_failure_bound: str
    controller_command_failure_bound: str
    host_call_failure_bound: str
    propagation_failure_bound: str

    def validate(self):
        label(self.name, "MACHINE_MODEL_NAME")
        if type(self.noise_contract) is not str or self.noise_contract != NOISE_CONTRACT:
            raise ValueError("MACHINE_NOISE_COUPLING_CONTRACT_REQUIRED")
        for name in ("initialization_cycles_per_distance", "initialization_parallel_patches",
                     "readout_cycles_per_distance", "readout_parallel_bits",
                     "controller_cycles_per_command", "transfer_ns_per_byte",
                     "factory_startup_cycles_per_distance", "factory_discard_reset_cycles_per_distance"):
            integer(getattr(self, name), "MACHINE_" + name.upper(), 1, 10**12)
        integer(self.transfer_fixed_ns, "MACHINE_TRANSFER_FIXED_NS", 0, 10**12)
        integer(self.factory_attempts_per_state, "MACHINE_FACTORY_ATTEMPTS", 1, 64)
        for name in ("factory_reject_probability_bound", "initialization_failure_bound",
                     "readout_failure_bound", "transfer_byte_failure_bound",
                     "controller_command_failure_bound", "host_call_failure_bound",
                     "propagation_failure_bound"):
            if dec(getattr(self, name), "MACHINE_" + name.upper()) >= 1:
                raise ValueError("MACHINE_FAILURE_PROBABILITY_RANGE")


def illustrative_lifecycle_model():
    """A fixed serialized arithmetic example, not a hardware recommendation.

    None of these newly explicit premises is a measurement or a confidence
    bound derived from testing. Serial initialization in particular can make a
    four-second W1 schedule unproductive; that says nothing about the fastest
    legal architecture. Do not retune this example or the original acceptance
    deadline/qubit cap to manufacture a successful native experiment.
    """
    return LifecycleModel(
        name="illustrative-serial-lifecycle-v1", noise_contract=NOISE_CONTRACT,
        initialization_cycles_per_distance=1, initialization_parallel_patches=1,
        readout_cycles_per_distance=1, readout_parallel_bits=1,
        controller_cycles_per_command=1, transfer_fixed_ns=1000, transfer_ns_per_byte=1,
        factory_startup_cycles_per_distance=1, factory_attempts_per_state=16,
        factory_discard_reset_cycles_per_distance=1,
        factory_reject_probability_bound="0.01", initialization_failure_bound="1e-30",
        readout_failure_bound="1e-30", transfer_byte_failure_bound="1e-30",
        controller_command_failure_bound="1e-30", host_call_failure_bound="1e-30",
        propagation_failure_bound="1e-30")


def _validate(domains, schedule, processors, classical_costs, model, lifecycle,
              physical_qubit_budget, predicate, horizon_seconds, reserved_maximum_winners):
    horizon(horizon_seconds)
    if type(domains) is not tuple or not 1 <= len(domains) <= MAX_DOMAINS:
        raise ValueError("MACHINE_DOMAINS")
    if type(schedule) is not tuple or not 1 <= len(schedule) <= MAX_TRIALS:
        raise ValueError("MACHINE_SCHEDULE")
    integer(reserved_maximum_winners, "MACHINE_RESERVED_WINNERS", 1, len(schedule))
    integer(processors, "MACHINE_PROCESSORS", 1, MAX_PROCESSORS)
    if type(predicate) is not str or predicate not in ("full", "prefix-restricted"):
        raise ValueError("MACHINE_PREDICATE")
    if type(classical_costs) is not tuple or len(classical_costs) != len(domains):
        raise ValueError("MACHINE_CLASSICAL_COSTS")
    for costs in classical_costs:
        if type(costs) is not ClassicalCosts:
            raise ValueError("MACHINE_CLASSICAL_COST_TYPE")
        costs.validate()
    if type(model) is not PhysicalModel or type(lifecycle) is not LifecycleModel:
        raise ValueError("MACHINE_MODEL_TYPE")
    model.validate()
    lifecycle.validate()
    integer(physical_qubit_budget, "MACHINE_PHYSICAL_QUBIT_BUDGET", 1, (1 << 256) - 1)
    for entry in schedule:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("MACHINE_SCHEDULE_ENTRY")
        integer(entry[0], "MACHINE_DOMAIN_INDEX", 0, len(domains) - 1)
        integer(entry[1], "MACHINE_ITERATIONS", 0, MAX_ITERATIONS)


def _resource_rows(checked, processors, classical_costs, model, predicate):
    constructor = OracleProgram if predicate == "full" else PrefixRestrictedProgram
    result = []
    for domain, costs in zip(checked, classical_costs):
        template = template_from_spec(domain["template"])
        program = constructor(template)
        resources = program.resources()
        request = program.resource_request(Workload(1, 1, processors, 1, 0, (), 0), costs)
        units = {name: stage_units(circuit, model) for name, circuit in request.circuits.items()}
        iteration = {key: bounded(2 * units["winner_compute"][key]
                                  + units["phase_marker"][key] + units["diffusion"][key])
                     for key in units["prepare"]}
        packet = canonical(template.spec())
        result.append({
            "domain_sha256": domain["domain_sha256"], "template_sha256": domain["template_sha256"],
            "construction_sha256": resources["construction_sha256"],
            "construction_schema": resources["schema"], "construction_scope": resources["scope"],
            "logical_qubits": resources["logical_qubits"], "nonce_bits": template.nonce_bits,
            "domain_size": domain["domain_size"],
            "phase_marked_count": domain["marked_count"] if predicate == "full"
                                  else domain["prefix_restricted_marked_count"],
            "full_w1_accepted_count": domain["marked_count"],
            "controller_input_bytes": len(packet),
            "controller_input_sha256": hashlib.sha256(packet).hexdigest(),
            "controller_input_encoding": "canonical JSON FixedTemplate.spec() UTF-8 bytes",
            "nonce_result_bytes": _ceil_div(template.nonce_bits, 8),
            "prepare_units": units["prepare"], "iteration_units": iteration,
            "prepare_gate_commands": resources["prepare"]["gate_count"],
            "iteration_gate_commands": bounded(resources["phase_oracle_gate_count"]
                                                + resources["diffusion"]["gate_count"]),
        })
    return result


def _planned_rounds(rows, schedule, processors, classical_costs, lifecycle, peak, initial_resident=None):
    rounds = []
    resident = initial_resident
    for index, (domain_index, iterations) in enumerate(schedule):
        row, costs = rows[domain_index], classical_costs[domain_index]
        setup = resident != row["domain_sha256"]
        resident = row["domain_sha256"]
        init_batches = _ceil_div(peak, lifecycle.initialization_parallel_patches)
        readout_batches = _ceil_div(row["nonce_bits"], lifecycle.readout_parallel_bits)
        states = bounded(row["prepare_units"]["t_states"] + iterations * row["iteration_units"]["t_states"])
        attempts = bounded(states * lifecycle.factory_attempts_per_state)
        gates = bounded(row["prepare_gate_commands"] + iterations * row["iteration_gate_commands"])
        controller = bounded(gates + attempts + init_batches + readout_batches + int(states > 0))
        data = bounded(row["prepare_units"]["data_cycles_per_distance"]
                       + iterations * row["iteration_units"]["data_cycles_per_distance"])
        scaled_cycles = {
            "initialize": bounded(init_batches * lifecycle.initialization_cycles_per_distance),
            "factory_startup": lifecycle.factory_startup_cycles_per_distance if states else 0,
            "logical_gates": data,
            "factory_attempt_service": bounded(attempts * row["factory_t_cycles_per_distance"]),
            "factory_discard_reset": bounded(attempts * lifecycle.factory_discard_reset_cycles_per_distance),
            "terminal_readout": bounded(readout_batches * lifecycle.readout_cycles_per_distance),
        }
        input_bytes = bounded(processors * row["controller_input_bytes"] * int(setup))
        output_bytes = bounded(processors * row["nonce_result_bytes"])
        input_messages = processors * int(setup)
        output_messages = processors
        host_calls = bounded((1 + processors) * int(setup) + 2 * processors)
        rounds.append({
            "schedule_index": index, "domain_index": domain_index, "iterations": iterations,
            "domain_sha256": row["domain_sha256"], "resident_setup_charged": setup,
            "cycles_per_distance_per_processor": scaled_cycles,
            "controller_commands_per_processor": controller,
            "controller_fixed_cycles_per_processor": bounded(controller * lifecycle.controller_cycles_per_command),
            "t_states_per_processor": states, "factory_attempt_slots_per_processor": attempts,
            "initialized_patches_per_processor": peak, "measured_nonce_bits_per_processor": row["nonce_bits"],
            "input_bytes_all_processors": input_bytes, "output_bytes_all_processors": output_bytes,
            "input_messages_all_processors": input_messages, "output_messages_all_processors": output_messages,
            "host_calls_before_winner": host_calls,
            "classical_nanoseconds": {
                "task_preprocessing": costs.task_preprocessing_ns * int(setup),
                "processor_setup": processors * costs.per_search_setup_ns * int(setup),
                "input_transfer": input_messages * lifecycle.transfer_fixed_ns + input_bytes * lifecycle.transfer_ns_per_byte,
                "host_readout_turnaround": costs.per_trial_reset_readout_ns,
                "output_transfer": output_messages * lifecycle.transfer_fixed_ns + output_bytes * lifecycle.transfer_ns_per_byte,
                "candidate_checks": processors * costs.per_completed_trial_candidate_check_ns,
                "winner_proof": costs.per_winner_proof_ns,
                "winner_propagation": costs.per_winner_propagation_ns,
            },
        })
    return rounds


def _time_round(row, model, distance):
    seconds_per_cycle = _fraction(model.cycle_ns) / 10**9
    quantum_seconds = {key: value * distance * seconds_per_cycle
                       for key, value in row["cycles_per_distance_per_processor"].items()}
    quantum_seconds["controller_waits"] = row["controller_fixed_cycles_per_processor"] * seconds_per_cycle
    classical_seconds = {key: Fraction(value, 10**9) for key, value in row["classical_nanoseconds"].items()}
    winner = classical_seconds["winner_proof"] + classical_seconds["winner_propagation"]
    search = sum(quantum_seconds.values(), Fraction(0)) + sum(classical_seconds.values(), Fraction(0)) - winner
    row["quantum_phase_seconds_exact"] = {key: ratio(value) for key, value in quantum_seconds.items()}
    row["classical_phase_seconds_exact"] = {key: ratio(value) for key, value in classical_seconds.items()}
    row["search_seconds_exact"] = ratio(search)
    row["winner_seconds_exact"] = ratio(winner)
    return search, winner


def build_machine_envelope(domains, schedule, processors, classical_costs, physical_model,
                            lifecycle_model, physical_qubit_budget, horizon_seconds,
                            *, predicate="full", reserved_maximum_winners=1,
                            reserved_service_patches_per_processor=None):
    """Replay literal inputs and construct the complete declared lifecycle ledger.

    The optional v2 allocation reserves extra logical patches for an explicitly
    declared physical service architecture. They are initialized each trial and
    charged throughout every quantum phase, including controller waits, before
    selecting the common distance. Their clock/error service is a caller premise,
    not a compiled layout. Omitting this option preserves the original v1 shape;
    even an explicit zero allocation uses the new v2 namespace.
    """
    _validate(domains, schedule, processors, classical_costs, physical_model, lifecycle_model,
              physical_qubit_budget, predicate, horizon_seconds, reserved_maximum_winners)
    reserved = reserved_service_patches_per_processor
    if reserved is not None:
        integer(reserved, "MACHINE_RESERVED_SERVICE_PATCHES", 0, 10**12)
    sources = _sources()
    checked = tuple(replay_domain(domain) for domain in domains)
    model, lifecycle = physical_model, lifecycle_model
    rows = _resource_rows(checked, processors, classical_costs, model, predicate)
    for row in rows:
        row["factory_t_cycles_per_distance"] = model.factory_t_cycles_per_distance
    oracle_peak = max(row["logical_qubits"] for row in rows)
    peak = bounded(oracle_peak + (0 if reserved is None else reserved))
    rounds = _planned_rounds(rows, schedule, processors, classical_costs, lifecycle, peak)
    events = {
        "initialization_patches": bounded(processors * peak * len(schedule)),
        "readout_bits": bounded(processors * sum(row["measured_nonce_bits_per_processor"] for row in rounds)),
        "transfer_bytes": bounded(sum(row["input_bytes_all_processors"] + row["output_bytes_all_processors"] for row in rounds)),
        "controller_commands": bounded(processors * sum(row["controller_commands_per_processor"] for row in rounds)),
        "magic_state_services": bounded(processors * sum(row["t_states_per_processor"] for row in rounds)),
        "factory_attempt_slots": bounded(processors * sum(row["factory_attempt_slots_per_processor"] for row in rounds)),
        "factory_discard_reset_slots": bounded(processors * sum(row["factory_attempt_slots_per_processor"] for row in rounds)),
        "factory_startups": processors * sum(row["t_states_per_processor"] > 0 for row in rounds),
        "host_calls_including_reserved_proofs": bounded(sum(row["host_calls_before_winner"] for row in rounds)
                                                        + reserved_maximum_winners),
        "proofs_reserved": reserved_maximum_winners,
        "propagations": reserved_maximum_winners,
    }
    rejected = probability_power_bounds(_fraction(lifecycle.factory_reject_probability_bound),
                                         lifecycle.factory_attempts_per_state)
    fixed_errors = {
        "initialization": events["initialization_patches"] * _fraction(lifecycle.initialization_failure_bound),
        "readout": events["readout_bits"] * _fraction(lifecycle.readout_failure_bound),
        "transfer": events["transfer_bytes"] * _fraction(lifecycle.transfer_byte_failure_bound),
        "controller": events["controller_commands"] * _fraction(lifecycle.controller_command_failure_bound),
        "accepted_magic_state_service": events["magic_state_services"] * _fraction(model.magic_state_error),
        "factory_attempts_exhausted": events["magic_state_services"] * rejected.upper,
        "host_calls": events["host_calls_including_reserved_proofs"] * _fraction(lifecycle.host_call_failure_bound),
        "propagation": events["propagations"] * _fraction(lifecycle.propagation_failure_bound),
    }
    fixed_union = sum(fixed_errors.values(), Fraction(0))
    budget = _fraction(model.total_failure_budget)
    if fixed_union >= budget:
        raise ValueError("MACHINE_FIXED_EVENT_ERROR_BUDGET_EXCEEDED")
    scaled = bounded(sum(sum(row["cycles_per_distance_per_processor"].values()) for row in rounds))
    fixed_cycles = bounded(sum(row["controller_fixed_cycles_per_processor"] for row in rounds))
    error_ratio = _fraction(model.physical_error) / _fraction(model.threshold)
    prefactor = _fraction(model.logical_error_prefactor)
    distance = None
    for candidate in range(3, model.maximum_distance + 1, 2):
        cycles = bounded(scaled * candidate + fixed_cycles)
        locations = bounded(peak * cycles * processors)
        logical_upper = prefactor * probability_power_bounds(error_ratio, (candidate + 1) // 2).upper
        data_error = locations * logical_upper
        if fixed_union + data_error <= budget:
            distance = candidate
            break
    if distance is None:
        raise ValueError("MACHINE_NO_DISTANCE_FOR_WHOLE_PLAN")
    errors = {**fixed_errors, "live_data_patch_cycles": data_error}
    failure_union = fixed_union + data_error
    data_qubits = bounded(peak * model.data_physical_qubits_per_d2 * distance**2)
    factory_qubits = bounded(model.factories_per_instance * model.factory_physical_qubits_per_d2 * distance**2)
    fleet_qubits = bounded(processors * (data_qubits + factory_qubits))
    if fleet_qubits > physical_qubit_budget:
        raise ValueError("MACHINE_INSUFFICIENT_PHYSICAL_QUBITS")
    trials = []
    for row in rounds:
        search, winner = _time_round(row, model, distance)
        domain = rows[row["domain_index"]]
        trials.append(ProbabilityTrial(domain["domain_size"], domain["phase_marked_count"],
                                        domain["full_w1_accepted_count"], row["iterations"], processors,
                                        search, winner))
    ideal = schedule_success_bounds(tuple(trials), horizon_seconds)
    bounds = ideal["delivery_probability"]
    interval = ProbabilityInterval(Fraction(**bounds["lower"]), Fraction(**bounds["upper"]))
    record = {
        "schema": SCHEMA if reserved is None else RESERVED_SERVICE_SCHEMA, "source_sha256": sources,
        "premises": {"schedule": [list(entry) for entry in schedule], "processors": processors,
                     "predicate": predicate, "classical_costs_ns": [asdict(costs) for costs in classical_costs],
                     "physical_model": asdict(model), "lifecycle_model": asdict(lifecycle),
                     "physical_qubit_budget": physical_qubit_budget, "horizon_seconds": horizon_seconds,
                     "reserved_maximum_winners": reserved_maximum_winners},
        "domain_resources": rows, "planned_rounds": rounds,
        "envelope": {
            "code_distance_for_whole_schedule": distance,
            "logical_patches_reserved_and_initialized_per_processor": peak,
            "data_physical_qubits_per_processor": data_qubits,
            "factory_physical_qubits_per_processor": factory_qubits,
            "physical_qubits_all_processors": fleet_qubits,
            "events_all_processors": events,
            "live_data_patch_cycles_all_processors": locations,
            "logical_patch_cycle_fault_upper": ratio(logical_upper),
            "factory_service_exhaustion_upper": ratio(rejected.upper),
            "failure_union_components_upper": {key: ratio(value) for key, value in errors.items()},
            "whole_plan_failure_union_upper": ratio(failure_union),
            "unchanged_declared_failure_budget": model.total_failure_budget,
            "early_success_and_censoring_do_not_reduce_provisioned_envelope": True,
            "maximum_proof_and_propagation_events_reserved": reserved_maximum_winners,
            "probability_scope_remains_first_winner_delivery": True,
        },
        "ideal_schedule_probability": ideal,
        "conditional_machine_delivery_probability": coupled_success_bounds(interval, failure_union).record(),
        "assumptions": {
            "noise": NOISE_CONTRACT,
            "union_bound": "sum of per-location history-conditional fault bounds; independence between faults is not required",
            "physical_formula": "the phenomenological prefactor*(physical_error/threshold)**((d+1)/2) must itself upper-bound each history-conditional live-data-patch-cycle fault; this is an uncalibrated premise, not a result established by the estimator",
            "success_coupling": "outside any declared fault event the actual timed trace equals the ideal timed trace; ideal lower minus epsilon to ideal upper plus epsilon",
            "factory_retries": "every rejection bound holds conditional on the full previous history including previous rejections; r slots give exhaustion <= a**r, not an inference from a marginal rejection rate",
            "factory_clock": "one serial service per processor; every attempt includes full production/delivery/injection/feedforward allocation and discard/reset, including padded slots after success; extra factories reserve space without throughput credit",
            "accepted_magic_error": "conditional accepted-output service fault includes factory internals, early-success buffer storage, transport and injection; it is not automatically equal to state infidelity",
            "data_cycles": "all peak data patches charged throughout initialization, factory startup, logical gates, attempts, resets, controller waits and terminal readout; factory internals covered by service contract",
            "controller": "one command per constructed logical gate, initialization/readout batch, factory startup and attempt; command fault bound covers cached input corruption and latency overruns",
            "input_transfer": "one canonical template message per processor on resident change; nonce result per processor each trial; shared serialized bus including fixed per-message overhead",
            "classical": "caller-declared clocks; task preprocessing plus per-processor setup includes required program generation/staging; reset_readout_ns is additional host turnaround after modeled physical readout; all P candidates checked serially",
            "residency": "only classical template bytes persist; all data patches are reinitialized per trial, with no coherent state through classical waits",
            "additional_winner_reservation": "the error envelope may reserve K proof/propagation events; its displayed probability still stops at the first winner; another path certificate must prove its complete action/event sequence fits this reservation",
            "clock_errors": "host and propagation failure bounds include incorrect results and exceeding declared clocks; empirical sample maxima are not proved runtime bounds",
            "probability_arithmetic": "outward dyadic power bounds; tiny positive risks keep a positive upper endpoint; rounding may conservatively refuse a feasible very small budget",
            "public_inputs": "fixed valid domain inputs preexist as a stated precondition; native task/parent/target admission and offline observer census are outside the mining clock",
        },
        "physical_parameters_calibrated": False,
        "fault_tolerant_layout_and_controller_compiled": False,
        "empirical_zero_failures_interpreted_as_zero_risk": False,
        "quantum_hardware_executed": False,
        "native_block_admission_verified": False,
        "minimum_attacker_cost_proved": False,
        "complete_energy_or_economic_machine_cost": False,
        "quantum_mining_qualified": False,
        "production_activation": False,
    }
    if reserved is not None:
        record["premises"]["reserved_service_patches_per_processor"] = reserved
        record["envelope"].update({
            "oracle_logical_patches_per_processor": oracle_peak,
            "service_logical_patches_per_processor": reserved,
            "oracle_data_physical_qubits_per_processor": bounded(
                oracle_peak * model.data_physical_qubits_per_d2 * distance**2),
            "service_physical_qubits_per_processor": bounded(
                reserved * model.data_physical_qubits_per_d2 * distance**2),
            "service_patches_initialized_and_charged_as_live_data": True,
        })
        record["assumptions"]["reserved_services"] = (
            "all declared auxiliary service patches add to the peak width, per-trial initialization, "
            "physical allocation and history-conditional live-patch fault union; service latency and "
            "error contracts must cover their actual use; neither their layout nor controller is compiled")
    if _sources() != sources:
        raise ValueError("MACHINE_SOURCE_CHANGED")
    record["record_sha256"] = _hash(record)
    return record


def machine_action_clock(verified_record, domain_index, iterations, *, resident_setup):
    """Price one action at an already selected common distance and peak width.

    The input must come from this process's ``build_machine_envelope`` or one
    successful ``verify_machine_envelope`` reconstruction. Hash equality checks
    accidental changes, not external authority. This helper checks the domain/q
    range only. A consumer taking multiple adaptive actions must separately
    prove that their cumulative event counts, template transfers, attempts and
    proofs/propagations are dominated by the full predeclared envelope.
    """
    if (type(verified_record) is not dict
            or verified_record.get("schema") not in (SCHEMA, RESERVED_SERVICE_SCHEMA)):
        raise ValueError("MACHINE_ACTION_RECORD")
    record = verified_record
    if (record.get("source_sha256") != _sources()
            or record.get("record_sha256") != _hash({key: value for key, value in record.items()
                                                     if key != "record_sha256"})):
        raise ValueError("MACHINE_ACTION_SOURCE_OR_RECORD_CHANGED")
    premises, rows, envelope = record["premises"], record["domain_resources"], record["envelope"]
    integer(domain_index, "MACHINE_ACTION_DOMAIN", 0, len(rows) - 1)
    integer(iterations, "MACHINE_ACTION_ITERATIONS", 0, MAX_ITERATIONS)
    if type(resident_setup) is not bool:
        raise ValueError("MACHINE_ACTION_RESIDENCY")
    planned = [row["iterations"] for row in record["planned_rounds"] if row["domain_index"] == domain_index]
    if not planned or iterations > max(planned):
        raise ValueError("MACHINE_ACTION_OUTSIDE_ENVELOPE")
    model, lifecycle = PhysicalModel(**premises["physical_model"]), LifecycleModel(**premises["lifecycle_model"])
    classical = tuple(ClassicalCosts(**values) for values in premises["classical_costs_ns"])
    initial = None if resident_setup else rows[domain_index]["domain_sha256"]
    action = _planned_rounds(rows, ((domain_index, iterations),), premises["processors"], classical,
                             lifecycle, envelope["logical_patches_reserved_and_initialized_per_processor"],
                             initial_resident=initial)[0]
    _time_round(action, model, envelope["code_distance_for_whole_schedule"])
    action["envelope_record_sha256"] = record["record_sha256"]
    action["code_distance_for_whole_schedule"] = envelope["code_distance_for_whole_schedule"]
    action["logical_patches_reserved_per_processor"] = envelope["logical_patches_reserved_and_initialized_per_processor"]
    action["cumulative_action_sequence_coverage_checked"] = False
    return action


def verify_machine_envelope(record, domains):
    """Rebuild all source, census, circuit, event, clock and probability fields."""
    if type(record) is not dict or record.get("schema") not in (SCHEMA, RESERVED_SERVICE_SCHEMA):
        raise ValueError("MACHINE_RECORD")
    premises = record.get("premises")
    keys = {"schedule", "processors", "predicate", "classical_costs_ns", "physical_model",
            "lifecycle_model", "physical_qubit_budget", "horizon_seconds", "reserved_maximum_winners"}
    reserved = None
    if record["schema"] == RESERVED_SERVICE_SCHEMA:
        keys.add("reserved_service_patches_per_processor")
        if type(premises) is not dict:
            raise ValueError("MACHINE_PREMISES")
        reserved = premises.get("reserved_service_patches_per_processor")
        integer(reserved, "MACHINE_RESERVED_SERVICE_PATCHES", 0, 10**12)
    if type(premises) is not dict or set(premises) != keys:
        raise ValueError("MACHINE_PREMISES")
    schedule, costs = premises["schedule"], premises["classical_costs_ns"]
    if (type(schedule) is not list or not 1 <= len(schedule) <= MAX_TRIALS
            or any(type(entry) is not list or len(entry) != 2 for entry in schedule)
            or type(costs) is not list or not 1 <= len(costs) <= MAX_DOMAINS):
        raise ValueError("MACHINE_SERIALIZED_SCHEDULE")
    for values, cls in ((premises["physical_model"], PhysicalModel),
                        (premises["lifecycle_model"], LifecycleModel),
                        *((value, ClassicalCosts) for value in costs)):
        if type(values) is not dict or set(values) != set(cls.__dataclass_fields__):
            raise ValueError("MACHINE_SERIALIZED_MODEL")
    rebuilt = build_machine_envelope(
        domains, tuple(tuple(entry) for entry in schedule), premises["processors"],
        tuple(ClassicalCosts(**value) for value in costs), PhysicalModel(**premises["physical_model"]),
        LifecycleModel(**premises["lifecycle_model"]), premises["physical_qubit_budget"],
        premises["horizon_seconds"], predicate=premises["predicate"],
        reserved_maximum_winners=premises["reserved_maximum_winners"],
        reserved_service_patches_per_processor=reserved)
    if canonical(record) != canonical(rebuilt):
        raise ValueError("MACHINE_REPLAY_MISMATCH")
    return rebuilt
