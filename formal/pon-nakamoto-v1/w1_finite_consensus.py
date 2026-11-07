"""Exact, conditional fork-replacement certificates on a finite literal W1 DAG.

The public classical branch is an already generated, fixed history. This is a
finite conditional catch-up problem, not a model of all future honest mining.
Every permitted private action is explicitly listed: fresh uniform Grover search
with a declared q, publication, waiting for the public tip, or stopping. Only one
processor is supported. A proof-complete private block can be extended before
publication; each nonce has its own actual block identity and successor domain.

The optimizer sees the observer's census. Its upper envelope must not be called
an attainable advice-free mining optimum. The separately sampled fixed-q policy
never reads a marked count or the optimized values. Construction clocks remain
hypotheses for one implementation, never minimum attacker costs.
"""
from __future__ import annotations

from dataclasses import asdict
from fractions import Fraction
import hashlib
from math import lcm
from pathlib import Path
import random

import contract_wire as wire
from quantum_oracle_resources import ClassicalCosts, PhysicalModel
from reference import retarget, timestamp_state, work
from w1_bounded_search import horizon
from w1_constructed_search import SOURCES, bind_constructed_search
from w1_marked_domain import enumerate_domain
from w1_machine_envelope import LifecycleModel, build_machine_envelope, machine_action_clock
from w1_quantum_oracle import canonical, template_from_spec

SCHEMA = "trnm-w1-finite-consensus-certificate-v1"
FIXTURE_SCHEMA = "trnm-w1-native-finite-dag-v1"
ROOT = Path(__file__).resolve().parents[2]
MAX_EXACT_ITERATIONS = 64
MAX_CONTEXTS = 16
MAX_ATTEMPTS = 8
MAX_STATES = 100_000
MAX_TRANSITION_EDGES = 500_000
POW_LIMIT = (1 << 255) - 1
WORK_MAX = (1 << 512) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, name)
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def rational(value):
    require(type(value) is dict and set(value) == {"numerator", "denominator"}, "RATIONAL_SCHEMA")
    n, d = value["numerator"], value["denominator"]
    require(type(n) is int and type(d) is int and d > 0, "RATIONAL_INTEGER")
    result = Fraction(n, d)
    require(ratio(result) == value, "RATIONAL_NOT_REDUCED")
    return result


def hexadecimal(value, size):
    require(type(value) is str and len(value) == size * 2, "HEX_LENGTH")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("HEX_VALUE") from error
    require(raw.hex() == value and len(raw) == size, "HEX_CANONICAL")
    return raw


def exact_nonce_probabilities(size, marked_nonces, iterations):
    """Independent small-q rational recurrence; no trig or interval kernel.

    a/sqrt(N) and b/sqrt(N) are per-item marked and unmarked amplitudes.
    The marked set describes the phase oracle, not final legal acceptance.
    """
    integer(size, "EXACT_DOMAIN_SIZE", 1, 4096)
    integer(iterations, "EXACT_ITERATIONS", 0, MAX_EXACT_ITERATIONS)
    require(type(marked_nonces) is tuple and len(set(marked_nonces)) == len(marked_nonces),
            "EXACT_MARKED_SET")
    for nonce in marked_nonces:
        integer(nonce, "EXACT_MARKED_NONCE", 0, size - 1)
    marked = frozenset(marked_nonces)
    p, a, b = Fraction(len(marked), size), Fraction(1), Fraction(1)
    for _ in range(iterations):
        a, b = (1 - 2 * p) * a + 2 * (1 - p) * b, -2 * p * a + (1 - 2 * p) * b
    values = tuple((a * a if nonce in marked else b * b) / size for nonce in range(size))
    require(sum(values) == 1 and all(value >= 0 for value in values), "EXACT_NORMALIZATION")
    return values


def _source_hashes():
    names = set(SOURCES) | {
        "formal/pon-nakamoto-v1/w1_finite_consensus.py",
        "formal/pon-nakamoto-v1/reference.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/w1_machine_envelope.py",
        "formal/pon-nakamoto-v1/w1_search_probability.py",
    }
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(names)}


def _metadata(row):
    require(type(row) is dict, "HEADER_METADATA")
    identifier = hexadecimal(row["block_id"], 32).hex()
    height = integer(row["height"], "HEADER_HEIGHT")
    timestamp = integer(row["timestamp"], "HEADER_TIMESTAMP")
    target = int.from_bytes(hexadecimal(row["target_hex"], 32), "big")
    require(1 <= target <= POW_LIMIT, "HEADER_TARGET")
    chainwork = int.from_bytes(hexadecimal(row["chainwork_hex"], 64), "big")
    parent = row["parent_id"]
    require((height == 0 and parent is None) or (height > 0 and type(parent) is str), "HEADER_PARENT")
    if parent is not None:
        hexadecimal(parent, 32)
    encoded = row.get("header_hex")
    if encoded is not None:
        raw = hexadecimal(encoded, 318)
        header = wire.header_decode(raw)
        require(header["height"] == height and header["timestamp"] == timestamp
                and header["target"].hex() == row["target_hex"]
                and header["parent"].hex() == parent, "HEADER_METADATA_MISMATCH")
        if row.get("trace") is not None:
            require(wire.H("block", raw, hexadecimal(row["trace"], 32)).hex() == identifier,
                    "HEADER_METADATA_IDENTITY")
    return {"block_id": identifier, "parent_id": parent, "height": height,
            "timestamp": timestamp, "target": target, "chainwork": chainwork}


def _required(parent, history):
    height = parent["height"] + 1
    if height % 16:
        return parent["target"]
    require(len(history) >= 16, "MISSING_RETARGET_HISTORY")
    return retarget(parent["target"], history[15]["timestamp"], parent["timestamp"],
                    16, 10, POW_LIMIT)


class FiniteModel:
    """Recomputed semantics. The certificate writer and checker share no DP values."""

    def __init__(self, fixture, parameters):
        require(type(fixture) is dict and fixture.get("schema") == FIXTURE_SCHEMA, "FINITE_FIXTURE_SCHEMA")
        require(fixture["interval"] == 16 and fixture["spacing_seconds"] == 10
                and fixture["future_skew_seconds"] == 120
                and int.from_bytes(hexadecimal(fixture["pow_limit_hex"], 32), "big") == POW_LIMIT,
                "FINITE_NATIVE_PARAMETERS")
        require(type(fixture.get("initial_resources")) is dict and fixture["initial_resources"],
                "INITIAL_RESOURCE_PREMISES_REQUIRED")
        self.source_hashes = _source_hashes()
        self.fixture_hash = digest(fixture)
        self.parameters = parameters
        self.execution_kind = parameters["execution_kind"]
        require(self.execution_kind in ("constructed-quantum", "classical-uniform-q0"), "FINITE_EXECUTION_KIND")
        self.limit = horizon(parameters["horizon_seconds"])
        self.iterations = tuple(parameters["iterations"])
        require(self.iterations and len(self.iterations) <= 16 and len(set(self.iterations)) == len(self.iterations),
                "FINITE_ITERATION_ACTIONS")
        for count in self.iterations:
            integer(count, "FINITE_ITERATIONS", 0, MAX_EXACT_ITERATIONS)
        self.attempts = integer(parameters["max_attempts"], "FINITE_ATTEMPTS", 1, MAX_ATTEMPTS)
        self.cap = integer(parameters["max_states"], "FINITE_STATE_CAP", 1, MAX_STATES)
        self.predicate = parameters["predicate"]
        require(self.predicate in ("full", "prefix-restricted"), "FINITE_PREDICATE")
        if self.execution_kind == "classical-uniform-q0":
            require(self.iterations == (0,) and self.predicate == "full", "CLASSICAL_UNIFORM_Q_ZERO_ONLY")
        self.origin = integer(fixture["clock_origin_timestamp"], "FINITE_CLOCK_ORIGIN")
        require(self.origin + self.limit.numerator // self.limit.denominator <= (1 << 64) - 1,
                "FINITE_CLOCK_U64_OVERFLOW")
        prefix = fixture["prefix"]
        rows = prefix["parent_first_headers"]
        require(type(rows) is list and 1 <= len(rows) <= 128, "FINITE_PREFIX")
        histories, blocks = {}, {}
        for row in reversed(rows):
            block = _metadata(row)
            identifier, parent_id = block["block_id"], block["parent_id"]
            require(identifier not in blocks, "DUPLICATE_PREFIX_BLOCK")
            if block["height"] == 0:
                require(not blocks and block["chainwork"] == 0 and block["target"] == POW_LIMIT,
                        "GENESIS_RESOURCE_PREMISE")
                history = []
            else:
                require(parent_id in blocks, "PREFIX_PARENT")
                parent, history = blocks[parent_id], histories[parent_id]
                require(block["height"] == parent["height"] + 1 and block["target"] == _required(parent, history),
                        "PREFIX_TARGET_OR_HEIGHT")
                require(block["chainwork"] == parent["chainwork"] + work(block["target"]), "PREFIX_CHAINWORK")
                require(timestamp_state(block["timestamp"], [h["timestamp"] for h in reversed(history[:11])],
                                        self.origin, 120) == "admissible", "PREFIX_TIMESTAMP")
            blocks[identifier], histories[identifier] = block, [block] + history
        self.prefix = hexadecimal(prefix["tip_id"], 32).hex()
        require(self.prefix == rows[0]["block_id"] and blocks[self.prefix]["height"] == prefix["height"]
                and blocks[self.prefix]["chainwork"] == int.from_bytes(hexadecimal(prefix["chainwork_hex"], 64), "big"),
                "PREFIX_TIP")
        public = _metadata(fixture["public_tip"])
        public_raw = hexadecimal(fixture["public_tip"]["header_hex"], 318)
        public_header = wire.header_decode(public_raw)
        public_trace = hexadecimal(fixture["public_tip"]["trace"], 32)
        require(wire.H("block", public_raw, public_trace).hex() == public["block_id"], "PUBLIC_BLOCK_ID")
        require(public["parent_id"] == self.prefix
                and public["height"] == blocks[self.prefix]["height"] + 1
                and public["target"] == _required(blocks[self.prefix], histories[self.prefix])
                and public["chainwork"] == blocks[self.prefix]["chainwork"] + work(public["target"]),
                "PUBLIC_BRANCH_ARITHMETIC")
        self.public_time = horizon(fixture["public_tip"]["publication_at_seconds"])
        require(self.origin + self.public_time.numerator // self.public_time.denominator <= (1 << 64) - 1,
                "FINITE_PUBLIC_CLOCK_U64_OVERFLOW")
        require(timestamp_state(public["timestamp"], [h["timestamp"] for h in reversed(histories[self.prefix][:11])],
                                self.origin + self.public_time.numerator // self.public_time.denominator,
                                120) == "admissible", "PUBLIC_TIME_ADMISSION")
        self.public = public
        for row in rows:
            if row.get("header_hex") is not None:
                prefix_header = wire.header_decode(bytes.fromhex(row["header_hex"]))
                require(all(prefix_header[key] == public_header[key] for key in ("network", "parameters")),
                        "PREFIX_NETWORK_OR_PARAMETERS")
        contexts = fixture["contexts"]
        require(type(contexts) is list and 1 <= len(contexts) <= MAX_CONTEXTS, "FINITE_CONTEXTS")
        self.root_context = fixture["root_context_id"]
        by_id = {}
        for context in contexts:
            identifier = context["context_id"]
            require(type(identifier) is str and 1 <= len(identifier) <= 128 and identifier not in by_id,
                    "FINITE_CONTEXT_ID")
            by_id[identifier] = context
        require(self.root_context in by_id, "FINITE_ROOT_CONTEXT")
        self.contexts, self.children, self.block_context = {}, {}, {}
        ordered, pending, seen = [], [(self.root_context, self.prefix)], set()
        while pending:
            identifier, expected_parent = pending.pop(0)
            require(identifier not in seen and identifier in by_id, "DUPLICATE_OR_MISSING_CHILD_CONTEXT")
            seen.add(identifier)
            context = by_id[identifier]
            require(context["parent_id"] == expected_parent, "CONTEXT_PARENT_BINDING")
            template = template_from_spec(context["template_spec"])
            require(template.profile == "PNH1", "FINITE_PNH1_ONLY")
            header = wire.header_decode(template.header)
            require(all(header[key] == public_header[key] for key in ("network", "parameters")),
                    "CONTEXT_NETWORK_OR_PARAMETERS")
            parent, history = blocks[expected_parent], histories[expected_parent]
            require(header["parent"].hex() == expected_parent and header["height"] == parent["height"] + 1
                    and template.target == _required(parent, history), "CONTEXT_REQUIRED_HEADER")
            require(timestamp_state(header["timestamp"], [h["timestamp"] for h in reversed(history[:11])],
                                    (1 << 64) - 1, 120) != "invalid-median", "CONTEXT_MEDIAN")
            domain = enumerate_domain(template)
            declared = context["winner_children"]
            require(type(declared) is list and len(declared) == domain["marked_count"], "COMPLETE_WINNER_BRANCHES_REQUIRED")
            child_map = {}
            for child in declared:
                nonce = integer(child["nonce"], "CHILD_NONCE", 0, domain["domain_size"] - 1)
                require(nonce not in child_map and domain["outcomes"][nonce]["winner"], "CHILD_NOT_UNIQUE_WINNER")
                raw = template.header_for(nonce)
                trace = bytes.fromhex(domain["outcomes"][nonce]["trace"])
                block_id = wire.H("block", raw, trace).hex()
                require(child["block_id"] == block_id and child["header_hex"] == raw.hex(), "CHILD_IDENTITY")
                require(block_id not in blocks, "DUPLICATE_PRIVATE_BLOCK")
                chainwork = parent["chainwork"] + work(template.target)
                require(chainwork <= WORK_MAX, "CHAINWORK_U512_OVERFLOW")
                block = {"block_id": block_id, "parent_id": expected_parent,
                         "height": header["height"], "timestamp": header["timestamp"],
                         "target": template.target, "chainwork": chainwork}
                blocks[block_id], histories[block_id] = block, [block] + history
                next_context = child["child_context_id"]
                if next_context is not None:
                    require(type(next_context) is str, "CHILD_CONTEXT_ID")
                    pending.append((next_context, block_id))
                child_map[nonce] = {"block_id": block_id, "child_context_id": next_context}
                self.block_context[block_id] = identifier
            require(set(child_map) == set(domain["marked_nonces"]), "MISSING_LEGAL_NONCE_BRANCH")
            self.contexts[identifier] = {"index": len(ordered), "domain": domain,
                                         "parent_id": expected_parent, "template": template}
            self.children[identifier] = child_map
            ordered.append(identifier)
        require(seen == set(by_id), "UNREACHABLE_CONTEXT")
        self.ordered, self.blocks = tuple(ordered), blocks
        self.domains = tuple(self.contexts[key]["domain"] for key in ordered)
        supplied_classical = tuple(ClassicalCosts(**row) for row in parameters["classical_costs"])
        require(len(supplied_classical) == len(contexts), "FINITE_CLASSICAL_COSTS")
        cost_by_id = dict(zip((row["context_id"] for row in contexts), supplied_classical))
        classical = tuple(cost_by_id[key] for key in ordered)
        physical = PhysicalModel(**parameters["physical_model"])
        physical.validate()
        for costs in classical:
            costs.validate()
        # Provision every domain for K q_max trials. Any permitted path is a
        # subprogram of this deliberately conservative shared-distance envelope.
        schedule = tuple((i, max(self.iterations)) for i in range(len(ordered)) for _ in range(self.attempts))
        self.binding, self.machine, self.classical_envelope, self.action_clocks = None, None, None, {}
        if self.execution_kind == "classical-uniform-q0":
            self.clocks = {key: {
                "domain_setup_seconds": Fraction(costs.task_preprocessing_ns + costs.per_search_setup_ns, 10**9),
                "prepare_seconds": Fraction(0), "iteration_seconds": Fraction(0),
                "measurement_seconds": Fraction(costs.per_trial_reset_readout_ns, 10**9),
                "candidate_check_seconds": Fraction(costs.per_completed_trial_candidate_check_ns, 10**9),
                "proof_seconds": Fraction(costs.per_winner_proof_ns, 10**9)} for key, costs in zip(ordered, classical)}
            self.propagation = {key: Fraction(costs.per_winner_propagation_ns, 10**9) for key, costs in zip(ordered, classical)}
            if parameters["lifecycle_model"] is not None:
                lifecycle = LifecycleModel(**parameters["lifecycle_model"])
                lifecycle.validate()
                host_calls = 2 * len(ordered) + 2 * len(ordered) * self.attempts + self.attempts
                components = {"host_calls": host_calls * Fraction(lifecycle.host_call_failure_bound),
                              "propagation": self.attempts * Fraction(lifecycle.propagation_failure_bound),
                              "quantum_faults": Fraction(0)}
                failure = sum(components.values(), Fraction(0))
                require(failure <= Fraction(physical.total_failure_budget), "CLASSICAL_HOST_ERROR_BUDGET")
                self.classical_envelope = {
                    "schema": "trnm-w1-classical-uniform-host-envelope-v1",
                    "classical_costs_ns_in_context_order": [asdict(costs) for costs in classical],
                    "host_nonce_generation_clock": "per_trial_reset_readout_ns repurposed explicitly as the assumed fresh classical uniform RNG host-call duration",
                    "events": {"task_and_template_setup_calls": 2 * len(ordered),
                               "nonce_generation_and_candidate_check_calls": 2 * len(ordered) * self.attempts,
                               "proofs_reserved": self.attempts, "propagations": self.attempts,
                               "host_calls_including_proofs": host_calls, "quantum_events": 0},
                    "physical_qubits": 0, "quantum_fault_probability": ratio(Fraction(0)),
                    "envelope": {"whole_plan_failure_union_upper": ratio(failure),
                                 "failure_union_components_upper": {key: ratio(value) for key, value in components.items()}},
                    "unchanged_declared_failure_budget": physical.total_failure_budget,
                    "coupling_premise": "history-conditional host correctness, fresh uniform RNG, cached-input integrity and clock-overrun bounds; propagation includes delivery and clock overruns",
                    "quantum_parameters_used_for_hardware_cost": False,
                    "host_runtime_calibrated": False}
        else:
            self.binding = bind_constructed_search(self.domains, schedule, 1, classical, physical,
                                                   parameters["physical_qubit_budget"], predicate=self.predicate)
            self.clocks = {key: {name: Fraction(value) for name, value in asdict(self.binding.costs[i]).items()
                                 if name != "clock_rounding"} for i, key in enumerate(ordered)}
            self.propagation = {key: Fraction(self.binding.propagation_seconds[i]) for i, key in enumerate(ordered)}
        if self.execution_kind == "constructed-quantum" and parameters["lifecycle_model"] is not None:
            lifecycle = LifecycleModel(**parameters["lifecycle_model"])
            self.machine = build_machine_envelope(
                self.domains, schedule, 1, classical, physical, lifecycle,
                parameters["physical_qubit_budget"], parameters["horizon_seconds"],
                predicate=self.predicate, reserved_maximum_winners=self.attempts)
            for i, key in enumerate(ordered):
                for count in self.iterations:
                    for setup in (False, True):
                        self.action_clocks[key, count, setup] = machine_action_clock(
                            self.machine, i, count, resident_setup=setup)
                common = self.action_clocks[key, self.iterations[0], True]
                self.propagation[key] = rational(common["classical_phase_seconds_exact"]["winner_propagation"])
        self.error_envelope = self.machine if self.machine is not None else self.classical_envelope
        self.probabilities = {}
        for key in ordered:
            domain = self.contexts[key]["domain"]
            marked = tuple(row["nonce"] for row in domain["outcomes"]
                           if row["winner"] and (self.predicate == "full" or row["prefix_all_accepted"]))
            for count in self.iterations:
                self.probabilities[key, count] = exact_nonce_probabilities(domain["domain_size"], marked, count)
        require(_source_hashes() == self.source_hashes, "FINITE_SOURCE_CHANGED")

    def initial(self):
        return {"time": ratio(Fraction(0)), "attempts": 0, "private_chain": [], "resident_context": None}

    def context_for(self, state):
        chain = state["private_chain"]
        if not chain:
            return self.root_context
        block = chain[-1]
        owner = self.block_context[block]
        return next(row["child_context_id"] for row in self.children[owner].values() if row["block_id"] == block)

    def tip(self, state):
        return self.blocks[state["private_chain"][-1] if state["private_chain"] else self.prefix]

    def actions(self, state):
        now = rational(state["time"])
        choices = [{"kind": "stop"}]
        if state["private_chain"]:
            choices.append({"kind": "publish"})
        if now < self.public_time <= self.limit:
            choices.append({"kind": "wait-for-public"})
        if now < self.limit and state["attempts"] < self.attempts and self.context_for(state) is not None:
            choices.extend({"kind": "search", "iterations": q} for q in self.iterations)
        return choices

    def transition(self, state, action):
        """Regenerate all exact outcomes; census membership is evaluator-only."""
        require(action in self.actions(state), "UNDECLARED_ACTION")
        now = rational(state["time"])
        chain = list(state["private_chain"])
        if action["kind"] == "stop":
            return [self.edge(Fraction(1), None, 0, {"result": "stopped", "time": state["time"], "private_chain": chain})]
        if action["kind"] == "wait-for-public":
            following = {**state, "time": ratio(self.public_time)}
            return [self.edge(Fraction(1), following, None, {"result": "public-tip-arrived", "time": following["time"]})]

        def pay(phases, current, name, planned):
            paid = min(planned, self.limit - current)
            phases.append({"phase": name, "planned": ratio(planned), "paid": ratio(paid), "complete": paid == planned})
            return current + paid, paid == planned

        if action["kind"] == "publish":
            phases = []
            planned = sum((self.propagation[self.block_context[block]] for block in chain), Fraction(0))
            finish, complete = pay(phases, now, "serial_bundle_propagation", planned)
            if complete:
                admissible = max(Fraction(max(0, self.blocks[block]["timestamp"] - self.origin - 120)) for block in chain)
                finish, complete = pay(phases, finish, "future_admission_wait", max(Fraction(0), admissible - finish))
            replacement = (complete and finish >= self.public_time
                           and self.tip(state)["chainwork"] > self.public["chainwork"]
                           and self.public["block_id"] not in chain)
            observation = {"result": "published" if complete else "horizon", "time": ratio(finish),
                           "private_chain": chain, "phases": phases, "publication_complete": complete,
                           "strict_work_replacement": replacement}
            return [self.edge(Fraction(1), None, int(replacement), observation)]

        key, count = self.context_for(state), action["iterations"]
        context, clock = self.contexts[key], self.clocks[key]
        phases, finish = [], now
        measured = checked = False
        proof_clock = clock["proof_seconds"]
        if self.execution_kind == "classical-uniform-q0":
            planned_phases = (("classical_task_and_template_setup", int(state["resident_context"] != key) * clock["domain_setup_seconds"]),
                              ("classical_nonce_generation", clock["measurement_seconds"]),
                              ("candidate_check", clock["candidate_check_seconds"]))
            nonce_received_phase = "classical_nonce_generation"
        elif self.machine is None:
            planned_phases = (("domain_setup", int(state["resident_context"] != key) * clock["domain_setup_seconds"]),
                              ("prepare", clock["prepare_seconds"]),
                              ("iterations", count * clock["iteration_seconds"]),
                              ("measurement", clock["measurement_seconds"]),
                              ("candidate_check", clock["candidate_check_seconds"]))
            nonce_received_phase = "measurement"
        else:
            row = self.action_clocks[key, count, state["resident_context"] != key]
            quantum = {name: rational(value) for name, value in row["quantum_phase_seconds_exact"].items()}
            classical = {name: rational(value) for name, value in row["classical_phase_seconds_exact"].items()}
            proof_clock = classical["winner_proof"]
            # This is the declared padded serial machine. The host receives a
            # usable sampled nonce only after readout, turnaround and transfer.
            planned_phases = tuple((name, classical[name]) for name in (
                "task_preprocessing", "processor_setup", "input_transfer")) + tuple(
                (name, quantum[name]) for name in ("initialize", "factory_startup", "logical_gates",
                    "factory_attempt_service", "factory_discard_reset", "controller_waits", "terminal_readout")) + (
                ("host_readout_turnaround", classical["host_readout_turnaround"]),
                ("output_transfer", classical["output_transfer"]),
                ("candidate_check", classical["candidate_checks"]))
            require(sum(value for _, value in planned_phases) == rational(row["search_seconds_exact"]),
                    "FINITE_MACHINE_PHASE_SUM")
            nonce_received_phase = "output_transfer"
        for name, planned in planned_phases:
            finish, complete = pay(phases, finish, name, planned)
            measured = measured or (name == nonce_received_phase and complete)
            checked = checked or (name == "candidate_check" and complete)
            if not complete:
                break
        base = {"context_id": key, "domain_sha256": context["domain"]["domain_sha256"],
                "parent_id": context["parent_id"], "iterations": count, "phases": phases,
                "nonce_available": measured, "nonce_source": self.execution_kind,
                "measurement_complete": measured and self.execution_kind == "constructed-quantum",
                "candidate_check_complete": checked}
        if not measured:
            return [self.edge(Fraction(1), None, 0, {**base, "nonce": None, "winner": None,
                              "proof_complete": False, "result": "horizon", "time": ratio(finish),
                              "private_chain": chain})]
        outcomes = []
        for nonce, probability in enumerate(self.probabilities[key, count]):
            if probability == 0:
                continue
            winner = context["domain"]["outcomes"][nonce]["winner"] if checked else None
            observation = {**base, "phases": list(phases), "nonce": nonce, "winner": winner,
                           "proof_complete": False, "block_id": None, "private_chain": chain,
                           "time": ratio(finish)}
            if not checked:
                observation["result"] = "horizon"
                outcomes.append(self.edge(probability, None, 0, observation))
                continue
            end, complete, next_chain = finish, True, chain
            if winner:
                end, complete = pay(observation["phases"], finish, "proof", proof_clock)
                observation["time"] = ratio(end)
                observation["proof_complete"] = complete
                if complete:
                    block_id = self.children[key][nonce]["block_id"]
                    next_chain = chain + [block_id]
                    observation.update(block_id=block_id, private_chain=next_chain)
            observation["result"] = "proved-private-block" if winner and complete else "checked-miss" if complete else "horizon"
            following = {"time": ratio(end), "attempts": state["attempts"] + 1,
                         "private_chain": next_chain, "resident_context": key} if complete else None
            outcomes.append(self.edge(probability, following, None if complete else 0, observation))
        require(sum(rational(edge["probability"]) for edge in outcomes) == 1, "TRANSITION_MASS")
        return outcomes

    @staticmethod
    def edge(probability, following, terminal, observation):
        return {"probability": ratio(probability), "next_state": following,
                "terminal_risk": terminal, "observation": observation}


def _parameters(classical_costs, physical_model, physical_qubit_budget, horizon_seconds,
                iterations, max_attempts, predicate, max_states, lifecycle_model, execution_kind):
    require(type(classical_costs) is tuple and all(type(row) is ClassicalCosts for row in classical_costs),
            "FINITE_CLASSICAL_COST_TYPES")
    require(type(physical_model) is PhysicalModel and type(iterations) is tuple, "FINITE_PARAMETER_TYPES")
    require(lifecycle_model is None or type(lifecycle_model) is LifecycleModel, "FINITE_LIFECYCLE_TYPE")
    return {"classical_costs": [asdict(row) for row in classical_costs], "physical_model": asdict(physical_model),
            "physical_qubit_budget": physical_qubit_budget, "horizon_seconds": horizon_seconds,
            "iterations": list(iterations), "max_attempts": max_attempts,
            "predicate": predicate, "max_states": max_states,
            "execution_kind": execution_kind,
            "lifecycle_model": None if lifecycle_model is None else asdict(lifecycle_model)}


def _fixed_action(model, state, iterations):
    """Observable fixed-q strategy. No census probabilities or optimized values."""
    choices = model.actions(state)
    lead = model.tip(state)["chainwork"] > model.public["chainwork"]
    if lead and rational(state["time"]) >= model.public_time and {"kind": "publish"} in choices:
        return {"kind": "publish"}
    if lead and {"kind": "wait-for-public"} in choices:
        return {"kind": "wait-for-public"}
    search = {"kind": "search", "iterations": iterations}
    return search if search in choices else {"kind": "stop"}


def _header(model, fixture):
    classical = model.execution_kind == "classical-uniform-q0"
    return {"schema": SCHEMA, "fixture_sha256": model.fixture_hash, "source_sha256": model.source_hashes,
            "parameters": model.parameters, "constructed_binding": None if model.binding is None else model.binding.certificate,
            "enumeration_limits": {"states": model.cap, "transition_edges": MAX_TRANSITION_EDGES},
            "machine_envelope": model.machine, "classical_host_envelope": model.classical_envelope,
            "action_envelope_coverage": {"maximum_attempts_per_path": model.attempts,
                "maximum_proofs_per_path": model.attempts, "maximum_propagations_per_path": model.attempts,
                "maximum_attempts_reserved_per_domain": model.attempts,
                "maximum_iterations_reserved_per_attempt": max(model.iterations),
                "setup_per_domain_per_path_at_most_one": True,
                "reason": "strictly increasing private heights forbid revisiting an earlier template; misses keep the same resident; every search consumes an attempt"},
            "context_order": list(model.ordered),
            "literal_domain_summaries": [{"context_id": key, "domain_sha256": model.contexts[key]["domain"]["domain_sha256"],
                "domain_size": model.contexts[key]["domain"]["domain_size"],
                "full_accepted_nonces": model.contexts[key]["domain"]["marked_nonces"],
                "native_shape": model.contexts[key]["domain"]["native_shape"]} for key in model.ordered],
            "initial_resources": fixture["initial_resources"],
            "scope": {"public_classical_history": "fixed already generated one-block competing extension; no further honest mining",
                "private_actions": "fresh classical uniform nonce, full candidate check, serial proof, private extension, publication, wait, stop" if classical else "declared fresh uniform Grover q, full candidate check, serial proof, private extension, publication, wait, stop",
                "quantum_processors": 0 if classical else 1, "classical_workers": 1,
                "coherent_state_carried_between_attempts": False,
                "cache": "single resident exact template; reuse only after completed setup",
                "publication": "serial propagation charge for every withheld block, then native future-clock deferral",
                "maximum_value_policy": "observer-census-aware envelope over the closed declared action class",
                "fixed_q_policy_reads_census": False, "fixed_q_policy_precommitment_attested": False,
                "nonzero_witness": "observer-selected positive-probability path, not a sampled attack",
                "native_prefix_validation": "external native fixture observation; prefix metadata arithmetic independently checked here",
                "native_winner_validation": "literal complete PNW1 scalar replay; online Node execution belongs to external bridge",
                "exact_probability_scope": "independent fresh classical uniform samples on the literal domain" if classical else "ideal finite literal-predicate Grover process, independent fresh attempts",
                "clock_model": "classical host calls, no QPU" if classical else "coherent-only comparison" if model.machine is None else "full conditional machine lifecycle",
                "nonce_observation": "after the declared classical RNG host call" if classical else "only after complete readout, host turnaround and output transfer in the lifecycle model",
                "unlisted_timestamp_search_algorithms_or_network_strategies_covered": False,
                "physical_clock_calibrated": False, "whole_machine_error_bound_composed": model.error_envelope is not None,
                "machine_coupling": "conditional on declared history-dependent event bounds and exact ideal timed trace outside their union; not calibrated hardware",
                "attacker_minimum_cost_proved": False, "quantum_hardware_executed": False,
                "mixed_quantum_classical_consensus_security_proved": False,
                "quantum_mining_qualified": False, "production_activation": False}}


def analyze_finite_consensus(fixture, classical_costs, physical_model, physical_qubit_budget,
                             *, horizon_seconds="4", iterations=(0, 1), max_attempts=2,
                             predicate="full", max_states=10_000, lifecycle_model=None,
                             execution_kind="constructed-quantum"):
    """Build an exact closed finite-model upper envelope and fixed-policy values."""
    parameters = _parameters(classical_costs, physical_model, physical_qubit_budget, horizon_seconds,
                             iterations, max_attempts, predicate, max_states, lifecycle_model, execution_kind)
    model = FiniteModel(fixture, parameters)
    return _analyze_model(model, _header(model, fixture), _fixed_action, _source_hashes)


def _analyze_model(model, report, fixed_action, source_hashes, *, risk_bounds=None):
    """Shared finite graph writer; callers supply versioned, closed semantics.

    The independent checker below never invokes this optimizer. The v1 fixed
    public-tip API retains its original semantics and output fields.
    """
    risk_bounds = _machine_risk if risk_bounds is None else risk_bounds
    nodes, values, visiting = {}, {}, set()
    edge_count = 0

    def solve(state):
        nonlocal edge_count
        key = digest(state)
        if key in values:
            return values[key]
        require(key not in visiting, "FINITE_GRAPH_CYCLE")
        if len(nodes) >= model.cap:
            raise OverflowError("FINITE_STATE_CAP_INCOMPLETE")
        visiting.add(key)
        node = {"state": state, "actions": []}
        nodes[key] = node
        maximum, best = Fraction(0), None
        for action in model.actions(state):
            edges = model.transition(state, action)
            edge_count += len(edges)
            if edge_count > MAX_TRANSITION_EDGES:
                raise OverflowError("FINITE_EDGE_CAP_INCOMPLETE")
            expected = Fraction(0)
            for edge in edges:
                continuation = (Fraction(edge["terminal_risk"]) if edge["next_state"] is None
                                else solve(edge["next_state"]))
                expected += rational(edge["probability"]) * continuation
            node["actions"].append({"action": action, "edges": edges, "value": ratio(expected)})
            if best is None or expected > maximum:
                maximum, best = expected, action
        node.update(value=ratio(maximum), maximizing_action=best)
        values[key] = maximum
        visiting.remove(key)
        return maximum

    try:
        maximum = solve(model.initial())
    except OverflowError as error:
        require(str(error) in ("FINITE_STATE_CAP_INCOMPLETE", "FINITE_EDGE_CAP_INCOMPLETE"), "UNEXPECTED_OVERFLOW")
        report.update(status="INCOMPLETE", reason=str(error), state_count=len(nodes),
                      risk_upper=None, fixed_policy_risks=None, positive_path=None, nodes=None,
                      finite_model_certificate_complete=False, conditional_machine_risk_bounds=None)
        report["certificate_sha256"] = digest(report)
        return report
    fixed = {}
    for count in model.iterations:
        cache = {}

        def evaluate(state):
            key = digest(state)
            if key not in cache:
                action = fixed_action(model, state, count)
                edges = model.transition(state, action)
                cache[key] = sum((rational(edge["probability"]) * (Fraction(edge["terminal_risk"])
                    if edge["next_state"] is None else evaluate(edge["next_state"])) for edge in edges), Fraction(0))
            return cache[key]

        fixed[str(count)] = ratio(evaluate(model.initial()))
    positive = None
    if maximum:
        state, trajectory, probability = model.initial(), [], Fraction(1)
        while True:
            node = nodes[digest(state)]
            action = node["maximizing_action"]
            edges = next(row["edges"] for row in node["actions"] if row["action"] == action)
            edge = next(edge for edge in edges if (edge["terminal_risk"] if edge["next_state"] is None
                                                   else values[digest(edge["next_state"])]) > 0)
            probability *= rational(edge["probability"])
            trajectory.append({"state": state, "action": action, "edge": edge})
            if edge["next_state"] is None:
                break
            state = edge["next_state"]
        positive = {"selection": "observer-census-advice existential witness", "probability": ratio(probability),
                    "trajectory": trajectory, "sampled_execution": False}
    report.update(status="COMPLETE", state_count=len(nodes), nodes=nodes, risk_upper=ratio(maximum),
                  fixed_policy_risks=fixed, positive_path=positive, finite_model_certificate_complete=True)
    report["conditional_machine_risk_bounds"] = risk_bounds(model, maximum, fixed)
    require(source_hashes() == model.source_hashes, "FINITE_SOURCE_CHANGED")
    report["certificate_sha256"] = digest(report)
    return report


def _machine_risk(model, maximum, fixed):
    """Elementary event coupling, independent of the interval probability kernel."""
    if model.error_envelope is None:
        return None
    epsilon = rational(model.error_envelope["envelope"]["whole_plan_failure_union_upper"])

    def interval(value):
        return {"lower": ratio(max(Fraction(0), value - epsilon)),
                "upper": ratio(min(Fraction(1), value + epsilon))}

    return {"failure_union_upper": ratio(epsilon), "census_advised_action_envelope": interval(maximum),
            "fixed_q_policies": {count: interval(rational(value)) for count, value in fixed.items()},
            "coupling_premise": "the actual timed trace equals the ideal trace outside the reserved history-conditional fault-event union",
            "all_paths_covered_by_reserved_events": True,
            "common_quantum_code_distance_used": model.machine is not None,
            "hardware_calibration_or_network_security_claimed": False}


def _check_certificate(record, model, fixture, *, header=None, fixed_action=_fixed_action, risk_bounds=None):
    """Check coverage, kernels and Bellman inequalities without invoking solve()."""
    header = _header(model, fixture) if header is None else header
    risk_bounds = _machine_risk if risk_bounds is None else risk_bounds
    require(type(record) is dict and record.get("schema") == header["schema"], "FINITE_CERTIFICATE_SCHEMA")
    without_hash = {key: value for key, value in record.items() if key != "certificate_sha256"}
    require(record.get("certificate_sha256") == digest(without_hash), "FINITE_CERTIFICATE_DIGEST")
    fields = {"certificate_sha256", "status", "state_count", "nodes", "risk_upper",
              "fixed_policy_risks", "positive_path", "finite_model_certificate_complete", "conditional_machine_risk_bounds"}
    if record.get("status") == "INCOMPLETE":
        fields.add("reason")
    require(set(record) == set(header) | fields, "FINITE_CERTIFICATE_FIELDS")
    for key, value in header.items():
        require(canonical(record.get(key)) == canonical(value), "FINITE_CERTIFICATE_PREMISE: " + key)
    if record.get("status") == "INCOMPLETE":
        require(record.get("risk_upper") is None and record.get("fixed_policy_risks") is None
                and record.get("positive_path") is None and record.get("nodes") is None
                and record.get("conditional_machine_risk_bounds") is None
                and record.get("finite_model_certificate_complete") is False,
                "INCOMPLETE_CANNOT_CERTIFY")
        return {"status": "INCOMPLETE", "bellman_checked": False, "risk_upper": None}
    require(record.get("status") == "COMPLETE" and record.get("finite_model_certificate_complete") is True,
            "FINITE_CERTIFICATE_STATUS")
    nodes = record["nodes"]
    integer(record["state_count"], "FINITE_CERTIFICATE_STATE_COUNT", 1, model.cap)
    require(type(nodes) is dict and len(nodes) == record["state_count"] <= model.cap, "FINITE_CERTIFICATE_NODES")
    queue, reachable, edges_checked = [model.initial()], set(), 0
    while queue:
        state = queue.pop()
        key = digest(state)
        if key in reachable:
            continue
        require(key in nodes and nodes[key]["state"] == state, "CERTIFICATE_MISSING_STATE")
        reachable.add(key)
        node = nodes[key]
        require(set(node) == {"state", "actions", "value", "maximizing_action"}, "FINITE_NODE_FIELDS")
        value = rational(node["value"])
        require(0 <= value <= 1, "CERTIFICATE_VALUE_RANGE")
        actions = model.actions(state)
        require(type(node["actions"]) is list and [row["action"] for row in node["actions"]] == actions,
                "CERTIFICATE_ACTION_COVERAGE")
        expected_values = []
        for row in node["actions"]:
            require(set(row) == {"action", "edges", "value"}, "FINITE_ACTION_FIELDS")
            edges = model.transition(state, row["action"])
            edges_checked += len(edges)
            require(edges_checked <= MAX_TRANSITION_EDGES, "CERTIFICATE_EDGE_CAP")
            require(canonical(row["edges"]) == canonical(edges), "CERTIFICATE_TRANSITION_MISMATCH")
            total = Fraction(0)
            for edge in edges:
                following = edge["next_state"]
                if following is None:
                    continuation = Fraction(edge["terminal_risk"])
                else:
                    next_key = digest(following)
                    require(next_key in nodes, "CERTIFICATE_OPEN_GRAPH")
                    # Every edge either consumes an attempt or strictly advances
                    # time without resetting attempts. This proves acyclicity.
                    require(following["attempts"] > state["attempts"] or
                            (following["attempts"] == state["attempts"] and rational(following["time"]) > rational(state["time"])),
                            "CERTIFICATE_NONDECREASING_RANK")
                    queue.append(following)
                    continuation = rational(nodes[next_key]["value"])
                total += rational(edge["probability"]) * continuation
            require(rational(row["value"]) == total and value >= total, "BELLMAN_INEQUALITY")
            expected_values.append(total)
        require(value == max(expected_values), "BELLMAN_NOT_EXACT_MAXIMUM")
        best = actions[expected_values.index(max(expected_values))]
        require(node["maximizing_action"] == best, "BELLMAN_MAXIMIZING_ACTION")
    require(reachable == set(nodes), "CERTIFICATE_UNREACHABLE_STATES")
    require(record["risk_upper"] == nodes[digest(model.initial())]["value"], "CERTIFICATE_INITIAL_VALUE")
    require(canonical(record["conditional_machine_risk_bounds"]) == canonical(
        risk_bounds(model, rational(record["risk_upper"]), record["fixed_policy_risks"])), "FINITE_MACHINE_COUPLING_BOUND")
    # Check each fixed policy independently by forward probability flow, rather
    # than reusing the generator's recursive value calculation.
    require(type(record["fixed_policy_risks"]) is dict
            and set(record["fixed_policy_risks"]) == {str(q) for q in model.iterations}, "FIXED_POLICY_KEYS")
    for count in model.iterations:
        flow, total = {digest(model.initial()): Fraction(1)}, Fraction(0)
        ordered = sorted(nodes, key=lambda key: (nodes[key]["state"]["attempts"], rational(nodes[key]["state"]["time"])))
        for key in ordered:
            mass = flow.get(key, Fraction(0))
            if not mass:
                continue
            state = nodes[key]["state"]
            action = fixed_action(model, state, count)
            for edge in model.transition(state, action):
                amount = mass * rational(edge["probability"])
                if edge["next_state"] is None:
                    total += amount * edge["terminal_risk"]
                else:
                    child = digest(edge["next_state"])
                    flow[child] = flow.get(child, Fraction(0)) + amount
        require(record["fixed_policy_risks"].get(str(count)) == ratio(total), "FIXED_POLICY_FLOW_MISMATCH")
    witness = record["positive_path"]
    if rational(record["risk_upper"]) == 0:
        require(witness is None, "ZERO_RISK_HAS_WITNESS")
    else:
        require(type(witness) is dict and set(witness) == {"selection", "probability", "trajectory", "sampled_execution"}
                and witness["sampled_execution"] is False
                and witness["selection"] == "observer-census-advice existential witness", "POSITIVE_WITNESS_SCOPE")
        state, product, terminal = model.initial(), Fraction(1), None
        for step in witness["trajectory"]:
            require(terminal is None and step["state"] == state, "WITNESS_STATE")
            edges = model.transition(state, step["action"])
            require(step["edge"] in edges, "WITNESS_EDGE")
            edge = step["edge"]
            product *= rational(edge["probability"])
            state, terminal = edge["next_state"], edge["terminal_risk"]
        require(terminal == 1 and product > 0 and witness["probability"] == ratio(product), "WITNESS_TERMINAL")
    return {"status": "COMPLETE", "bellman_checked": True, "risk_upper": record["risk_upper"],
            "states_checked": len(nodes), "fixed_policy_forward_flow_checked": True,
            "mixed_quantum_classical_consensus_security_proved": False}


def verify_finite_certificate(record, fixture):
    """Re-enumerate literal W1, rebuild construction clocks and check every edge."""
    model = FiniteModel(fixture, record["parameters"])
    result = _check_certificate(record, model, fixture)
    require(_source_hashes() == model.source_hashes, "FINITE_SOURCE_CHANGED")
    return result


def sample_finite_policy(record, fixture, *, iterations=0, seed=9):
    """Sample one predeclared fixed-q policy, including misses, without float RNG."""
    integer(seed, "FINITE_SAMPLE_SEED")
    integer(iterations, "FINITE_SAMPLE_ITERATIONS", 0, MAX_EXACT_ITERATIONS)
    model = FiniteModel(fixture, record["parameters"])
    _check_certificate(record, model, fixture)
    return _sample_model(record, model, iterations, seed, _fixed_action, _source_hashes)


def _sample_model(record, model, iterations, seed, fixed_action, source_hashes):
    """Sample an already independently checked closed model without its values."""
    require(record["status"] == "COMPLETE" and iterations in model.iterations, "FINITE_SAMPLE_POLICY")
    rng, state, trajectory = random.Random(seed), model.initial(), []
    while True:
        action = fixed_action(model, state, iterations)
        edges = model.transition(state, action)
        denominator = lcm(*(rational(edge["probability"]).denominator for edge in edges))
        draw, running, selected = rng.randrange(denominator), 0, None
        for edge in edges:
            running += int(rational(edge["probability"]) * denominator)
            if draw < running:
                selected = edge
                break
        require(selected is not None, "FINITE_SAMPLE_NORMALIZATION")
        trajectory.append({"state": state, "action": action, "edge": selected})
        if selected["next_state"] is None:
            break
        state = selected["next_state"]
    observation = selected["observation"]
    require(source_hashes() == model.source_hashes, "FINITE_SOURCE_CHANGED")
    return {"schema": "trnm-w1-finite-fixed-policy-sample-v1", "certificate_sha256": record["certificate_sha256"],
            "fixture_sha256": model.fixture_hash, "seed": seed, "iterations": iterations,
            "clock_model": record["scope"]["clock_model"],
            "machine_envelope_sha256": None if model.machine is None else model.machine["record_sha256"],
            "classical_host_envelope_sha256": None if model.classical_envelope is None else digest(model.classical_envelope),
            "sample_kind": "ideal no-fault model trajectory; physical faults not sampled",
            "trajectory": trajectory, "selected_private_path": observation.get("private_chain", state["private_chain"]),
            "strict_work_replacement": selected["terminal_risk"] == 1,
            "policy_reads_marked_count_or_bellman_values": False,
            "publication_complete": observation.get("publication_complete", False),
            "sampler": "exact rational categorical draw with randrange(common denominator)",
            "native_blocks_admitted_by_this_function": 0, "quantum_hardware_executed": False,
            "quantum_mining_qualified": False}
