"""Exact finite certificates for a responsive, reduced two-miner model.

This model has stochastic honest attempts, delayed publication/notification,
live honest rebinding and charged cancellation. Its Bernoulli laws, constant
per-block work and discrete clocks are explicit hypotheses. They are NOT an
enumeration of native W1 domains, a QPU experiment, a physical cost bound or a
long-horizon settlement theorem. Native execution has a separate byte reader.

The checker regenerates every transition and checks local Bellman equations;
it never calls the optimizer. A state/edge cap produces INCOMPLETE with no risk
bound. Every tick advances time, including wait and stop. Completed in-flight
packets survive later cancellation, and honest attempts continue after a
private miner stops or publishes. Honest descendants of private blocks count
as private-branch survival even when the final tip is honest-owned.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import itertools
import json
from math import lcm
from pathlib import Path
import random

SCHEMA = "trnm-w1-responsive-consensus-certificate-v1"
PARAMETERS_SCHEMA = "trnm-w1-responsive-reduced-parameters-v1"
SAMPLE_SCHEMA = "trnm-w1-responsive-fixed-policy-sample-v1"
RISK_EVENTS = ("ever_private_replacement", "private_tip_at_horizon",
               "private_ancestor_at_horizon", "initial_public_block_orphaned_at_horizon")
OWNERS = ("base", "public", "honest", "private")
MAX_STATES, MAX_EDGES = 100_000, 1_000_000
FIXED_POLICY = "mine-private-then-publish-v1"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def integer(value, code, minimum=0, maximum=1 << 63):
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def rational(value):
    require(type(value) is dict and set(value) == {"numerator", "denominator"}, "RESPONSIVE_RATIONAL")
    integer(value["numerator"], "RESPONSIVE_NUMERATOR", -(1 << 4096), 1 << 4096)
    integer(value["denominator"], "RESPONSIVE_DENOMINATOR", 1, 1 << 4096)
    answer = Fraction(value["numerator"], value["denominator"])
    require(ratio(answer) == value, "RESPONSIVE_RATIONAL_NOT_REDUCED")
    return answer


def canonical(value):
    def visit(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for child in item:
                visit(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                visit(child)
            return
        raise ValueError("RESPONSIVE_CANONICAL_TYPE")
    visit(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def source_hashes():
    return {"formal/pon-nakamoto-v1/w1_responsive_consensus.py":
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def declared_parameters(**changes):
    """A frozen 4s reduced scenario; it is not native target calibration.

    The honest-start cap matches the native experiment's six opportunities.
    Exhaustion stays in the model and every unfinished/cancelled start consumes
    its declared opportunity. The abstract success laws remain separate.
    """
    result = {
        "schema": PARAMETERS_SCHEMA, "tick_seconds": ratio(Fraction(1, 4)),
        "horizon_ticks": 16, "honest_attempt_ticks": 3, "honest_delivery_ticks": 1,
        "honest_tip_notification_ticks": 1, "max_honest_attempts": 6,
        "private_candidate_ticks": 1, "private_winner_proof_ticks": 4,
        "private_propagation_ticks": 1, "max_private_attempts": 2,
        "success_laws": {owner: {parent: ratio(Fraction(1, 8)) for parent in OWNERS}
                         for owner in ("honest", "private")},
        "initial_public_work": 1, "block_work": 1,
        "allow_rebase": False, "max_states": 10000, "max_edges": 100000,
        "clock_scope": "declared reduced grid; no physical calibration",
        "work_scope": "constant-work finite stratum; no retarget boundary or timestamp freedom",
        "fault_union_upper": ratio(Fraction(0)),
        "fault_coupling_scope": "conditional reduced whole-trace coupling assumption, not observed hardware evidence",
    }
    result.update(changes)
    return result


def validate_parameters(parameters):
    require(type(parameters) is dict and set(parameters) == set(declared_parameters()),
            "RESPONSIVE_PARAMETER_FIELDS")
    require(parameters["schema"] == PARAMETERS_SCHEMA, "RESPONSIVE_PARAMETER_SCHEMA")
    tick = rational(parameters["tick_seconds"])
    integer(parameters["horizon_ticks"], "RESPONSIVE_HORIZON", 1, 32)
    require(tick > 0 and tick * parameters["horizon_ticks"] == 4, "RESPONSIVE_ORIGINAL_FOUR_SECONDS")
    for key in ("honest_attempt_ticks", "honest_delivery_ticks", "private_candidate_ticks",
                "private_winner_proof_ticks", "private_propagation_ticks"):
        integer(parameters[key], "RESPONSIVE_" + key.upper(), 1, 1_000_000)
    integer(parameters["honest_tip_notification_ticks"], "RESPONSIVE_NOTIFICATION", 0, 32)
    integer(parameters["max_honest_attempts"], "RESPONSIVE_HONEST_CAP", 1, 8)
    integer(parameters["max_private_attempts"], "RESPONSIVE_PRIVATE_CAP", 1, 4)
    integer(parameters["initial_public_work"], "RESPONSIVE_INITIAL_WORK", 1, 64)
    integer(parameters["block_work"], "RESPONSIVE_BLOCK_WORK", 1, 64)
    integer(parameters["max_states"], "RESPONSIVE_STATE_CAP", 1, MAX_STATES)
    integer(parameters["max_edges"], "RESPONSIVE_EDGE_CAP", 1, MAX_EDGES)
    require(type(parameters["allow_rebase"]) is bool, "RESPONSIVE_REBASE_FLAG")
    for key in ("clock_scope", "work_scope", "fault_coupling_scope"):
        require(type(parameters[key]) is str and 1 <= len(parameters[key]) <= 2048,
                "RESPONSIVE_SCOPE_TEXT")
    require(0 <= rational(parameters["fault_union_upper"]) <= 1, "RESPONSIVE_FAULT_BOUND")
    laws = parameters["success_laws"]
    require(type(laws) is dict and set(laws) == {"honest", "private"}, "RESPONSIVE_LAW_OWNERS")
    for values in laws.values():
        require(type(values) is dict and set(values) == set(OWNERS), "RESPONSIVE_LAW_PARENTS")
        for probability in values.values():
            require(0 <= rational(probability) <= 1, "RESPONSIVE_PROBABILITY_RANGE")


class ResponsiveModel:
    def __init__(self, parameters):
        validate_parameters(parameters)
        self.parameters = deepcopy(parameters)
        self.limit = parameters["horizon_ticks"]
        self.source = source_hashes()

    def initial(self):
        state = {"tick": 0, "nodes": {
                    "base": {"parent": None, "owner": "base", "work": 0},
                    "public": {"parent": "base", "owner": "public",
                               "work": self.parameters["initial_public_work"]}},
                 "selected": "public", "honest_view": "public", "view_generation": 0,
                 "selection_generation": 0, "private_tip": "base", "private_chain": [],
                 "published": [], "honest_active": None, "private_active": None,
                 "deliveries": [], "notifications": [], "honest_started": 0,
                 "private_started": 0, "honest_completed": 0, "honest_cancelled": 0,
                 "private_checks_completed": 0, "private_proofs_completed": 0,
                 "honest_elapsed_ticks": 0, "honest_cancelled_ticks": 0,
                 "private_elapsed_ticks": 0, "private_propagation_elapsed_ticks": 0,
                 "honest_network_elapsed_ticks": 0, "private_stopped": False,
                 "ever_private_replacement": False}
        self._start_honest(state, [])
        return state

    def _start_honest(self, state, events):
        if (state["tick"] >= self.limit or state["honest_active"] is not None
                or state["honest_started"] >= self.parameters["max_honest_attempts"]):
            return
        state["honest_started"] += 1
        state["honest_active"] = {"id": "h" + str(state["honest_started"]),
            "parent": state["honest_view"], "start": state["tick"],
            "due": state["tick"] + self.parameters["honest_attempt_ticks"]}
        events.append({"kind": "honest-start", "tick": state["tick"], **state["honest_active"]})

    def actions(self, state):
        if state["tick"] == self.limit:
            return []
        if state["private_active"] is not None or state["private_stopped"]:
            return [{"kind": "wait"}]
        result = [{"kind": "wait"}, {"kind": "stop"}]
        if state["private_started"] < self.parameters["max_private_attempts"]:
            result.append({"kind": "search"})
        if any(block not in state["published"] for block in state["private_chain"]):
            result.append({"kind": "publish"})
        if self.parameters["allow_rebase"] and state["private_tip"] != state["selected"]:
            result.append({"kind": "rebase"})
        return result

    def _begin(self, state, action, events):
        kind, now = action["kind"], state["tick"]
        if kind == "search":
            state["private_started"] += 1
            state["private_active"] = {"kind": "candidate", "id": "p" + str(state["private_started"]),
                "parent": state["private_tip"], "start": now,
                "due": now + self.parameters["private_candidate_ticks"]}
            events.append({"kind": "private-start", "tick": now,
                           "attempt": deepcopy(state["private_active"])})
        elif kind == "publish":
            unseen = [block for block in state["private_chain"] if block not in state["published"]]
            for index, block in enumerate(unseen, 1):
                state["deliveries"].append({"owner": "private", "block": block,
                    "due": now + index * self.parameters["private_propagation_ticks"]})
            state["private_active"] = {"kind": "propagation", "start": now,
                "due": now + len(unseen) * self.parameters["private_propagation_ticks"]}
            events.append({"kind": "private-publish-start", "tick": now, "blocks": unseen,
                           "finish": state["private_active"]["due"]})
        elif kind == "stop":
            state["private_stopped"] = True
            events.append({"kind": "private-stop", "tick": now})
        elif kind == "rebase":
            state["private_tip"], state["private_chain"] = state["selected"], []
            events.append({"kind": "private-rebase", "tick": now, "parent": state["selected"]})

    def _probability(self, owner, parent, state):
        return rational(self.parameters["success_laws"][owner][state["nodes"][parent]["owner"]])

    def _block(self, state, identifier, parent, owner):
        require(identifier not in state["nodes"], "RESPONSIVE_BLOCK_ID_REUSE")
        state["nodes"][identifier] = {"parent": parent, "owner": owner,
            "work": state["nodes"][parent]["work"] + self.parameters["block_work"]}

    def _advance(self, state, honest_success, private_success, events):
        now = state["tick"] + 1
        if state["honest_active"] is not None:
            state["honest_elapsed_ticks"] += 1
        if state["private_active"] is not None:
            if state["private_active"]["kind"] == "propagation":
                state["private_propagation_elapsed_ticks"] += 1
            else:
                state["private_elapsed_ticks"] += 1
        state["honest_network_elapsed_ticks"] += sum(row["owner"] == "honest" for row in state["deliveries"])
        state["tick"] = now
        honest = state["honest_active"]
        if honest is not None and honest["due"] == now:
            require(type(honest_success) is bool, "RESPONSIVE_HONEST_COMPLETION_OUTCOME")
            state["honest_active"] = None
            state["honest_completed"] += 1
            events.append({"kind": "honest-complete", "tick": now, "attempt": honest,
                           "success": honest_success})
            if honest_success:
                self._block(state, honest["id"], honest["parent"], "honest")
                state["deliveries"].append({"owner": "honest", "block": honest["id"],
                    "due": now + self.parameters["honest_delivery_ticks"]})

        # Already completed stale packets remain in this queue. Arrival ordering
        # is based on exact integer ticks, honest first and private parent-first.
        arrivals = [row for row in state["deliveries"] if row["due"] == now]
        state["deliveries"] = [row for row in state["deliveries"] if row["due"] != now]
        arrivals.sort(key=lambda row: (row["owner"] != "honest",
                                      state["nodes"][row["block"]]["work"], row["block"]))
        for row in arrivals:
            old, block = state["selected"], row["block"]
            require(state["nodes"][block]["parent"] in state["nodes"], "RESPONSIVE_ARRIVAL_PARENT")
            if state["nodes"][block]["work"] > state["nodes"][old]["work"]:
                state["selected"] = block
                state["selection_generation"] += 1
                state["notifications"].append({"due": now + self.parameters["honest_tip_notification_ticks"],
                    "generation": state["selection_generation"], "tip": block})
                if row["owner"] == "private" and state["nodes"][old]["owner"] != "private":
                    state["ever_private_replacement"] = True
            if row["owner"] == "private":
                state["published"].append(block)
            events.append({"kind": "receiver-admit", "tick": now, "owner": row["owner"],
                           "block": block, "selected_before": old, "selected_after": state["selected"]})

        notices = sorted((row for row in state["notifications"] if row["due"] == now),
                         key=lambda row: row["generation"])
        state["notifications"] = [row for row in state["notifications"] if row["due"] != now]
        for row in notices:
            if row["generation"] <= state["view_generation"]:
                events.append({"kind": "honest-notice-stale", "tick": now, **row})
                continue
            old_view = state["honest_view"]
            state["view_generation"], state["honest_view"] = row["generation"], row["tip"]
            events.append({"kind": "honest-notify", "tick": now, "generation": row["generation"],
                           "old_view_tip": old_view, "new_view_tip": row["tip"]})
            active = state["honest_active"]
            if active is not None and active["parent"] != row["tip"]:
                elapsed = now - active["start"]
                state["honest_cancelled"] += 1
                state["honest_cancelled_ticks"] += elapsed
                state["honest_active"] = None
                events.append({"kind": "honest-cancel", "tick": now, "attempt": active,
                               "new_parent": row["tip"], "charged_elapsed_ticks": elapsed})

        private = state["private_active"]
        if private is not None and private["due"] == now:
            kind = private["kind"]
            if kind == "candidate":
                require(type(private_success) is bool, "RESPONSIVE_PRIVATE_CHECK_OUTCOME")
                state["private_checks_completed"] += 1
                events.append({"kind": "private-check", "tick": now, "attempt": private,
                               "success": private_success})
                state["private_active"] = ({**private, "kind": "proof", "proof_start": now,
                    "due": now + self.parameters["private_winner_proof_ticks"]} if private_success else None)
            elif kind == "proof":
                self._block(state, private["id"], private["parent"], "private")
                state["private_tip"] = private["id"]
                state["private_chain"].append(private["id"])
                state["private_proofs_completed"] += 1
                state["private_active"] = None
                events.append({"kind": "private-complete", "tick": now, "attempt": private,
                               "block": private["id"]})
            else:
                state["private_active"] = None
                events.append({"kind": "private-publication-complete", "tick": now})
        self._start_honest(state, events)
        self.check_state(state)
        return state

    def check_state(self, state):
        require(0 <= state["tick"] <= self.limit, "RESPONSIVE_STATE_TIME")
        require(state["honest_started"] == state["honest_completed"] + state["honest_cancelled"]
                + int(state["honest_active"] is not None), "RESPONSIVE_HONEST_START_DENOMINATOR")
        require(state["honest_started"] <= self.parameters["max_honest_attempts"]
                and state["private_started"] <= self.parameters["max_private_attempts"],
                "RESPONSIVE_ATTEMPT_BUDGET")
        active_paid = 0 if state["honest_active"] is None else state["tick"] - state["honest_active"]["start"]
        require(state["honest_elapsed_ticks"] ==
                state["honest_completed"] * self.parameters["honest_attempt_ticks"]
                + state["honest_cancelled_ticks"] + active_paid, "RESPONSIVE_CANCEL_COST_CONSERVATION")
        require(all(row["due"] > state["tick"] for row in state["deliveries"] + state["notifications"]),
                "RESPONSIVE_OVERDUE_EVENT")
        require(state["selected"] in state["nodes"] and state["honest_view"] in state["nodes"],
                "RESPONSIVE_UNKNOWN_TIP")

    def transition(self, state, action):
        require(action in self.actions(state), "RESPONSIVE_UNDECLARED_ACTION")
        working, beginning = deepcopy(state), []
        self._begin(working, action, beginning)
        now = state["tick"] + 1
        distributions = []
        for owner, active in (("honest", working["honest_active"]),
                              ("private", working["private_active"])):
            due = active is not None and active["due"] == now
            random_completion = due and (owner == "honest" or active["kind"] == "candidate")
            if random_completion:
                probability = self._probability(owner, active["parent"], working)
                distributions.append([(False, 1 - probability), (True, probability)])
            else:
                distributions.append([(None, Fraction(1))])
        edges = []
        for honest, private in itertools.product(*distributions):
            probability = honest[1] * private[1]
            if probability == 0:
                continue
            events = deepcopy(beginning)
            following = self._advance(deepcopy(working), honest[0], private[0], events)
            edges.append({"probability": ratio(probability), "next_state": following,
                          "events": events})
        require(sum((rational(edge["probability"]) for edge in edges), Fraction(0)) == 1,
                "RESPONSIVE_TRANSITION_NORMALIZATION")
        return edges

    def outcomes(self, state):
        ancestry, tip = [], state["selected"]
        while tip is not None:
            require(tip not in ancestry, "RESPONSIVE_ANCESTRY_CYCLE")
            ancestry.append(tip)
            tip = state["nodes"][tip]["parent"]
        return {"ever_private_replacement": int(state["ever_private_replacement"]),
                "private_tip_at_horizon": int(state["nodes"][state["selected"]]["owner"] == "private"),
                "private_ancestor_at_horizon": int(any(state["nodes"][key]["owner"] == "private" for key in ancestry)),
                "initial_public_block_orphaned_at_horizon": int("public" not in ancestry)}


def fixed_action(model, state):
    """Only current time, received tip and already completed private outcomes."""
    choices = model.actions(state)
    publish, search = {"kind": "publish"}, {"kind": "search"}
    if publish in choices and (state["private_started"] >= model.parameters["max_private_attempts"]
            or state["nodes"][state["private_tip"]]["work"] > state["nodes"][state["selected"]]["work"]
            or state["tick"] + model.parameters["private_candidate_ticks"]
            + model.parameters["private_winner_proof_ticks"]
            + (len(state["private_chain"]) + 1) * model.parameters["private_propagation_ticks"] > model.limit):
        return publish
    if search in choices:
        return search
    return {"kind": "wait"}


def _scope():
    return {"classification": "CONDITIONAL_REDUCED_MODEL",
            "native_W1_domain_probabilities_enumerated": False,
            "native_DAA_or_timestamp_security_proved": False,
            "stochastic_honest_attempts_in_declared_model": True,
            "honest_parent_reacts_to_received_selection": True,
            "honest_completed_stale_packets_retained": True,
            "cancelled_and_censored_work_charged": True,
            "private_search_and_proof_are_nonpreemptive": True,
            "equal_time_order": "honest-completion; honest-before-private-delivery; notices; private-completion; honest-restart",
            "ancestor_includes_tip": True,
            "fixed_policy_reads_future_outcomes": False,
            "optimizer_knows_declared_success_laws": True,
            "optimizer_reads_future_realized_outcomes": False,
            "information_scope": "past honest start/completion broadcasts, queued packets and receiver notifications are observable; future outcomes are not",
            "arbitrary_timestamp_strategies_covered": False,
            "arbitrary_quantum_algorithms_covered": False,
            "physical_clock_calibrated": False,
            "quantum_hardware_executed": False,
            "long_horizon_settlement_security_proved": False,
            "quantum_mining_qualified": False, "production_activation": False}


def _header(model):
    return {"schema": SCHEMA, "parameters": model.parameters, "source_sha256": model.source,
            "initial_state": model.initial(), "risk_events": list(RISK_EVENTS),
            "fixed_policy": FIXED_POLICY, "scope": _scope()}


class _CapReached(Exception):
    pass


def _fault_bounds(model, values):
    error = rational(model.parameters["fault_union_upper"])
    return {key: {"lower": ratio(max(Fraction(0), value - error)),
                  "upper": ratio(min(Fraction(1), value + error))} for key, value in values.items()}


def analyze_responsive_consensus(parameters):
    model, nodes, visiting = ResponsiveModel(parameters), {}, set()
    edges_seen = 0

    def visit(state):
        nonlocal edges_seen
        key = digest(state)
        if key in nodes:
            return nodes[key]
        require(key not in visiting, "RESPONSIVE_GRAPH_CYCLE")
        if len(nodes) + len(visiting) >= parameters["max_states"]:
            raise _CapReached("state cap")
        visiting.add(key)
        if state["tick"] == model.limit:
            values = {name: Fraction(value) for name, value in model.outcomes(state).items()}
            node = {"state": state, "actions": [], "maximum": {k: ratio(v) for k, v in values.items()},
                    "fixed": {k: ratio(v) for k, v in values.items()}}
        else:
            action_rows = []
            for action in model.actions(state):
                edges = model.transition(state, action)
                edges_seen += len(edges)
                if edges_seen > parameters["max_edges"]:
                    raise _CapReached("edge cap")
                maximum = {name: Fraction(0) for name in RISK_EVENTS}
                fixed = dict(maximum)
                serialized = []
                for edge in edges:
                    child = visit(edge["next_state"])
                    probability = rational(edge["probability"])
                    for event in RISK_EVENTS:
                        maximum[event] += probability * rational(child["maximum"][event])
                        fixed[event] += probability * rational(child["fixed"][event])
                    serialized.append({"probability": edge["probability"],
                                       "next": digest(edge["next_state"]), "events": edge["events"]})
                action_rows.append({"action": action, "edges": serialized,
                                    "maximum": {k: ratio(v) for k, v in maximum.items()},
                                    "fixed_if_chosen": {k: ratio(v) for k, v in fixed.items()}})
            maximum = {event: max(rational(row["maximum"][event]) for row in action_rows) for event in RISK_EVENTS}
            chosen = next(row for row in action_rows if row["action"] == fixed_action(model, state))
            node = {"state": state, "actions": action_rows,
                    "maximum": {k: ratio(v) for k, v in maximum.items()},
                    "fixed": chosen["fixed_if_chosen"]}
        visiting.remove(key)
        nodes[key] = node
        return node

    report = _header(model)
    try:
        root = visit(model.initial())
        report.update(status="COMPLETE", nodes=nodes, maximum_risks=root["maximum"],
                      fixed_policy_risks=root["fixed"],
                      conditional_fault_risk_bounds=_fault_bounds(model,
                          {key: rational(value) for key, value in root["maximum"].items()}),
                      incomplete_reason=None)
    except _CapReached as error:
        report.update(status="INCOMPLETE", nodes={}, maximum_risks=None, fixed_policy_risks=None,
                      conditional_fault_risk_bounds=None, incomplete_reason=str(error))
    report["search_accounting"] = {"completed_state_values": len(nodes), "transition_edges_visited": edges_seen,
                                   "unresolved_recursion_states": len(visiting)}
    require(source_hashes() == model.source, "RESPONSIVE_SOURCE_CHANGED")
    report["certificate_sha256"] = digest(report)
    return report


def verify_responsive_certificate(report):
    require(type(report) is dict and report.get("schema") == SCHEMA, "RESPONSIVE_CERTIFICATE_SCHEMA")
    require(report.get("certificate_sha256") == digest({k: v for k, v in report.items() if k != "certificate_sha256"}),
            "RESPONSIVE_CERTIFICATE_DIGEST")
    model = ResponsiveModel(report["parameters"])
    for key, value in _header(model).items():
        require(canonical(report.get(key)) == canonical(value), "RESPONSIVE_PREMISE:" + key)
    require(report.get("status") in ("COMPLETE", "INCOMPLETE"), "RESPONSIVE_STATUS")
    accounting = report.get("search_accounting")
    require(type(accounting) is dict and set(accounting) == {"completed_state_values", "transition_edges_visited", "unresolved_recursion_states"},
            "RESPONSIVE_ACCOUNTING")
    for key, value in accounting.items():
        integer(value, "RESPONSIVE_ACCOUNTING_COUNT", 0, MAX_EDGES + MAX_STATES + 16)
    if report["status"] == "INCOMPLETE":
        require(report.get("nodes") == {} and all(report.get(k) is None for k in
                ("maximum_risks", "fixed_policy_risks", "conditional_fault_risk_bounds"))
                and report.get("incomplete_reason") in ("state cap", "edge cap"),
                "RESPONSIVE_INCOMPLETE_CANNOT_CERTIFY")
        return {"status": "INCOMPLETE", "bellman_checked": False, "quantum_mining_qualified": False}
    nodes = report.get("nodes")
    require(type(nodes) is dict and 1 <= len(nodes) <= model.parameters["max_states"], "RESPONSIVE_NODE_COUNT")
    pending, seen, edge_count = [model.initial()], set(), 0
    while pending:
        state = pending.pop()
        key = digest(state)
        if key in seen:
            continue
        require(key in nodes, "RESPONSIVE_MISSING_REACHABLE_STATE")
        node = nodes[key]
        require(node["state"] == state, "RESPONSIVE_STATE_IDENTITY")
        model.check_state(state)
        seen.add(key)
        for metric in ("maximum", "fixed"):
            require(type(node.get(metric)) is dict and set(node[metric]) == set(RISK_EVENTS), "RESPONSIVE_RISK_FIELDS")
            require(all(0 <= rational(value) <= 1 for value in node[metric].values()), "RESPONSIVE_RISK_RANGE")
        if state["tick"] == model.limit:
            expected = {event: ratio(Fraction(value)) for event, value in model.outcomes(state).items()}
            require(node["actions"] == [] and node["maximum"] == expected and node["fixed"] == expected,
                    "RESPONSIVE_TERMINAL_RISK")
            continue
        choices = model.actions(state)
        require(type(node.get("actions")) is list and [row["action"] for row in node["actions"]] == choices,
                "RESPONSIVE_COMPLETE_ACTION_INVENTORY")
        maxima = {event: Fraction(0) for event in RISK_EVENTS}
        fixed_selected = None
        for row in node["actions"]:
            regenerated = model.transition(state, row["action"])
            expected = [{"probability": edge["probability"], "next": digest(edge["next_state"]),
                         "events": edge["events"]} for edge in regenerated]
            require(row["edges"] == expected, "RESPONSIVE_TRANSITION_MISMATCH")
            edge_count += len(regenerated)
            require(edge_count <= model.parameters["max_edges"], "RESPONSIVE_EDGE_COUNT")
            values = {event: Fraction(0) for event in RISK_EVENTS}
            fixed = dict(values)
            for edge, item in zip(regenerated, expected):
                following = edge["next_state"]
                require(following["tick"] == state["tick"] + 1 and item["next"] in nodes,
                        "RESPONSIVE_FINITE_TIME_OR_CHILD")
                child = nodes[item["next"]]
                probability = rational(edge["probability"])
                for event in RISK_EVENTS:
                    values[event] += probability * rational(child["maximum"][event])
                    fixed[event] += probability * rational(child["fixed"][event])
                pending.append(following)
            require(row["maximum"] == {k: ratio(v) for k, v in values.items()}
                    and row["fixed_if_chosen"] == {k: ratio(v) for k, v in fixed.items()},
                    "RESPONSIVE_BELLMAN_ACTION_VALUE")
            maxima = {event: max(maxima[event], values[event]) for event in RISK_EVENTS}
            if row["action"] == fixed_action(model, state):
                fixed_selected = {k: ratio(v) for k, v in fixed.items()}
        require(node["maximum"] == {k: ratio(v) for k, v in maxima.items()} and node["fixed"] == fixed_selected,
                "RESPONSIVE_BELLMAN_STATE_VALUE")
    require(seen == set(nodes), "RESPONSIVE_UNREACHABLE_OR_OMITTED_STATE")
    root = nodes[digest(model.initial())]
    require(report["maximum_risks"] == root["maximum"] and report["fixed_policy_risks"] == root["fixed"],
            "RESPONSIVE_ROOT_VALUE")
    require(report["conditional_fault_risk_bounds"] == _fault_bounds(model,
            {key: rational(value) for key, value in root["maximum"].items()}), "RESPONSIVE_FAULT_COMPOSITION")
    require(accounting == {"completed_state_values": len(nodes), "transition_edges_visited": edge_count,
                           "unresolved_recursion_states": 0}, "RESPONSIVE_SEARCH_ACCOUNTING")
    require(report["incomplete_reason"] is None and source_hashes() == model.source, "RESPONSIVE_COMPLETE_SOURCE")
    return {"status": "VERIFIED", "bellman_checked": True, "states": len(nodes), "edges": edge_count,
            "native_W1_probabilities_certified": False, "quantum_mining_qualified": False}


def sample_responsive_policy(parameters, seed=9):
    integer(seed, "RESPONSIVE_SEED", 0, (1 << 64) - 1)
    model, generator = ResponsiveModel(parameters), random.Random(seed)
    state, trajectory, probability = model.initial(), [], Fraction(1)
    while state["tick"] < model.limit:
        action = fixed_action(model, state)
        edges = model.transition(state, action)
        denominator = lcm(*(rational(edge["probability"]).denominator for edge in edges))
        draw, cumulative, selected = generator.randrange(denominator), 0, None
        for edge in edges:
            cumulative += int(rational(edge["probability"]) * denominator)
            if draw < cumulative:
                selected = edge
                break
        require(selected is not None, "RESPONSIVE_SAMPLE_NORMALIZATION")
        probability *= rational(selected["probability"])
        trajectory.append({"state": state, "action": action, "edge": selected})
        state = selected["next_state"]
    require(source_hashes() == model.source, "RESPONSIVE_SOURCE_CHANGED")
    return {"schema": SAMPLE_SCHEMA, "parameters": model.parameters, "source_sha256": model.source,
            "seed": seed, "policy": FIXED_POLICY, "trajectory": trajectory,
            "probability_of_ideal_sample_path": ratio(probability), "outcomes": model.outcomes(state),
            "scope": _scope(), "sample_sha256": digest(trajectory)}


def verify_responsive_sample(sample):
    require(type(sample) is dict and sample.get("schema") == SAMPLE_SCHEMA, "RESPONSIVE_SAMPLE_SCHEMA")
    require(set(sample) == {"schema", "parameters", "source_sha256", "seed", "policy", "trajectory",
                           "probability_of_ideal_sample_path", "outcomes", "scope", "sample_sha256"},
            "RESPONSIVE_SAMPLE_FIELDS")
    model = ResponsiveModel(sample["parameters"])
    integer(sample["seed"], "RESPONSIVE_SEED", 0, (1 << 64) - 1)
    require(sample["source_sha256"] == model.source and sample["scope"] == _scope()
            and sample["policy"] == FIXED_POLICY, "RESPONSIVE_SAMPLE_PREMISES")
    trajectory = sample["trajectory"]
    require(type(trajectory) is list and len(trajectory) == model.limit
            and sample["sample_sha256"] == digest(trajectory), "RESPONSIVE_SAMPLE_LENGTH_OR_DIGEST")
    state, probability, generator = model.initial(), Fraction(1), random.Random(sample["seed"])
    for row in trajectory:
        require(type(row) is dict and set(row) == {"state", "action", "edge"}
                and row["state"] == state and row["action"] == fixed_action(model, state),
                "RESPONSIVE_SAMPLE_CAUSAL_POLICY")
        edges = model.transition(state, row["action"])
        denominator = lcm(*(rational(edge["probability"]).denominator for edge in edges))
        draw, cumulative = generator.randrange(denominator), 0
        expected = None
        for edge in edges:
            cumulative += int(rational(edge["probability"]) * denominator)
            if expected is None and draw < cumulative:
                expected = edge
        require(row["edge"] == expected, "RESPONSIVE_SAMPLE_TRANSITION_OR_SEED")
        probability *= rational(expected["probability"])
        state = expected["next_state"]
    require(sample["probability_of_ideal_sample_path"] == ratio(probability)
            and sample["outcomes"] == model.outcomes(state) and source_hashes() == model.source,
            "RESPONSIVE_SAMPLE_TERMINAL_OR_SOURCE")
    return {"status": "VERIFIED", "ticks": len(sample["trajectory"]),
            "outcomes": sample["outcomes"], "fixed_policy_reads_future_outcomes": False}


def fixed_policy_probability(parameters):
    """Forward probability propagation, independently of backward Bellman DP."""
    model = ResponsiveModel(parameters)
    initial = model.initial()
    distribution = {digest(initial): (initial, Fraction(1))}
    visited = 0
    for _ in range(model.limit):
        following = {}
        for state, mass in distribution.values():
            for edge in model.transition(state, fixed_action(model, state)):
                child, probability = edge["next_state"], mass * rational(edge["probability"])
                key = digest(child)
                old = following.get(key, (child, Fraction(0)))
                following[key] = (child, old[1] + probability)
        require(sum((mass for _, mass in following.values()), Fraction(0)) == 1,
                "RESPONSIVE_FORWARD_MASS")
        visited += len(following)
        require(visited <= parameters["max_states"], "RESPONSIVE_FORWARD_STATE_CAP")
        distribution = following
    risks = {name: sum((mass * model.outcomes(state)[name] for state, mass in distribution.values()), Fraction(0))
             for name in RISK_EVENTS}
    require(source_hashes() == model.source, "RESPONSIVE_SOURCE_CHANGED")
    return {"schema": "trnm-w1-responsive-forward-probability-v1", "status": "VERIFIED",
            "parameters_sha256": digest(parameters), "source_sha256": model.source,
            "fixed_policy_risks": {name: ratio(value) for name, value in risks.items()},
            "terminal_states": len(distribution), "state_visits": visited,
            "native_W1_probabilities_certified": False}
