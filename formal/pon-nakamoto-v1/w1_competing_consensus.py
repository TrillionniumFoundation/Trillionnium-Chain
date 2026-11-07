"""Exact finite W1 races against a declared continuing public-branch schedule.

The public producer has an isolated view: it receives no private publication
before the horizon and extends its own admitted tip. Arrivals at the separate
receiver are exact conditional inputs, not sampled honest mining or measured
network latency. The private miner retains all v1 lifecycle clocks and makes
one terminal publication. A temporary replacement and private selection at the
horizon are separate events. Neither event is a settlement-security theorem.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
from pathlib import Path

import contract_wire as wire
from reference import timestamp_state, work
import w1_finite_consensus as finite

SCHEMA = "trnm-w1-competing-consensus-certificate-v1"
FIXTURE_SCHEMA = "trnm-w1-native-competition-fixture-v1"
SAMPLE_SCHEMA = "trnm-w1-competing-fixed-policy-sample-v1"
RISK_EVENTS = ("ever-private-replacement", "private-active-at-horizon")
MAX_HONEST_BLOCKS = 32
MAX_SCENARIOS = 8
ROOT = Path(__file__).resolve().parents[2]
require, ratio, rational = finite.require, finite.ratio, finite.rational
digest, integer, hexadecimal = finite.digest, finite.integer, finite.hexadecimal


def source_hashes():
    result = finite._source_hashes()
    name = "formal/pon-nakamoto-v1/w1_competing_consensus.py"
    result[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return dict(sorted(result.items()))


class CompetingModel(finite.FiniteModel):
    """Private action graph with an independently specified public event stream."""

    def __init__(self, fixture, competition, parameters):
        require(type(competition) is dict and competition.get("schema") == FIXTURE_SCHEMA,
                "COMPETITION_FIXTURE_SCHEMA")
        require(competition.get("base_fixture_canonical_sha256") == digest(fixture),
                "COMPETITION_BASE_FIXTURE_BINDING")
        require(parameters.get("risk_event") in RISK_EVENTS, "COMPETITION_RISK_EVENT")
        require(type(competition.get("initial_resources")) is dict
                and competition["initial_resources"], "COMPETITION_COST_PREMISES")
        require(competition.get("public_producer_view") == "isolated-public-branch-until-horizon",
                "COMPETITION_PRODUCER_VIEW")
        require(competition.get("equal_time_order") == "honest-before-private-parent-first",
                "COMPETITION_EQUAL_TIME_ORDER")
        super().__init__(fixture, parameters)
        require(self.public_time == 0, "COMPETITION_INITIAL_PUBLIC_TIP_AT_ZERO")
        self.source_hashes = source_hashes()
        self.risk_event = parameters["risk_event"]
        self.competition_hash = digest(competition)
        self.competition = competition
        self.blocks[self.public["block_id"]] = self.public
        history = [self.public] + [finite._metadata(row)
                                  for row in fixture["prefix"]["parent_first_headers"]]
        network = wire.header_decode(bytes.fromhex(fixture["public_tip"]["header_hex"]))
        rows = competition.get("honest_blocks")
        require(type(rows) is list and 1 <= len(rows) <= MAX_HONEST_BLOCKS,
                "COMPETITION_HONEST_BLOCKS")
        self.honest = []
        for row in rows:
            block, parent = finite._metadata(row), history[0]
            raw = hexadecimal(row.get("header_hex"), 318)
            header = wire.header_decode(raw)
            trace = hexadecimal(row.get("trace"), 32)
            require(wire.H("block", raw, trace).hex() == block["block_id"],
                    "COMPETITION_HONEST_BLOCK_ID")
            require(all(header[name] == network[name] for name in ("network", "parameters")),
                    "COMPETITION_NETWORK_OR_PARAMETERS")
            require(block["block_id"] not in self.blocks, "COMPETITION_DUPLICATE_BLOCK")
            require(block["parent_id"] == parent["block_id"]
                    and block["height"] == parent["height"] + 1
                    and block["target"] == finite._required(parent, history),
                    "COMPETITION_HONEST_DAA_OR_PARENT")
            require(block["chainwork"] == parent["chainwork"] + work(block["target"])
                    and block["chainwork"] <= finite.WORK_MAX, "COMPETITION_HONEST_CHAINWORK")
            require(timestamp_state(block["timestamp"], [h["timestamp"] for h in reversed(history[:11])],
                                    (1 << 64) - 1, 120) != "invalid-median", "COMPETITION_HONEST_MEDIAN")
            self.honest.append(block)
            self.blocks[block["block_id"]] = block
            history = [block] + history
        scenarios = competition.get("scenarios")
        require(type(scenarios) is list and 1 <= len(scenarios) <= MAX_SCENARIOS,
                "COMPETITION_SCENARIOS")
        identifiers = [row.get("scenario_id") for row in scenarios]
        require(all(type(key) is str and 1 <= len(key) <= 128 for key in identifiers)
                and len(set(identifiers)) == len(identifiers), "COMPETITION_SCENARIO_IDS")
        require(parameters.get("scenario_id") in identifiers, "COMPETITION_SCENARIO_ID")
        # Validate every declared schedule, not just the one being optimized.
        schedules = {}
        for scenario in scenarios:
            require(set(scenario) == {"scenario_id", "arrivals"}, "COMPETITION_SCENARIO_FIELDS")
            arrivals = scenario["arrivals"]
            require(type(arrivals) is list and len(arrivals) == len(self.honest),
                    "COMPETITION_COMPLETE_ARRIVAL_INVENTORY")
            previous, checked = Fraction(0), []
            for arrival, block in zip(arrivals, self.honest):
                require(type(arrival) is dict and set(arrival) == {"block_id", "at_seconds"},
                        "COMPETITION_ARRIVAL_FIELDS")
                at = rational(arrival["at_seconds"])
                require(0 < at <= self.limit and at >= previous, "COMPETITION_ARRIVAL_TIME")
                require(arrival["block_id"] == block["block_id"], "COMPETITION_ARRIVAL_PARENT_ORDER")
                now = self.origin + at.numerator // at.denominator
                require(now <= (1 << 64) - 1 and block["timestamp"] <= now + 120,
                        "COMPETITION_ARRIVAL_FUTURE_TIME")
                checked.append((at, block))
                previous = at
            schedules[scenario["scenario_id"]] = tuple(checked)
        self.arrivals = schedules[parameters["scenario_id"]]
        require(source_hashes() == self.source_hashes, "COMPETITION_SOURCE_CHANGED")

    def public_at(self, at):
        tip = self.public
        for when, block in self.arrivals:
            if when > at:
                break
            tip = block
        return tip

    def actions(self, state):
        choices = [row for row in super().actions(state) if row["kind"] != "wait-for-public"]
        if any(at > rational(state["time"]) for at, _ in self.arrivals):
            choices.append({"kind": "wait-next-honest"})
        return choices

    def receiver_trace(self, chain, publication_at=None):
        """Every actual admission is parent-first; exact time ties favor honest.

        The native harness independently compares each selected tip, rather
        than trusting a terminal success boolean or sorting on float seconds.
        """
        events = [(at, 0, index, "honest", block)
                  for index, (at, block) in enumerate(self.arrivals)]
        if publication_at is not None:
            require(0 <= publication_at <= self.limit, "COMPETITION_PUBLICATION_TIME")
            events += [(publication_at, 1, index, "private", self.blocks[block_id])
                       for index, block_id in enumerate(chain)]
        events.sort(key=lambda row: row[:3])
        selected, result, ever = self.public, [], False
        private = set(chain) if publication_at is not None else set()
        for at, _, _, owner, block in events:
            before = selected
            if block["chainwork"] > selected["chainwork"]:
                selected = block
            replacement = (owner == "private" and selected["block_id"] == block["block_id"]
                           and before["block_id"] not in private)
            ever = ever or replacement
            result.append({"owner": owner, "at_seconds": ratio(at),
                           "block_id": block["block_id"], "parent_id": block["parent_id"],
                           "height": block["height"], "block_chainwork_hex": f"{block['chainwork']:0128x}",
                           "selected_tip_before": before["block_id"],
                           "selected_tip": selected["block_id"],
                           "selected_chainwork_hex": f"{selected['chainwork']:0128x}",
                           "selection_changed": selected["block_id"] != before["block_id"],
                           "private_replacement": replacement})
        return {"receiver_events": result, "receiver_observed_until_seconds": ratio(self.limit),
                "ever_private_replacement": ever,
                "private_active_at_horizon": selected["block_id"] in private,
                "selected_tip_at_horizon": selected["block_id"],
                "selected_chainwork_at_horizon_hex": f"{selected['chainwork']:0128x}"}

    def transition(self, state, action):
        require(action in self.actions(state), "UNDECLARED_ACTION")
        start = rational(state["time"])
        if action["kind"] == "wait-next-honest":
            at, block = next((at, block) for at, block in self.arrivals if at > start)
            following = {**state, "time": ratio(at)}
            return [self.edge(Fraction(1), following, None,
                              {"result": "honest-arrival-observed", "time": ratio(at),
                               "public_tip": self.public_at(at)["block_id"],
                               "first_arrival_at_this_time": block["block_id"]})]
        edges = super().transition(state, action)
        for edge in edges:
            observed = edge["observation"]
            end = rational(observed["time"])
            observed["honest_arrivals_during_action"] = [
                {"at_seconds": ratio(at), "block_id": block["block_id"]}
                for at, block in self.arrivals if start < at <= end]
            observed["public_tip_at_action_end"] = self.public_at(end)["block_id"]
            if edge["next_state"] is None:
                published = observed.get("publication_complete", False)
                trajectory = self.receiver_trace(observed.get("private_chain", []), end if published else None)
                observed.update(trajectory)
                observed["strict_work_replacement"] = trajectory["ever_private_replacement"]
                metric = ("ever_private_replacement" if self.risk_event == RISK_EVENTS[0]
                          else "private_active_at_horizon")
                edge["terminal_risk"] = int(trajectory[metric])
        return edges


def fixed_action(model, state, iterations):
    """Only current public work and private results; no future arrival lookup."""
    choices = model.actions(state)
    if (model.tip(state)["chainwork"] > model.public_at(rational(state["time"]))["chainwork"]
            and {"kind": "publish"} in choices):
        return {"kind": "publish"}
    search = {"kind": "search", "iterations": iterations}
    return search if search in choices else {"kind": "stop"}


def header(model, fixture):
    report = finite._header(model, fixture)
    report.update(schema=SCHEMA, competition_fixture_sha256=model.competition_hash,
                  risk_event=model.risk_event, honest_blocks=model.honest,
                  honest_arrivals=[{"at_seconds": ratio(at), "block_id": block["block_id"]}
                                   for at, block in model.arrivals])
    report["scope"] = {**report["scope"],
        "public_classical_history": "continuing isolated public producer, exact conditional receiver schedule",
        "public_producer_view": "extends its own public branch; private publications not delivered to it before horizon",
        "publication": "one terminal private bundle; every block pays existing serial propagation; honest-first equal-time order",
        "maximum_value_policy": "observer-census-and-complete-future-public-schedule-aware envelope over the closed declared action class",
        "risk_event": model.risk_event,
        "receiver_events": "all honest arrivals through the horizon, including after a private miner stops or publishes",
        "fixed_q_policy_reads_future_honest_arrivals": False,
        "private_action_atomicity": "search including proof, and propagation are non-preemptive; honest arrivals during them are observed at the next private decision",
        "mid_action_abort_restart_or_public_branch_switch_covered": False,
        "honest_production_and_network_costs": "external conditional schedule with separate native CPU receipts; not charged as private quantum work",
        "external_honest_schedule_condition": "fixed authenticated block identities and exact arrivals; their faults and delay uncertainty are not bounded by the private machine envelope",
        "whole_network_machine_error_bound_composed": False,
        "public_producer_reacts_to_private_publication": False,
        "stochastic_continuing_honest_mining_covered": False,
        "long_horizon_settlement_security_proved": False}
    report["honest_initial_resources"] = model.competition["initial_resources"]
    return report


def private_machine_risk(model, maximum, fixed):
    result = finite._machine_risk(model, maximum, fixed)
    if result is not None:
        result["coupling_premise"] = (
            "conditional on exact external honest block identities, arrivals and receiver transitions, "
            "the actual private timed trace equals its ideal trace outside the reserved "
            "history-conditional private-machine fault-event union")
        result["external_honest_and_receiver_trajectory_is_exact_condition"] = True
        result["honest_production_receiver_or_network_failures_bounded"] = False
    return result


def analyze_competing_consensus(fixture, competition, parameters):
    model = CompetingModel(fixture, competition, parameters)
    return finite._analyze_model(model, header(model, fixture), fixed_action, source_hashes,
                                 risk_bounds=private_machine_risk)


def verify_competing_certificate(record, fixture, competition):
    model = CompetingModel(fixture, competition, record["parameters"])
    result = finite._check_certificate(record, model, fixture, header=header(model, fixture),
                                       fixed_action=fixed_action, risk_bounds=private_machine_risk)
    require(source_hashes() == model.source_hashes, "COMPETITION_SOURCE_CHANGED")
    return {**result, "risk_event": model.risk_event,
            "honest_arrivals_checked": len(model.arrivals),
            "whole_network_machine_error_bound_composed": False}


def sample_competing_policy(record, fixture, competition, *, iterations=0, seed=9):
    integer(seed, "COMPETITION_SAMPLE_SEED")
    integer(iterations, "COMPETITION_SAMPLE_ITERATIONS", 0, finite.MAX_EXACT_ITERATIONS)
    model = CompetingModel(fixture, competition, record["parameters"])
    finite._check_certificate(record, model, fixture, header=header(model, fixture),
                              fixed_action=fixed_action, risk_bounds=private_machine_risk)
    result = finite._sample_model(record, model, iterations, seed, fixed_action, source_hashes)
    terminal = result["trajectory"][-1]["edge"]["observation"]
    result.update(schema=SAMPLE_SCHEMA, risk_event=model.risk_event,
                  competition_fixture_sha256=model.competition_hash,
                  ever_private_replacement=terminal["ever_private_replacement"],
                  private_active_at_horizon=terminal["private_active_at_horizon"],
                  strict_work_replacement=terminal["ever_private_replacement"],
                  policy_reads_future_honest_arrivals=False)
    return result


def observer_selected_path(record, fixture, competition):
    """Retain the same selected private path even when honest competition wins.

    This follows positive-probability outcomes chosen by an observer. It never
    supplies a random-sample success rate or an implementable winning-nonce
    oracle. Forced terminal publication is a listed action even if unprofitable.
    """
    model = CompetingModel(fixture, competition, record["parameters"])
    require(model.execution_kind == "classical-uniform-q0", "OBSERVER_CONTROL_CLASSICAL_ONLY")
    finite._check_certificate(record, model, fixture, header=header(model, fixture),
                              fixed_action=fixed_action, risk_bounds=private_machine_risk)
    require(record["status"] == "COMPLETE", "OBSERVER_CONTROL_INCOMPLETE")
    state, trajectory, probability = model.initial(), [], Fraction(1)
    while True:
        choices = model.actions(state)
        search = {"kind": "search", "iterations": 0}
        if search in choices:
            action = search
            candidates = model.transition(state, action)
            edge = next((edge for edge in candidates if edge["observation"].get("proof_complete") is True), None)
            if edge is None:
                return None
        else:
            action = {"kind": "publish"} if {"kind": "publish"} in choices else {"kind": "stop"}
            edge = model.transition(state, action)[0]
        probability *= rational(edge["probability"])
        trajectory.append({"state": state, "action": action, "edge": edge})
        if edge["next_state"] is None:
            break
        state = edge["next_state"]
    require(source_hashes() == model.source_hashes, "COMPETITION_SOURCE_CHANGED")
    return {"selection": "observer-census-advice private-path control, including unsuccessful publication",
            "probability_of_selected_ideal_outcomes": ratio(probability),
            "trajectory": trajectory, "sampled_execution": False,
            "quantum_hardware_executed": False, "native_blocks_admitted_by_this_function": 0}
