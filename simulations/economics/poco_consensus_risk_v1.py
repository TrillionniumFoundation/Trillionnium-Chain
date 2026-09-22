#!/usr/bin/env python3
"""Bounded PoCO/BFT counterexample model, NOT a validator or activation gate.

Controller labels and bond records are assumptions supplied to this model.
A digest identifies the input; it does not authenticate economic independence,
funding provenance, live collateral, a checkpoint, or an external observer.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from settlement_risk_v2 import Reject, bounded, checked_add, checked_mul, commitment, identifier, uint

PPM = 1_000_000
U64_MAX = (1 << 64) - 1
MAX_VALIDATORS = 100
MAX_TOTAL_WEIGHT = 100_000  # Explicit model/DP resource limit, NOT a consensus parameter.
MAX_FLOWS = 1024


@dataclass(frozen=True)
class ValidatorRiskV1:
    validator_id: str
    controller_id: str
    weight: int
    bond_id: str
    bond: int
    locked_until_epoch: int


@dataclass(frozen=True)
class ConsensusRiskPolicyV1:
    target_epoch: int
    evidence_window_epochs: int
    trusting_period_epochs: int
    unbonding_delay_epochs: int
    bond_per_weight: int
    max_controller_share_ppm: int
    assumed_double_vote_slash_ppm: int

    def validate(self) -> None:
        for value in (self.target_epoch, self.evidence_window_epochs,
                      self.trusting_period_epochs, self.unbonding_delay_epochs):
            uint(value, "epoch-range", U64_MAX)
        if self.target_epoch + self.evidence_window_epochs > U64_MAX:
            raise Reject("epoch-overflow")
        uint(self.bond_per_weight, "bond-per-weight")
        if self.bond_per_weight == 0:
            raise Reject("bond-per-weight")
        uint(self.max_controller_share_ppm, "controller-cap", PPM)
        if self.max_controller_share_ppm == 0:
            raise Reject("controller-cap")
        uint(self.assumed_double_vote_slash_ppm, "slash-fraction", PPM)
        if (self.unbonding_delay_epochs < self.evidence_window_epochs
                or self.unbonding_delay_epochs <= self.trusting_period_epochs):
            raise Reject("withdrawal-horizon")


def quorum(total_weight: int) -> int:
    uint(total_weight, "weight-range", MAX_TOTAL_WEIGHT)
    if total_weight == 0:
        raise Reject("zero-weight")
    return 2 * total_weight // 3 + 1


def _minimum_coalition_cost(groups: list[tuple[int, int]], threshold: int) -> int:
    """0/1 DP: a declared controller can occur at most once in a coalition.

At most 100 * 100001 cell visits per call. This is a model's exact minimum
under its supplied labels/costs, not a bound on bribes, theft or short profits.
"""
    uint(threshold, "coalition-threshold", MAX_TOTAL_WEIGHT)
    if len(groups) > MAX_VALIDATORS or threshold == 0:
        raise Reject("coalition-bounds")
    costs: list[int | None] = [None] * (threshold + 1)
    costs[0] = 0
    for weight, cost in groups:
        uint(weight, "weight-range", MAX_TOTAL_WEIGHT)
        uint(cost, "cost-range")
        updated = costs.copy()
        for previous, previous_cost in enumerate(costs):
            if previous_cost is None:
                continue
            target = min(threshold, previous + weight)
            candidate = checked_add(previous_cost, cost)
            if updated[target] is None or candidate < updated[target]:
                updated[target] = candidate
        costs = updated
    result = costs[threshold]
    if result is None:
        raise Reject("coalition-unreachable")
    return result


def _cyclic_run(schedule: list[str], controllers: set[str]) -> int:
    run = maximum = 0
    for controller in schedule + schedule:
        run = min(len(schedule), run + 1) if controller in controllers else 0
        maximum = max(maximum, run)
    return maximum


def analyze_set(policy: ConsensusRiskPolicyV1, validators: Iterable[ValidatorRiskV1],
                faulty_controllers: Iterable[str] = ()) -> dict[str, object]:
    policy.validate()
    rows = bounded(validators, MAX_VALIDATORS, "validator-count")
    if not rows:
        raise Reject("validators-empty")
    ids: set[str] = set()
    bonds: set[str] = set()
    for row in rows:
        if not isinstance(row, ValidatorRiskV1):
            raise Reject("validator-shape")
        for value in (row.validator_id, row.controller_id, row.bond_id):
            identifier(value, "identity-unresolved")
        if row.validator_id in ids:
            raise Reject("duplicate-validator")
        if row.bond_id in bonds:
            raise Reject("bond-double-pledge")
        ids.add(row.validator_id)
        bonds.add(row.bond_id)
        uint(row.weight, "weight-range", U64_MAX)
        if row.weight == 0:
            raise Reject("zero-weight")
        uint(row.bond, "bond-range")
        uint(row.locked_until_epoch, "epoch-range", U64_MAX)
    rows.sort(key=lambda row: row.validator_id)
    total_weight = sum(row.weight for row in rows)
    uint(total_weight, "model-weight-budget", MAX_TOTAL_WEIGHT)
    q = quorum(total_weight)
    groups: dict[str, dict[str, int]] = {}
    uncovered: list[str] = []
    total_bond = 0
    for row in rows:
        total_bond = checked_add(total_bond, row.bond)
        required = checked_mul(row.weight, policy.bond_per_weight)
        covered = (row.locked_until_epoch > policy.target_epoch + policy.evidence_window_epochs
                   and row.bond >= required)
        if not covered:
            uncovered.append(row.validator_id)
        group = groups.setdefault(row.controller_id, {"weight": 0, "leaders": 0,
                                                     "covered_bond": 0, "model_penalty": 0})
        group["weight"] += row.weight
        group["leaders"] += 1
        # An uncovered declaration supplies no conservative slash guarantee.
        group["covered_bond"] = checked_add(group["covered_bond"], row.bond if covered else 0)
        penalty = checked_mul(row.bond, policy.assumed_double_vote_slash_ppm) // PPM if covered else 0
        group["model_penalty"] = checked_add(group["model_penalty"], penalty)
    faulty_list = bounded(faulty_controllers, MAX_VALIDATORS, "faulty-count")
    if any(not isinstance(item, str) or item not in groups for item in faulty_list):
        raise Reject("unknown-faulty-controller")
    if len(faulty_list) != len(set(faulty_list)):
        raise Reject("duplicate-faulty-controller")
    faulty = set(faulty_list)
    bad_weight = sum(groups[name]["weight"] for name in faulty)
    bad_leaders = sum(groups[name]["leaders"] for name in faulty)
    violations = sorted(name for name, group in groups.items()
                        if checked_mul(group["weight"], PPM)
                        > checked_mul(total_weight, policy.max_controller_share_ppm))
    blocking = total_weight - q + 1
    intersection = 2 * q - total_weight
    report = {
        "schema": "trnm-poco-consensus-risk-model-v1", "model_only": True,
        "total_weight": total_weight, "quorum_weight": q,
        "blocking_weight": blocking, "two_quorum_intersection_weight": intersection,
        "uncovered_validators": uncovered, "controller_cap_violations": violations,
        "controllers": {key: groups[key] for key in sorted(groups)},
        "faulty_weight": bad_weight, "strict_byzantine_weight_assumption_holds": 3 * bad_weight < total_weight,
        "faulty_leader_slots": bad_leaders, "leader_slots": len(rows),
        "maximum_consecutive_faulty_slots": _cyclic_run([row.controller_id for row in rows], faulty),
        "minimum_declared_bond_in_blocking_coalition": _minimum_coalition_cost(
            [(group["weight"], group["covered_bond"]) for group in groups.values()], blocking),
        "minimum_assumed_penalty_in_intersection_coalition": _minimum_coalition_cost(
            [(group["weight"], group["model_penalty"]) for group in groups.values()], intersection),
        "identity_claims_authenticated": False, "collateral_claims_authenticated": False,
        "safety_proof": False, "economic_activation_authority": False, "production_activation": False,
        "limitations": ["Declared controller labels can be false or incomplete.",
                        "Blocking alone does not imply a slashable offense.",
                        "A quorum intersection bound is necessary, not an executable fork attack.",
                        "The slash fraction is an explicit hypothesis, not an activated schedule.",
                        "No valuation, detection probability, bribery or external profit guarantee is supplied."],
    }
    report["input_commitment"] = commitment("trnm.poco-consensus-risk.input.v1", {
        "policy": asdict(policy), "validators": [asdict(row) for row in rows],
        "faulty_controllers": sorted(faulty),
    })
    return report


def analyze_handoff(old_policy: ConsensusRiskPolicyV1, old: Iterable[ValidatorRiskV1],
                    new_policy: ConsensusRiskPolicyV1, new: Iterable[ValidatorRiskV1],
                    faulty_controllers: Iterable[str] = ()) -> dict[str, object]:
    old_policy.validate()
    new_policy.validate()
    if new_policy.target_epoch != old_policy.target_epoch + 1:
        raise Reject("nonconsecutive-epoch")
    old_rows = bounded(old, MAX_VALIDATORS, "validator-count")
    new_rows = bounded(new, MAX_VALIDATORS, "validator-count")
    faulty_rows = bounded(faulty_controllers, MAX_VALIDATORS, "faulty-count")
    if any(not isinstance(row, ValidatorRiskV1) for row in old_rows + new_rows):
        raise Reject("validator-shape")
    if any(not isinstance(name, str) for name in faulty_rows):
        raise Reject("unknown-faulty-controller")
    if len(faulty_rows) != len(set(faulty_rows)):
        raise Reject("duplicate-faulty-controller")
    for row in old_rows + new_rows:
        identifier(row.controller_id, "identity-unresolved")
    known = {row.controller_id for row in old_rows + new_rows}
    if not set(faulty_rows) <= known:
        raise Reject("unknown-faulty-controller")
    old_faulty = [name for name in faulty_rows if any(row.controller_id == name for row in old_rows)]
    new_faulty = [name for name in faulty_rows if any(row.controller_id == name for row in new_rows)]
    old_report = analyze_set(old_policy, old_rows, old_faulty)
    new_report = analyze_set(new_policy, new_rows, new_faulty)
    return {"old": old_report, "new": new_report,
            "both_declared_fault_bounds_hold": old_report["strict_byzantine_weight_assumption_holds"]
                                                 and new_report["strict_byzantine_weight_assumption_holds"],
            "joint_certificate_verified": False, "checkpoint_committed": False,
            "signing_authority": False, "production_activation": False}


def possible_consumption_cycles(flows: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Return SCCs of *declared* payer->provider flows; not proof of collusion.

The 100-controller graph is deliberately bounded. Reporting a loop must never
create a slashing instruction or change the frozen v0 relationship rule.
"""
    rows = bounded(flows, MAX_FLOWS, "flow-count")
    graph: dict[str, set[str]] = {}
    for row in rows:
        if not isinstance(row, tuple) or len(row) != 2:
            raise Reject("flow-shape")
        payer, provider = row
        identifier(payer, "flow-identity")
        identifier(provider, "flow-identity")
        graph.setdefault(payer, set()).add(provider)
        graph.setdefault(provider, set())
        if len(graph) > MAX_VALIDATORS:
            raise Reject("controller-count")
    reachable: dict[str, set[str]] = {}
    for source in graph:
        visited: set[str] = set()
        pending = list(graph[source])
        while pending:
            node = pending.pop()
            if node not in visited:
                visited.add(node)
                pending.extend(graph[node] - visited)
        reachable[source] = visited
    remaining = set(graph)
    result: list[list[str]] = []
    while remaining:
        node = min(remaining)
        component = {other for other in remaining
                     if other in reachable[node] and node in reachable[other]}
        if component:
            result.append(sorted(component))
            remaining -= component
        else:
            remaining.remove(node)
    return result
