#!/usr/bin/env python3
"""Conditional, finite-horizon PoN cost / withholding / confirmation experiment.

This program never creates or admits a proof. Successful trials assume a fully
valid PNW1 and application transition. Input costs are explicit hypotheses,
not measured hashrate or an adversarial share. The native rules are a read-only
control; the fixed-target arm is a counterfactual, never a deployable profile.

One producer group can publish at most one block per slot. Each worker reserves
context setup, complete attempts, a winning witness and publication. Spare time
is discarded. This synchronized, capped model is deliberately narrower than a
continuous network: it does not establish production attack probabilities.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import statistics


ROOT = Path(__file__).resolve().parents[2]
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
U512 = (1 << 512) - 1
NANOSECONDS = 1_000_000_000
TIMESTAMP_POLICIES = {"wall", "median_plus_one", "future_boundary", "period_endpoints"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def uint(value: int, high: int = U64, low: int = 0) -> int:
    require(type(value) is int and low <= value <= high, "bounded integer required")
    return value


def exact_keys(value: dict, names: set[str]) -> None:
    require(type(value) is dict and set(value) == names, "unexpected or missing fields")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_number(_):
    raise ValueError("JSON noninteger numbers are not accepted")


def load_json(raw: bytes):
    return json.loads(raw, object_pairs_hook=unique, parse_float=reject_number,
                      parse_constant=reject_number)


def required_work(target: int) -> int:
    return (1 << 256) // (uint(target, U256, 1) + 1)


def add_work(left: int, right: int) -> int:
    return uint(uint(left, U512) + uint(right, U512), U512)


def retarget(parent: int, first: int, last: int, interval: int,
             spacing: int, limit: int) -> int:
    """Checked native u64 time arithmetic and 256-bit output, no float target."""
    try:
        uint(first)
        uint(last)
        uint(interval, U64, 16)
        uint(spacing, U64, 1)
        uint(limit, U256, 1)
        uint(parent, limit, 1)
        desired = uint((interval - 1) * spacing, U64, 1)
        upper = uint(desired * 4)
    except ValueError as error:
        raise ValueError("TARGET_PARAMETERS") from error
    observed = min(upper, max((desired + 3) // 4, max(1, last - first)))
    return min(limit, max(1, parent * observed // desired))


def check_time(candidate: int, parent_first: list[int], now: int, skew: int) -> None:
    uint(candidate)
    uint(now)
    uint(skew)
    require(bool(parent_first), "UNKNOWN_PARENT")
    recent = sorted(uint(value) for value in parent_first[:11])
    require(candidate > recent[len(recent) // 2], "TIME")
    # Native compares in u128. A u64 overflow must not wrap this bound.
    require(candidate <= now + skew, "TIME_DEFERRED")


@dataclass(frozen=True)
class Parameters:
    initial: int
    limit: int
    genesis: int
    interval: int
    spacing: int
    skew: int
    confirmation_depth: int
    confirmation_multiplier: int

    @classmethod
    def installed(cls):
        config = load_json((ROOT / "config/pon/devnet-v1.json").read_bytes())
        return cls(int(config["initial_target_hex"], 16), int(config["pow_limit_hex"], 16),
                   config["genesis_timestamp"], config["retarget_interval"],
                   config["target_spacing_seconds"], config["future_skew_seconds"],
                   config["confirmation_depth"], config["confirmation_work_multiplier"])

    def __post_init__(self):
        uint(self.genesis)
        uint(self.initial, uint(self.limit, U256, 1), 1)
        uint(self.skew)
        uint(self.confirmation_depth, U64, 1)
        uint(self.confirmation_multiplier, U64, 1)
        retarget(self.initial, 0, 1, self.interval, self.spacing, self.limit)


@dataclass(frozen=True)
class Header:
    height: int
    timestamp: int
    target: int
    chainwork: int


class Branch:
    """Synthetic valid-proof premise, never a capability accepted by the node."""
    def __init__(self, parameters: Parameters, fixed_target: bool = False):
        require(type(fixed_target) is bool, "boolean control required")
        self.parameters = parameters
        self.fixed_target = fixed_target
        self.headers = [Header(0, parameters.genesis, parameters.initial, 0)]
        self.retargets = 0

    @property
    def tip(self) -> Header:
        return self.headers[-1]

    def next_target(self) -> int:
        height = self.tip.height + 1
        p = self.parameters
        if self.fixed_target:
            return p.initial
        if height % p.interval:
            return self.tip.target
        return retarget(self.tip.target, self.headers[height - p.interval].timestamp,
                        self.tip.timestamp, p.interval, p.spacing, p.limit)

    def parent_times(self) -> list[int]:
        return [header.timestamp for header in self.headers[-11:][::-1]]

    def timestamp(self, now: int, policy: str) -> int:
        require(policy in TIMESTAMP_POLICIES, "unknown timestamp policy")
        times = sorted(self.parent_times())
        minimum = times[len(times) // 2] + 1
        phase = (self.tip.height + 1) % self.parameters.interval
        if policy == "median_plus_one" or (policy == "period_endpoints" and phase == 0):
            return minimum
        if policy == "future_boundary" or (
                policy == "period_endpoints" and phase == self.parameters.interval - 1):
            return uint(now + self.parameters.skew)
        return max(minimum, now)

    def append(self, timestamp: int, now: int) -> Header:
        check_time(timestamp, self.parent_times(), now, self.parameters.skew)
        target = self.next_target()
        header = Header(uint(self.tip.height + 1), timestamp, target,
                        add_work(self.tip.chainwork, required_work(target)))
        if not self.fixed_target and header.height % self.parameters.interval == 0:
            self.retargets += 1
        self.headers.append(header)
        return header

    def confirmed(self, included_height: int = 1) -> bool:
        uint(included_height, U64, 1)
        if self.tip.height < included_height:
            return False
        included = self.headers[included_height]
        return (self.tip.height - included_height >= self.parameters.confirmation_depth
                and self.tip.chainwork - included.chainwork >=
                required_work(included.target) * self.parameters.confirmation_multiplier)


COMMON_COST_FIELDS = {"kind", "task_class", "context_setup_ns", "winning_witness_ns",
                      "publication_ns"}
CLASSICAL_FIELDS = COMMON_COST_FIELDS | {"full_attempt_ns"}
QUANTUM_FIELDS = COMMON_COST_FIELDS | {
    "full_clean_oracle_and_diffusion_ns", "measurement_check_restart_ns", "iterations",
    "nonce_bits", "occupancy_hypothesis"}


def validate_cost(cost: dict) -> None:
    require(type(cost) is dict and cost.get("kind") in {"classical", "quantum"}, "cost kind")
    exact_keys(cost, CLASSICAL_FIELDS if cost["kind"] == "classical" else QUANTUM_FIELDS)
    require(type(cost["task_class"]) is str and bool(cost["task_class"]), "task class")
    for key in ("context_setup_ns", "winning_witness_ns", "publication_ns"):
        uint(cost[key], U64)
    if cost["kind"] == "classical":
        uint(cost["full_attempt_ns"], U64, 1)
    else:
        uint(cost["full_clean_oracle_and_diffusion_ns"], U64, 1)
        uint(cost["measurement_check_restart_ns"], U64, 1)
        # Quantum measurement alone cannot publish a classical PNW1 witness.
        uint(cost["winning_witness_ns"], U64, 1)
        uint(cost["iterations"], 1_000_000_000)
        uint(cost["nonce_bits"], 64, 1)
        require(cost["occupancy_hypothesis"] in {"floor_mean", "ceil_mean"}, "occupancy hypothesis")


def grover_success(nonce_bits: int, marked: int, iterations: int) -> float:
    """Ideal conditional M-marked domain; does not learn M or choose a stop."""
    domain = 1 << uint(nonce_bits, 64, 1)
    uint(marked, domain)
    uint(iterations, 1_000_000_000)
    if marked == 0:
        return 0.0
    if marked == domain:
        return 1.0
    if marked * 2 == domain:
        return 0.5
    if marked * 2 > domain:
        # Preserve a small unmarked set before converting to binary64. Direct
        # marked/domain can round to 1 (e.g. 2^64-1 marked), losing a phase
        # difference that many iterations amplify. For odd 2*k+1 the original
        # sin^2((2*k+1)*(pi/2-delta)) is exactly cos^2((2*k+1)*delta).
        # This remains a floating-point conditional model, not a security bound.
        angle = math.asin(math.sqrt((domain - marked) / domain))
        return math.cos((2 * iterations + 1) * angle) ** 2
    angle = math.asin(math.sqrt(marked / domain))
    return math.sin((2 * iterations + 1) * angle) ** 2


def at_least_one(probability: float, attempts: int) -> float:
    require(math.isfinite(probability) and 0 <= probability <= 1, "success probability")
    uint(attempts)
    if attempts == 0 or probability == 0:
        return 0.0
    if probability == 1:
        return 1.0
    return -math.expm1(attempts * math.log1p(-probability))


def opportunity(cost: dict, workers: int, slot_ns: int, target: int) -> dict:
    """Per-slot bound with inclusive attempts; nested costs are not added twice."""
    uint(workers, 1_000_000)
    uint(slot_ns, U64, 1)
    uint(target, U256, 1)
    p = (target + 1) / (1 << 256)
    available = max(0, slot_ns - cost["context_setup_ns"] - cost["winning_witness_ns"]
                    - cost["publication_ns"])
    if cost["kind"] == "classical":
        attempt_ns = cost["full_attempt_ns"]
        probability = p
        marked = None
        empty_domain = None
    else:
        attempt_ns = (cost["iterations"] * cost["full_clean_oracle_and_diffusion_ns"]
                      + cost["measurement_check_restart_ns"])
        domain = 1 << cost["nonce_bits"]
        numerator = domain * (target + 1)
        marked, remainder = divmod(numerator, 1 << 256)
        if cost["occupancy_hypothesis"] == "ceil_mean" and remainder:
            marked += 1
        probability = grover_success(cost["nonce_bits"], marked, cost["iterations"])
        # This is a separate Bernoulli-domain diagnostic, not the probability
        # law used by the fixed-M hypothesis above. It must not be multiplied
        # into that conditional probability and called a marginal result.
        empty_domain = 0.0 if p == 1 else math.exp(domain * math.log1p(-p))
    attempts = uint((available // attempt_ns) * workers)
    return {"success_probability": at_least_one(probability, attempts),
            "complete_attempts_budget": attempts, "attempt_ns": attempt_ns,
            "reserved_worker_wall_ns": workers * slot_ns,
            "marked_count_hypothesis": marked,
            "independent_bernoulli_empty_domain_diagnostic": empty_domain}


def validate_suite(suite: dict) -> None:
    exact_keys(suite, {"schema", "cost_provenance", "seed", "trials", "slot_seconds",
                       "horizon_slots", "costs", "scenarios"})
    require(suite["schema"] == "pon-conditional-risk-input-v1", "input schema")
    require(suite["cost_provenance"] == "explicit-synthetic-hypotheses-not-measurements",
            "this model does not certify measured costs")
    uint(suite["seed"])
    uint(suite["trials"], 4096, 1)
    uint(suite["slot_seconds"], 86400, 1)
    uint(suite["horizon_slots"], 4096, 1)
    require(type(suite["costs"]) is dict and bool(suite["costs"]), "cost profiles")
    for cost in suite["costs"].values():
        validate_cost(cost)
    scenarios = suite["scenarios"]
    require(type(scenarios) is list and 1 <= len(scenarios) <= 32, "scenarios")
    require(suite["trials"] * suite["horizon_slots"] * len(scenarios) <= 10_000_000,
            "bounded simulation grid required")
    names = set()
    for scenario in scenarios:
        exact_keys(scenario, {"name", "honest", "private", "private_timestamp", "release_delay_slots"})
        name = scenario["name"]
        require(type(name) is str and bool(name) and name not in names, "unique scenario name")
        names.add(name)
        require(scenario["private_timestamp"] in TIMESTAMP_POLICIES, "timestamp policy")
        uint(scenario["release_delay_slots"], suite["horizon_slots"])
        for actor in ("honest", "private"):
            require(type(scenario[actor]) is list and bool(scenario[actor]), "phase schedule")
            start = 0
            for phase in scenario[actor]:
                exact_keys(phase, {"start", "end", "workers", "cost"})
                require(uint(phase["start"]) == start, "phase gaps or overlaps")
                start = uint(phase["end"], suite["horizon_slots"], start + 1)
                uint(phase["workers"], 1_000_000)
                require(phase["cost"] in suite["costs"], "unknown cost profile")
            require(start == suite["horizon_slots"], "incomplete phase schedule")


def phase_at(phases: list[dict], slot: int) -> dict:
    return next(phase for phase in phases if phase["start"] <= slot < phase["end"])


def run_trial(suite: dict, scenario: dict, trial: int, fixed_target: bool,
              parameters: Parameters | None = None) -> dict:
    """Same uniform samples pair all scenarios and the fixed-target control."""
    p = parameters or Parameters.installed()
    branches = {actor: Branch(p, fixed_target) for actor in ("honest", "private")}
    rng = random.Random(f'{suite["seed"]}:{trial}')
    confirmed_slot = None
    release_slot = None
    pending = None
    release_attempts = 0
    failed_releases = 0
    private_heavier_early = False
    trace = []
    for slot in range(suite["horizon_slots"]):
        now = uint(p.genesis + (slot + 1) * suite["slot_seconds"])
        for actor in ("honest", "private"):
            phase = phase_at(scenario[actor], slot)
            branch = branches[actor]
            cost = suite["costs"][phase["cost"]]
            chance = opportunity(cost, phase["workers"], suite["slot_seconds"] * NANOSECONDS,
                                 branch.next_target())
            if rng.random() < chance["success_probability"]:
                policy = "wall" if actor == "honest" else scenario["private_timestamp"]
                old_target = branch.tip.target
                header = branch.append(branch.timestamp(now, policy), now)
                if header.target != old_target:
                    trace.append({"slot": slot, "event": "target_change", "actor": actor,
                                  "height": header.height, "timestamp": header.timestamp,
                                  "target_hex": f'{header.target:064x}',
                                  "required_work": str(required_work(header.target))})
        honest, private = branches["honest"], branches["private"]
        if confirmed_slot is None and honest.confirmed():
            confirmed_slot = slot
            trace.append({"slot": slot, "event": "observed_depth_and_work_confirmation",
                          "height": honest.tip.height})
        if confirmed_slot is None and private.tip.chainwork > honest.tip.chainwork:
            private_heavier_early = True
        if confirmed_slot is not None and pending is None and private.tip.chainwork > honest.tip.chainwork:
            # Freeze the exact offered prefix. Blocks mined during download are
            # not silently appended to this offer or credited before delivery.
            pending = (slot + scenario["release_delay_slots"], tuple(private.headers))
            release_attempts += 1
        if pending is not None and slot >= pending[0]:
            offered = pending[1]
            require(all(header.timestamp <= now + p.skew for header in offered), "TIME_DEFERRED")
            if offered[-1].chainwork > honest.tip.chainwork:
                release_slot = slot
                trace.append({"slot": slot, "event": "strictly_heavier_private_prefix_delivered",
                              "offered_height": offered[-1].height,
                              "offered_chainwork": str(offered[-1].chainwork),
                              "public_chainwork": str(honest.tip.chainwork)})
                break
            failed_releases += 1
            pending = None
    return {"confirmed_slot": confirmed_slot, "reorg_slot": release_slot,
            "no_confirmation_before_horizon": confirmed_slot is None,
            "confirmation_survived_only_to_horizon": confirmed_slot is not None and release_slot is None,
            "private_heavier_before_confirmation": private_heavier_early,
            "release_attempts": release_attempts, "failed_release_attempts": failed_releases,
            "release_in_flight_at_horizon": pending is not None and release_slot is None,
            "honest_height": branches["honest"].tip.height,
            "private_height": branches["private"].tip.height,
            "honest_chainwork": str(branches["honest"].tip.chainwork),
            "private_chainwork": str(branches["private"].tip.chainwork),
            "honest_daa_boundaries": branches["honest"].retargets,
            "private_daa_boundaries": branches["private"].retargets,
            "trace": trace}


def wilson(successes: int, count: int) -> dict | None:
    """95% Wilson interval for simulation sampling only, not chain security."""
    uint(count)
    uint(successes, count)
    if count == 0:
        return None
    z = 1.959963984540054
    observed = successes / count
    denominator = 1 + z * z / count
    center = (observed + z * z / (2 * count)) / denominator
    radius = z * math.sqrt(observed * (1 - observed) / count + z * z / (4 * count * count)) / denominator
    return {"events": successes, "denominator": count, "fraction": observed,
            "wilson_95_low": max(0.0, center - radius),
            "wilson_95_high": min(1.0, center + radius)}


def experiment(suite: dict) -> dict:
    validate_suite(suite)
    parameters = Parameters.installed()
    results = []
    for scenario in suite["scenarios"]:
        for fixed in (False, True):
            trials = [run_trial(suite, scenario, trial, fixed, parameters)
                      for trial in range(suite["trials"])]
            confirmed = sum(row["confirmed_slot"] is not None for row in trials)
            losses = sum(row["reorg_slot"] is not None for row in trials)
            confirmations = [row["confirmed_slot"] + 1 for row in trials if row["confirmed_slot"] is not None]
            results.append({
                "scenario": scenario["name"], "mode": "fixed_target_counterfactual" if fixed else "native_daa_rules",
                "reorg_after_confirmation_all_trials": wilson(losses, len(trials)),
                "reorg_after_confirmation_conditioned_on_observation": wilson(losses, confirmed),
                "no_confirmation_before_horizon": len(trials) - confirmed,
                "confirmed_but_only_survived_to_horizon": confirmed - losses,
                "median_slots_to_confirmation": statistics.median(confirmations) if confirmations else None,
                "release_in_flight_at_horizon": sum(row["release_in_flight_at_horizon"] for row in trials),
                "release_attempts": sum(row["release_attempts"] for row in trials),
                "failed_release_attempts": sum(row["failed_release_attempts"] for row in trials),
                "honest_daa_boundaries": sum(row["honest_daa_boundaries"] for row in trials),
                "private_daa_boundaries": sum(row["private_daa_boundaries"] for row in trials),
                "illustrative_trial_zero": trials[0],
            })
    canonical = json.dumps(suite, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "pon-conditional-risk-report-v1", "input_sha256": hashlib.sha256(canonical).hexdigest(),
        "model_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "installed_parameters_sha256": hashlib.sha256((ROOT / "config/pon/devnet-v1.json").read_bytes()).hexdigest(),
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                    "platform": platform.platform()},
        "input": suite, "parameters": {key: str(value) for key, value in vars(parameters).items()},
        "results": results,
        "boundaries": {
            "production_activation": False, "changes_consensus_rules": False,
            "contains_new_hashcash_or_work_gate": False, "valid_pnw1_is_a_model_premise": True,
            "measured_costs_or_adversary_fraction": False, "physical_quantum_oracle_measured": False,
            "quantum_marked_count_is_a_hypothesis": True, "unknown_marked_count_marginal_probability": False,
            "quantum_iterations_frozen_in_input_not_selected_using_marked_count": True,
            "synchronous_at_most_one_block_per_group_per_slot": True,
            "witness_and_publication_time_reserved_before_success_can_count": True,
            "phase_changes_discard_unfinished_work": True,
            "confirmation_is_reversible_observation": True, "finite_horizon_censoring_retained": True,
            "intervals_describe_model_sampling_only": True, "public_network_qualification": False,
            "floating_point_probabilities_are_not_interval_proofs": True,
            "same_uniform_samples_across_scenarios_and_controls": True,
        },
        "unmodeled": [
            "W1 hardness, adaptive legal solvers and actual selectable-task probabilities",
            "continuous races, multiple winners per slot, stale work and general network topology",
            "real bandwidth/CPU admission queues, adaptive withholding and transaction economics",
            "unknown marked-count distribution, physical fault tolerance and minimal clean oracle cost",
            "a proof of chain quality or an absolute confirmation-risk bound",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).with_name("vectors") / "pon-risk-scenarios-v1.json")
    args = parser.parse_args()
    report = experiment(load_json(args.input.read_bytes()))
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
