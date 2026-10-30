#!/usr/bin/env python3
"""Conditional quantum-search experiments over native PoN integer DAA rules.

This is NOT a W1 miner, reversible W1 circuit, stochastic settlement proof, or
consensus successor. Synthetic headers assume valid fresh work. Only required
work, retarget, timestamp and accumulated-work arithmetic are reproduced here.
All physical quantum cost, work hardness and production qualification stay open.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path

U64_MAX = (1 << 64) - 1
TARGET_MAX = (1 << 256) - 1
WORK_MAX = (1 << 512) - 1
SOURCE = "5e797326b9c7635e43b93f97c65a309e51eafb46"
NATIVE_SOURCE_BLOB = "2f63dd18dc5893e3020bb00b18f7dcb90bae41ae"
ROOT = Path(__file__).resolve().parents[2]


class Reject(ValueError):
    pass


def uint(value: int, maximum: int, code: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise Reject(code)
    return value


def required_work(target: int) -> int:
    uint(target, TARGET_MAX, "TARGET")
    if target == 0:
        raise Reject("TARGET")
    return (1 << 256) // (target + 1)


def add_work(left: int, right: int) -> int:
    uint(left, WORK_MAX, "CHAINWORK_OVERFLOW")
    uint(right, WORK_MAX, "CHAINWORK_OVERFLOW")
    return uint(left + right, WORK_MAX, "CHAINWORK_OVERFLOW")


def retarget(parent: int, first: int, last: int, interval: int,
             spacing: int, pow_limit: int) -> int:
    """Exact native u64/512-bit integer rules, including ceiling lower clamp."""
    for value in (first, last, interval, spacing):
        uint(value, U64_MAX, "TARGET_PARAMETERS")
    for value in (parent, pow_limit):
        uint(value, TARGET_MAX, "TARGET_PARAMETERS")
    if interval < 16 or spacing == 0 or not 0 < parent <= pow_limit:
        raise Reject("TARGET_PARAMETERS")
    desired = uint((interval - 1) * spacing, U64_MAX, "TARGET_PARAMETERS")
    upper = uint(desired * 4, U64_MAX, "TARGET_PARAMETERS")
    lower = desired // 4 + int(desired % 4 != 0)
    observed = min(upper, max(lower, max(1, last - first)))
    adjusted = uint(parent * observed, WORK_MAX, "CHAINWORK_OVERFLOW") // desired
    return min(pow_limit, max(1, adjusted))


def check_time(candidate: int, ancestors: list[int], now: int, skew: int) -> None:
    for value in (candidate, now, skew, *ancestors):
        uint(value, U64_MAX, "TIME_RANGE")
    if not ancestors:
        raise Reject("UNKNOWN_PARENT")
    recent = sorted(ancestors[:11])
    if candidate <= recent[len(recent) // 2]:
        raise Reject("TIME")
    # The native sum is u128, so u64::MAX + skew must not wrap or saturate.
    if candidate > now + skew:
        raise Reject("TIME_DEFERRED")


@dataclass(frozen=True)
class Parameters:
    initial: int
    pow_limit: int
    interval: int
    spacing: int
    skew: int
    genesis_time: int
    input_sha256: str

    @classmethod
    def load(cls, path: Path) -> Parameters:
        raw = path.read_bytes()
        data = json.loads(raw)
        if data.get("production_activation") is not False or data.get("not_mainnet") is not True:
            raise Reject("RESEARCH_PROFILE_REQUIRED")
        if data.get("median_time_width") != 11 or data.get("retarget_factor") != 4:
            raise Reject("UNSUPPORTED_NATIVE_TIME_RULES")
        result = cls(int(data["initial_target_hex"], 16), int(data["pow_limit_hex"], 16),
                     data["retarget_interval"], data["target_spacing_seconds"],
                     data["future_skew_seconds"], data["genesis_timestamp"],
                     hashlib.sha256(raw).hexdigest())
        retarget(result.initial, 0, 1, result.interval, result.spacing, result.pow_limit)
        uint(result.genesis_time, U64_MAX, "TIME_RANGE")
        uint(result.skew, U64_MAX, "TIME_RANGE")
        return result


@dataclass(frozen=True)
class SyntheticHeader:
    """No proof, state root, signature or native-admission authority."""
    height: int
    timestamp: int
    target: int
    chainwork: int


class Branch:
    def __init__(self, parameters: Parameters, *, fixed_target_experiment: bool = False):
        self.parameters = parameters
        self.fixed_target_experiment = fixed_target_experiment
        self.headers = [SyntheticHeader(0, parameters.genesis_time, parameters.initial, 0)]

    @property
    def tip(self) -> SyntheticHeader:
        return self.headers[-1]

    def expected_target(self) -> int:
        p = self.parameters
        height = self.tip.height + 1
        if self.fixed_target_experiment or height % p.interval:
            return self.tip.target
        if len(self.headers) < p.interval:
            raise Reject("UNKNOWN_PARENT")
        return retarget(self.tip.target, self.headers[-p.interval].timestamp,
                        self.tip.timestamp, p.interval, p.spacing, p.pow_limit)

    def append(self, timestamp: int, now: int, *, alleged_target: int | None = None) -> None:
        target = self.expected_target()
        if alleged_target is not None and alleged_target != target:
            raise Reject("TARGET")
        check_time(timestamp, [h.timestamp for h in reversed(self.headers[-11:])],
                   now, self.parameters.skew)
        self.headers.append(SyntheticHeader(self.tip.height + 1, timestamp, target,
                                            add_work(self.tip.chainwork, required_work(target))))

    def validate_published_history(self, now: int) -> None:
        """Replay from genesis; no inherited target/time verdict is accepted."""
        replay = Branch(self.parameters, fixed_target_experiment=self.fixed_target_experiment)
        for h in self.headers[1:]:
            replay.append(h.timestamp, now, alleged_target=h.target)
            if replay.tip != h:
                raise Reject("HISTORY_MISMATCH")


def success_probability(target: int) -> Decimal:
    required_work(target)
    return Decimal(target + 1) / Decimal(1 << 256)


def expected_attempt_seconds(parameters: Parameters, target: int, relative_rate: Decimal,
                             model: str, proof_seconds: Decimal = Decimal(0)) -> Decimal:
    """An explicit abstract oracle-cost assumption, never a W1 resource estimate.

    relative_rate is the baseline isolated block-production rate relative to the
    honest classical network, before per-success proof overhead. The normalized
    query model omits Grover constants, failure variance and new-tip interruptions.
    """
    if not relative_rate.is_finite() or relative_rate <= 0:
        raise Reject("RATE")
    if not proof_seconds.is_finite() or proof_seconds < 0:
        raise Reject("PROOF_COST")
    ratio = success_probability(parameters.initial) / success_probability(target)
    if model == "quantum_query_cost_assumption":
        ratio = ratio.sqrt()
    elif model != "classical_query_cost_assumption":
        raise Reject("MODEL")
    return Decimal(parameters.spacing) * ratio / relative_rate + proof_seconds


def run_withholding(parameters: Parameters, *, model: str, relative_rate: Decimal,
                    ramp_epochs: int = 8, hold_epochs: int = 3,
                    catch_up_tip: bool = False, fixed_target_experiment: bool = False,
                    proof_seconds: Decimal = Decimal(0)) -> dict:
    """Deterministic expected-time schedule, NOT an attack success probability."""
    if not (1 <= ramp_epochs <= 32 and 1 <= hold_epochs <= 32):
        raise Reject("SIMULATION_BOUND")
    private = Branch(parameters, fixed_target_experiment=fixed_target_experiment)
    now = Decimal(parameters.genesis_time)
    total = (ramp_epochs + hold_epochs) * parameters.interval
    if total > 100_000:
        raise Reject("SIMULATION_BOUND")
    with localcontext() as ctx:
        ctx.prec = 90
        for index in range(total):
            target = private.expected_target()
            # Committed timestamp is selected BEFORE the assumed mining cost.
            increment = max(1, parameters.spacing // 2) if index < ramp_epochs * parameters.interval else parameters.spacing
            timestamp = private.tip.timestamp + increment
            if catch_up_tip and index == total - 1:
                timestamp = max(timestamp, int(now))
            now += expected_attempt_seconds(parameters, target, relative_rate, model, proof_seconds)
            private.append(timestamp, int(now))
        private.validate_published_history(int(now))
        elapsed = now - parameters.genesis_time
        honest = Branch(parameters, fixed_target_experiment=fixed_target_experiment)
        honest_time = Decimal(parameters.genesis_time)
        for _ in range(1_000_000):
            next_time = honest_time + expected_attempt_seconds(
                parameters, honest.expected_target(), Decimal(1), "classical_query_cost_assumption")
            if next_time > now:
                break
            honest_time = next_time
            honest.append(int(honest_time), int(honest_time))
        else:
            raise Reject("HONEST_SIMULATION_BOUND")
        return {
            "model": model,
            "relative_isolated_rate_at_initial_target": str(relative_rate),
            "time_model": "deterministic_expected_query_cost_not_stochastic_consensus",
            "constant_success_proof_seconds_assumed": str(proof_seconds),
            "fixed_target_experiment": fixed_target_experiment,
            "catch_up_tip": catch_up_tip,
            "elapsed_seconds": str(elapsed),
            "private_blocks": private.tip.height,
            "honest_blocks": honest.tip.height,
            "private_chainwork": str(private.tip.chainwork),
            "honest_chainwork": str(honest.tip.chainwork),
            "private_heavier": private.tip.chainwork > honest.tip.chainwork,
            "maximum_relative_required_work": str(Decimal(max(required_work(h.target) for h in private.headers)) / Decimal(required_work(parameters.initial))),
            "tip_age_seconds": str(now - private.tip.timestamp),
            "modeled_time_and_required_work_rules_checked": True,
            "native_retarget_rule_used": not fixed_target_experiment,
            "history_valid_under_selected_model": True,
            "valid_w1_generated_or_verified": False,
            "quantum_resource_estimate": None,
            "quantum_pon_hardness_qualified": False,
        }


def fresh_work_sensitivity() -> dict:
    """Algebraic sensitivity of w(m)~m with p0 fixed; no cost lower bound."""
    rows = []
    for m in (1, 4, 16, 64, 256):
        rows.append({"fresh_work_units": m,
                     "assumed_linear_oracle_relative_weight_rate": 1,
                     "assumed_sqrt_oracle_relative_weight_rate": str(Decimal(m).sqrt())})
    return {
        "status": "unproven_research_hypothesis_not_a_protocol_successor",
        "formula": "weight_rate(m)/weight_rate(1) = m / (Cq(m)/Cq(1)) for fixed p0",
        "rows": rows,
        "mandatory_unproven_assumptions": [
            "m and the complete header are bound before the first fresh neural step",
            "round seeds bind previous transcript and index; no selectable or reusable prefix",
            "proof randomness and post-work metadata cannot create lottery trials",
            "Cq(m) is linear under one declared physical resource budget, including uncompute",
            "classical batching, low-rank shortcuts, quantum parallelism and data loading are counted",
            "useful neural outputs, latency, liveness and full chain-quality model are separately qualified",
        ],
        "production_activation": False,
        "quantum_pon_hardness_qualified": False,
    }


def report(parameters: Parameters) -> dict:
    native = (ROOT / "trillionnium/crates/trnm-pon-node/src/consensus.rs").read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(native)).encode() + b"\0" + native).hexdigest()
    if blob != NATIVE_SOURCE_BLOB:
        raise Reject("NATIVE_SOURCE_CHANGED_REVIEW_AND_REBIND")
    cases = [run_withholding(parameters, model=model, relative_rate=Decimal("0.25"),
                             catch_up_tip=catch, fixed_target_experiment=fixed)
             for model, catch, fixed in [
                 ("classical_query_cost_assumption", False, False),
                 ("quantum_query_cost_assumption", False, False),
                 ("quantum_query_cost_assumption", True, False),
                 ("quantum_query_cost_assumption", False, True),
             ]]
    return {"schema": "pon-quantum-daa-conditional-model-v1",
            "native_arithmetic_source_commit": SOURCE, "native_arithmetic_source_blob": blob,
            "native_rust_parity_executed_by_this_report": False,
            "devnet_file_sha256": parameters.input_sha256,
            "scope": "source-bound_integer_semantics_and_conditional_cost_model_only",
            "cases": cases, "fixed_probability_fresh_work": fresh_work_sensitivity(),
            "production_activation": False, "quantum_pon_hardness_qualified": False,
            "native_pq_node_integrated": False,
            "not_measured": ["reversible_W1_circuit", "quantum_error_correction", "physical_mining_rate",
                             "stochastic_attack_probability", "network_partition_chain_quality"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parameters", type=Path, default=ROOT / "config/pon/devnet-v1.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = json.dumps(report(Parameters.load(args.parameters)), indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(value, end="")
    else:
        args.output.write_text(value)


if __name__ == "__main__":
    main()
