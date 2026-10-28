"""Conditional PoN/DAA cost model; never a miner, proof, or consensus owner.

Integer target/time/chainwork rules are executable arithmetic. Decimal clocks
are *assumed* costs, not measurements of W1 or a quantum circuit. In particular,
sqrt difficulty is an idealized query scaling hypothesis, not a quantum attack
receipt. Every report keeps production and quantum-qualification flags false.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
from typing import Literal

from reference import retarget, timestamp_state, work

U256 = 1 << 256
POW_LIMIT = (1 << 255) - 1
PRECISION = 70
Policy = Literal["periodic-target", "asert-raw", "asert-mtp11", "fixed-p-work"]
Cost = Literal["classical", "quantum-search", "linear-work", "sublinear-work"]


def uint(value: int, name: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(name)
    return value


def trunc_div(numerator: int, denominator: int) -> int:
    """C++/Rust signed division; Python // is wrong for negative exponents."""
    if denominator <= 0:
        raise ValueError("DENOMINATOR")
    return (1 if numerator >= 0 else -1) * (abs(numerator) // denominator)


def asert_target(anchor_target: int, time_delta: int, intervals: int,
                 spacing: int, half_life: int, pow_limit: int) -> int:
    """Isolated exact-u256 ASERT research arithmetic, with no nBits rounding.

Equivalent to #487 AsertInputs with intervals=candidate_height-anchor_height.
For BCH CalculateASERT vectors use intervals=height_diff+1. The fixed-point
polynomial/rounding follows BCHN src/pow.cpp, pinned in the vector fixture.
This does not activate #487 or import its native shadow/scheduling code.
"""
    for value, name in ((anchor_target, "ANCHOR"), (pow_limit, "POW_LIMIT")):
        uint(value, name, U256 - 1)
    for value, name in ((intervals, "INTERVALS"), (spacing, "SPACING"),
                        (half_life, "HALF_LIFE")):
        uint(value, name)
    if not 1 <= anchor_target <= pow_limit or not intervals or not spacing or not half_life:
        raise ValueError("ASERT_PARAMETERS")
    if type(time_delta) is not int or not -(1 << 64) < time_delta < (1 << 64):
        raise ValueError("TIME_DELTA")
    scaled = (time_delta - spacing * intervals) * 65536
    if not -(1 << 127) <= scaled < (1 << 127):
        raise ValueError("ASERT_I128_RANGE")
    exponent = trunc_div(scaled, half_life)
    shifts, fraction = divmod(exponent, 65536)
    factor = 65536 + ((195766423245049 * fraction +
                      971821376 * fraction * fraction +
                      5127 * fraction * fraction * fraction + (1 << 47)) >> 48)
    if shifts >= 256:
        return pow_limit
    if shifts <= -512:
        return 1
    value = anchor_target * factor
    value = value << shifts if shifts >= 0 else value >> -shifts
    return min(pow_limit, max(1, value >> 16))


def probability(target: int) -> Fraction:
    uint(target, "TARGET", U256 - 1)
    if target == 0:
        raise ValueError("TARGET")
    return Fraction(target + 1, U256)


def decimal(value: Fraction | int | str) -> Decimal:
    if isinstance(value, Fraction):
        return Decimal(value.numerator) / Decimal(value.denominator)
    return Decimal(value)


def text_decimal(value: Decimal) -> str:
    """Bounded reporting precision; integer target/work fields remain exact."""
    return format(value, ".24g")


def next_work_budget(parent: int, first: int, last: int, interval: int,
                     spacing: int, maximum: int) -> int:
    """New hypothesis: invert the periodic span to adjust mandatory work units.

Ceiling rounds upward; units are bounded and never fractional. This is not
existing consensus. A unit is an abstract cost premise, not a verified FLOP.
"""
    for value, name in ((parent, "WORK_UNITS"), (first, "FIRST"), (last, "LAST"),
                        (interval, "INTERVAL"), (spacing, "SPACING"),
                        (maximum, "MAX_UNITS")):
        uint(value, name)
    if interval < 16 or spacing == 0 or not 1 <= parent <= maximum:
        raise ValueError("BUDGET_PARAMETERS")
    desired = (interval - 1) * spacing
    observed = min(desired * 4, max((desired + 3) // 4, max(1, last - first)))
    return min(maximum, max(1, (parent * desired + observed - 1) // observed))


@dataclass(frozen=True)
class Header:
    height: int
    timestamp: int
    target: int
    units: int = 1024


def common_history() -> list[Header]:
    """Arithmetic-only common prefix from the native development pow_limit.

Eight short windows produce a nontrivial target; a full ordinary window then
allows identical steady honest controls for periodic, raw-ASERT and MTP-ASERT.
No signatures, tasks, W1 proofs or native admission are implied by this prefix.
"""
    history = [Header(0, 0, POW_LIMIT)]
    for height in range(1, 144):
        parent = history[-1]
        target = parent.target
        if height % 16 == 0:
            target = retarget(target, history[-16].timestamp, parent.timestamp,
                              16, 10, POW_LIMIT)
        timestamp = height if height < 128 else 127 + (height - 127) * 10
        history.append(Header(height, timestamp, target))
    return history


@dataclass(frozen=True)
class Scenario:
    name: str
    policy: Policy
    cost: Cost
    half_life: int = 160
    attacker_rate: str = "0.25"
    proof_delay_seconds: str = "0"
    ramp_blocks: int = 128
    hold_blocks: int = 48
    down_blocks: int = 288
    max_tail_blocks: int = 12000
    initial_units: int = 1024
    max_units: int = 1048576

    def validate(self) -> None:
        if self.policy not in ("periodic-target", "asert-raw", "asert-mtp11", "fixed-p-work"):
            raise ValueError("POLICY")
        allowed = ("linear-work", "sublinear-work") if self.policy == "fixed-p-work" else (
            "classical", "quantum-search")
        if self.cost not in allowed:
            raise ValueError("COST_POLICY")
        for value, name in ((self.half_life, "HALF_LIFE"),
                            (self.ramp_blocks, "RAMP_BLOCKS"),
                            (self.hold_blocks, "HOLD_BLOCKS"),
                            (self.down_blocks, "DOWN_BLOCKS"),
                            (self.max_tail_blocks, "TAIL_BLOCKS"),
                            (self.initial_units, "INITIAL_UNITS"),
                            (self.max_units, "MAX_UNITS")):
            uint(value, name, 1 << 24)
        if not self.half_life or not 1 <= self.initial_units <= self.max_units:
            raise ValueError("SCENARIO_PARAMETERS")
        if self.ramp_blocks + self.hold_blocks + self.down_blocks + self.max_tail_blocks > 100000:
            raise ValueError("MODEL_ROW_LIMIT")
        try:
            rate, delay = Decimal(self.attacker_rate), Decimal(self.proof_delay_seconds)
        except (InvalidOperation, TypeError, ValueError) as error:
            raise ValueError("SCENARIO_DECIMAL") from error
        if not rate.is_finite() or not 0 < rate <= 1:
            raise ValueError("ATTACKER_RATE")
        if not delay.is_finite() or not 0 <= delay <= 86400:
            raise ValueError("PROOF_DELAY")


def required(history: list[Header], case: Scenario, anchor: Header,
             anchor_parent_time: int, initial_target: int) -> tuple[int, int]:
    parent = history[-1]
    height = parent.height + 1
    target, units = parent.target, parent.units
    if case.policy in ("periodic-target", "fixed-p-work"):
        if height % 16 == 0:
            if case.policy == "periodic-target":
                target = retarget(target, history[-16].timestamp, parent.timestamp,
                                  16, 10, POW_LIMIT)
            else:
                units = next_work_budget(units, history[-16].timestamp,
                                         parent.timestamp, 16, 10, case.max_units)
        if case.policy == "fixed-p-work":
            target = initial_target
    elif height <= anchor.height:
        target = initial_target
    else:
        clock = parent.timestamp
        if case.policy == "asert-mtp11":
            recent = sorted(h.timestamp for h in history[-11:])
            clock = recent[len(recent) // 2]
        target = asert_target(initial_target, clock - anchor_parent_time,
                              height - anchor.height, 10, case.half_life, POW_LIMIT)
    return target, units


def cost_ratio(case: Scenario, target: int, initial_target: int, units: int) -> Decimal:
    if case.policy == "fixed-p-work":
        ratio = Decimal(units) / case.initial_units
        return ratio if case.cost == "linear-work" else ratio.sqrt()
    ratio = Decimal(initial_target + 1) / Decimal(target + 1)
    return ratio if case.cost == "classical" else ratio.sqrt()


def _run(case: Scenario) -> tuple[dict, list[dict]]:
    case.validate()
    history = [Header(h.height, h.timestamp, h.target, case.initial_units)
               for h in common_history()]
    start = history[-1].timestamp
    initial_target = retarget(history[-1].target, history[-16].timestamp,
                              history[-1].timestamp, 16, 10, POW_LIMIT)
    anchor = Header(history[-1].height + 1, start + 10, initial_target, case.initial_units)
    anchor_time = start
    if case.policy == "asert-mtp11":
        anchor_time = sorted(h.timestamp for h in history[-11:])[5]
    unit_weight = work(initial_target)
    baseline_weight = unit_weight * (case.initial_units if case.policy == "fixed-p-work" else 1)
    now, elapsed_compute, elapsed_wait = Decimal(start), Decimal(0), Decimal(0)
    credit, rows, caught_up = 0, [], False
    phase_end = case.ramp_blocks + case.hold_blocks + case.down_blocks
    for index in range(phase_end + case.max_tail_blocks):
        if index < case.ramp_blocks:
            phase, step = "compress-time", 5
        elif index < case.ramp_blocks + case.hold_blocks:
            phase, step = "hold-hard-work", 10
        elif index < phase_end:
            phase, step = "relax-time", 20
        else:
            phase, step = "catch-up-tip-time", 10
        target, units = required(history, case, anchor, anchor_time, initial_target)
        compute = Decimal(10) / Decimal(case.attacker_rate) * cost_ratio(
            case, target, initial_target, units)
        finish = now + compute + Decimal(case.proof_delay_seconds)
        timestamp = history[-1].timestamp + step
        # If a proposed stamp is too far in the future, charge the whole wait.
        wait = max(Decimal(0), Decimal(timestamp - 120) - finish)
        finish += wait
        status = timestamp_state(timestamp, [h.timestamp for h in history[-11:]],
                                 int(finish), 120)
        if status != "admissible":
            raise ValueError("MODEL_INVALID_TIMESTAMP:" + status)
        header = Header(history[-1].height + 1, timestamp, target, units)
        weight = work(target) * (units if case.policy == "fixed-p-work" else 1)
        credit += weight
        elapsed_compute += compute
        elapsed_wait += wait
        now = finish
        honest_blocks = int((now - start) // 10)
        honest_credit = honest_blocks * baseline_weight
        rows.append({
            "index": index, "height": header.height, "phase": phase,
            "timestamp": timestamp, "target_hex": f"{target:064x}",
            "modeled_completion_time": int(finish),
            "mandatory_units": units, "required_work": str(weight),
            "cumulative_work": str(credit), "honest_model_work": str(honest_credit),
            "modeled_compute_seconds": text_decimal(compute),
            "modeled_wait_seconds": text_decimal(wait),
            "modeled_elapsed_seconds": text_decimal(now - start),
            "timestamp_status": status,
        })
        history.append(header)
        if index >= phase_end and timestamp >= int(now) - 10:
            caught_up = True
            break
    last = rows[-1] if rows else None
    if last is None:
        raise ValueError("EMPTY_MODEL")
    honest_work = int(last["honest_model_work"])
    summary = {
        "name": case.name, "policy": case.policy, "cost_assumption": case.cost,
        "rows": len(rows), "initial_target_hex": f"{initial_target:064x}",
        "probability_numerator": str(initial_target + 1), "probability_denominator": str(U256),
        "attacker_rate_at_baseline_assumed": case.attacker_rate,
        "proof_delay_seconds_assumed": case.proof_delay_seconds,
        "initial_units": case.initial_units, "half_life_seconds": case.half_life,
        "modeled_elapsed_seconds": text_decimal(now - start),
        "modeled_compute_seconds": text_decimal(elapsed_compute),
        "modeled_wait_seconds": text_decimal(elapsed_wait),
        "modeled_proof_delay_seconds": text_decimal(Decimal(case.proof_delay_seconds) * len(rows)),
        "cumulative_work": str(credit), "honest_model_work": str(honest_work),
        "work_ratio": text_decimal(Decimal(credit) / honest_work) if honest_work else None,
        "tip_timestamp_lag_seconds": text_decimal(now - history[-1].timestamp),
        "caught_up_tip_time": caught_up, "tail_budget_exhausted": not caught_up,
        "more_work_than_honest_model": credit > honest_work,
        "conditional_reorg_schedule": caught_up and credit > honest_work,
        "minimum_target_hex": min(r["target_hex"] for r in rows),
        "maximum_target_hex": max(r["target_hex"] for r in rows),
        "minimum_units": min(r["mandatory_units"] for r in rows),
        "maximum_units": max(r["mandatory_units"] for r in rows),
        "native_packets_generated": 0, "quantum_circuit_executed": False,
        "w1_cost_measured": False, "security_theorem": False,
        "production_consensus_activation": False,
    }
    return summary, rows


def run_scenario(case: Scenario) -> tuple[dict, list[dict]]:
    with localcontext() as context:
        context.prec = PRECISION
        return _run(case)


def standard_scenarios() -> list[Scenario]:
    return [
        Scenario("periodic_classical_control", "periodic-target", "classical", max_tail_blocks=512),
        Scenario("periodic_quantum_query_hypothesis", "periodic-target", "quantum-search"),
        Scenario("asert_raw_hl160_query_hypothesis", "asert-raw", "quantum-search", ramp_blocks=256),
        Scenario("asert_mtp_hl160_query_hypothesis", "asert-mtp11", "quantum-search", ramp_blocks=256),
        Scenario("asert_raw_hl160_extended_schedule", "asert-raw", "quantum-search",
                 ramp_blocks=256, max_tail_blocks=16000),
        Scenario("asert_mtp_hl160_extended_schedule", "asert-mtp11", "quantum-search",
                 ramp_blocks=256, max_tail_blocks=16000),
        Scenario("asert_raw_hl7200_bounded_schedule", "asert-raw", "quantum-search", half_life=7200,
                 ramp_blocks=256, max_tail_blocks=512),
        Scenario("fixed_p_linear_cost_hypothesis", "fixed-p-work", "linear-work", max_tail_blocks=512),
        Scenario("fixed_p_sublinear_cost_counterexample", "fixed-p-work", "sublinear-work"),
        Scenario("periodic_quantum_proof_latency_sensitivity", "periodic-target", "quantum-search",
                 proof_delay_seconds="5"),
        Scenario("periodic_quantum_proof_latency_extended", "periodic-target", "quantum-search",
                 proof_delay_seconds="5", max_tail_blocks=24000),
    ]


ASSUMPTIONS = {
    "scope": "conditional_arithmetic_and_cost_model_only",
    "actual_native_or_quantum_attack": False,
    "quantum_oracle_gate_depth": None,
    "quantum_logical_qubits": None,
    "quantum_error_correction_cost": None,
    "real_w1_attempt_cost": None,
    "single_operator_python_execution": True,
    "quantum_search_cost": "sqrt(p_baseline/p), constant factors absorbed into assumed baseline rate",
    "fixed_probability_candidate": "all mandatory unique challenge-bound units before one lottery ticket",
    "fixed_probability_unproved": [
        "minimum classical and quantum winner-search cost linear in units",
        "no cross-unit/nonce/parent amortization, selective completion, or duplicate credit",
        "quantum-cost lower bound for full W1 predicate rather than final SHA256 alone",
        "all-unit statement binding and post-quantum proof soundness",
        "task availability, propagation, reorg state and honest service",
    ],
    "honest_network_model": "constant baseline rate, deterministic expected 10-second blocks; no stochastic confidence bound",
    "network_and_tasks": "assumed available; no actual packets, state, lease, fee or model evaluation",
    "asert_status": "isolated counterfactual arithmetic; raw and MTP variants are not activated",
    "proof_cost_status": "constant-delay sensitivity only; no proof produced or measured",
    "release_ready": False,
}
