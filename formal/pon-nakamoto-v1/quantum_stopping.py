#!/usr/bin/env python3
"""Conditional finite-domain search races; no production DAA or physical rates.

All marked counts and timings are assumptions. A Grover iteration costs a full
clean W1 phase oracle PLUS diffusion; measurement/classical checking, context
setup and winning witness/publication are separate. See the companion research
document for the derivation, independence assumptions and excluded strategies.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path


MAX_NUMERIC_PHASE_RADIANS = 64.0
OUTCOME_PRECISION = 80


class Reject(ValueError):
    """An unsupported or ill-defined conditional experiment."""


def _real(value, name: str, *, positive=False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Reject(name)
    try:
        value = float(value)
    except OverflowError as error:
        raise Reject(name) from error
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise Reject(name)
    return value


def _integer(value, name: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise Reject(name)
    return value


def grover_outcomes(nonce_bits: int, marked: int, iterations: int) -> tuple[float, float]:
    """Ideal known-M success/failure tails, rounded separately to binary64.

    For x=1-2M/N, cos((4j+2)theta)=T_(2j+1)(x). Binary doubling evaluates
    that Chebyshev polynomial in O(log(j+1)) Decimal operations. This avoids
    subtracting a rounded success from one, and avoids rounded-pi/2 residuals
    near a Grover peak. The retained phase bound remains an explicit domain
    restriction; eighty digits are a numerical method, not interval proof.
    """
    bits = _integer(nonce_bits, "NONCE_BITS", 1, 64)
    size = 1 << bits
    _integer(marked, "MARKED_COUNT", 0, size)
    _integer(iterations, "ITERATIONS", 0, (1 << 52) - 1)
    if marked == 0:
        return 0.0, 1.0
    if marked == size:
        return 1.0, 0.0
    # M/N can round to one for N=2**64,M=N-1. The complementary angle retains
    # the small unmarked count, including at long stopping times.
    complement = marked > size // 2
    angle = math.asin(math.sqrt((size - marked if complement else marked) / size))
    phase = (2 * iterations + 1) * angle
    # Complementing prevents loss of a nearly-full marked count, but cannot
    # repair arbitrarily accumulated angle error. Deliberately reject long
    # phases for every M rather than special-case symmetric marked sets.
    if phase > MAX_NUMERIC_PHASE_RADIANS:
        raise Reject("GROVER_PHASE_OUTSIDE_NUMERIC_DOMAIN")
    with localcontext() as context:
        context.prec = OUTCOME_PRECISION
        x = 1 - 2 * Decimal(marked) / Decimal(size)
        left, right = Decimal(1), x
        for bit in bin(2 * iterations + 1)[2:]:
            middle = 2 * left * right - x
            if bit == "0":
                left, right = 2 * left * left - 1, middle
            else:
                left, right = middle, 2 * right * right - 1
        success, failure = (1 - left) / 2, (1 + left) / 2
        if not 0 <= success <= 1 or not 0 <= failure <= 1:
            raise Reject("PROBABILITY_NUMERIC_RANGE")
        return float(success), float(failure)


def grover_success(nonce_bits: int, marked: int, iterations: int) -> float:
    """Compatibility success projection; campaign callers retain both tails."""
    return grover_outcomes(nonce_bits, marked, iterations)[0]


def empty_domain_probability(nonce_bits: int, target_probability: float) -> float:
    """P(M=0) ONLY under independent Bernoulli marking, not proved for W1."""
    bits = _integer(nonce_bits, "NONCE_BITS", 1, 64)
    probability = _real(target_probability, "TARGET_PROBABILITY")
    if probability > 1:
        raise Reject("TARGET_PROBABILITY")
    return 0.0 if probability == 1 else math.exp((1 << bits) * math.log1p(-probability))


def _log_power(log_ratio: float, count: int) -> float:
    if count == 0:
        return 0.0
    try:
        return log_ratio * count
    except OverflowError:
        return -math.inf if log_ratio < 0 else 0.0


def _geometric(log_ratio: float, count: int | None) -> float:
    if count == 0:
        return 0.0
    denominator = -math.expm1(log_ratio)
    if denominator == 0:
        return math.inf if count is None else float(count)
    return (1.0 if count is None else -math.expm1(_log_power(log_ratio, count))) / denominator


def _integral(rate: float, duration: float) -> float:
    """Integral of exp(-rate*t) from zero to duration, including rate=0."""
    product = rate * duration
    if product < 1e-8:
        return duration * (1 - product / 2 + product * product / 6)
    return -math.expm1(-product) / rate


@dataclass(frozen=True)
class Timing:
    oracle_and_diffusion_seconds: float
    measure_check_restart_seconds: float
    context_setup_seconds: float = 0.0
    winning_witness_publication_seconds: float = 0.0

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = _real(getattr(self, name), name, positive=name in (
                "oracle_and_diffusion_seconds", "measure_check_restart_seconds"))
            object.__setattr__(self, name, value)

    def attempt_seconds(self, iterations: int) -> float:
        _integer(iterations, "ITERATIONS", 0, (1 << 52) - 1)
        return _real(iterations * self.oracle_and_diffusion_seconds
                     + self.measure_check_restart_seconds, "ATTEMPT_SECONDS", positive=True)


@dataclass(frozen=True)
class FixedStop:
    success_probability: float
    attempt_seconds: float
    context_setup_seconds: float = 0.0
    winning_witness_publication_seconds: float = 0.0
    failure_probability: float | None = None

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            if name == "failure_probability":
                continue
            value = _real(getattr(self, name), name, positive=name == "attempt_seconds")
            if name == "success_probability" and value > 1:
                raise Reject(name)
            object.__setattr__(self, name, value)
        failure = (1 - self.success_probability if self.failure_probability is None
                   else _real(self.failure_probability, "failure_probability"))
        if failure > 1 or math.fsum((self.success_probability, failure)) != 1.0:
            raise Reject("INCONSISTENT_OUTCOME_TAILS")
        object.__setattr__(self, "failure_probability", failure)
        _real(float(self.first_completion()), "FIRST_COMPLETION", positive=True)

    def log_failure(self) -> float:
        if self.failure_probability == 0:
            return -math.inf
        # A small success may round its complement to one; a small failure
        # may round success to one. Use the retained minority tail in either
        # case so subsequent work and later-worker wins remain represented.
        return (math.log1p(-self.success_probability) if self.success_probability <= 0.5
                else math.log(self.failure_probability))

    def first_completion(self) -> Fraction:
        return (Fraction(self.context_setup_seconds) + Fraction(self.attempt_seconds)
                + Fraction(self.winning_witness_publication_seconds))

    def completed_by(self, budget: Fraction) -> int:
        # Exact arithmetic on supplied binary64 times; never enlarge the budget
        # by an epsilon to accept a genuinely late completion.
        remaining = (budget - Fraction(self.context_setup_seconds)
                     - Fraction(self.winning_witness_publication_seconds))
        return max(0, remaining // Fraction(self.attempt_seconds))


def search_stop(nonce_bits: int, marked: int, iterations: int, timing: Timing) -> FixedStop:
    success, failure = grover_outcomes(nonce_bits, marked, iterations)
    return FixedStop(success,
                     timing.attempt_seconds(iterations), timing.context_setup_seconds,
                     timing.winning_witness_publication_seconds, failure)


def campaign(stop: FixedStop, external_tip_rate: float = 0.0,
             budget_seconds: float | None = None) -> dict:
    """Closed form for D=c+Geom(p)*s+v, independent T~Exp(lambda).

    Return P(D<=min(T,B)), E[min(D,T,B)] and terminal probabilities. Repeated
    attempts sample the same finite marked set and may repeat candidates. Only
    independent identically reset contexts give the unbounded renewal rate.
    """
    rate = _real(external_tip_rate, "EXTERNAL_TIP_RATE")
    budget = None if budget_seconds is None else Fraction(_real(
        budget_seconds, "BUDGET_SECONDS", positive=True))
    p, step = stop.success_probability, stop.attempt_seconds
    first_exact, first = stop.first_completion(), float(stop.first_completion())
    count = None if budget is None else stop.completed_by(budget)
    if p == 0:
        win = 0.0
        spent = ((None if rate == 0 else 1 / rate) if budget is None
                 else _integral(rate, float(budget)))
        expires = 0.0 if budget is None else math.exp(-rate * float(budget))
    else:
        log_failure = stop.log_failure()
        log_ratio = log_failure - rate * step
        win = math.exp(-rate * first) * p * _geometric(log_ratio, count)
        expires = (0.0 if budget is None else
                   math.exp(-rate * float(budget) + _log_power(log_failure, count)))
        if budget is not None and budget <= first_exact:
            spent = _integral(rate, float(budget))
        else:
            if budget is None:
                series = _integral(rate, step) * _geometric(log_ratio, None)
            else:
                periods, remainder = divmod(budget - first_exact, Fraction(step))
                series = (_integral(rate, step) * _geometric(log_ratio, periods)
                          + math.exp(_log_power(log_ratio, periods))
                          * _integral(rate, float(remainder)))
            spent = (_integral(rate, first) + math.exp(-rate * first)
                     * stop.failure_probability * series)
    if spent is not None and (not math.isfinite(spent) or spent <= 0):
        raise Reject("EXPECTED_TIME_NUMERIC_RANGE")
    external = 0.0 if spent is None else min(1.0, rate * spent)
    win = min(1.0, max(0.0, win))
    return {
        "win_probability": win, "external_tip_probability": external,
        "budget_expiry_probability": expires,
        "nontermination_probability": 1.0 if spent is None else 0.0,
        "expected_context_seconds": spent,
        "reward_per_expected_second": 0.0 if spent is None else win / spent,
        "completed_attempt_opportunities": count,
        "interpretation": ("conditional_iid_context_renewal_rate" if budget is None
                           else "bounded_campaign_reward_time_ratio"),
    }


def poisson_classical_race(own_rate: float, competing_rates: list[float],
                           budget_seconds: float | None = None) -> dict:
    """Independent exponential classical baseline; no quantum-rate calibration."""
    own = _real(own_rate, "OWN_RATE")
    try:
        other = math.fsum(_real(r, "COMPETING_RATE") for r in competing_rates)
    except OverflowError as error:
        raise Reject("TOTAL_RATE") from error
    total = _real(own + other, "TOTAL_RATE")
    budget = None if budget_seconds is None else _real(budget_seconds, "BUDGET_SECONDS", positive=True)
    if total == 0:
        spent = budget
    else:
        spent = 1 / total if budget is None else _integral(total, budget)
    if spent is not None and (not math.isfinite(spent) or spent <= 0):
        raise Reject("EXPECTED_TIME_NUMERIC_RANGE")
    return {
        "own_win_probability": 0.0 if spent is None else own * spent,
        "competing_win_probability": 0.0 if spent is None else other * spent,
        "budget_expiry_probability": 0.0 if budget is None else math.exp(-total * budget),
        "nontermination_probability": 1.0 if spent is None else 0.0,
        "expected_context_seconds": spent,
    }


def fixed_stop_race(stops: list[FixedStop], budget_seconds: float,
                    external_tip_rate: float = 0.0, event_limit: int = 10000) -> dict:
    """Finite-budget race of independent fixed-stop workers, exact time ordering.

    At simultaneous completion, uniformly choose among successful workers.
    This explicit research tie rule is NOT a native fork-choice change. All
    workers lose their current context on another winner or an external tip.
    No strategic equilibrium, adaptive measurement, entanglement or latency.
    """
    if not 1 <= len(stops) <= 4:
        raise Reject("RACE_WORKERS")
    _integer(event_limit, "EVENT_LIMIT", 1, 100000)
    budget = Fraction(_real(budget_seconds, "BUDGET_SECONDS", positive=True))
    rate = _real(external_tip_rate, "EXTERNAL_TIP_RATE")
    counts = [stop.completed_by(budget) for stop in stops]
    if sum(counts) > event_limit:
        raise Reject("EVENT_BUDGET_EXCEEDED")
    events: dict[Fraction, list[int]] = {}
    for index, (stop, count) in enumerate(zip(stops, counts)):
        for k in range(count):
            at = stop.first_completion() + k * Fraction(stop.attempt_seconds)
            events.setdefault(at, []).append(index)
    log_survival, spent, previous = 0.0, 0.0, Fraction(0)
    wins = [0.0] * len(stops)
    tie_mass = 0.0
    for at, due in sorted(events.items()):
        spent += math.exp(log_survival - rate * float(previous)) * _integral(rate, float(at - previous))
        weighted_survival = math.exp(log_survival - rate * float(at))
        for successes in itertools.product((False, True), repeat=len(due)):
            probability = math.prod(stops[i].success_probability if success
                                    else stops[i].failure_probability
                                    for i, success in zip(due, successes))
            winners = [i for i, success in zip(due, successes) if success]
            if winners:
                mass = weighted_survival * probability
                for index in winners:
                    wins[index] += mass / len(winners)
                if len(winners) > 1:
                    tie_mass += mass
        log_survival += math.fsum(stops[i].log_failure() for i in due)
        previous = at
    spent += math.exp(log_survival - rate * float(previous)) * _integral(rate, float(budget - previous))
    return {
        "worker_win_probabilities": wins,
        "external_tip_probability": rate * spent,
        "budget_expiry_probability": math.exp(log_survival - rate * float(budget)),
        "expected_context_seconds": spent,
        "simultaneous_success_probability": tie_mass,
        "completion_opportunities_enumerated": sum(counts),
        "distinct_completion_times": len(events),
        "tie_rule": "uniform_among_simultaneous_successes_research_only",
        "equilibrium_or_native_network_claim": False,
    }


def best_first_peak(nonce_bits: int, marked: int, timing: Timing,
                    external_tip_rate: float = 0.0,
                    budget_seconds: float | None = None) -> dict:
    """Exhaustive declared first-peak stops, not a global strategy optimum."""
    grover_success(nonce_bits, marked, 0)
    size = 1 << nonce_bits
    last = 0 if marked == 0 else math.floor(math.pi / (4 * math.asin(math.sqrt(marked / size))))
    if last > 10000:
        raise Reject("DECLARED_STOP_SEARCH_BUDGET_EXCEEDED")
    candidates = []
    for iterations in range(last + 1):
        stop = search_stop(nonce_bits, marked, iterations, timing)
        value = campaign(stop, external_tip_rate, budget_seconds)
        candidates.append(dict(value, iterations=iterations,
                               attempt_success_probability=stop.success_probability,
                               attempt_seconds=stop.attempt_seconds))
    best = max(candidates, key=lambda row: (row["reward_per_expected_second"], -row["iterations"]))
    return dict(best, enumerated_stops=len(candidates), candidate_first=0, candidate_last=last,
                global_strategy_optimum=False)


def report() -> dict:
    timing = Timing(0.01, 0.01, 0.02, 0.03)
    comparison = []
    # Finite actual M is supplied, not estimated from a W1 target. Relative
    # weights and work multipliers are counterfactual, not consensus changes.
    for rate in (0.0, 0.1, 1.0):
        for multiplier in (1, 4, 16, 64, 256):
            for candidate in ("decrease_marked_fraction", "fixed_fraction_linear_oracle",
                              "fixed_fraction_sqrt_oracle"):
                marked = 65536 // multiplier if candidate == "decrease_marked_fraction" else 65536
                scale = (1.0 if candidate == "decrease_marked_fraction" else
                         float(multiplier) if candidate == "fixed_fraction_linear_oracle"
                         else math.sqrt(multiplier))
                nonoracle_scale = 1.0 if candidate == "decrease_marked_fraction" else float(multiplier)
                # Mandatory classical checking cannot become free at j=0 when
                # work grows. This explicit comparison scales setup, checking
                # and winning-tail costs linearly in both variable-work rows.
                cost = Timing(timing.oracle_and_diffusion_seconds * scale,
                              timing.measure_check_restart_seconds * nonoracle_scale,
                              timing.context_setup_seconds * nonoracle_scale,
                              timing.winning_witness_publication_seconds * nonoracle_scale)
                chosen = best_first_peak(24, marked, cost, rate)
                comparison.append({"candidate": candidate, "multiplier": multiplier,
                                   "actual_marked_assumption": marked, "nonce_bits": 24,
                                   "external_tip_rate_assumption": rate,
                                   "oracle_cost_multiplier_assumption": scale,
                                   "nonoracle_cost_multiplier_assumption": nonoracle_scale,
                                   "relative_weight_assumption": multiplier,
                                   "relative_weight_per_second": multiplier * chosen["reward_per_expected_second"],
                                   "best_declared_stop": chosen})
    stopping = [{"external_tip_rate_assumption": rate,
                 "choice": best_first_peak(24, 65536, timing, rate)}
                for rate in (0.0, 0.1, 1.0, 10.0)]
    races = []
    for left, right in ((6, 6), (6, 12), (12, 6), (12, 12)):
        stops = [search_stop(24, 65536, j, timing) for j in (left, right)]
        races.append({"fixed_iterations": [left, right],
                      "result": fixed_stop_race(stops, 2.0, 0.1)})
    omitted_timing = Timing(timing.oracle_and_diffusion_seconds * 256,
                            timing.measure_check_restart_seconds, timing.context_setup_seconds,
                            timing.winning_witness_publication_seconds)
    return {
        "schema": "pon-finite-nonce-stopping-conditional-model-v2",
        "model_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "status": "research_conditional_not_production",
        "scope": {
            "actual_marked_count_known_assumed": True,
            "known_M_oracle_or_quantum_counting_cost_included": False,
            "independent_measurements_after_full_reset_assumed": True,
            "external_tips_independent_poisson_assumed": True,
            "abandon_on_tip_immediate_without_salvage_assumed": True,
            "binary64_probabilities_exact_fraction_time_order": True,
            "success_and_failure_tails_rounded_separately": True,
            "grover_outcome_decimal_precision": OUTCOME_PRECISION,
            "grover_minority_angle_phase_limit_radians": MAX_NUMERIC_PHASE_RADIANS,
            "native_W1_executed_by_this_model": False,
            "full_clean_W1_plus_diffusion_time_measured": False,
            "relative_rate_r_0_25_measured": False,
            "difficulty_retarget_or_protocol_semantics_changed": False,
            "production_activation": False,
            "quantum_security_qualified": False,
        },
        "timing_seconds_assumptions": asdict(timing),
        "q_zero_empty_marked_domain": campaign(search_stop(64, 0, 12, timing), 0.1, 5.0),
        "empty_uninterrupted_unbounded": campaign(search_stop(64, 0, 12, timing)),
        "iid_bernoulli_empty_domain_sensitivity": [
            {"nonce_bits": 64, "target_probability_assumption": p,
             "empty_probability": empty_domain_probability(64, p)}
            for p in (2.0 ** -60, 2.0 ** -64, 2.0 ** -68)],
        "stopping_sensitivity": stopping,
        "finite_budget_examples": [
            {"budget_seconds": budget,
             "result": campaign(search_stop(24, 65536, 6, timing), 0.1, budget)}
            for budget in (0.01, 0.11, 0.25, 1.0)],
        "classical_independent_competitor_baseline": poisson_classical_race(0.25, [0.5, 0.5]),
        "q_zero_classical_baseline": poisson_classical_race(0.0, [0.5, 0.5]),
        "two_worker_fixed_stop_examples": races,
        "difficulty_vs_work_comparison": comparison,
        "oracle_only_scaling_negative_control": {
            "omission": "leaving_classical_check_setup_and_winning_tail_fixed_when_work_grows",
            "counterfactual_work_multiplier": 256,
            "best_declared_stop": best_first_peak(24, 65536, omitted_timing),
            "timing_assumptions": asdict(omitted_timing),
            "valid_work_scaling_conclusion": False,
        },
        "unresolved": ["actual_W1_marked_distribution", "unknown_M_policy_cost",
                       "cheapest_legal_quantum_oracle", "physical_fault_tolerant_timing",
                       "adaptive_interrupt_measurement_salvage", "strategic_multi_miner_equilibrium",
                       "network_delays_and_native_tie_resolution", "chain_quality_under_DAA",
                       "fresh_work_independence_and_reuse", "hardware_cost_advantage"],
        "primary_references": ["https://arxiv.org/html/quant-ph/9605034v1",
                               "https://arxiv.org/html/2403.08023v2",
                               "https://arxiv.org/abs/1809.03671v2",
                               "https://www.rle.mit.edu/rgallager/documents/Poisson.pdf",
                               "https://ocw.mit.edu/courses/6-262-discrete-stochastic-processes-spring-2011/resources/mit6_262s11_chap04/"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(report(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        with args.output.open("x") as destination:
            destination.write(encoded)


if __name__ == "__main__":
    main()
