"""Bounded attacker choices over explicitly conditional lottery premises.

The optimizer knows the public target and its declared prior, never a sampled
marked count. Its objective is renewal throughput at one fixed target, not
network profit or a global mining optimum. For finite domains, that objective
requires a fresh independent domain after every measured batch. Persistent
domains, including M=0, are supported by the event evaluator separately.

Binomial weights below are exact rational numbers on a deliberately small
support. Zero-iteration measurements and special Grover fractions 1/4, 1/2 and
3/4 use rational batch probabilities before one float64 conversion; the special
fractions have exact periodic reductions. Other Grover amplitudes and the
optimization remain float64 calculations.
No normal/Poisson approximation, large-binomial sampler, BBHT implementation,
complete W1 circuit, hardware measurement or security threshold is implied.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import math
from typing import Any

MAX_ITERATIONS = 100_000_000
MAX_CANDIDATES = 4096
MAX_DOMAIN_SIZE = 4096
MAX_EXACT_BINOMIAL_SIZE = 64
MAX_PROCESSORS = 1024
MAX_CLOCK_SECONDS = 1e30
# Network declarations are capped above; a permitted factor as small as 1e-9
# can make an effective per-iteration clock larger before horizon censoring.
MAX_EFFECTIVE_CLOCK_SECONDS = 1e40

ADVERSARIAL_ASSUMPTIONS = {
    "schema": "trnm-quantum-adversarial-assumptions-v2",
    "optimizer": "finite candidate set; fixed-target renewal throughput, not profit or global optimum",
    "optimizer_information": "public target, declared prior, clocks and processor count; no sampled M",
    "finite_domain": "frozen candidate/header and shared marked count across retries and processors",
    "finite_domain_sampler": "at most 4096 exact integer 256-bit Bernoulli comparisons per domain",
    "finite_domain_prior": "iid uniform ticket premise, not a theorem about the W1 relation",
    "finite_fixed_count": "caller-conditioned test premise; count unavailable to strategy selection",
    "fresh_domain": "explicit template/domain salt and paid setup; W1 realizability unproved",
    "binomial_optimizer_support": MAX_EXACT_BINOMIAL_SIZE,
    "binomial_weights": "exact rational; zero iterations and special Grover fractions 1/4, 1/2, 3/4 aggregate exactly before float64 conversion; other probabilities and rates use float64",
    "measurement_sampler": "exact Bernoulli for the represented binary64 probability; at most 1074 random bits",
    "parallelism": "independent measurements conditional on one shared domain M; all processors paid",
    "persistent_domain_optimality": "not claimed; no BBHT or posterior-optimal policy implemented",
    "release_information": "private branch plus miner-delayed public messages; no observer/global tip",
    "timestamp": "frozen before search; branch median and local clock; backward parent steps permitted",
    "native_scope": "exact periodic target/work/time arithmetic; successful W1 predicates assumed",
    "search_scope": "declared bounded strategy grid and seeds; no statistical safety threshold",
    "receipt_scope": "source-consistent deterministic replay, not authenticated execution attestation",
    "quantum_work_lower_bound_proved": False,
    "full_W1_oracle_constructed": False,
    "quantum_hardware_executed": False,
    "native_w1_verified": False,
    "security_theorem": False,
    "production_consensus_activation": False,
    "release_ready": False,
}


def integer(value: Any, label: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(label)
    return value


def seconds(value: Any, label: str, *, positive: bool = False) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(label)
    if not 0 <= value <= MAX_EFFECTIVE_CLOCK_SECONDS or (positive and not value):
        raise ValueError(label)
    return float(value)


def rational_probability(value: Any) -> Fraction:
    if (type(value) is not Fraction or not 0 <= value <= 1
            or value.denominator.bit_length() > 513):
        raise ValueError("RATIONAL_PROBABILITY")
    return value


def upward_float(value: Fraction) -> float:
    """Smallest finite binary float at or above a nonnegative exact clock."""
    if type(value) is not Fraction or value < 0:
        raise ValueError("EXACT_NONNEGATIVE_CLOCK")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError("EVENT_CLOCK_OVERFLOW") from error
    if not math.isfinite(result):
        raise ValueError("EVENT_CLOCK_OVERFLOW")
    if Fraction.from_float(result) < value:
        result = math.nextafter(result, math.inf)
    if not math.isfinite(result):
        raise ValueError("EVENT_CLOCK_OVERFLOW")
    return result


def batch_success(p: float, iterations: int, processors: int = 1) -> float:
    """Independent measurements conditional on one fixed marked fraction.

    With zero iterations, measurement preserves the stated fraction directly.
    For p=1/4, 1/2 or 3/4, theta is respectively pi/6, pi/4 or pi/3.
    Integer-period reduction prevents trigonometric roundoff from inventing
    marked outcomes at exact zeros or drifting at large iteration counts.
    Those cases aggregate independent processors rationally and convert once;
    other fractions retain the explicitly approximate binary64 calculation.
    """
    if type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1:
        raise ValueError("PROBABILITY")
    integer(iterations, "ITERATIONS", MAX_ITERATIONS)
    integer(processors, "PROCESSORS", MAX_PROCESSORS, 1)
    if p == 0 or p == 1:
        return float(p)
    if iterations == 0 and processors == 1:
        return float(p)
    if iterations == 0 or p in (0.25, 0.5, 0.75):
        single_exact = Fraction(p)
        if iterations and p != 0.5 and iterations % 3 == 1:
            single_exact = Fraction(int(p == 0.25))
        return float(1 - (1 - single_exact) ** processors)
    single = math.sin((2 * iterations + 1) * math.asin(math.sqrt(p))) ** 2
    return 1.0 if single >= 1 else -math.expm1(processors * math.log1p(-single))


def finite_domain_success(size: int, marked: int, iterations: int, processors: int) -> float:
    integer(size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE, 1)
    integer(marked, "MARKED_COUNT", size)
    return batch_success(marked / size, iterations, processors)


def sample_binary_probability(rng: Any, probability: float) -> bool:
    """Sample the represented probability without a 53-bit random() floor.

    Binary64 probabilities are dyadic rationals. A uniform integer over their
    denominator makes the comparison exact, including subnormal probabilities.
    This does not remove rounding in the preceding Grover amplitude calculation.
    The seeded simulation PRNG is not evidence of quantum hardware randomness.
    """
    if (type(probability) not in (int, float) or not 0 <= probability <= 1
            or not math.isfinite(probability)):
        raise ValueError("PROBABILITY")
    if probability == 0 or probability == 1:
        return bool(probability)
    numerator, denominator = float(probability).as_integer_ratio()
    return rng.getrandbits(denominator.bit_length() - 1) < numerator


def sample_marked_count(rng: Any, size: int, target: int) -> int:
    """Exact bounded binomial sampler under the uniform 256-bit-ticket premise.

    A single sample belongs to the domain. Calling this once per processor or
    once per retry would erase the shared no-solution event and is incorrect.
    This deliberately uses no approximate binomial API for large domains.
    """
    integer(size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE, 1)
    integer(target, "TARGET", (1 << 256) - 1)
    return sum(rng.getrandbits(256) <= target for _ in range(size))


@lru_cache(maxsize=8)
def binomial_weights(size: int, p: Fraction) -> tuple[Fraction, ...]:
    integer(size, "EXACT_BINOMIAL_SUPPORT", MAX_EXACT_BINOMIAL_SIZE, 1)
    rational_probability(p)
    numerator, denominator = p.numerator, p.denominator
    failure = denominator - numerator
    common_denominator = denominator ** size
    return tuple(Fraction(math.comb(size, m) * numerator ** m * failure ** (size - m),
                          common_denominator) for m in range(size + 1))


def binomial_batch_success(size: int, p: Fraction, iterations: int, processors: int) -> float:
    """Average independent measurements *after conditioning on their shared M*."""
    integer(iterations, "ITERATIONS", MAX_ITERATIONS)
    integer(processors, "PROCESSORS", MAX_PROCESSORS, 1)
    return math.fsum(float(weight) * finite_domain_success(size, m, iterations, processors)
                     for m, weight in enumerate(binomial_weights(size, p)))


@dataclass(frozen=True)
class TrialCosts:
    prepare_seconds: float
    iteration_seconds: float
    measurement_seconds: float
    candidate_check_seconds: float
    proof_seconds: float
    domain_setup_seconds: float = 0.0
    clock_rounding: str = "nearest"

    def validate(self) -> None:
        if self.clock_rounding not in ("nearest", "upward"):
            raise ValueError("CLOCK_ROUNDING")
        for name in ("prepare_seconds", "proof_seconds", "domain_setup_seconds"):
            seconds(getattr(self, name), name)
        for name in ("iteration_seconds", "measurement_seconds", "candidate_check_seconds"):
            seconds(getattr(self, name), name, positive=True)

    def measured_batch_seconds(self, iterations: int) -> float:
        self.validate()
        integer(iterations, "ITERATIONS", MAX_ITERATIONS)
        if self.clock_rounding == "upward":
            exact = sum((Fraction.from_float(float(value)) for value in (
                self.domain_setup_seconds, self.prepare_seconds,
                self.measurement_seconds, self.candidate_check_seconds)), Fraction(0))
            exact += iterations * Fraction.from_float(float(self.iteration_seconds))
            result = upward_float(exact)
        else:
            result = (self.domain_setup_seconds + self.prepare_seconds
                      + iterations * self.iteration_seconds + self.measurement_seconds
                      + self.candidate_check_seconds)
        if not math.isfinite(result) or result <= 0:
            raise ValueError("BATCH_CLOCK")
        return result


@dataclass(frozen=True)
class TrialChoice:
    iterations: int
    success_probability: float
    measured_batch_seconds: float
    expected_cycle_seconds: float
    expected_winners_per_second: float
    processor_seconds_per_measured_batch: float
    processors: int
    candidate_count: int
    finite_domain_size: int | None
    objective: str = "bounded-fixed-target-renewal-throughput"
    sampled_marked_count_used: bool = False
    global_optimum_claimed: bool = False


def validate_candidates(candidates: tuple[int, ...], maximum: int = MAX_ITERATIONS) -> None:
    if type(candidates) is not tuple or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise ValueError("ITERATION_CANDIDATES")
    previous = -1
    for value in candidates:
        integer(value, "ITERATION_CANDIDATE", maximum)
        if value <= previous:
            raise ValueError("ITERATION_CANDIDATE_ORDER")
        previous = value


def bounded_throughput_choice(p: Fraction, candidates: tuple[int, ...],
                              processors: int, costs: TrialCosts, *,
                              finite_domain_size: int | None = None) -> TrialChoice:
    """Choose the highest stated renewal rate in the caller's finite grid.

    All candidates use the same paid processors and clocks. Proof production is
    serial and paid once per winning batch; all measured candidates pay readout
    and classical checking. A finite-domain option averages over a *new* shared
    M per batch and includes its setup time. It is not a geometric approximation
    for retries on one persistent M. An earliest-iteration tie break is explicit.
    """
    rational_probability(p)
    validate_candidates(candidates)
    integer(processors, "PROCESSORS", MAX_PROCESSORS, 1)
    if type(costs) is not TrialCosts:
        raise ValueError("TRIAL_COSTS")
    costs.validate()
    if finite_domain_size is not None:
        integer(finite_domain_size, "EXACT_BINOMIAL_SUPPORT", MAX_EXACT_BINOMIAL_SIZE, 1)
    best: TrialChoice | None = None
    for iterations in candidates:
        success = (batch_success(float(p), iterations, processors) if finite_domain_size is None else
                   binomial_batch_success(finite_domain_size, p, iterations, processors))
        elapsed = costs.measured_batch_seconds(iterations)
        cycle = elapsed + success * costs.proof_seconds
        choice = TrialChoice(iterations, success, elapsed, cycle, success / cycle,
                             processors * elapsed, processors, len(candidates), finite_domain_size)
        if best is None or choice.expected_winners_per_second > best.expected_winners_per_second:
            best = choice
    assert best is not None
    return best
