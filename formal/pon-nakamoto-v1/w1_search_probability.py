"""Certified numerical bounds for a fixed, finite ideal-search schedule.

The two-dimensional Grover recurrence has rational coefficients. Outward
rounded dyadic interval matrix powers therefore enclose its exact probability
without treating a binary64 trigonometric result as a bound. The full accepted
set may strictly contain the phase-marked set. No random-ticket assumption is
made: these counts must be supplied by a separately verified literal census.

A schedule stops at its first accepted batch. Proof and delivery must both fit
the deadline. A winning branch may time out while the losing branch continues
to a later, cheaper proof. The error coupling is additive and does not assume
independence between faults and an ideal winning measurement.

The ideal amplification model is the uniform-search specialization of Brassard,
Hoyer, Mosca and Tapp, arXiv:quant-ph/0005055v1. Outward interval evaluation and
the first-winner deadline decomposition here certify only this stated model;
they prove neither W1 ticket independence nor optimality over legal strategies.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from w1_bounded_search import horizon, ratio
from w1_marked_domain import MAX_ITERATIONS, MAX_PROCESSORS, MAX_REDUCED_NONCE_BITS, MAX_TRIALS

SCHEMA = "trnm-w1-certified-schedule-probability-v1"
PRECISION_BITS = 384
_SCALE = 1 << PRECISION_BITS


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(name)


@dataclass(frozen=True)
class ProbabilityInterval:
    lower: Fraction
    upper: Fraction

    def __post_init__(self):
        if (type(self.lower) is not Fraction or type(self.upper) is not Fraction
                or not 0 <= self.lower <= self.upper <= 1):
            raise ValueError("PROBABILITY_INTERVAL")

    def record(self):
        return {"lower": ratio(self.lower), "upper": ratio(self.upper)}


@dataclass(frozen=True)
class _Dyadic:
    low: int
    high: int

    @classmethod
    def rational(cls, value):
        scaled = value * _SCALE
        return cls(scaled.numerator // scaled.denominator,
                   -((-scaled.numerator) // scaled.denominator))

    def __add__(self, other):
        return _Dyadic(self.low + other.low, self.high + other.high)

    def __neg__(self):
        return _Dyadic(-self.high, -self.low)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, other):
        products = (self.low * other.low, self.low * other.high,
                    self.high * other.low, self.high * other.high)
        return _Dyadic(min(products) // _SCALE, -((-max(products)) // _SCALE))

    def square(self):
        low = 0 if self.low <= 0 <= self.high else min(self.low**2, self.high**2)
        high = max(self.low**2, self.high**2)
        return _Dyadic(low // _SCALE, -((-high) // _SCALE))

    def probability(self):
        # Intersect only where the derivation already proves a probability.
        low, high = max(0, self.low), min(_SCALE, self.high)
        if low > high:
            raise ArithmeticError("PROBABILITY_ENCLOSURE_EMPTY")
        return _Dyadic(low, high)

    def power(self, exponent):
        result, base = _ONE, self
        while exponent:
            if exponent & 1:
                result = (result * base).probability()
            exponent >>= 1
            if exponent:
                base = base.square().probability()
        return result

    def public(self):
        value = self.probability()
        return ProbabilityInterval(Fraction(value.low, _SCALE), Fraction(value.high, _SCALE))


_ZERO, _ONE = _Dyadic(0, 0), _Dyadic(_SCALE, _SCALE)


def _matrix_product(left, right):
    return tuple(tuple(left[row][0] * right[0][column]
                       + left[row][1] * right[1][column]
                       for column in range(2)) for row in range(2))


def _counts(size, marked, accepted, iterations, processors):
    _integer(size, "PROBABILITY_DOMAIN_SIZE", 1, 1 << MAX_REDUCED_NONCE_BITS)
    if size & (size - 1):
        raise ValueError("PROBABILITY_POWER_OF_TWO_DOMAIN")
    _integer(marked, "PROBABILITY_PHASE_MARKED", 0, size)
    _integer(accepted, "PROBABILITY_ACCEPTED", marked, size)
    _integer(iterations, "PROBABILITY_ITERATIONS", 0, MAX_ITERATIONS)
    _integer(processors, "PROBABILITY_PROCESSORS", 1, MAX_PROCESSORS)


def grover_success_bounds(domain_size, phase_marked_count, full_accepted_count,
                          iterations, processors=1):
    """Enclose the exact ideal probability of at least one legal candidate.

    All independent processors start uniformly in the same declared domain.
    If ``a,b`` are amplitudes relative to their initial uniform coefficient,
    one Grover step sends them to
    ``((1-2p)*a + 2*(1-p)*b, -2*p*a + (1-2*p)*b)``.
    Legal unmarked candidates contribute ``(accepted-marked)/N * b**2``.
    Binary exponentiation needs O(log(iterations)) bounded-precision steps.
    """
    n, m, legal = domain_size, phase_marked_count, full_accepted_count
    _counts(n, m, legal, iterations, processors)
    if legal == n:
        return _ONE.public()
    if not legal:
        return _ZERO.public()
    if not iterations or not m:
        single = _Dyadic.rational(Fraction(legal, n))
    else:
        p = Fraction(m, n)
        base = tuple(tuple(_Dyadic.rational(value) for value in row) for row in
                     ((1 - 2*p, 2*(1-p)), (-2*p, 1 - 2*p)))
        matrix = ((_ONE, _ZERO), (_ZERO, _ONE))
        exponent = iterations
        while exponent:
            if exponent & 1:
                matrix = _matrix_product(matrix, base)
            exponent >>= 1
            if exponent:
                base = _matrix_product(base, base)
        a, b = matrix[0][0] + matrix[0][1], matrix[1][0] + matrix[1][1]
        single = (_Dyadic.rational(p) * a.square()
                  + _Dyadic.rational(Fraction(legal - m, n)) * b.square()).probability()
    return (_ONE - (_ONE - single).power(processors)).public()


def probability_power_bounds(value, exponent):
    """Bound a probability power without unbounded rational denominators.

    A positive value smaller than the working precision gets a positive upper
    endpoint, never an asserted zero failure probability.
    """
    if type(value) is not Fraction or not 0 <= value <= 1:
        raise ValueError("PROBABILITY_POWER_BASE")
    _integer(exponent, "PROBABILITY_POWER_EXPONENT", 0, 10**9)
    return _Dyadic.rational(value).power(exponent).public()


@dataclass(frozen=True)
class ProbabilityTrial:
    domain_size: int
    phase_marked_count: int
    full_accepted_count: int
    iterations: int
    processors: int
    search_seconds: Fraction
    winner_seconds: Fraction

    def validate(self):
        _counts(self.domain_size, self.phase_marked_count, self.full_accepted_count,
                self.iterations, self.processors)
        if (type(self.search_seconds) is not Fraction or self.search_seconds <= 0
                or type(self.winner_seconds) is not Fraction or self.winner_seconds < 0
                or self.search_seconds > 10**40 or self.winner_seconds > 10**40):
            raise ValueError("PROBABILITY_TRIAL_CLOCK")


def coupled_success_bounds(ideal, failure_union):
    """Couple to an ideal run outside an event of probability at most epsilon.

    Every actual successful outcome must still satisfy the specified acceptance
    and delivery event. A logical infidelity or an observed sample failure rate
    is not, by itself, evidence for this coupling premise.
    """
    if type(ideal) is not ProbabilityInterval:
        raise ValueError("PROBABILITY_IDEAL_INTERVAL")
    if type(failure_union) is not Fraction or not 0 <= failure_union <= 1:
        raise ValueError("PROBABILITY_FAILURE_UNION")
    return ProbabilityInterval(max(Fraction(0), ideal.lower - failure_union),
                               min(Fraction(1), ideal.upper + failure_union))


def schedule_success_bounds(trials, horizon_seconds):
    """Enclose first-winner delivery for a fixed schedule and exact deadline.

    ``search_seconds`` includes all setup, preparation, iterations, readout and
    checks for the entire batch. ``winner_seconds`` includes one complete proof
    and delivery. Timing the counterfactual all-failure path determines when
    each mutually exclusive first-winner branch could begin its proof.
    """
    deadline = horizon(horizon_seconds)
    if type(trials) is not tuple or not 1 <= len(trials) <= MAX_TRIALS:
        raise ValueError("PROBABILITY_SCHEDULE")
    for trial in trials:
        if type(trial) is not ProbabilityTrial:
            raise ValueError("PROBABILITY_TRIAL_TYPE")
        trial.validate()
    elapsed = Fraction(0)
    reach, delivered, censored_winner, censored_search = _ONE, _ZERO, _ZERO, _ZERO
    rows = []
    for index, trial in enumerate(trials):
        finish = elapsed + trial.search_seconds
        row = {"schedule_index": index, "all_prior_trials_failed_probability": reach.public().record(),
               "all_failure_path_start_seconds_exact": ratio(elapsed),
               "all_failure_path_checks_finish_seconds_exact": ratio(finish),
               "search_complete_by_deadline": elapsed < deadline and finish <= deadline,
               "delivery_complete_by_deadline": False}
        if not row["search_complete_by_deadline"]:
            censored_search = reach
            reach = _ZERO
            rows.append(row)
            break
        bounds = grover_success_bounds(trial.domain_size, trial.phase_marked_count,
                                       trial.full_accepted_count, trial.iterations, trial.processors)
        probability = _Dyadic.rational(bounds.lower)
        probability = _Dyadic(probability.low, _Dyadic.rational(bounds.upper).high)
        first = (reach * probability).probability()
        completion = finish + trial.winner_seconds
        row.update({"conditional_batch_accepted_probability": bounds.record(),
                    "first_accepted_batch_probability": first.public().record(),
                    "winning_branch_delivery_finish_seconds_exact": ratio(completion),
                    "delivery_complete_by_deadline": completion <= deadline})
        if completion <= deadline:
            delivered = (delivered + first).probability()
        else:
            censored_winner = (censored_winner + first).probability()
        reach = (reach * (_ONE - probability)).probability()
        rows.append(row)
        elapsed = finish
    return {
        "schema": SCHEMA, "horizon_seconds": horizon_seconds,
        "precision_bits": PRECISION_BITS,
        "arithmetic": "outward-dyadic rational Grover matrix powers; no binary64 trigonometry",
        "delivery_probability": delivered.public().record(),
        "first_winner_censored_probability": censored_winner.public().record(),
        "search_censored_probability": censored_search.public().record(),
        "schedule_exhausted_without_winner_probability": reach.public().record(),
        "planned_trials": len(trials), "evaluated_trial_branches": rows,
        "phase_marked_set_and_full_accepted_set_are_distinct": True,
        "fresh_independent_ideal_processor_measurements": True,
        "deadline_clocks_are_assumptions": True,
        "quantum_hardware_executed": False,
        "quantum_mining_qualified": False,
    }
