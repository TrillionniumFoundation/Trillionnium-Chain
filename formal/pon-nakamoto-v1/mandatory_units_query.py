"""Conservative finite QROM query certificate for the frozen MU1 relation.

The complete derivation is in MANDATORY_UNITS_RELATION_V1.md.  No measured W1
gate count is substituted for a minimum query cost.  Unit work is deliberately
free in the stronger idealized search game.  Initial terminal-oracle advice,
unaccounted public help, and an unbounded output list are not covered.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import comb

from mandatory_units_relation import IDEAL_TICKET_PROBABILITY, MAX_CREDIT


@dataclass(frozen=True)
class QueryBudget:
    full_value_queries: int
    complete_outputs: int
    preprocessing_charged: bool
    public_final_queries_charged: bool
    initial_state: str = "terminal-oracle-independent"


def _integer(value: int, code: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(code)
    return value


def _budget(budget: QueryBudget) -> None:
    if type(budget) is not QueryBudget:
        raise ValueError("QUERY_BUDGET_TYPE")
    _integer(budget.full_value_queries, "FINITE_QUERY_CHECK_LIMIT", 4096)
    _integer(budget.complete_outputs, "FINITE_OUTPUT_CHECK_LIMIT", 64)
    if budget.preprocessing_charged is not True:
        raise ValueError("UNPAID_PREPROCESSING")
    if budget.public_final_queries_charged is not True:
        raise ValueError("UNPAID_PUBLIC_HELP")
    if budget.initial_state != "terminal-oracle-independent":
        raise ValueError("UNQUALIFIED_RESIDUAL_STATE")


def bernoulli_bounds(queries: int, successes: int,
                     p: Fraction = IDEAL_TICKET_PROBABILITY) -> dict[str, Fraction]:
    """Two independently upper-rounded consequences of the same norm proof.

    a[N,i] <= min(1, C(N,i)*(2*sqrt(p*(1-p)))**i).
    Selected-coordinate projection norm is
        sqrt(C(k,i))*p**((k-i)/2)*(1-p)**(i/2).
    The first bound replaces sqrt(C(k,i)) by C(k,i).  The second applies
    Cauchy--Schwarz and retains the saturation a[N,i] <= 1.  Both are exact
    rational upper bounds; their minimum remains a valid upper bound.
    """
    _integer(queries, "FINITE_QUERY_CHECK_LIMIT", 8256)
    _integer(successes, "FINITE_SUCCESS_CHECK_LIMIT", 64)
    if type(p) is not Fraction or not 0 < p < 1:
        raise ValueError("BERNOULLI_PROBABILITY")
    if successes == 0:
        return {"triangle_rational": Fraction(1), "cauchy_saturated": Fraction(1),
                "bound": Fraction(1)}
    k, n = successes, queries
    inner = sum((Fraction(comb(k, i) * comb(n, i)) * (2 * (1 - p)) ** i
                 for i in range(min(k, n) + 1)), Fraction(0))
    triangle = min(Fraction(1), p ** k * inner ** 2)
    cauchy = min(Fraction(1), (k + 1) * sum((
        Fraction(comb(k, i)) * p ** (k - i) * (1 - p) ** i
        * min(Fraction(1), Fraction(comb(n, i) ** 2) * (4 * p * (1 - p)) ** i)
        for i in range(min(k, n) + 1)
    ), Fraction(0)))
    return {"triangle_rational": triangle, "cauchy_saturated": cauchy,
            "bound": min(triangle, cauchy)}


def residual_bernoulli_bound(queries: int, successes: int,
                             initial_tail_squared: tuple[Fraction, ...],
                             p: Fraction = IDEAL_TICKET_PROBABILITY) -> dict[str, object]:
    """Conditional arithmetic for an externally proved JOINT record-tail law.

    Input b[i] must upper-bound ||P_{>=i} psi_initial||**2, including the
    inaccessible oracle reference, all helpers, and retained quantum advice.
    These checks only validate the profile's numeric shape; they DO NOT prove
    that it describes an actual initial state.  A private reduced density
    matrix, observed remaining unit count, or budget flag is not this proof.

    The norm recurrence gives a[N,i] <= sum_j C(N,j)*c**j*a[0,i-j].
    Cauchy over only the nonzero summands gives an exact rational upper bound
    on its square.  With b=(1,0,...) this recovers cauchy_saturated above;
    with b=(1,1,...) the bound is one.  No fresh-game budget is silently reset.
    """
    _integer(queries, "FINITE_QUERY_CHECK_LIMIT", 8256)
    _integer(successes, "FINITE_SUCCESS_CHECK_LIMIT", 64)
    if type(p) is not Fraction or not 0 < p < 1:
        raise ValueError("BERNOULLI_PROBABILITY")
    if (type(initial_tail_squared) is not tuple
            or len(initial_tail_squared) != successes + 1
            or any(type(b) is not Fraction or not 0 <= b <= 1
                   for b in initial_tail_squared)
            or initial_tail_squared[0] != 1
            or any(left < right for left, right in
                   zip(initial_tail_squared, initial_tail_squared[1:]))):
        raise ValueError("JOINT_RECORD_TAIL_PROFILE")
    n, k = queries, successes
    propagated = []
    for i in range(k + 1):
        terms = [Fraction(comb(n, j) ** 2) * (4 * p * (1 - p)) ** j
                 * initial_tail_squared[i - j]
                 for j in range(min(n, i) + 1)
                 if initial_tail_squared[i - j] > 0]
        propagated.append(min(Fraction(1), len(terms) * sum(terms, Fraction(0))))
    value = min(Fraction(1), (k + 1) * sum((
        Fraction(comb(k, i)) * p ** (k - i) * (1 - p) ** i * propagated[i]
        for i in range(k + 1)
    ), Fraction(0)))
    return {
        "model": "conditional-joint-record-tail-arithmetic-v1",
        "queries_N": n,
        "distinct_outputs_k": k,
        "initial_joint_tail_squared": initial_tail_squared,
        "propagated_joint_tail_squared_upper": tuple(propagated),
        "bound": value,
        "input_tail_certificate_proved_by_this_function": False,
        "actual_w1_residual_state_certificate": False,
        "physical_resource_bound": False,
        "native_confirmation_risk": False,
    }


def quantum_weight_bound(budget: QueryBudget, credit: int) -> dict[str, object]:
    """Global fresh-game bound under the explicitly stated idealization.

    Distinct MU1 credit identities imply distinct final-lottery inputs.  All
    unit validation is free to the adversary.  A full-value random-oracle query
    is simulated with at most two Bernoulli-bit queries, using independent
    conditional-output tables.  At most M virtual membership checks select the
    successful outputs, so N=2Q+M.  The extra checks are not claimed to be paid
    by the attacker's CPU; M is a separate declared complete-output cap.
    """
    _budget(budget)
    _integer(credit, "CREDIT_THRESHOLD", (1 << 64) - 1)
    k = (credit + MAX_CREDIT - 1) // MAX_CREDIT
    n = 2 * budget.full_value_queries + budget.complete_outputs
    if k > budget.complete_outputs:
        components = {"triangle_rational": Fraction(0),
                      "cauchy_saturated": Fraction(0), "bound": Fraction(0)}
    else:
        components = bernoulli_bounds(n, k)
    return {
        "model": "mu1-ideal-terminal-oracle-global-budget-v1",
        "p": IDEAL_TICKET_PROBABILITY,
        "maximum_identity_credit": MAX_CREDIT,
        "full_value_queries_Q": budget.full_value_queries,
        "complete_outputs_M": budget.complete_outputs,
        "simulated_bit_queries_N": n,
        "required_distinct_successes_k": k,
        "credit_threshold": credit,
        **components,
        "actual_sha_qrom_reduction_proved": False,
        "attacker_only_online_query_budget": False,
        "mandatory_u_minimum_gate_cost_proved": False,
        "physical_resource_bound": False,
        "native_confirmation_risk": False,
    }


def classical_weight_bound(budget: QueryBudget, credit: int) -> Fraction:
    """Sharper exact classical-only envelope; invalid for coherent queries.

    Each previously unseen full-output query or final virtual check is an
    independent Bernoulli trial in the stated ideal model.  Repeated inputs
    cannot add unique credit.  All pre/post-selection computations may be free.
    """
    _budget(budget)
    _integer(credit, "CREDIT_THRESHOLD", (1 << 64) - 1)
    k = (credit + MAX_CREDIT - 1) // MAX_CREDIT
    if k == 0:
        return Fraction(1)
    if k > budget.complete_outputs:
        return Fraction(0)
    n, p = budget.full_value_queries + budget.complete_outputs, IDEAL_TICKET_PROBABILITY
    return sum((Fraction(comb(n, j)) * p ** j * (1 - p) ** (n - j)
                for j in range(k, n + 1)), Fraction(0))
