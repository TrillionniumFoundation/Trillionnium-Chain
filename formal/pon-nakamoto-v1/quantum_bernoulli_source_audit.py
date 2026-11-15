"""Exact source-bound regression audit for the frozen p=1/16 Bernoulli model.

The printed expression from arXiv:2012.15254v4 is evaluated as algebra only.
A finite three-partition Grover strategy exceeds that printed expression.
Consequently this module never issues a chain-security probability certificate.
The repository's separate conservative recording proof remains independent.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from math import comb, gcd
import json

DENSITY = Fraction(1, 16)
MAX_QUERIES = 8256
MAX_OUTPUTS = 64


def _integer(value: int, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(code)
    return value


@dataclass(frozen=True)
class Quadratic15:
    """Nonnegative (a + b*sqrt(15))/d; every decision uses integers."""
    a: int
    b: int
    d: int

    def __post_init__(self) -> None:
        if (any(type(x) is not int for x in (self.a, self.b, self.d))
                or min(self.a, self.b) < 0 or self.d <= 0):
            raise ValueError("QUADRATIC15")
        common = gcd(gcd(self.a, self.b), self.d)
        object.__setattr__(self, "a", self.a // common)
        object.__setattr__(self, "b", self.b // common)
        object.__setattr__(self, "d", self.d // common)

    def strictly_below(self, threshold: Fraction) -> bool:
        """Decide an exact strict comparison, including zero/equality."""
        if type(threshold) is not Fraction or threshold < 0:
            raise ValueError("NONNEGATIVE_RATIONAL_THRESHOLD")
        delta = threshold.numerator * self.d - threshold.denominator * self.a
        radical_coefficient = threshold.denominator * self.b
        return delta > 0 and delta * delta > 15 * radical_coefficient ** 2

    def as_record(self) -> dict[str, object]:
        with localcontext() as context:
            context.prec = 40
            display = ((Decimal(self.a) + Decimal(self.b) * Decimal(15).sqrt())
                       / Decimal(self.d))
        return {"a": str(self.a), "b": str(self.b), "d": str(self.d),
                "radicand": 15, "decimal_display_only": str(display),
                "strictly_below_one_exact": self.strictly_below(Fraction(1))}


def _printed_sum(queries: int, outputs: int) -> Quadratic15:
    _integer(queries, 1, MAX_QUERIES, "PRINTED_QUERY_RANGE")
    _integer(outputs, 1, min(MAX_OUTPUTS, queries), "PRINTED_OUTPUT_RANGE")
    # Sum_i C(queries,i)*(sqrt(15)/4)^i = (A+B*sqrt(15))/4**outputs.
    a_sum = b_sum = 0
    for i in range(outputs + 1):
        coefficient = comb(queries, i) * 15 ** (i // 2) * 4 ** (outputs - i)
        if i % 2:
            b_sum += coefficient
        else:
            a_sum += coefficient
    return Quadratic15(
        15 * (a_sum * a_sum + 15 * b_sum * b_sum),
        30 * a_sum * b_sum,
        4 * 256 ** outputs,
    )


def printed_bernoulli_expression(queries: int, outputs: int) -> Quadratic15:
    """The printed finite sum, NOT an established probability upper bound."""
    return _printed_sum(queries, outputs)


def printed_chain_expression(chain_queries: int, outputs: int) -> Quadratic15:
    """Algebraic N+k substitution; does not certify its source or reduction."""
    _integer(chain_queries, 1, 4096, "CHAIN_QUERY_RANGE")
    _integer(outputs, 1, min(MAX_OUTPUTS, chain_queries), "CHAIN_OUTPUT_RANGE")
    return _printed_sum(chain_queries + outputs, outputs)


def printed_diagonal_geometric_expression(n: int) -> Quadratic15:
    """(15/4)*((1921+496*sqrt(15))/4096)**n, algebra only."""
    _integer(n, 1, MAX_OUTPUTS, "FINITE_DIAGONAL_RANGE")
    a, b = 1, 0
    for _ in range(n):
        a, b = 1921 * a + 15 * 496 * b, 496 * a + 1921 * b
    return Quadratic15(15 * a, 15 * b, 4 * 4096 ** n)


def one_grover_partition_success(size: int = 16,
                                 density: Fraction = DENSITY) -> Fraction:
    """Exact average of one-query Grover success over iid marked bits.

    Conditional on j marked addresses, success is
    (j/size)*(3-4*j/size)**2. The query is a Boolean phase-oracle query.
    No query is used to verify the final measured output in this search game.
    """
    _integer(size, 1, 256, "FINITE_PARTITION_SIZE")
    if type(density) is not Fraction or not 0 <= density <= 1:
        raise ValueError("BERNOULLI_DENSITY")
    answer = Fraction(0)
    for j in range(size + 1):
        mass = comb(size, j) * density ** j * (1 - density) ** (size - j)
        marked_fraction = Fraction(j, size)
        answer += mass * marked_fraction * (3 - 4 * marked_fraction) ** 2
    return answer


def _fraction_record(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def source_counterexample() -> dict[str, object]:
    """Three disjoint 16-address partitions inside a 64-address domain."""
    one = one_grover_partition_success()
    success = one ** 3
    printed = printed_bernoulli_expression(3, 3)
    delta = success.numerator * printed.d - success.denominator * printed.a
    radical = success.denominator * printed.b
    return {
        "oracle": "Boolean Bernoulli phase oracle",
        "domain_size": 64,
        "disjoint_partitions": 3,
        "partition_size": 16,
        "phase_queries": 3,
        "distinct_outputs_required": 3,
        "density": _fraction_record(DENSITY),
        "one_partition_success": _fraction_record(one),
        "three_partition_success": _fraction_record(success),
        "printed_bernoulli_expression": printed.as_record(),
        "success_strictly_exceeds_printed_expression_exact":
            printed.strictly_below(success),
        "comparison_delta_positive": delta > 0,
        "comparison_squared_gap": str(delta * delta - 15 * radical * radical),
        "full_value_chain_attack_demonstrated": False,
        "actual_w1_attack_demonstrated": False,
    }


def audit_report(chain_queries: int = 21, outputs: int = 21) -> dict[str, object]:
    printed = printed_chain_expression(chain_queries, outputs)
    witness = source_counterexample()
    # This result remains a rejection even when an algebraic expression is <1.
    return {
        "schema": "quantum-bernoulli-source-audit-v1",
        "status": "REJECT_PRINTED_SOURCE_BOUND",
        "source": "https://arxiv.org/html/2012.15254v4",
        "printed_chain_queries_N": chain_queries,
        "printed_chain_outputs_k": outputs,
        "printed_reduction_argument_N_plus_k": chain_queries + outputs,
        "printed_chain_expression_only": printed.as_record(),
        "counterexample": witness,
        "source_bound_usable": False,
        "printed_expression_is_probability_certificate": False,
        "no_uncharged_advice_established": False,
        "independent_joint_initial_state_established": False,
        "actual_w1_cost_lower_bound": False,
        "native_consensus_security_certified": False,
        "production_qualified": False,
        "existing_conservative_proof":
            "MANDATORY_UNITS_RELATION_V1.md sections 6-7; mandatory_units_query.py",
    }


def certified_chain_tail(*_args: object, **_kwargs: object) -> None:
    """Fail closed if an integration tries to consume the rejected source."""
    raise ValueError("PRINTED_SOURCE_BOUND_REJECTED")


if __name__ == "__main__":
    print(json.dumps(audit_report(), indent=2, sort_keys=True))
