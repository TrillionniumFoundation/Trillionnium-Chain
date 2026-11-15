#!/usr/bin/env python3
"""Bounded exact arithmetic for one conditional query-error expression.

Solve A * alpha**ell <= 2**(-s), with alpha and A explicitly supplied as
Fractions. This does not establish alpha, the multiplier, a theorem mapping,
an extractor, any other error term, or any project security claim.

The default CLI report reconstructs the external P3 profile's fixed m=1000
query expression and six hypothetical multipliers. An optional custom case
requires both --alpha N/D and --assumed-multiplier N/D. Decimal floats,
implicit profile transfer, and unbounded exact-integer searches are refused.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
import math
import re
import sys


OUTPUT_SCHEMA = 'TRNM-W1-QUERY-EXPRESSION-FEASIBILITY1'
P3_REVISION = 'cc836dfc13ef0006eb0878abd8cb5eca9a76bec0'
P3_ESTIMATOR_REVISION = 'a21e3ed42905040ad49c519e402f018381c12d0c'
P3_ALPHA_AT_M1000 = Fraction(2001, 4000)
HYPOTHETICAL_MULTIPLIER_EXPONENTS = (0, 16, 32, 64, 128, 256)

# Evaluator resource limits, not cryptographic parameter limits. The bound on
# each comparison operand is checked before any integer exponentiation.
MAX_INPUT_INTEGER_BITS = 1024
MAX_FRACTION_TEXT_LENGTH = 640
MAX_TARGET_BITS = 4096
MAX_QUERIES = 16384
MAX_COMPARISON_BITS = 262144


class QueryExpressionRefusal(ValueError):
    """A structured input/resource refusal, never a protocol verdict."""

    def __init__(self, code: str, field: str, reason: str, **details):
        super().__init__(f'{field}: {reason}')
        self.code = code
        self.field = field
        self.reason = reason
        self.details = details

    def as_dict(self):
        return {'code': self.code, 'field': self.field, 'reason': self.reason,
                'details': self.details}


def _integer(value, field, maximum):
    if type(value) is not int or value < 0:
        raise QueryExpressionRefusal(
            'INVALID_INPUT', field, 'expected a nonnegative int, not bool/float')
    if value > maximum:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', field, 'integer exceeds evaluator limit',
            maximum=maximum)
    return value


def _fraction(value, field):
    if type(value) is not Fraction:
        raise QueryExpressionRefusal(
            'INVALID_INPUT', field, 'an explicit Fraction is required')
    if max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > \
            MAX_INPUT_INTEGER_BITS:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', field, 'fraction component exceeds evaluator bit limit',
            maximum_integer_bits=MAX_INPUT_INTEGER_BITS)
    return value


def _alpha(value):
    value = _fraction(value, 'alpha')
    if not 0 < value < 1:
        raise QueryExpressionRefusal('INVALID_INPUT', 'alpha', 'must lie in (0, 1)')
    return value


def _multiplier(value):
    value = _fraction(value, 'multiplier')
    if value < 1:
        raise QueryExpressionRefusal(
            'INVALID_INPUT', 'multiplier', 'must be at least one')
    return value


def _query_limit(alpha, multiplier, target_bits):
    """Conservative pre-power bit bound for both cross-product operands."""
    left_room = (MAX_COMPARISON_BITS - target_bits
                 - multiplier.numerator.bit_length())
    right_room = MAX_COMPARISON_BITS - multiplier.denominator.bit_length()
    return max(0, min(MAX_QUERIES,
                      left_room // alpha.numerator.bit_length(),
                      right_room // alpha.denominator.bit_length()))


def query_term(queries: int, *, alpha: Fraction) -> Fraction:
    """Return alpha**queries exactly, within the evaluator's finite limits."""
    queries = _integer(queries, 'queries', MAX_QUERIES)
    alpha = _alpha(alpha)
    allowed = _query_limit(alpha, Fraction(1), 0)
    if queries > allowed:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', 'queries', 'exact power exceeds operand bit limit',
            maximum_queries_for_inputs=allowed,
            maximum_comparison_bits=MAX_COMPARISON_BITS)
    return Fraction(pow(alpha.numerator, queries), pow(alpha.denominator, queries))


def minimum_queries(target_bits: int, multiplier: Fraction, *, alpha: Fraction) -> int:
    """Least ell with A*alpha**ell <= 2**(-target_bits), by exact comparison.

    A returned ell is sufficient only for this single contribution. If a
    nonnegative sum or maximum contains it, this is a necessary condition for
    that expression to meet the target. No theorem supplies A or alpha here.

    Search and power sizes have hard limits. A resource refusal means that
    this evaluator did not return a result; it does not assert that no finite
    mathematical solution exists. No floating-point value decides a bound.
    """
    target_bits = _integer(target_bits, 'target_bits', MAX_TARGET_BITS)
    multiplier = _multiplier(multiplier)
    alpha = _alpha(alpha)
    threshold = Fraction(1, 1 << target_bits)
    if multiplier <= threshold:
        return 0

    maximum = _query_limit(alpha, multiplier, target_bits)
    # Bernoulli: (1-d)**ell >= 1-ell*d. If this lower expression is
    # already too large at the greatest affordable ell, every smaller ell
    # fails too. This catches alpha extremely close to one before any pow.
    lower_at_maximum = multiplier * (1 - maximum * (1 - alpha))
    if maximum == 0 or lower_at_maximum > threshold:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', 'query_search',
            'Bernoulli bound excludes a solution inside the evaluator budget',
            maximum_queries_for_inputs=maximum,
            maximum_comparison_bits=MAX_COMPARISON_BITS)

    def feasible(queries):
        # queries <= maximum ensures each operand stays within the bit cap.
        left = (multiplier.numerator * pow(alpha.numerator, queries)) << target_bits
        right = multiplier.denominator * pow(alpha.denominator, queries)
        return left <= right

    low, high = 0, 1
    while not feasible(high):
        low = high
        if high == maximum:
            raise QueryExpressionRefusal(
                'RESOURCE_LIMIT', 'query_search',
                'no result within the finite query and exact-power limits',
                maximum_queries_for_inputs=maximum,
                maximum_comparison_bits=MAX_COMPARISON_BITS)
        high = min(2 * high, maximum)
    while high - low > 1:
        mid = (low + high) // 2
        if feasible(mid):
            high = mid
        else:
            low = mid
    return high


def johnson_strict_necessary_queries(target_bits: int, amplifier_bits: int) -> int:
    """Necessary ell for rate 1/4, alpha>1/2 and A=2**amplifier_bits.

    For ell>0, A*alpha**ell > 2**(amplifier_bits-ell); hence the target
    requires ell >= target_bits+amplifier_bits+1. This is not sufficient for
    an unspecified alpha. The trivial target_bits=amplifier_bits=0 admits ell=0.
    """
    target_bits = _integer(target_bits, 'target_bits', MAX_TARGET_BITS)
    amplifier_bits = _integer(amplifier_bits, 'amplifier_bits', MAX_TARGET_BITS)
    return 0 if target_bits == amplifier_bits == 0 else target_bits + amplifier_bits + 1


def _ratio(value):
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def qualification():
    return {
        'end_to_end_qualified': False,
        'noninteractive_qualified': False,
        'quantum_qualified': False,
        'recursive_qualified': False,
        'lifecycle_qualified': False,
        'pq128_qualified': False,
        'theorem_6_10_mapping_qualified': False,
        'theorem_11_3_mapping_qualified': False,
        'unconditional_project_security_bits': None,
        'complete_noninteractive_security_bits': None,
        'quantum_security_bits': None,
        'recursive_security_bits': None,
        'lifecycle_security_bits': None,
    }


def make_report(target_bits=128, *, assumed_alpha=None, assumed_multiplier=None):
    target_bits = _integer(target_bits, 'target_bits', MAX_TARGET_BITS)
    if (assumed_alpha is None) != (assumed_multiplier is None):
        raise QueryExpressionRefusal(
            'INVALID_INPUT', 'hypothetical_case',
            'supply both an explicit alpha and an explicit assumed multiplier')
    rows = []
    for exponent in HYPOTHETICAL_MULTIPLIER_EXPONENTS:
        multiplier = Fraction(1 << exponent)
        rows.append({
            'hypothetical_multiplier_power_of_two_exponent': exponent,
            'hypothetical_multiplier': _ratio(multiplier),
            'least_queries_for_this_expression': minimum_queries(
                target_bits, multiplier, alpha=P3_ALPHA_AT_M1000),
            'strict_johnson_necessary_queries_only': johnson_strict_necessary_queries(
                target_bits, exponent),
        })
    custom = None
    if assumed_alpha is not None:
        custom = {
            'scope': 'user-supplied hypothetical expression; no protocol or theorem mapping',
            'alpha': _ratio(_alpha(assumed_alpha)),
            'assumed_multiplier': _ratio(_multiplier(assumed_multiplier)),
            'least_queries_for_this_expression': minimum_queries(
                target_bits, assumed_multiplier, alpha=assumed_alpha),
        }
    return {
        'schema': OUTPUT_SCHEMA,
        'status': 'arithmetic_only',
        'scope': 'one conditional query expression, not actual failure or attack cost',
        'formula': 'A * alpha^ell <= 2^(-s)',
        'target_expression_exponent_s': target_bits,
        'profile': {
            'identity': 'external-p3-research-cc836dfc13ef',
            'application_revision': P3_REVISION,
            'p3_version': '0.8.0',
            'estimator_source_revision': P3_ESTIMATOR_REVISION,
            'p3_security_archive_independently_verified': False,
            'base_field': 'Goldilocks',
            'extension_degree': 2,
            'inverse_rate': 4,
            'folding_factor': 2,
            'terminal_extension_coefficients': 1,
            'queries': 64,
            'query_pow': 0,
            'fixed_ldr_m': 1000,
            'alpha': _ratio(P3_ALPHA_AT_M1000),
            'risc0_parameter_transfer_qualified': False,
        },
        'fixed_p3_query_expression': {
            'formula': '(2001/4000)^64',
            'exact_value': _ratio(query_term(64, alpha=P3_ALPHA_AT_M1000)),
            'negative_log2_expression_approx': -64 * math.log2(float(P3_ALPHA_AT_M1000)),
            'floating_point_used_for_decisions': False,
        },
        'multiplier_provenance': 'explicit hypothetical factors; not adopted theorem/lifetime budgets',
        'p3_fixed_m_hypothetical_rows': rows,
        'strict_johnson_condition': {
            'premises': 'rho=1/4; alpha>1/2; A=2^a; s,a nonnegative integers',
            'inequality_for_positive_queries': 'A*alpha^ell > 2^(a-ell)',
            'necessary_queries_for_nontrivial_target': 'ell >= s+a+1',
            'trivial_s_and_a_zero_queries': 0,
            'sufficient_for_unspecified_alpha': False,
            'risc0_radix16_theorem_mapping_qualified': False,
        },
        'hypothetical_case': custom,
        'resource_limits': {
            'maximum_input_integer_bits': MAX_INPUT_INTEGER_BITS,
            'maximum_target_exponent': MAX_TARGET_BITS,
            'maximum_queries': MAX_QUERIES,
            'maximum_comparison_operand_bits': MAX_COMPARISON_BITS,
            'kind': 'evaluator bounds; refusal is not a cryptographic result',
        },
        'qualification': qualification(),
    }


def _parse_fraction(text, field):
    if len(text) > MAX_FRACTION_TEXT_LENGTH:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', field, 'fraction text exceeds evaluator length limit',
            maximum_characters=MAX_FRACTION_TEXT_LENGTH)
    if not re.fullmatch(r'(0|[1-9][0-9]*)(/(0|[1-9][0-9]*))?', text):
        raise QueryExpressionRefusal(
            'INVALID_INPUT', field, 'use a canonical integer or numerator/denominator')
    parts = text.split('/')
    numerator, denominator = int(parts[0]), int(parts[1]) if len(parts) == 2 else 1
    if denominator == 0:
        raise QueryExpressionRefusal('INVALID_INPUT', field, 'zero denominator')
    # Check before Fraction normalization so huge reducible components do not
    # bypass the textual-input size policy.
    if max(numerator.bit_length(), denominator.bit_length()) > MAX_INPUT_INTEGER_BITS:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', field, 'fraction component exceeds evaluator bit limit',
            maximum_integer_bits=MAX_INPUT_INTEGER_BITS)
    return Fraction(numerator, denominator)


def _parse_target(text):
    if len(text) > 4:
        raise QueryExpressionRefusal(
            'RESOURCE_LIMIT', 'target_bits', 'target text exceeds evaluator range')
    if not re.fullmatch(r'0|[1-9][0-9]*', text):
        raise QueryExpressionRefusal('INVALID_INPUT', 'target_bits', 'use a canonical integer')
    return _integer(int(text), 'target_bits', MAX_TARGET_BITS)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise QueryExpressionRefusal('INVALID_INPUT', 'arguments', message)


class _UniqueOption(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, '_explicit_numerical_options', set())
        if self.dest in seen:
            raise QueryExpressionRefusal(
                'INVALID_INPUT', self.dest, 'repeated numerical option is ambiguous')
        seen.add(self.dest)
        namespace._explicit_numerical_options = seen
        setattr(namespace, self.dest, values)


def main(argv=None):
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--target-bits', default='128', metavar='S', action=_UniqueOption,
                        help='target exponent for this expression only (default: 128)')
    parser.add_argument('--alpha', metavar='N/D', action=_UniqueOption,
                        help='explicit rational for an additional hypothetical case')
    parser.add_argument('--assumed-multiplier', metavar='N/D', action=_UniqueOption,
                        help='explicit hypothetical factor; requires --alpha')
    try:
        args = parser.parse_args(argv)
        report = make_report(
            _parse_target(args.target_bits),
            assumed_alpha=None if args.alpha is None else _parse_fraction(args.alpha, 'alpha'),
            assumed_multiplier=(None if args.assumed_multiplier is None else
                                _parse_fraction(args.assumed_multiplier, 'multiplier')))
    except QueryExpressionRefusal as error:
        report = {'schema': OUTPUT_SCHEMA, 'status': 'refused',
                  'error': error.as_dict(), 'qualification': qualification()}
        print(json.dumps(report, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
