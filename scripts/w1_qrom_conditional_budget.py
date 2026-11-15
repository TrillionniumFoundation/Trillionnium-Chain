#!/usr/bin/env python3
"""Exact, hypothetical component arithmetic from CDHZ's 2026-01-01 manuscript.

This evaluates the RHS of Theorem 6.10 and the four named Theorem 8.3
components. It does NOT implement Theorem 11.3, its maximization and query
overheads, Theorem 10.6 composition, or an implementation-to-QROM reduction.
Every project qualification remains false and every project bit count null.

Usage:
    python scripts/w1_qrom_conditional_budget.py             # unknown inputs
    python scripts/w1_qrom_conditional_budget.py --example   # hypothetical only
    python scripts/w1_qrom_conditional_budget.py --example-input
    python scripts/w1_qrom_conditional_budget.py --input scenario.json

Use --input - for stdin. Omitted numerical fields and JSON null remain unknown;
no default substitutes a classical estimate, a stored digest width, or w=t.
Integers may be JSON integers or canonical decimal strings. Fractions are
objects with exactly numerator and denominator, each an integer. Floats and
booleans are rejected. The evaluator's finite size limits are resource limits,
not cryptographic limits. Merkle lengths must already be powers of two: it
does not silently pad a profile or alter a commitment encoding.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import sys


INPUT_SCHEMA = 'TRNM-W1-QROM-CONDITIONAL-INPUT1'
OUTPUT_SCHEMA = 'TRNM-W1-QROM-CONDITIONAL-COMPONENTS1'
MAX_INPUT_BYTES = 65536
MAX_INTEGER_BITS = 2048
MAX_EXPONENT = 4096
PQSR_FIELDS = {'t', 'k', 'w', 'r_min', 'kappa_rrbr', 'target_error'}
MERKLE_FIELDS = {'t', 'k', 'w_vc', 'sigma', 'ell_max', 'n', 'q_s', 'target_error'}


class BudgetError(ValueError):
    """Invalid or unsupported hypothetical input; never a security verdict."""


def integer(value, name, minimum=0, maximum=None):
    if value is None:
        return None
    if type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value):
        if len(value) > 617:  # ceil(log10(2**MAX_INTEGER_BITS))
            raise BudgetError(f'{name}: integer exceeds evaluator size limit')
        value = int(value)
    if type(value) is not int:
        raise BudgetError(f'{name}: expected an exact integer, not bool/float')
    if value < minimum or (maximum is not None and value > maximum):
        raise BudgetError(f'{name}: outside supported range')
    if value.bit_length() > MAX_INTEGER_BITS:
        raise BudgetError(f'{name}: integer exceeds evaluator size limit')
    return value


def rational(value, name, *, probability=False, positive=False):
    if value is None:
        return None
    if type(value) is dict:
        if set(value) != {'numerator', 'denominator'}:
            raise BudgetError(f'{name}: fraction needs numerator and denominator only')
        numerator = integer(value['numerator'], name + '.numerator')
        denominator = integer(value['denominator'], name + '.denominator', 1)
        if numerator is None or denominator is None:
            raise BudgetError(f'{name}: use null for an unknown whole fraction')
        result = Fraction(numerator, denominator)
    else:
        result = Fraction(integer(value, name))
    if positive and result <= 0:
        raise BudgetError(f'{name}: must be positive')
    if probability and result > 1:
        raise BudgetError(f'{name}: probability must not exceed one')
    return result


def fields(value, allowed, name):
    if value is None:
        return dict.fromkeys(sorted(allowed))
    if type(value) is not dict:
        raise BudgetError(f'{name}: expected an object or null')
    extra = set(value) - allowed
    if extra:
        raise BudgetError(f'{name}: unknown fields: {sorted(extra)}')
    return {key: value.get(key) for key in sorted(allowed)}


def mass_bound(mass, queries, name):
    if mass is not None and queries is not None and mass > queries:
        raise BudgetError(f'{name}: total query mass must not exceed t')


def normalize(raw):
    if type(raw) is not dict:
        raise BudgetError('input: expected an object')
    allowed = {'schema', 'input_kind', 'pqsr', 'merkle'}
    if set(raw) - allowed:
        raise BudgetError(f'input: unknown fields: {sorted(set(raw) - allowed)}')
    if raw.get('schema') != INPUT_SCHEMA:
        raise BudgetError('input: unsupported schema')
    if raw.get('input_kind') != 'hypothetical':
        raise BudgetError('input_kind must be hypothetical; project certification is unsupported')
    pqsr = fields(raw.get('pqsr'), PQSR_FIELDS, 'pqsr')
    merkle = fields(raw.get('merkle'), MERKLE_FIELDS, 'merkle')
    for name, values in (('pqsr', pqsr), ('merkle', merkle)):
        for key in ('t', 'k'):
            values[key] = integer(values[key], name + '.' + key, int(key == 'k'))
        values['target_error'] = rational(values['target_error'], name + '.target_error',
                                           probability=True, positive=True)
    pqsr['w'] = rational(pqsr['w'], 'pqsr.w')
    pqsr['r_min'] = integer(pqsr['r_min'], 'pqsr.r_min', 1, MAX_EXPONENT)
    pqsr['kappa_rrbr'] = rational(pqsr['kappa_rrbr'], 'pqsr.kappa_rrbr', probability=True)
    mass_bound(pqsr['w'], pqsr['t'], 'pqsr.w')
    merkle['w_vc'] = rational(merkle['w_vc'], 'merkle.w_vc')
    mass_bound(merkle['w_vc'], merkle['t'], 'merkle.w_vc')
    merkle['sigma'] = integer(merkle['sigma'], 'merkle.sigma', 1, MAX_EXPONENT)
    merkle['ell_max'] = integer(merkle['ell_max'], 'merkle.ell_max', 1)
    for key in ('n', 'q_s'):
        merkle[key] = integer(merkle[key], 'merkle.' + key)
    length, count = merkle['ell_max'], merkle['k']
    if length is not None and length & (length - 1):
        raise BudgetError('merkle.ell_max: supply the actual power-of-two padded length')
    if count is not None and merkle['n'] is not None and merkle['n'] > count:
        raise BudgetError('merkle.n: checked subset size must not exceed k')
    if count is not None and length is not None and merkle['q_s'] is not None:
        if merkle['q_s'] > count * length:
            raise BudgetError('merkle.q_s: total query-set size must not exceed k * ell_max')
    return pqsr, merkle


def known(expression, *values):
    """Unknown factors remain unknown, including products with a known zero."""
    return None if any(value is None for value in values) else expression(*values)


def pqsr_component(values):
    t, k, w = (values[key] for key in ('t', 'k', 'w'))
    coefficient = known(lambda a, b, c: 80 * (a + b + 1) * (c + b), t, k, w)
    finite = known(lambda a, b, r: Fraction((a + b + 1) * b, 1 << r),
                   t, k, values['r_min'])
    rrbr = known(lambda a, b: a * b, coefficient, values['kappa_rrbr'])
    total = known(lambda a, b: a + b, rrbr, finite)
    target = values['target_error']
    feasible = known(lambda a, b: a <= b, finite, target)
    required = None
    if feasible is True and coefficient is not None:
        required = min(Fraction(1), (target - finite) / coefficient)
    return {
        'theorem': '2026-01-01 manuscript, Theorem 6.10, page 46',
        'rrbr_coefficient': coefficient,
        'finite_randomness_addend': finite,
        'rrbr_addend': rrbr,
        'conditional_upper_expression': total,
        'conditional_expression_meets_target': known(lambda a, b: a <= b, total, target),
        'target_analysis': {
            'finite_randomness_addend_exceeds_target': known(lambda a, b: a > b, finite, target),
            'some_nonnegative_rrbr_bound_can_meet_target_by_this_expression': feasible,
            'kappa_rrbr_required_at_most': required,
        },
        'unknown_inputs': [key for key, value in values.items() if value is None],
        'boundary': 'The finite addend is a floor of this upper expression, not an attack lower bound. '
                    'kappa_rrbr must bound relaxed round-by-round knowledge error over the entire '
                    'allowed statement set; no implementation bound is supplied or inferred.',
    }


def merkle_components(values):
    t, w, sigma, length, n, q_s = (values[key] for key in
                                  ('t', 'w_vc', 'sigma', 'ell_max', 'n', 'q_s'))
    denominator = known(lambda bits: 1 << bits, sigma)
    components = {
        'commutativity': known(lambda a, d: Fraction(240 * (a + 1), d), t, denominator),
        'extraction_correctness': known(lambda a, b, d: Fraction(8 * a * b, d),
                                       n, length, denominator),
        'offline_extractability': known(
            lambda a, b, c, ell, d: (160 * b * a * a + 16 * c * (ell.bit_length() - 1)) / d,
            t, w, q_s, length, denominator),
        'online_indistinguishability': known(lambda a, b, d: 240 * b * a * a / d,
                                            t, w, denominator),
    }
    return {
        'theorem': '2026-01-01 manuscript, Theorem 8.3, page 53',
        'conditional_expressions': components,
        'each_expression_meets_component_target': {
            key: known(lambda a, b: a <= b, value, values['target_error'])
            for key, value in components.items()
        },
        'unknown_inputs': [key for key, value in values.items() if value is None],
        'boundary': 'Separate named errors, not a combined proof failure probability. '
                    'w_vc is the mass on commitment oracles. No positional substitution into '
                    'Theorem 11.3 is made; the indexed January signatures need reconciliation. '
                    'sigma denotes an ideal oracle output width, not stored digest bytes.',
    }


def qualification():
    return {
        'unconditional_project_security_bits': None,
        'quantum_security_bits': None,
        'full_recursive_security_bits': None,
        'qrom_theorem_instantiated': False,
        'post_quantum_soundness_qualified': False,
        'whole_recursive_proof_soundness_qualified': False,
        'complete_w1_attack_established': False,
        'production_qualified': False,
        'consensus_admission': False,
    }


def serializable(value):
    if isinstance(value, Fraction):
        return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}
    if type(value) is int:
        return str(value)  # preserve large integers through JSON consumers
    if type(value) is dict:
        return {key: serializable(item) for key, item in value.items()}
    if type(value) is list:
        return [serializable(item) for item in value]
    return value


def make_report(raw):
    pqsr, merkle = normalize(raw)
    return serializable({
        'schema': OUTPUT_SCHEMA,
        'status': 'hypothetical_component_arithmetic_only',
        'source': {
            'paper': 'https://eprint.iacr.org/2025/2166',
            'indexed_copy': 'https://files01.core.ac.uk/download/690750245.pdf',
            'indexed_manuscript_date': '2026-01-01',
            'latest_revision_date_observed_in_metadata': '2026-03-02',
            'latest_revision_full_text_equivalence_verified': False,
            'scope': 'Selected indexed formal theorem statements; not a whole-manuscript proof audit.',
        },
        'inputs': {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
                   'pqsr': pqsr, 'merkle': merkle},
        'pqsr_component': pqsr_component(pqsr),
        'merkle_components': merkle_components(merkle),
        'theorem_11_3_full_bound': None,
        'theorem_10_6_composed_bound': None,
        'qualification': qualification(),
        'unresolved_obligations': [
            'Match the entire implemented IOR and statement set to relaxed RBR knowledge soundness.',
            'Match concrete hash/transcript/Merkle encodings to the stipulated quantum oracle model.',
            'Theorem 11.3 needs a monotone output relation, committed-relation decider costs, '
            'mass maximization, shifted query budgets, factors 4/4/8/4 and a commutator term.',
            'Theorem 10.6 needs compatible relations and the same emulated oracle, two doubled '
            'extraction terms at enlarged query budgets, and a commutator cross-term.',
            'Resolve indexed January parameter-signature differences against an authoritative revision.',
            'Account for all permitted recursive programs and lifetime adversarial quantum queries.',
        ],
    })


def example_input():
    """Chosen illustrative numbers; none are sourced from the locked W1 profile."""
    return {
        'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
        'pqsr': {'t': 1 << 64, 'k': 16, 'w': 1 << 64, 'r_min': 384,
                 'kappa_rrbr': {'numerator': 1, 'denominator': 1 << 320},
                 'target_error': {'numerator': 1, 'denominator': 1 << 128}},
        'merkle': {'t': 1 << 64, 'k': 16, 'w_vc': 1 << 64, 'sigma': 384,
                   'ell_max': 1 << 20, 'n': 8, 'q_s': 128,
                   'target_error': {'numerator': 1, 'denominator': 1 << 128}},
    }


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BudgetError(f'JSON: duplicate field {key}')
        result[key] = value
    return result


def reject_constant(value):
    raise BudgetError(f'JSON: non-finite constant {value} is unsupported')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--input', help='hypothetical input JSON path, or - for stdin')
    mode.add_argument('--example', action='store_true', help='evaluate illustrative non-project inputs')
    mode.add_argument('--example-input', action='store_true', help='print editable illustrative inputs')
    args = parser.parse_args(argv)
    try:
        if args.input:
            if args.input == '-':
                data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            else:
                with Path(args.input).open('rb') as stream:
                    data = stream.read(MAX_INPUT_BYTES + 1)
            if len(data) > MAX_INPUT_BYTES:
                raise BudgetError('input exceeds evaluator byte limit')
            raw = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object,
                             parse_constant=reject_constant)
        elif args.example or args.example_input:
            raw = example_input()
        else:
            raw = {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical'}
        result = serializable(raw) if args.example_input else make_report(raw)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (BudgetError, OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(json.dumps({'schema': OUTPUT_SCHEMA, 'status': 'invalid_input',
                          'error': str(exc), 'qualification': qualification()},
                         sort_keys=True, allow_nan=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
