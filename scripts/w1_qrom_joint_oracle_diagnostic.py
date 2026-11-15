#!/usr/bin/env python3
"""Exact two-query countermodel to an unjustified independent-oracle replacement.

This finite hypothetical experiment compares two purpose interfaces to ONE
uniform ideal function with two INDEPENDENT uniform ideal functions. Both
marginals are uniform. If the encoded inputs coincide, their joint laws differ.
For range size M the equality test has acceptance-probability gap 1 - 1/M.
Distinct encoded inputs are a positive control, for this one experiment only.

The experiment does not model Poseidon2, assert a real hash's uniformity, assign
a digest entropy, find an accepted proof, or establish a W1 attack. In particular
it does not choose M from eight field words. Missing input bytes or M stay unknown.

Usage:
  python3 scripts/w1_qrom_joint_oracle_diagnostic.py
  python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example alias
  python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example separated
  python3 scripts/w1_qrom_joint_oracle_diagnostic.py --example-input alias
  python3 scripts/w1_qrom_joint_oracle_diagnostic.py --input scenario.json
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import sys

INPUT_SCHEMA = 'TRNM-W1-JOINT-ORACLE-TOY-INPUT1'
OUTPUT_SCHEMA = 'TRNM-W1-JOINT-ORACLE-TOY-REPORT1'
MAX_INPUT_BYTES = 131072
MAX_ENCODED_BYTES = 4096
MAX_RANGE_BITS = 512


class OracleModelError(ValueError):
    """Unsupported input to the finite model, not an implementation finding."""


def require(condition, message):
    if not condition:
        raise OracleModelError(message)


def range_size(value):
    if value is None:
        return None
    if type(value) is str:
        require(len(value) <= 155 and re.fullmatch(r'[1-9][0-9]*', value) is not None,
                'range_cardinality: canonical positive integer required')
        value = int(value)
    require(type(value) is int and 1 <= value and value.bit_length() <= MAX_RANGE_BITS,
            'range_cardinality: exact positive integer within evaluator limit required')
    return value


def encoded_input(value, name):
    if value is None:
        return None
    require(type(value) is str and len(value) <= 2 * MAX_ENCODED_BYTES
            and len(value) % 2 == 0 and re.fullmatch(r'[0-9a-f]*', value) is not None,
            name + ': bounded canonical lowercase hexadecimal bytes required')
    return value


def qualification():
    return {
        'unconditional_project_security_bits': None,
        'quantum_security_bits': None,
        'actual_poseidon_distribution_proved': False,
        'actual_purpose_independence_proved': False,
        'complete_w1_soundness_qualified': False,
        'accepted_w1_proof_attack_demonstrated': False,
        'pq_signature_qualification_inferred': False,
        'quantum_work_qualified': False,
        'production_qualified': False,
        'consensus_admission': False,
    }


def serializable(value):
    if isinstance(value, Fraction):
        return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        return {key: serializable(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [serializable(item) for item in value]
    return value


def make_report(raw):
    require(type(raw) is dict, 'input: object required')
    allowed = {'schema', 'input_kind', 'range_cardinality',
               'left_encoded_input_hex', 'right_encoded_input_hex'}
    require(not set(raw) - allowed, 'input: unknown fields or actual-system assertion')
    require(raw.get('schema') == INPUT_SCHEMA, 'input: unsupported schema')
    require(raw.get('input_kind') == 'hypothetical', 'input_kind must be hypothetical')
    cardinality = range_size(raw.get('range_cardinality'))
    left = encoded_input(raw.get('left_encoded_input_hex'), 'left_encoded_input_hex')
    right = encoded_input(raw.get('right_encoded_input_hex'), 'right_encoded_input_hex')
    same = None if left is None or right is None else left == right
    marginal = None if cardinality is None else Fraction(1, cardinality)
    complete = cardinality is not None and same is not None
    shared_diagonal = (marginal if same else marginal * marginal) if complete else None
    shared_off_diagonal = (Fraction(0) if same else marginal * marginal) if complete else None
    independent_pair = None if marginal is None else marginal * marginal
    shared_equality = (Fraction(1) if same else marginal) if complete else None
    gap = (1 - marginal if same else Fraction(0)) if complete else None
    return serializable({
        'schema': OUTPUT_SCHEMA,
        'status': 'finite_hypothetical_joint_law_only',
        'inputs': {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
                   'range_cardinality': cardinality,
                   'left_encoded_input_hex': left, 'right_encoded_input_hex': right},
        'assumptions': {
            'shared_world': 'One uniformly sampled ideal function; both interfaces use it.',
            'independent_world': 'Two independently sampled uniform ideal functions, one per purpose.',
            'input_choice': 'Two fixed non-adaptive classical queries; an equality test on the outputs.',
            'range_choice': 'An explicit hypothetical M, never inferred from a native hash representation.',
        },
        'encoded_inputs_alias': same,
        'oracle_queries_in_this_experiment': 2,
        'each_single_output_is_uniform_under_both_model_assumptions': True,
        'each_single_output_point_probability': marginal,
        'shared_joint_law': {'probability_of_each_diagonal_pair': shared_diagonal,
                             'probability_of_each_off_diagonal_pair': shared_off_diagonal},
        'independent_joint_law': {'probability_of_each_diagonal_pair': independent_pair,
                                  'probability_of_each_off_diagonal_pair': independent_pair},
        'equality_test': {
            'shared_acceptance_probability': shared_equality,
            'independent_acceptance_probability': marginal,
            'acceptance_probability_gap': gap,
        },
        'joint_total_variation_distance': gap,
        'equal_prior_optimal_guess_success': None if gap is None else (1 + gap) / 2,
        'scope': {
            'numeric_results_conditional_on_toy_assumptions': True,
            'positive_control_scope': 'Distinct inputs concern only this fixed two-query experiment; '
                                      'they do not prove global domain separation of a program.',
            'actual_shared_permutation_vector_is_separate_evidence': True,
            'actual_w1_statement_or_reachable_commitment_checked': False,
            'permutation_queries_to_cdhz_oracle_queries_mapping_proved': False,
        },
        'qualification': qualification(),
        'next_obligations': [
            'Specify the actual joint encoded-input family and identify every domain intersection.',
            'Prove a compatible single-oracle emulation/reduction, or prove disjoint domains for '
            'every interface where independent functions are invoked in a theorem.',
            'Account for extraction, Fiat-Shamir and all other exposed uses in that same model.',
            'Establish whether any exhibited encoding intersection is reachable under the '
            'fixed accepted proof relation before making an implementation security claim.',
        ],
    })


def example_input(kind='alias'):
    require(kind in ('alias', 'separated'), 'unknown example')
    left = '0001020304'
    return {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical', 'range_cardinality': 16,
            'left_encoded_input_hex': left,
            'right_encoded_input_hex': left if kind == 'alias' else '0101020304'}


def strict_json(raw):
    require(len(raw) <= MAX_INPUT_BYTES, 'input exceeds evaluator byte limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise OracleModelError('nonfinite JSON number: ' + value)
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise OracleModelError(str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--input')
    choice.add_argument('--example', choices=('alias', 'separated'))
    choice.add_argument('--example-input', choices=('alias', 'separated'))
    args = parser.parse_args(argv)
    try:
        if args.input:
            if args.input == '-':
                raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            else:
                with Path(args.input).open('rb') as stream:
                    raw = stream.read(MAX_INPUT_BYTES + 1)
            data = strict_json(raw)
        elif args.example or args.example_input:
            data = example_input(args.example or args.example_input)
        else:
            data = {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical'}
        report = serializable(data) if args.example_input else make_report(data)
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (OracleModelError, OSError, RecursionError) as error:
        print(json.dumps({'schema': OUTPUT_SCHEMA, 'status': 'invalid_input', 'error': str(error),
                          'qualification': qualification()}, sort_keys=True, allow_nan=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
