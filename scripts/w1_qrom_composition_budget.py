#!/usr/bin/env python3
"""Exact hypothetical arithmetic for CDHZ's indexed January Theorem 10.6.

This is a sequential-composition expression evaluator, not a proof checker.
The source is the January 1, 2026 manuscript, pages 71--73, not a verified copy
of the March revision. No Theorem 11.3/Merkle substitution is performed.

Each component upper envelope is an explicitly ASSUMED nonnegative polynomial
in the query bound, on a declared finite domain and a fixed (lambda, n) slice.
It is evaluated at the theorem's enlarged query bound, never just at the
adversary's original t. Matching hashes describe matching hypothetical
specifications; they do not prove that an implementation satisfies them.
Missing numbers, coefficients, domains and descriptions remain unknown.

Usage:
  python3 scripts/w1_qrom_composition_budget.py
  python3 scripts/w1_qrom_composition_budget.py --example
  python3 scripts/w1_qrom_composition_budget.py --example-input
  python3 scripts/w1_qrom_composition_budget.py --input scenario.json
  python3 scripts/w1_qrom_composition_budget.py --input -

JSON integers and canonical decimal strings are accepted; floats, booleans,
duplicate keys, nonfinite values and unknown fields are refused. Fractions
have exactly numerator and denominator. Output integer/fraction parts are
strings. Resource limits are evaluator limits, not cryptographic parameters.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys


INPUT_SCHEMA = 'TRNM-W1-CDHZ-JAN1-COMPOSITION-INPUT1'
OUTPUT_SCHEMA = 'TRNM-W1-CDHZ-JAN1-COMPOSITION-EXPRESSION1'
MAX_INPUT_BYTES = 131072
MAX_INTEGER_BITS = 512
MAX_RESULT_BITS = 8192
MAX_DEGREE = 8
QUERY_FIELDS = {'t', 'q_sim', 'q_com', 'q_v1', 'q_v2', 'q_e1', 'q_e2', 'q_r2', 'q_r3'}
ERROR_FIELDS = {'simulation', 'commutativity', 'extractability'}
RELATION_FIELDS = {'strict_specification_sha256', 'relaxed_specification_sha256'}
ORACLE_FIELDS = {'init_specification_sha256', 'ordinary_oracle_specification_sha256',
                 'extraction_oracle_specification_sha256'}


class CompositionError(ValueError):
    """Invalid hypothetical input or a component queried outside its claim."""


def require(condition, message):
    if not condition:
        raise CompositionError(message)


def obj(value, allowed, label):
    if value is None:
        return {key: None for key in sorted(allowed)}
    require(type(value) is dict, label + ': object or null required')
    require(not set(value) - set(allowed), label + ': unknown fields')
    return {key: value.get(key) for key in sorted(allowed)}


def integer(value, label, minimum=0):
    if value is None:
        return None
    if type(value) is str:
        require(len(value) <= 155 and re.fullmatch(r'0|[1-9][0-9]*', value) is not None,
                label + ': canonical nonnegative decimal integer required')
        value = int(value)
    require(type(value) is int, label + ': exact integer required, not bool/float')
    require(value >= minimum and value.bit_length() <= MAX_INTEGER_BITS,
            label + ': outside evaluator range')
    return value


def checked(value):
    if value is None:
        return None
    value = Fraction(value)
    require(value.numerator.bit_length() <= MAX_RESULT_BITS
            and value.denominator.bit_length() <= MAX_RESULT_BITS,
            'derived rational exceeds evaluator size limit')
    return value


def rational(value, label, *, probability=False, positive=False):
    if value is None:
        return None
    if type(value) is dict:
        require(set(value) == {'numerator', 'denominator'}, label + ': exact fraction fields required')
        numerator = integer(value['numerator'], label + '.numerator')
        denominator = integer(value['denominator'], label + '.denominator', 1)
        require(numerator is not None and denominator is not None,
                label + ': use null for an unknown whole fraction')
        result = Fraction(numerator, denominator)
    else:
        result = Fraction(integer(value, label))
    require(not positive or result > 0, label + ': must be positive')
    require(not probability or result <= 1, label + ': probability exceeds one')
    return result


def specification(value, label):
    if value is None:
        return None
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
            label + ': specification SHA256 or null required')
    return value


def descriptor(value, fields, label):
    return {key: specification(item, label + '.' + key)
            for key, item in obj(value, fields, label).items()}


def polynomial(value, label):
    if value is None:
        return None
    allowed = {'kind', 'security_parameter', 'instance_size_bound', 'max_queries', 'coefficients'}
    require(type(value) is dict and set(value) == allowed, label + ': exact polynomial fields required')
    require(value['kind'] == 'assumed_nonnegative_polynomial',
            label + ': only assumed_nonnegative_polynomial is supported')
    coefficients = value['coefficients']
    require(type(coefficients) is list and 1 <= len(coefficients) <= MAX_DEGREE + 1,
            label + ': a nonempty bounded coefficient list is required')
    return {
        'kind': value['kind'],
        'security_parameter': integer(value['security_parameter'], label + '.security_parameter', 1),
        'instance_size_bound': integer(value['instance_size_bound'], label + '.instance_size_bound'),
        'max_queries': integer(value['max_queries'], label + '.max_queries'),
        'coefficients': [rational(item, label + '.coefficients[' + str(i) + ']')
                         for i, item in enumerate(coefficients)],
    }


def stage(value, label):
    values = obj(value, {'input_relation', 'output_relation', 'emulated_oracle', 'errors'}, label)
    errors = obj(values['errors'], ERROR_FIELDS, label + '.errors')
    return {
        'input_relation': descriptor(values['input_relation'], RELATION_FIELDS, label + '.input_relation'),
        'output_relation': descriptor(values['output_relation'], RELATION_FIELDS, label + '.output_relation'),
        'emulated_oracle': descriptor(values['emulated_oracle'], ORACLE_FIELDS, label + '.emulated_oracle'),
        'errors': {key: polynomial(item, label + '.errors.' + key) for key, item in errors.items()},
    }


def matching(first, second, label):
    """Reject a known incompatibility; an incomplete description stays unknown."""
    for key in first:
        if first[key] is not None and second[key] is not None:
            require(first[key] == second[key], label + ': incompatible ' + key)
    return True if all(first[key] is not None and second[key] is not None for key in first) else None


def normalize(raw):
    require(type(raw) is dict, 'input: object required')
    allowed = {'schema', 'input_kind', 'security_parameter', 'instance_size_bound',
               'intermediate_instance_size_bound', 'queries', 'left', 'right', 'target_error'}
    require(not set(raw) - allowed, 'input: unknown fields or qualification override')
    require(raw.get('schema') == INPUT_SCHEMA, 'input: unsupported schema or theorem revision')
    require(raw.get('input_kind') == 'hypothetical', 'input_kind must be hypothetical')
    result = {
        'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
        'security_parameter': integer(raw.get('security_parameter'), 'security_parameter', 1),
        'instance_size_bound': integer(raw.get('instance_size_bound'), 'instance_size_bound'),
        'intermediate_instance_size_bound': integer(
            raw.get('intermediate_instance_size_bound'), 'intermediate_instance_size_bound'),
        'queries': {key: integer(value, 'queries.' + key)
                    for key, value in obj(raw.get('queries'), QUERY_FIELDS, 'queries').items()},
        'left': stage(raw.get('left'), 'left'), 'right': stage(raw.get('right'), 'right'),
        'target_error': rational(raw.get('target_error'), 'target_error', probability=True, positive=True),
    }
    bound, intermediate = result['instance_size_bound'], result['intermediate_instance_size_bound']
    if bound is not None and intermediate is not None:
        require(intermediate <= bound, 'intermediate instance exceeds the common n slice')
    matching(result['left']['output_relation'], result['right']['input_relation'], 'middle relation')
    matching(result['left']['emulated_oracle'], result['right']['emulated_oracle'], 'emulated oracle')
    for side in ('left', 'right'):
        for kind, model in result[side]['errors'].items():
            if model is not None:
                for field in ('security_parameter', 'instance_size_bound'):
                    if model[field] is not None and result[field] is not None:
                        require(model[field] == result[field], side + '.' + kind + ': mismatched ' + field)
    return result


def known(function, *values):
    # Even zero times unknown remains unknown: no unproved factor is discarded.
    return None if any(value is None for value in values) else function(*values)


def evaluate(model, queries, context, label):
    if model is None:
        return None, ['missing_component_envelope']
    missing = []
    if queries is None:
        missing.append('required_query_bound')
    for field in ('security_parameter', 'instance_size_bound'):
        if model[field] is None or context[field] is None:
            missing.append(field)
    if model['max_queries'] is None:
        missing.append('valid_query_domain')
    if any(value is None for value in model['coefficients']):
        missing.append('coefficient')
    if queries is not None and model['max_queries'] is not None:
        require(queries <= model['max_queries'], label + ': shifted query bound exceeds claimed domain')
    if missing:
        return None, missing
    value = Fraction(0)
    for coefficient in reversed(model['coefficients']):
        value = checked(value * queries + coefficient)
    return value, []


def qualification():
    return {
        'unconditional_project_security_bits': None,
        'quantum_security_bits': None,
        'full_recursive_security_bits': None,
        'latest_revision_equivalence_verified': False,
        'component_envelopes_proved': False,
        'actual_emulated_oracle_hypothesis_proved': False,
        'actual_relation_compatibility_proved': False,
        'qrom_theorem_instantiated': False,
        'complete_w1_soundness_qualified': False,
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
    inputs = normalize(raw)
    q = inputs['queries']
    points = {
        'left_extractability': known(lambda t, v1, v2, e2: t + v1 + v2 + e2,
                                     q['t'], q['q_v1'], q['q_v2'], q['q_e2']),
        'right_extractability': known(lambda t, v1: t + v1, q['t'], q['q_v1']),
        'shared_commutativity': known(lambda t, v1, v2, e2, r2, r3: t + 2*v1 + v2 + e2 + r2 + r3,
                                     q['t'], q['q_v1'], q['q_v2'], q['q_e2'], q['q_r2'], q['q_r3']),
        'simulation': q['q_sim'], 'commutativity': q['q_com'],
    }
    observations = []
    def value(side, kind, point):
        expression, missing = evaluate(inputs[side]['errors'][kind], points[point], inputs,
                                       side + '.' + kind + '@' + point)
        observations.append({'stage': side, 'component': kind, 'query_point': point,
                             'required_queries': points[point], 'expression': expression,
                             'unknown_dependencies': missing})
        return expression

    left_extract = value('left', 'extractability', 'left_extractability')
    right_extract = value('right', 'extractability', 'right_extractability')
    shifted_com = known(min, value('left', 'commutativity', 'shared_commutativity'),
                        value('right', 'commutativity', 'shared_commutativity'))
    simulation = known(min, value('left', 'simulation', 'simulation'),
                       value('right', 'simulation', 'simulation'))
    commutativity = known(min, value('left', 'commutativity', 'commutativity'),
                          value('right', 'commutativity', 'commutativity'))
    cross_coefficient = known(lambda e2, v1, r2, r3: 2 * e2**2 * (v1**2 + (r2 + r3)**2),
                              q['q_e2'], q['q_v1'], q['q_r2'], q['q_r3'])
    terms = {
        'twice_left_extraction': known(lambda item: checked(2 * item), left_extract),
        'twice_right_extraction': known(lambda item: checked(2 * item), right_extract),
        'commutator_coefficient': cross_coefficient,
        'common_commutativity_at_shifted_queries': shifted_com,
        'commutator_addend': known(lambda a, b: checked(a * b), cross_coefficient, shifted_com),
    }
    expression = known(lambda a, b, c: checked(a + b + c), terms['twice_left_extraction'],
                       terms['twice_right_extraction'], terms['commutator_addend'])
    middle = matching(inputs['left']['output_relation'], inputs['right']['input_relation'],
                      'middle relation')
    oracle = matching(inputs['left']['emulated_oracle'], inputs['right']['emulated_oracle'],
                      'emulated oracle')
    relations_complete = True if all(
        value is not None for side in ('left', 'right')
        for relation in ('input_relation', 'output_relation')
        for value in inputs[side][relation].values()) else None
    size_coverage = known(lambda n, intermediate: intermediate <= n,
                          inputs['instance_size_bound'], inputs['intermediate_instance_size_bound'])
    descriptions_complete = all(value is True for value in
                                (middle, oracle, relations_complete, size_coverage))
    conditional = expression if descriptions_complete else None
    return serializable({
        'schema': OUTPUT_SCHEMA,
        'status': 'hypothetical_sequential_expression_only',
        'source': {
            'paper': 'https://eprint.iacr.org/2025/2166',
            'indexed_copy': 'https://files01.core.ac.uk/download/690750245.pdf',
            'manuscript_date': '2026-01-01',
            'statement': 'Theorem 10.6, pages 72-73; Definition 10.3 and Remark 10.4',
            'latest_revision_equivalence_verified': False,
            'whole_manuscript_proof_audited': False,
        },
        'inputs': inputs,
        'query_points': points,
        'component_evaluations': observations,
        'terms': terms,
        'arithmetic_extraction_upper_expression': expression,
        'conditional_extraction_upper_expression': conditional,
        'simulation_upper_expression': simulation,
        'commutativity_upper_expression': commutativity,
        'expression_meets_hypothetical_target': known(lambda a, b: a <= b, conditional, inputs['target_error']),
        'expression_exceeds_one': known(lambda item: item > 1, conditional),
        'composed_verifier_query_bound': known(lambda a, b: a + b, q['q_v1'], q['q_v2']),
        'composed_extractor_query_bound': known(lambda a, b, c: a + b + c,
                                              q['q_v1'], q['q_e1'], q['q_e2']),
        'query_bound_scope': 'The displayed composite costs add calls in Construction 10.5 and its E3; '
                             'the declared algorithm costs and common instance-size coverage are not proved.',
        'description_checks': {
            'middle_strict_and_relaxed_relation_descriptions_match': middle,
            'same_emulated_oracle_description': oracle,
            'all_relation_descriptions_present': relations_complete,
            'declared_intermediate_instances_fit_common_n': size_coverage,
            'complete_hypothetical_descriptions': descriptions_complete,
            'checks_prove_the_hypotheses': False,
        },
        'theorem_11_3_instantiated_bound': None,
        'qualification': qualification(),
        'unresolved_obligations': [
            'Both full NRDX algorithms need Definition 10.3 guarantees relative to one identical '
            'Init/U1/U2 emulation, including quantum side information and adaptive statements.',
            'Ordinary oracle queries must commute perfectly; classical repetition must preserve '
            'outputs and internal state. Extraction-query commutators need the claimed envelope.',
            'Strict and relaxed intermediate relations, verifier traces and extractor witnesses must match.',
            'Every polynomial must be proved an upper bound for its entire declared query/parameter domain.',
            'All intermediate instances must be covered by the common n slice used for both error functions.',
            'The actual recursive verifier must implement the sequential construction or have a proved reduction to it.',
            'The January/authoritative-version correspondence remains unverified; no Theorem 11.3 substitution is made.',
        ],
    })


def example_input():
    def digest(label):
        return hashlib.sha256(('hypothetical specification: ' + label).encode()).hexdigest()
    def relation(label):
        return {'strict_specification_sha256': digest(label),
                'relaxed_specification_sha256': digest(label + ':relaxed')}
    oracle = {key: digest(key) for key in ORACLE_FIELDS}
    def model(coefficients):
        return {'kind': 'assumed_nonnegative_polynomial',
                'security_parameter': 128, 'instance_size_bound': 1024,
                'max_queries': 256, 'coefficients': coefficients}
    def fraction(bits, multiplier=1):
        return {'numerator': multiplier, 'denominator': 1 << bits}
    return {
        'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
        'security_parameter': 128, 'instance_size_bound': 1024,
        'intermediate_instance_size_bound': 32,
        'queries': {'t': 5, 'q_sim': 7, 'q_com': 11, 'q_v1': 2, 'q_v2': 3,
                    'q_e1': 7, 'q_e2': 4, 'q_r2': 1, 'q_r3': 6},
        'left': {'input_relation': relation('R1'), 'output_relation': relation('R2'),
                 'emulated_oracle': oracle,
                 'errors': {'simulation': model([0]),
                            'commutativity': model([fraction(96), fraction(96)]),
                            'extractability': model([0, 0, fraction(64)])}},
        'right': {'input_relation': relation('R2'), 'output_relation': relation('R3'),
                  'emulated_oracle': dict(oracle),
                  'errors': {'simulation': model([0]),
                             'commutativity': model([fraction(96, 2), fraction(96, 2)]),
                             'extractability': model([fraction(64), fraction(64)])}},
        'target_error': fraction(32),
    }


def strict_json(raw):
    require(len(raw) <= MAX_INPUT_BYTES, 'input exceeds evaluator byte limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise CompositionError('nonfinite JSON number: ' + value)
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise CompositionError(str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--input')
    choice.add_argument('--example', action='store_true')
    choice.add_argument('--example-input', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.input:
            if args.input == '-':
                raw_bytes = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            else:
                with Path(args.input).open('rb') as stream:
                    raw_bytes = stream.read(MAX_INPUT_BYTES + 1)
            raw = strict_json(raw_bytes)
        elif args.example or args.example_input:
            raw = example_input()
        else:
            raw = {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical'}
        result = serializable(raw) if args.example_input else make_report(raw)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (CompositionError, OSError, RecursionError) as error:
        print(json.dumps({'schema': OUTPUT_SCHEMA, 'status': 'invalid_input',
                          'error': str(error), 'qualification': qualification()},
                         sort_keys=True, allow_nan=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
