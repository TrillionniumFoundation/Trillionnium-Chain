#!/usr/bin/env python3
"""Exact hypothetical BCS envelope with semantic VC masses and continuous max.

This is a conservative adapter derived from the byte-checked March CDHZ
manuscript, not an instantiation of its theorem for P3 or RISC Zero. It uses
the named ordinary-VC mass from Lemma 9.7, and additionally charges q_V for
the ordinary VC checks in Construction 11.11. It does not silently choose a
positional reading of the inconsistent w_M/w_VC signatures.

The nonnegative affine objective is maximized over REAL masses with
w_FS + w_VC + w_M <= t. No integer enumeration, independent per-purpose
budget, empirical permutation count or stored digest width is substituted.
All arithmetic inputs/envelopes remain hypothetical; all project bits null.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys

import w1_qrom_composition_budget as exact

INPUT_SCHEMA = 'TRNM-W1-CDHZ-MARCH-BCS-ASSUMED-INPUT1'
OUTPUT_SCHEMA = 'TRNM-W1-CDHZ-MARCH-BCS-ASSUMED-EXPRESSION1'
FIELDS = {'t', 'k', 'q_v', 'q_r_input', 'q_r_output', 'n_y', 'n_y_prime',
          'q_y', 'q_pi', 'ell_max', 'sigma', 'r_min', 'kappa_rrbr'}
DOMAINS = {'pqsr_max_queries', 'vc_max_queries', 'commutativity_max_queries'}
MAX_EXPONENT = 4096


def normalize(raw):
    exact.require(type(raw) is dict and not set(raw) - {
        'schema', 'input_kind', 'parameters', 'declared_query_domains', 'target_error'},
        'input: unknown fields or qualification override')
    exact.require(raw.get('schema') == INPUT_SCHEMA, 'input schema/revision')
    exact.require(raw.get('input_kind') == 'hypothetical', 'only hypothetical envelopes are supported')
    p = exact.obj(raw.get('parameters'), FIELDS, 'parameters')
    for key in FIELDS - {'kappa_rrbr'}:
        p[key] = exact.integer(p[key], key, minimum=1 if key in {'k', 'ell_max', 'sigma', 'r_min'} else 0)
    p['kappa_rrbr'] = exact.rational(p['kappa_rrbr'], 'kappa_rrbr', probability=True)
    for key in ('sigma', 'r_min'):
        exact.require(p[key] is None or p[key] <= MAX_EXPONENT, key + ': evaluator exponent limit')
    length = p['ell_max']
    exact.require(length is None or length & (length - 1) == 0,
                  'ell_max: supply the actual power-of-two vector bound')
    if p['q_v'] is not None and p['k'] is not None:
        exact.require(p['q_v'] >= p['k'],
                      'q_v must include at least k Fiat-Shamir verifier queries')
    if all(p[key] is not None for key in ('q_y', 'n_y', 'ell_max')):
        exact.require(p['q_y'] <= p['n_y'] * length, 'q_y exceeds declared input vectors')
    if all(p[key] is not None for key in ('q_pi', 'k', 'ell_max')):
        exact.require(p['q_pi'] <= p['k'] * length, 'q_pi exceeds declared IOR vectors')
    domains = {key: exact.integer(value, key) for key, value in
               exact.obj(raw.get('declared_query_domains'), DOMAINS, 'declared_query_domains').items()}
    target = exact.rational(raw.get('target_error'), 'target_error', probability=True, positive=True)
    return p, domains, target


def known(fn, *values):
    return exact.known(lambda *items: exact.checked(fn(*items)), *values)


def qualifications():
    return {
        'pinned_january_to_march_statement_correspondence_verified': True,
        'complete_manuscript_proof_independently_verified': False,
        'author_erratum_claimed': False,
        'component_hypotheses_proved_for_implementation': False,
        'actual_joint_oracle_model_proved': False,
        'qrom_theorem_instantiated': False,
        'complete_w1_soundness_qualified': False,
        'post_quantum_soundness_qualified': False,
        'quantum_work_qualified': False,
        'production_qualified': False,
        'consensus_admission': False,
        'unconditional_project_security_bits': None,
        'whole_lifetime_failure_bound': None,
    }


def make_report(raw):
    p, domains, target = normalize(raw)
    t, k, v = p['t'], p['k'], p['q_v']
    d = exact.known(lambda a, b: a + b, p['q_r_input'], p['q_r_output'])
    u = exact.known(lambda a: 2 * a + 1, t)
    total = exact.known(lambda a, b, c, e: a + 1 + b + c + e, t, v, k, d)
    com_query = exact.known(lambda a, b, c: a + 1 + b + c, t, k, v)
    q_set = exact.known(lambda a, b, c, e: a + b + c * e,
                        p['q_y'], p['q_pi'], p['ell_max'], p['n_y_prime'])
    denominator = exact.known(lambda a: 1 << a, p['sigma'])
    required_domains = {'pqsr_max_queries': t,
                        'vc_max_queries': exact.known(max, u, total),
                        'commutativity_max_queries': com_query}
    domain_checks = {}
    for key, point in required_domains.items():
        limit = domains[key]
        if point is not None and limit is not None:
            exact.require(point <= limit, key + ': enlarged query point exceeds declared domain')
        domain_checks[key] = None if point is None or limit is None else True

    coefficient_fs = known(lambda a, b, e: 320 * (a + b + 1) * e,
                           t, k, p['kappa_rrbr'])
    coefficient_vc = known(lambda a, b, den: Fraction(1280 * a * a + 960 * b * b, den),
                           u, total, denominator)
    constants = {
        'state_restoration_rrbr': known(lambda a, b, e: 320 * (a + b + 1) * b * e,
                                        t, k, p['kappa_rrbr']),
        'finite_randomness': known(lambda a, b, r: Fraction(4 * (a + b + 1) * b, 1 << r),
                                   t, k, p['r_min']),
        'input_commitment_extraction': known(lambda n, ell, den: Fraction(32 * n * ell, den),
                                              p['n_y'], p['ell_max'], denominator),
        'offline_opening_set': known(lambda q, ell, den: Fraction(128 * q * (ell.bit_length() - 1), den),
                                     q_set, p['ell_max'], denominator),
        'online_fixed_vc_mass_including_verifier_checks': known(
            lambda dec, verifier, queries, den: Fraction(960 * (dec + verifier) * queries * queries, den),
            d, v, total, denominator),
        'commutator': known(lambda verifier, queries, den: Fraction(480 * verifier**2 * (queries + 1), den),
                            v, com_query, denominator),
    }
    constant = known(lambda *values: sum(values, Fraction()), *constants.values())
    slope = known(max, coefficient_fs, coefficient_vc)
    optimized = known(lambda c, queries, a: c + queries * a, constant, t, slope)
    uniform_domains = all(value is True for value in domain_checks.values())
    conditional = optimized if uniform_domains else None
    optimizer = None
    if coefficient_fs is not None and coefficient_vc is not None and t is not None:
        # A vertex attains the exact maximum for this affine objective, over
        # the entire real simplex. This is not a rule for nonlinear envelopes.
        optimizer = {'w_fs': t if coefficient_fs >= coefficient_vc else 0,
                     'w_vc': t if coefficient_vc > coefficient_fs else 0, 'w_m': 0}
    additional_vc = known(lambda verifier, queries, den: Fraction(960 * verifier * queries**2, den),
                           v, total, denominator)
    return exact.serializable({
        'schema': OUTPUT_SCHEMA,
        'status': 'HYPOTHETICAL_CONSERVATIVE_ADAPTER_ONLY',
        'source': {
            'paper': 'https://eprint.iacr.org/2025/2166',
            'march_pdf': 'https://eprint.iacr.org/archive/2025/2166/1772467621.pdf',
            'march_pdf_sha256': '2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30',
            'january_pdf_sha256': '215a62b9a1b5144c89ae103aaabaf6049eab23f7ccb23130bc7d65d597c1eac9',
            'interfaces': ['Theorem 6.10', 'Theorem 8.3', 'Lemma 8.8', 'Lemma 9.7',
                           'Theorem 11.3', 'Construction 11.11'],
            'interpretation': 'Named ordinary-VC mass from Lemma 9.7; includes q_V for step-13 VC checks. '
                              'Conservative derived adapter, not an author correction or a complete theorem audit.',
        },
        'inputs': {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
                   'parameters': p, 'declared_query_domains': domains, 'target_error': target},
        'query_points': {'adversary_t': t, 'extract_and_offline_t': u,
                         'online_t': total, 'commutativity_t': com_query,
                         'decider_queries': d, 'offline_opening_set_size': q_set},
        'ordinary_vc_mass': 'w_vc + q_v + q_r_input + q_r_output',
        'extraction_mass': 'w_m + 1', 'record_mass': 'w_fs + k',
        'required_query_domains': required_domains, 'domain_checks': domain_checks,
        'constant_terms': constants, 'constant_total': constant,
        'affine_coefficients': {'w_fs': coefficient_fs, 'w_vc': coefficient_vc, 'w_m': Fraction(0)},
        'maximum_domain': 'real nonnegative w_fs,w_vc,w_m with sum <= t',
        'affine_maximum_formula': 'C + t * max(a_fs, a_vc)',
        'an_attaining_mass_assignment': optimizer,
        'arithmetic_maximized_upper_expression': optimized,
        'conditional_expression_on_declared_query_domains': conditional,
        'additional_fixed_vc_check_mass_addend': additional_vc,
        'hypothetical_expression_meets_target': exact.known(lambda a, b: a <= b, conditional, target),
        'expression_exceeds_one': exact.known(lambda a: a > 1, conditional),
        'qualification': qualifications(),
        'unresolved_premises': [
            'Actual IOR relations, monotonicity, compiler semantics and uniform RRBR knowledge extractor.',
            'Admissible quantum multi-extractor for the actual salted/capped/encoded commitment and joint oracle.',
            'Validity of every assumed envelope, query bound and statement-size/proximity scope for the implementation.',
            'Actual FS construction, all recursive programs, matching middle relations and sequential extraction costs.',
            'A truthful whole-lifetime adversarial budget; this is one hypothetical reduction expression only.',
        ],
    })


def example_input():
    return {
        'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical',
        'parameters': {'t': 5, 'k': 2, 'q_v': 3, 'q_r_input': 1, 'q_r_output': 4,
                       'n_y': 1, 'n_y_prime': 1, 'q_y': 1, 'q_pi': 2, 'ell_max': 16,
                       'sigma': 96, 'r_min': 64,
                       'kappa_rrbr': {'numerator': '1', 'denominator': str(1 << 80)}},
        'declared_query_domains': {key: 1024 for key in DOMAINS},
        'target_error': {'numerator': '1', 'denominator': str(1 << 32)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--input')
    group.add_argument('--example', action='store_true')
    group.add_argument('--example-input', action='store_true')
    args = parser.parse_args()
    try:
        if args.input:
            if args.input == '-':
                data = sys.stdin.buffer.read(exact.MAX_INPUT_BYTES + 1)
            else:
                with Path(args.input).open('rb') as stream:
                    data = stream.read(exact.MAX_INPUT_BYTES + 1)
            raw = exact.strict_json(data)
        elif args.example or args.example_input:
            raw = example_input()
        else:
            raw = {'schema': INPUT_SCHEMA, 'input_kind': 'hypothetical'}
        result = exact.serializable(raw) if args.example_input else make_report(raw)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({'schema': OUTPUT_SCHEMA, 'status': 'invalid_input',
                          'error': str(error), 'qualification': qualifications()},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
