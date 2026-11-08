#!/usr/bin/env python3
"""Independently recompute the fixed seal's DEEP/FRI arithmetic register by register.

This reviewer does not import the new algebra replay. It regenerates the
transcript and Merkle openings using the exact pinned predecessor, then uses
ordinary integer convolution in F_p[X]/(X^4 + 11), expands all 163 register
terms separately, computes inverse DFT16 sums directly, and evaluates the final
polynomial with Horner's rule. Its AIR output is only the check-polynomial side
of the equality: the generated constraint program is deliberately not evaluated.

Zero denominators are refused. This is a restriction of this finite audit:
the upstream SDK defines inv(0)=0. This script proves neither general SDK
equivalence, native receipt acceptance, source/AIR semantics, nor QROM security.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[3]
PREDECESSOR = 'scripts/w1_fri_query_replay.py'
PREDECESSOR_SHA256 = '4a6a4f96baea59d5ff872d65ce9ba4f77eaf97306b97446442d5584369453b0f'
P = 2013265921
R_INV = pow(1 << 32, -1, P)
ZERO = (0, 0, 0, 0)
ONE = (1, 0, 0, 0)
FIELD_SOURCE = 'risc0/core/src/field/baby_bear.rs'
TAPS_SOURCE = 'risc0/circuit/recursion/src/taps.rs'


class ReviewError(ValueError):
    """A pinned source, finite arithmetic identity, or scope condition failed."""


def require(ok, message):
    if not ok:
        raise ReviewError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def base(value):
    return (value % P, 0, 0, 0)


def add(left, right):
    return tuple((left[i] + right[i]) % P for i in range(4))


def sub(left, right):
    return tuple((left[i] - right[i]) % P for i in range(4))


def mul(left, right):
    # Independent coefficient convolution, not the optimized four formulas.
    coefficients = [0] * 7
    for i in range(4):
        for j in range(4):
            coefficients[i + j] += left[i] * right[j]
    for i in range(6, 3, -1):
        coefficients[i - 4] -= 11 * coefficients[i]
    return tuple(value % P for value in coefficients[:4])


def power(value, exponent):
    require(type(exponent) is int and exponent >= 0, 'invalid exponent')
    result = ONE
    while exponent:
        if exponent & 1:
            result = mul(result, value)
        value = mul(value, value)
        exponent //= 2
    return result


def inverse_nonzero(value):
    require(value != ZERO, 'audit refuses zero denominator; SDK inv(0)=0')
    inverse = power(value, P ** 4 - 2)
    require(mul(value, inverse) == ONE, 'independent inverse product failed')
    return inverse


def evaluate(coefficients, point):
    result = ZERO
    for coefficient in reversed(coefficients):
        result = add(mul(result, point), coefficient)
    return result


def canonical_bytes(values):
    require(all(type(x) is int and 0 <= x < P for x in values),
            'noncanonical ordinary field word')
    return struct.pack('<' + 'I' * len(values), *values)


def roots(text, name):
    matches = re.findall(r'const ' + name + r'.*?rou_array!\[(.*?)\]', text, re.S)
    require(len(matches) == 1, 'ambiguous roots declaration')
    require(re.fullmatch(r'[\s\d,]+', matches[0]) is not None,
            'unsupported roots syntax')
    result = [int(value) for value in re.findall(r'\d+', matches[0])]
    require(len(result) == 28, 'unexpected roots count')
    for index, value in enumerate(result):
        require(0 < value < P and pow(value, 1 << index, P) == 1,
                'invalid root order')
        if index:
            require(pow(value, 1 << (index - 1), P) != 1, 'root order too small')
    return result


def register_terms(text, coefficients, mix):
    pattern = (r'TapData\s*\{\s*offset:\s*(\d+),\s*back:\s*(\d+),'
               r'\s*group:\s*(\d+),\s*combo:\s*(\d+),\s*skip:\s*(\d+),\s*\}')
    taps = [tuple(map(int, match)) for match in re.findall(pattern, text)]
    require(len(taps) == 643 and len(coefficients) == 659, 'fixed tap/U count')
    result, cursor, weight = [], 0, ONE
    combo_backs = {}
    while cursor < len(taps):
        offset, _, group, combo, size = taps[cursor]
        selected = taps[cursor:cursor + size]
        require(1 <= size <= 6 and len(selected) == size, 'register size')
        require(all(row[0] == offset and row[2:] == (group, combo, size)
                    for row in selected), 'nonuniform register declaration')
        backs = tuple(row[1] for row in selected)
        require(backs == tuple(sorted(set(backs))), 'noncanonical register backs')
        require(combo not in combo_backs or combo_backs[combo] == backs,
                'one combo has different symbolic denominator')
        combo_backs[combo] = backs
        result.append((offset, group, combo, backs, weight,
                       coefficients[cursor:cursor + size]))
        cursor += size
        weight = mul(weight, mix)
    require(cursor == 643 and len(result) == 163 and len(combo_backs) == 5,
            'fixed register/combo count')
    check_weights = []
    for _ in range(16):
        check_weights.append(weight)
        weight = mul(weight, mix)
    return result, check_weights


def load_predecessor(root):
    path = root
    for part in Path(PREDECESSOR).parts:
        path = path / part
        require(not path.is_symlink(), 'symlink predecessor')
    with path.open('rb') as stream:
        data = stream.read(65537)
    require(len(data) <= 65536 and sha(data) == PREDECESSOR_SHA256,
            'predecessor byte identity mismatch')
    module = ModuleType('_independent_review_pinned_query_replay')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def build_report(root=ROOT):
    predecessor = load_predecessor(root)
    sources = predecessor.load_snapshot(root)
    receipt = predecessor.bounded_file(root, predecessor.RECEIPT_PATH,
                                       predecessor.RECEIPT_BYTES)
    replay = predecessor.ReplayEngine(sources, root).run(receipt)
    begin = replay['receipt']['seal_file_offset_bytes']
    seal = receipt[begin:begin + replay['receipt']['seal_bytes']]
    raw = struct.unpack('<' + str(replay['receipt']['seal_words']) + 'I', seal)
    require(all(0 <= value < P for value in raw), 'noncanonical Montgomery word')
    ordinary = [value * R_INV % P for value in raw]
    forward = roots(sources[FIELD_SOURCE], 'ROU_FWD')
    reverse = roots(sources[FIELD_SOURCE], 'ROU_REV')
    require(all(a * b % P == 1 for a, b in zip(forward, reverse)),
            'forward/reverse roots not inverses')
    events = {event['id']: tuple(event.get('normal_words', []))
              for event in replay['ordered_transcript_events']}
    u_begin, u_end = replay['coefficient_commitments'][0]['word_range_half_open']
    coefficients = [tuple(ordinary[i:i + 4]) for i in range(u_begin, u_end, 4)]
    z, mix = events['deep_point_z'], events['fri_batch_mix']
    registers, check_weights = register_terms(sources[TAPS_SOURCE], coefficients, mix)

    # Check side only: no use of the new generated-AIR interpreter.
    air_check = ZERO
    for i, remapped in enumerate((0, 2, 1, 3)):
        for j in range(4):
            unit = tuple(int(k == j) for k in range(4))
            term = mul(mul(coefficients[643 + remapped + 4 * j], power(z, i)), unit)
            air_check = add(air_check, term)
    air_check = mul(air_check, sub(power(mul(base(3), z), 1 << 18), ONE))

    final_begin, final_end = replay['coefficient_commitments'][1]['word_range_half_open']
    final_flat = ordinary[final_begin:final_end]
    require(len(final_flat) == 256, 'fixed terminal coefficient length')
    final_coefficients = [tuple(final_flat[j * 64 + i] for j in range(4))
                          for i in range(64)]
    denominator_records, queries = [], []
    all_denominator_bytes = bytearray()
    for query in replay['queries']:
        number = query['query_number']
        rows = {opening['oracle']: ordinary[slice(*opening['leaf_word_range_half_open'])]
                for opening in query['openings']}
        point = base(pow(forward[20], query['initial_index'], P))
        inverses, goal = {}, ZERO
        for offset, group, combo, backs, weight, polynomial in registers:
            if combo not in inverses:
                denominator = ONE
                for back in backs:
                    denominator = mul(denominator,
                                      sub(point, mul(z, base(pow(reverse[18], back, P)))))
                inverses[combo] = inverse_nonzero(denominator)
                encoded = canonical_bytes(denominator)
                all_denominator_bytes.extend(encoded)
                denominator_records.append({'query': number, 'combo': combo,
                                            'normal_words_le_sha256': sha(encoded)})
            numerator = sub(base(rows[('accum', 'code', 'data')[group]][offset]),
                            evaluate(polynomial, point))
            # Expand every register separately; never form the new replay's combo-U.
            goal = add(goal, mul(mul(weight, numerator), inverses[combo]))
        numerator = ZERO
        for j in range(16):
            numerator = add(numerator, mul(check_weights[j],
                                          sub(base(rows['check'][j]), coefficients[643 + j])))
        denominator = sub(point, power(z, 4))
        inverse = inverse_nonzero(denominator)
        encoded = canonical_bytes(denominator)
        all_denominator_bytes.extend(encoded)
        denominator_records.append({'query': number, 'combo': 'check',
                                    'normal_words_le_sha256': sha(encoded)})
        goal = add(goal, mul(numerator, inverse))
        goals = [goal]
        for round_ in query['folding_positions']:
            name = round_['oracle']
            values = [tuple(rows[name][j * 16 + i] for j in range(4)) for i in range(16)]
            require(values[round_['quotient']] == goal,
                    f'query {number} {name}: selected component differs from goal')
            folded_coefficients = []
            for i in range(16):
                coefficient = ZERO
                for j in range(16):
                    coefficient = add(coefficient,
                                      mul(values[j], base(pow(reverse[4], i * j, P))))
                folded_coefficients.append(mul(coefficient, base(pow(16, -1, P))))
            log_domain = (16 * round_['domain_rows']).bit_length() - 1
            fold_point = mul(events[name + '_fold_mix'],
                             base(pow(reverse[log_domain], round_['group'], P)))
            goal = evaluate(folded_coefficients, fold_point)
            goals.append(goal)
        terminal = evaluate(final_coefficients,
                            base(pow(forward[8], query['terminal_evaluation_index'], P)))
        require(goal == terminal, f'query {number}: terminal equality failed')
        queries.append({'query': number, 'initial_index': query['initial_index'],
                        'deep_and_three_fold_goals_normal': goals,
                        'terminal_index': query['terminal_evaluation_index'],
                        'terminal_equality': True})
    require(len(queries) == 50 and len(denominator_records) == 300,
            'fixed query/denominator coverage')
    replay_json = json.dumps(replay, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return {
        'schema': 'TRNM-W1-INDEPENDENT-REGISTER-DEEP-REVIEW1',
        'result': 'FIXED_REGISTER_DEEP_FOLD_TERMINAL_EQUALITIES_REPRODUCED_HOLD',
        'generator_sha256': sha(Path(__file__).read_bytes()),
        'predecessor': {'path': PREDECESSOR, 'sha256': PREDECESSOR_SHA256},
        'upstream_commit': replay['upstream_commit'],
        'source_snapshot': replay['source_snapshot'],
        'source_files': replay['source_files'],
        'receipt': replay['receipt'],
        'regenerated_predecessor_report_canonical_json_sha256': sha(replay_json),
        'checks': {'merkle_openings_replayed_by_pinned_predecessor': 350,
                   'registers_expanded_per_query': 163,
                   'deep_to_first_leaf_equalities': 50,
                   'selected_fri_component_equalities': 150,
                   'folds_recomputed': 150, 'terminal_equalities': 50,
                   'distinct_symbolic_denominators_per_query': 6,
                   'nonzero_denominator_inverse_products': 300},
        'air_check_side_normal_words': air_check,
        'denominators_ordered_normal_le_sha256': sha(bytes(all_denominator_bytes)),
        'denominators': denominator_records,
        'queries': queries,
        'scope': {
            'imports_new_algebra_replay': False,
            'generated_air_program_evaluated': False,
            'native_sdk_executed': False,
            'full_receipt_verified': False,
            'sdk_general_language_equivalence_proved': False,
            'zero_denominator_policy': 'Audit refuses; SDK inv(0)=0. Fixed fixture has none.',
            'qrom_instantiated': False,
            'security_bits_quantum': None,
            'whole_chain_pq_qualified': False,
            'production_qualified': False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path,
                        help='Create a new JSON report; refuse existing output')
    args = parser.parse_args()
    try:
        report = build_report(args.repo_root)
        encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(encoded)
        else:
            print(encoded, end='')
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        print(f'Independent register review refused: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
