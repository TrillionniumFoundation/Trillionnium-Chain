#!/usr/bin/env python3
"""Check the fixed v2 seal's mixed AIR, DEEP, radix-16 FRI and terminal equations.

The historical transcript/Merkle replay is executed from exact pinned local
bytes, then the previously omitted equations are evaluated independently in
Fp[X]/(X^4+11). This is a bounded numerical replay of ONE historical seal,
not an accepted-language equivalence proof, a complete outer-receipt verifier,
a compiler/VM semantics proof, an RBR extractor, or a QROM instantiation.
Zero DEEP denominators are rejected by this audit; the SDK defines inverse(0)
as zero. Thus this stricter audit does not claim general acceptance equivalence.

The new source supplement retains Apache-2.0 upstream source as data. No Rust
source, remote content, build script, or supplied report is executed. The CLI
does not accept a precomputed transcript report or caller-selected profile.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
BASE_HEAD = '2e5150c41484a8b3196b33de2e997794145edd7c'
REPLAY_PATH = 'scripts/w1_fri_query_replay.py'
REPLAY_SHA256 = '4a6a4f96baea59d5ff872d65ce9ba4f77eaf97306b97446442d5584369453b0f'
SUPPLEMENT_PATH = 'evidence/pon-w1-fri-algebra-20261108/algebra-source-supplement.json.gz'
SUPPLEMENT_BYTES = 70636
SUPPLEMENT_SHA256 = 'f649c85ff3775c275d3b7f891e4866ecea13a17ac5225eae8b359ec464051f86'
UPSTREAM = '8c215e2f4ccdd935f0517bf05d90f1ae032840a9'
POLY_SOURCE = 'risc0/circuit/recursion/src/poly_ext.rs'
NTT_SOURCE = 'risc0/zkp/src/core/ntt.rs'
FIELD_SOURCE = 'risc0/core/src/field/baby_bear.rs'
TAPS_SOURCE = 'risc0/circuit/recursion/src/taps.rs'
SUPPLEMENT_IDENTITIES = {
    POLY_SOURCE: (922857, '176f99041c0d3867ecd100b7292adbeb29294a0abe7a8f1f0a05807278da43b3',
                  '07b0b8e95f60ef6ba52f76247f5435c75af56f73'),
    NTT_SOURCE: (14765, '5e363e48f97bbeb17642fa1829e56488747921cf5923c010ef533d2130b2cb1f',
                 '51ebaeda83dfe94c8da7ea3e4899ad9693376d0d'),
}
P = 2013265921
ZERO, ONE = (0, 0, 0, 0), (1, 0, 0, 0)


class AlgebraReplayError(ValueError):
    """Source binding, bounded parsing, or a numerical equation failed."""


def require(condition, message):
    if not condition:
        raise AlgebraReplayError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def canonical_ext(value, label='extension element'):
    require(isinstance(value, (tuple, list)) and len(value) == 4
            and all(type(x) is int and 0 <= x < P for x in value), label + ': noncanonical Fp4')
    return tuple(value)


def add(a, b):
    return tuple((x + y) % P for x, y in zip(a, b))


def sub(a, b):
    return tuple((x - y) % P for x, y in zip(a, b))


def scale(a, x):
    return tuple(y * x % P for y in a)


def mul(a, b):
    """Ordinary polynomial multiplication reduced by X^4 = -11."""
    a0, a1, a2, a3 = a
    b0, b1, b2, b3 = b
    return ((a0*b0 - 11*(a1*b3 + a2*b2 + a3*b1)) % P,
            (a0*b1 + a1*b0 - 11*(a2*b3 + a3*b2)) % P,
            (a0*b2 + a1*b1 + a2*b0 - 11*a3*b3) % P,
            (a0*b3 + a1*b2 + a2*b1 + a3*b0) % P)


def power(a, exponent):
    require(type(exponent) is int and exponent >= 0, 'negative/nonintegral field exponent')
    result = ONE
    while exponent:
        if exponent & 1:
            result = mul(result, a)
        a = mul(a, a)
        exponent >>= 1
    return result


def inverse(a):
    require(a != ZERO, 'zero DEEP denominator outside audit scope')
    result = power(a, P**4 - 2)
    require(mul(a, result) == ONE, 'extension inverse consistency')
    return result


def evaluate(coefficients, x):
    result = ZERO
    for coefficient in reversed(coefficients):
        result = add(mul(result, x), coefficient)
    return result


def one(pattern, source, label):
    matches = list(re.finditer(pattern, source, re.S))
    require(len(matches) == 1, label + ': missing or ambiguous source declaration')
    return matches[0]


def integers(source, label):
    body = one(r'\b' + re.escape(label) + r':\s*&\[(.*?)\]', source, label).group(1)
    require(re.fullmatch(r'[\s,0-9]*', body) is not None, label + ': unsupported array syntax')
    return tuple(int(x.strip()) for x in body.split(',') if x.strip())


def roots(source):
    result = {}
    for direction in ('FWD', 'REV'):
        body = one(r'const ROU_' + direction + r": &'static \[Elem\] = &rou_array!\[(.*?)\];",
                   source, 'roots ' + direction).group(1)
        require(re.fullmatch(r'[\s,0-9]*', body) is not None, 'unsupported root syntax')
        values = tuple(int(x.strip()) for x in body.split(',') if x.strip())
        require(len(values) == 28 and all(0 < x < P for x in values), 'root table shape')
        for i, x in enumerate(values):
            require(pow(x, 1 << i, P) == 1 and (i == 0 or pow(x, 1 << (i-1), P) != 1),
                    'root table exact order')
            require(i == 0 or x*x % P == values[i-1], 'root table nesting')
        result[direction] = values
    require(all(a*b % P == 1 for a, b in zip(result['FWD'], result['REV'])),
            'forward/reverse root mismatch')
    return result


def taps(source):
    entries = [tuple(map(int, match.groups())) for match in re.finditer(
        r'TapData\s*\{\s*offset:\s*(\d+),\s*back:\s*(\d+),\s*group:\s*(\d+),'
        r'\s*combo:\s*(\d+),\s*skip:\s*(\d+),\s*\}', source)]
    require(len(entries) == 643 and source.count('TapData {') == 643, 'fixed tap roster')
    combo_taps, begins = integers(source, 'combo_taps'), integers(source, 'combo_begin')
    require(len(begins) == 6 and begins[0] == 0 and begins[-1] == len(combo_taps) == 20,
            'fixed combo shape')
    require(all(a < b for a, b in zip(begins, begins[1:])), 'nonincreasing combo boundaries')
    combos = tuple(combo_taps[a:b] for a, b in zip(begins, begins[1:]))
    registers = []
    cursor = 0
    while cursor < len(entries):
        offset, _, group, combo, size = entries[cursor]
        require(group < 3 and combo < len(combos) and size > 0
                and cursor + size <= len(entries), 'tap register bounds')
        selected = entries[cursor:cursor+size]
        require(all((r[0], r[2], r[3], r[4]) == (offset, group, combo, size) for r in selected),
                'tap register metadata disagreement')
        backs = tuple(r[1] for r in selected)
        require(backs == combos[combo], 'tap/combo backs disagreement')
        registers.append({'group': group, 'offset': offset, 'combo': combo,
                          'size': size, 'backs': backs, 'coefficient_start': cursor})
        cursor += size
    require(len(registers) == 163, 'fixed register count')
    widths = (12, 23, 128)
    for group, width in enumerate(widths):
        require([r['offset'] for r in registers if r['group'] == group] == list(range(width)),
                'tap register offset ordering')
    require(integers(source, 'group_begin') == (0, 16, 39, 643), 'fixed group boundaries')
    return {'registers': registers, 'combos': combos, 'combo_begin': begins,
            'widths': widths, 'tap_count': len(entries)}


ARITIES = {'Const': 1, 'ConstExt': 4, 'Get': 1, 'GetGlobal': 2,
           'Add': 2, 'Sub': 2, 'Mul': 2, 'True': 0, 'AndEqz': 2, 'AndCond': 3}


def parse_air(source):
    clean = re.sub(r'//[^\n]*', '', source)
    definition = one(r'pub const DEF:\s*PolyExtStepDef\s*=\s*PolyExtStepDef\s*\{\s*'
                     r'block:\s*&\[(.*?)\]\s*,\s*ret:\s*(\d+)\s*,?\s*\};', clean, 'AIR DEF')
    body, returned = definition.group(1), int(definition.group(2))
    token = re.compile(r'\s*PolyExtStep::([A-Za-z_][A-Za-z_0-9]*)(?:\(([^()]*)\))?\s*,')
    cursor, operations = 0, []
    while cursor < len(body):
        match = token.match(body, cursor)
        if match is None and not body[cursor:].strip():
            break
        require(match is not None, 'unsupported AIR operation syntax')
        cursor = match.end()
        name, arguments = match.groups()
        require(name in ARITIES, 'unsupported AIR operation: ' + name)
        pieces = [] if arguments is None else [x.strip() for x in arguments.split(',')]
        require(all(re.fullmatch(r'[0-9]+', x) for x in pieces), 'nonliteral AIR argument')
        args = tuple(int(x) for x in pieces)
        require(len(args) == ARITIES[name], 'AIR operation arity')
        operations.append((name, args))
    require(operations, 'empty AIR program')
    return operations, returned


def execute_air(program, mix, evaluations, globals_):
    operations, returned = program
    fp, mixes = [], []
    counts = Counter()

    def previous(values, index, label):
        require(type(index) is int and 0 <= index < len(values), label + ': forward/out-of-range register')
        return values[index]

    for name, args in operations:
        counts[name] += 1
        if name in ('Const', 'ConstExt'):
            require(all(0 <= x <= 0xffffffff for x in args), 'AIR u32 constant')
            fp.append((args[0] % P, 0, 0, 0) if name == 'Const' else tuple(x % P for x in args))
        elif name == 'Get':
            fp.append(previous(evaluations, args[0], 'AIR tap'))
        elif name == 'GetGlobal':
            group = previous(globals_, args[0], 'AIR global group')
            fp.append((previous(group, args[1], 'AIR global value'), 0, 0, 0))
        elif name in ('Add', 'Sub', 'Mul'):
            a, b = (previous(fp, i, 'AIR field') for i in args)
            fp.append({'Add': add, 'Sub': sub, 'Mul': mul}[name](a, b))
        elif name == 'True':
            mixes.append((ZERO, ONE))
        elif name == 'AndEqz':
            total, multiplier = previous(mixes, args[0], 'AIR mix')
            value = previous(fp, args[1], 'AIR field')
            mixes.append((add(total, mul(multiplier, value)), mul(multiplier, mix)))
        elif name == 'AndCond':
            total, multiplier = previous(mixes, args[0], 'AIR mix')
            condition = previous(fp, args[1], 'AIR field')
            inner_total, inner_multiplier = previous(mixes, args[2], 'AIR mix')
            mixes.append((add(total, mul(mul(condition, inner_total), multiplier)),
                          mul(multiplier, inner_multiplier)))
        else:
            raise AlgebraReplayError('unsupported AIR operation: ' + name)
    require(len(mixes) == returned + 1 and len(fp) + len(mixes) == len(operations),
            'AIR final register counts')
    return mixes[returned], {'operations': len(operations), 'field_registers': len(fp),
                            'mix_registers': len(mixes), 'opcode_counts': dict(sorted(counts.items()))}


def inverse_dft16(values, reverse_root):
    require(len(values) == 16 and pow(reverse_root, 16, P) == 1
            and pow(reverse_root, 8, P) != 1, 'radix-16 inverse DFT inputs')
    norm = pow(16, -1, P)
    coefficients = []
    for i in range(16):
        coefficient = ZERO
        for j, value in enumerate(values):
            coefficient = add(coefficient, scale(value, pow(reverse_root, i*j, P)))
        coefficients.append(scale(coefficient, norm))
    return tuple(coefficients)


def load_replayer(root):
    path = root
    for part in Path(REPLAY_PATH).parts:
        path = path / part
        require(not path.is_symlink(), 'symlink replay helper path')
    with path.open('rb') as stream:
        data = stream.read(65537)
    require(len(data) <= 65536 and sha(data) == REPLAY_SHA256, 'fixed replay helper SHA-256 mismatch')
    module = ModuleType('_w1_algebra_pinned_replay')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def load_supplement(root, replay):
    encoded = replay.bounded_file(root, SUPPLEMENT_PATH, SUPPLEMENT_BYTES)
    require(len(encoded) == SUPPLEMENT_BYTES and sha(encoded) == SUPPLEMENT_SHA256,
            'fixed algebra source supplement identity')
    with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as archive:
        data = archive.read(2 * 1024 * 1024 + 1)
    require(len(data) <= 2 * 1024 * 1024, 'algebra source supplement expansion bound')
    result = replay.strict_json(data)
    require(result['schema'] == 'TRNM-W1-ALGEBRA-SOURCE-SUPPLEMENT1'
            and result['repository'] == 'risc0/risc0' and result['commit'] == UPSTREAM,
            'algebra source supplement scope')
    require(len(result['files']) == len(SUPPLEMENT_IDENTITIES), 'algebra source supplement roster')
    sources = {}
    for row in result['files']:
        path = row['path']
        require(path in SUPPLEMENT_IDENTITIES and path not in sources, 'algebra source supplement path')
        content = row['content'].encode('utf-8')
        expected_bytes, expected_sha, expected_blob = SUPPLEMENT_IDENTITIES[path]
        blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        require(len(content) == row['bytes'] == expected_bytes
                and sha(content) == row['sha256'] == expected_sha
                and blob == row['git_blob_sha1'] == expected_blob
                and row['source_url'] == f'https://github.com/risc0/risc0/blob/{UPSTREAM}/{path}',
                'algebra source member identity: ' + path)
        sources[path] = row['content']
    return sources


def capture_inputs(replay, report, receipt):
    """Only used after live pinned replay; not a verifier for user-supplied reports."""
    require(sha(receipt) == report['receipt']['sha256'] == replay.RECEIPT_SHA256,
            'algebra capture receipt identity')
    start = report['receipt']['seal_file_offset_bytes']
    raw = receipt[start:start+report['receipt']['seal_bytes']]
    words = tuple(x for x, in struct.iter_unpack('<I', raw))
    require(sha(raw) == report['receipt']['seal_sha256'], 'algebra capture seal identity')

    def span(bounds):
        require(type(bounds) is list and len(bounds) == 2
                and all(type(x) is int for x in bounds)
                and 0 <= bounds[0] <= bounds[1] <= len(words), 'algebra capture word range')
        return replay.normal_words(words[bounds[0]:bounds[1]])

    events = {row['id']: row for row in report['ordered_transcript_events']}
    require(len(events) == len(report['ordered_transcript_events']) == 69, 'algebra transcript event roster')
    coefficients = {row['id']: row for row in report['coefficient_commitments']}
    u_flat = span(coefficients['u_coefficients']['word_range_half_open'])
    final_flat = span(coefficients['final_polynomial']['word_range_half_open'])
    require(len(u_flat) == 4*(643+16) and len(final_flat) == 4*64, 'algebra coefficient shape')
    queries = []
    for number, query in enumerate(report['queries']):
        require(query['query_number'] == number, 'algebra query order')
        leaves = {}
        for opening in query['openings']:
            bounds = opening['leaf_word_range_half_open']
            leaf = span(bounds)
            raw_leaf = replay.words_bytes(words[bounds[0]:bounds[1]])
            require(sha(raw_leaf) == opening['leaf_raw_bytes_sha256'], 'algebra leaf capture identity')
            require(opening['oracle'] not in leaves, 'duplicate algebra leaf')
            leaves[opening['oracle']] = leaf
        queries.append({'index': query['initial_index'], 'leaves': leaves})
    require(len(queries) == 50, 'algebra query count')
    return {
        'outputs': replay.normal_words(words[:32]),
        'accum_mix': tuple(events['accum_mix']['normal_words']),
        'constraint_mix': tuple(events['constraint_mix']['normal_words']),
        'z': tuple(events['deep_point_z']['normal_words']),
        'batch_mix': tuple(events['fri_batch_mix']['normal_words']),
        'fold_mixes': tuple(tuple(events[f'fri{i}_fold_mix']['normal_words']) for i in range(3)),
        'u': tuple(tuple(u_flat[i:i+4]) for i in range(0, len(u_flat), 4)),
        'final': tuple(tuple(final_flat[j*64+i] for j in range(4)) for i in range(64)),
        'queries': queries,
    }


class AlgebraEngine:
    """Numerical equations on captured fixed-shape values, for fault injection too."""

    def __init__(self, sources, supplement):
        self.roots = roots(sources[FIELD_SOURCE])
        self.taps = taps(sources[TAPS_SOURCE])
        self.program = parse_air(supplement[POLY_SOURCE])
        require(len(self.program[0]) == 12359 and self.program[1] == 1228, 'fixed AIR program shape')

    def validate_inputs(self, values):
        for key, count in (('outputs', 32), ('accum_mix', 20)):
            row = values[key]
            require(isinstance(row, (tuple, list)) and len(row) == count
                    and all(type(x) is int and 0 <= x < P for x in row), key + ': canonical shape')
        for key in ('constraint_mix', 'z', 'batch_mix'):
            canonical_ext(values[key], key)
        for key, count in (('fold_mixes', 3), ('u', 659), ('final', 64)):
            require(len(values[key]) == count, key + ': fixed shape')
            for row in values[key]:
                canonical_ext(row, key)
        require(len(values['queries']) == 50, 'fixed query count')
        widths = {'accum': 12, 'code': 23, 'data': 128, 'check': 16,
                  'fri0': 64, 'fri1': 64, 'fri2': 64}
        for query in values['queries']:
            require(type(query['index']) is int and 0 <= query['index'] < 1 << 20,
                    'query index outside fixed domain')
            require(set(query['leaves']) == set(widths), 'fixed opened oracle roster')
            for key, count in widths.items():
                leaf = query['leaves'][key]
                require(len(leaf) == count and all(type(x) is int and 0 <= x < P for x in leaf),
                        key + ': canonical leaf shape')

    def run(self, values):
        self.validate_inputs(values)
        regs, combos, begins = (self.taps[key] for key in ('registers', 'combos', 'combo_begin'))
        u, z, mix = values['u'], tuple(values['z']), tuple(values['batch_mix'])
        back_one = self.roots['REV'][18]
        evaluations = []
        for reg in regs:
            start, size = reg['coefficient_start'], reg['size']
            for back in reg['backs']:
                evaluations.append(evaluate(u[start:start+size], scale(z, pow(back_one, back, P))))
        require(len(evaluations) == 643, 'AIR tap evaluation count')
        (air_result, air_multiplier), execution = execute_air(
            self.program, tuple(values['constraint_mix']), evaluations,
            [values['outputs'], values['accum_mix']])
        require((execution['field_registers'], execution['mix_registers']) == (11130, 1229),
                'fixed AIR execution register counts')
        check = ZERO
        for i, remapped in enumerate((0, 2, 1, 3)):
            for j in range(4):
                basis = tuple(1 if k == j else 0 for k in range(4))
                check = add(check, mul(mul(u[643+remapped+4*j], power(z, i)), basis))
        zerofier = sub(power(scale(z, 3), 1 << 18), ONE)
        check = mul(check, zerofier)
        require(check == air_result, 'mixed AIR validity equation mismatch')

        combo_u = [ZERO] * 21
        tap_powers, check_powers = [], []
        cur = ONE
        for reg in regs:
            for i in range(reg['size']):
                at = begins[reg['combo']] + i
                combo_u[at] = add(combo_u[at], mul(cur, u[reg['coefficient_start']+i]))
            tap_powers.append(cur)
            cur = mul(cur, mix)
        for i in range(16):
            combo_u[20] = add(combo_u[20], mul(cur, u[643+i]))
            check_powers.append(cur)
            cur = mul(cur, mix)

        queries = []
        for number, query in enumerate(values['queries']):
            position = query['index']
            x = pow(self.roots['FWD'][20], position, P)
            rows = [query['leaves'][name] for name in ('accum', 'code', 'data')]
            totals = [ZERO] * 6
            for reg, cur in zip(regs, tap_powers):
                at = reg['combo']
                totals[at] = add(totals[at], scale(cur, rows[reg['group']][reg['offset']]))
            for cur, value in zip(check_powers, query['leaves']['check']):
                totals[5] = add(totals[5], scale(cur, value))
            goal, divisors = ZERO, []
            for i, backs in enumerate(combos):
                numerator = sub(totals[i], evaluate(combo_u[begins[i]:begins[i+1]], (x, 0, 0, 0)))
                divisor = ONE
                for back in backs:
                    factor = sub((x, 0, 0, 0), scale(z, pow(back_one, back, P)))
                    require(factor != ZERO, f'query {number}: zero DEEP factor outside audit scope')
                    divisor = mul(divisor, factor)
                goal = add(goal, mul(numerator, inverse(divisor)))
                divisors.append(divisor)
            check_divisor = sub((x, 0, 0, 0), power(z, 4))
            goal = add(goal, mul(sub(totals[5], combo_u[20]), inverse(check_divisor)))
            divisors.append(check_divisor)
            deep_goal = goal
            rounds = []
            for i, domain in enumerate((1 << 16, 1 << 12, 1 << 8)):
                quotient, group = divmod(position, domain)
                leaf = query['leaves'][f'fri{i}']
                data = tuple(tuple(leaf[j*16+k] for j in range(4)) for k in range(16))
                require(data[quotient] == goal, f'query {number} fri{i}: incoming fold goal mismatch')
                coefficients = inverse_dft16(data, self.roots['REV'][4])
                inv_wk = pow(self.roots['REV'][domain.bit_length()-1+4], group, P)
                evaluation_point = scale(tuple(values['fold_mixes'][i]), inv_wk)
                outgoing = evaluate(coefficients, evaluation_point)
                rounds.append({'oracle': f'fri{i}', 'input_position': position, 'quotient': quotient,
                               'group': group, 'domain_rows': domain, 'incoming_goal': goal,
                               'selected_opened_value': data[quotient],
                               'inverse_dft_coefficients_sha256': sha(canonical_json(coefficients)),
                               'fold_evaluation_point': evaluation_point, 'outgoing_goal': outgoing,
                               'incoming_equality_checked': True})
                goal, position = outgoing, group
            final_x = pow(self.roots['FWD'][8], position, P)
            final_value = evaluate(values['final'], (final_x, 0, 0, 0))
            require(final_value == goal, f'query {number}: terminal polynomial equation mismatch')
            queries.append({'query_number': number, 'initial_index': query['index'],
                            'deep_evaluation_x': x, 'deep_divisors': divisors,
                            'deep_denominators_nonzero': True, 'deep_goal': deep_goal,
                            'rounds': rounds, 'terminal_index': position, 'terminal_x': final_x,
                            'terminal_value': final_value, 'terminal_goal': goal,
                            'terminal_equality_checked': True})
        return {
            'mixed_air': {**execution, 'tap_evaluations': len(evaluations),
                          'returned_total': air_result, 'returned_multiplier': air_multiplier,
                          'check_polynomial_times_zerofier': check, 'zerofier_at_deep_point': zerofier,
                          'equality_checked': True},
            'deep': {'registers_batched': 163, 'check_columns_batched': 16, 'tap_combos': 5,
                     'combo_coefficients': combo_u, 'denominator_factor_count': 50*21,
                     'divisor_inverse_count': 50*6, 'all_divisors_nonzero': True,
                     'query_values_checked_against_first_fri_leaf': 50},
            'fri': {'folding_factor': 16, 'rounds': 3, 'incoming_goal_equalities': 150,
                    'interpolations': 150, 'terminal_coefficients': 64,
                    'terminal_equalities': 50, 'queries': queries},
        }


def build_report(root=ROOT):
    replay = load_replayer(root)
    sources = replay.load_snapshot(root)
    supplement = load_supplement(root, replay)
    receipt = replay.bounded_file(root, replay.RECEIPT_PATH, replay.RECEIPT_BYTES)
    base = replay.ReplayEngine(sources, root).run(receipt)
    captured = capture_inputs(replay, base, receipt)
    algebra = AlgebraEngine(sources, supplement).run(captured)
    return {
        'schema': 'TRNM-W1-FRI-ALGEBRA-REPLAY1',
        'result': 'FIXED_SEAL_NUMERICAL_EQUATIONS_REPLAYED_SECURITY_HOLD',
        'integration_base': BASE_HEAD, 'upstream_commit': UPSTREAM,
        'profile_id': base['profile_id'], 'receipt': base['receipt'],
        'qualification': {
            'fixed_mixed_air_validity_equation_checked': True,
            'fixed_deep_ali_evaluations_checked': True,
            'fixed_fri_folding_equations_checked': True,
            'fixed_terminal_polynomial_evaluations_checked': True,
            'complete_receipt_verified': False, 'accepted_language_equivalence_proved': False,
            'source_guest_vm_air_semantics_proved': False,
            'all_recursive_program_semantics_verified': False,
            'round_by_round_knowledge_extractor_supplied': False,
            'qrom_instantiated': False, 'post_quantum_soundness_qualified': False,
            'complete_w1_soundness_qualified': False, 'quantum_work_qualified': False,
            'production_qualified': False, 'consensus_admission': False,
            'unconditional_project_security_bits': None, 'full_security_bound': None,
        },
        'fresh_transcript_replay': {
            'helper_path': REPLAY_PATH, 'helper_sha256': REPLAY_SHA256,
            'report_sha256': sha(canonical_json(base)),
            'merkle_openings_verified': base['reproduced_checks']['merkle_openings_verified'],
            'transcript_events': len(base['ordered_transcript_events']),
            'exact_seal_consumption': base['reproduced_checks']['exact_seal_consumption'],
            'read_precomputed_report': False,
        },
        'source_snapshot': base['source_snapshot'],
        'source_supplement': {'path': SUPPLEMENT_PATH, 'bytes': SUPPLEMENT_BYTES,
                              'sha256': SUPPLEMENT_SHA256,
                              'members': [{'path': path, 'bytes': row[0], 'sha256': row[1],
                                           'git_blob_sha1': row[2]}
                                          for path, row in SUPPLEMENT_IDENTITIES.items()]},
        'execution': {'generator_sha256': sha(Path(__file__).read_bytes()),
                      'upstream_source_executed': False, 'native_rust_verifier_invoked': False,
                      'field_arithmetic': 'normal form Fp[X]/(X^4+11)',
                      'fold_interpolation': 'direct inverse DFT, natural coefficient order'},
        'algebra': algebra,
        'scope': [
            'One exact po2=18 historical join seal; fixed standard circuit_debug-disabled path.',
            'Numerical mixed AIR, DEEP, FRI and terminal equations, not intended program/VM semantics.',
            'Outer receipt claim, journal, assumptions and suffix are identity-bound but not interpreted.',
            'Zero DEEP divisors are rejected by this audit; SDK zero-inverse behavior is not equated.',
            'No uniform soundness, RBR extractor, quantum extraction or lifetime bound follows.',
            'Fault-injected captured values in unit tests are not accepted malformed receipts or attacks.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, help='Create a new report; never overwrite evidence')
    args = parser.parse_args()
    try:
        report = build_report(args.repo_root)
        encoded = canonical_json(report)
        if args.output is None:
            sys.stdout.buffer.write(encoded)
        else:
            with args.output.open('xb') as stream:
                stream.write(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('FRI algebra replay refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
