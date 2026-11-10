#!/usr/bin/env python3
"""Strict, independent reader for from-scratch native W1 rejection observations.

The reader reconstructs every public input, failed ticket and witness, then
replays the pinned scalar relation. Reported clocks are observations, not a
cryptographic resource bound or authenticated execution identity. The existing
rejection-cost V2 collector and its honest-proof acquisition contract are intact.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'ci'))
from pq_source_reader import SourceReadError, read_regular

SCHEMA = 'pon-fresh-rejection-cost-v1'
PROFILE = 'pon-matmul-transcript-64-v1'
CLASSES = ('dense', 'zero', 'rank-one', 'sparse')
TARGETS = ('7f' + 'ff' * 31, '07' + 'ff' * 31)
KERNELS = ('production-full-limb', 'scalar-reference')
LIMIT, SAMPLES, N, R, Q = 4096, 8, 64, 8, 4294967291
CELLS, PROOF_BYTES = N * N, 49188
RAW_LIMIT = 64 * 1024 * 1024
FLAGS = ('hardness_qualified', 'worst_case_rejection_qualified',
         'public_service_measured', 'production_activation')
REFERENCE_COMMIT = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
REFERENCE_FILES = {
    'formal/pon-nakamoto-v1/work_oracle.py': '2b90584fc4f102e9eb40ed5ab138746f4a4b3748544cd287f076a8804c955c18',
    'formal/pon-nakamoto-v1/contract_wire.py': 'cbe45d72ad20ed5683d50dceaa97b93bc74cdafced7d0896386edf9cbe9f98f6',
    'config/pon/ledger-v1.json': '6755e36aab0ab9f4743da331a8dcd3374d657ff80f027ecf28db922e6d5ea39a',
    'config/pon/work-profile-v1.json': '03f7537b2fc3fa0c2f7036dd73d7088ba1ce50eafe6f2c907087d30385320880',
    'config/pon/model-family-v1.json': '30b250db074e7fbb5776c1474371258a6110cc1742e0e9970232a799ab790ca1',
    'config/pon/devnet-v1.json': '4491b96ead11a020e8d71f27713368b65e663eef5cfc6fd0800a166b0c2a20d4',
}


def require(value, message):
    if not value:
        raise ValueError('fresh W1 rejection: ' + message)


def exact(value, fields, label):
    require(type(value) is dict and set(value) == set(fields), label + ' exact fields')


def integer(value, label, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, label + ' integer range')
    return value


def hash_text(value, label):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            label + ' canonical hash')
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def h(tag, *parts):
    result = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in parts:
        result.update(len(part).to_bytes(4, 'little') + part)
    return result.digest()


@lru_cache(maxsize=4)
def material(class_name):
    require(class_name in CLASSES, 'known input class')
    if class_name == 'zero':
        a = b = (0,) * CELLS
    elif class_name == 'sparse':
        a = b = tuple(int(i // N == i % N) for i in range(CELLS))
    elif class_name == 'rank-one':
        a = tuple((i // N + 1) * (i % N + 1) for i in range(CELLS))
        b = tuple((i // N + 2) * (i % N + 1) for i in range(CELLS))
    else:
        a = tuple(i % 31 for i in range(CELLS))
        b = tuple((i * 7) % 37 for i in range(CELLS))
    pack = lambda values: struct.pack('<' + 'I' * CELLS, *values)
    # Deliberately no matrix product: this is a zero *claim*, including dense A/B.
    prefix = b'PNW1' + pack(a) + pack(b) + bytes(4 * CELLS)
    return a, b, prefix, h(b'task', pack(a), pack(b)).hex()


def challenge_for(class_name, target, sample):
    return h(b'fresh-rejection-challenge-v1', class_name.encode(), bytes.fromhex(target),
             sample.to_bytes(8, 'little'))


def trace_for(challenge, nonce):
    return h(b'fresh-rejection-fake-trace-v1', challenge, nonce.to_bytes(8, 'little'))


def verify_reference_sources():
    for name, expected in REFERENCE_FILES.items():
        try:
            data = read_regular(ROOT, name, RAW_LIMIT)
        except SourceReadError as error:
            raise ValueError('fresh W1 rejection: independent reference ' + name + ': ' + str(error)) from error
        require(digest(data) == expected,
                'changed or missing independent reference ' + name)


@lru_cache(maxsize=1)
def scalar_reference():
    verify_reference_sources()
    base = ROOT / 'formal/pon-nakamoto-v1'
    # Bind the oracle's one local import to the verified original module. Restore
    # any pre-existing import after initialization; never consume an unrelated one.
    old = sys.modules.get('contract_wire')
    try:
        wire_spec = importlib.util.spec_from_file_location('contract_wire', base / 'contract_wire.py')
        wire = importlib.util.module_from_spec(wire_spec)
        wire_spec.loader.exec_module(wire)
        sys.modules['contract_wire'] = wire
        spec = importlib.util.spec_from_file_location('_fresh_rejection_scalar', base / 'work_oracle.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old is None:
            sys.modules.pop('contract_wire', None)
        else:
            sys.modules['contract_wire'] = old


@lru_cache(maxsize=64)
def independent_trace(class_name, challenge_hex):
    a, b, _, _ = material(class_name)
    return scalar_reference().evaluate(bytes.fromhex(challenge_hex), a, b)[1]


def expected_progress(challenge):
    sequence = bytearray([0])
    counts = []
    for label in range(4):
        accepted, counter = 0, 0
        while accepted < N * R:
            require(counter < 128, 'noise expansion budget')
            sequence.extend(bytes([1, label]) + struct.pack('<I', counter))
            words = struct.unpack('<8I', h(b'noise', challenge, bytes([label]), struct.pack('<I', counter)))
            accepted += sum(value < Q for value in words)
            counter += 1
        counts.append(counter)
    for _ in range(2):
        for row in range(N):
            sequence.extend(b'\x02' + struct.pack('<I', row))
    for row in range(N // R):
        for column in range(N // R):
            for inner in range(N // R):
                sequence.extend(b'\x03' + struct.pack('<III', row, column, inner))
    return {'timed': False, 'actual_result': 'Transcript', 'sequence_sha256': digest(sequence),
            'noise_counts': counts, 'before_replay': 1, 'matrix_rows': 128,
            'transcript_tiles': 512, 'before_product': 0, 'before_verified_work': 0}


def checked_probe(probe, challenge):
    expected = expected_progress(challenge)
    exact(probe, expected, 'progress probe')
    require(probe['timed'] is False, 'probe cannot become timed receiver observation')
    for name in ('before_replay', 'matrix_rows', 'transcript_tiles', 'before_product', 'before_verified_work'):
        integer(probe[name], 'probe ' + name)
    require(type(probe['noise_counts']) is list and len(probe['noise_counts']) == 4, 'noise counts')
    for count in probe['noise_counts']:
        integer(count, 'noise count')
    require(probe == expected, 'complete ordered transcript rejection required')


def validate_row(row, class_name, target, sample):
    exact(row, ('class', 'sample', 'target', 'task', 'challenge', 'prefix_sha256', 'setup',
                'search', 'proof', 'acquisition', 'precheck', 'measurements'), 'sample')
    integer(row['sample'], 'sample index')
    require((row['class'], row['target'], row['sample']) == (class_name, target, sample),
            'fixed class/target/sample order')
    _, _, prefix, task = material(class_name)
    challenge = challenge_for(class_name, target, sample)
    require(row['task'] == task and row['challenge'] == challenge.hex(), 'exact task and challenge')
    require(row['prefix_sha256'] == digest(prefix), 'public input and zero-product claim encoding')
    setup = row['setup']
    fields = ('material_ns', 'task_ns', 'challenge_ns', 'prefix_ns', 'wall_ns', 'overhead_ns')
    exact(setup, fields, 'setup')
    for field in fields:
        integer(setup[field], 'setup ' + field)
    require(setup['wall_ns'] == sum(setup[field] for field in fields if field != 'wall_ns'),
            'setup costs must reconcile without subtraction')
    search = row['search']
    exact(search, ('outcome', 'attempt_limit', 'wall_ns', 'trace_ns', 'ticket_ns', 'overhead_ns', 'attempts'), 'search')
    integer(search['attempt_limit'], 'attempt limit')
    require(search['attempt_limit'] == LIMIT, 'fixed search cap')
    for field in ('wall_ns', 'trace_ns', 'ticket_ns', 'overhead_ns'):
        integer(search[field], 'search ' + field)
    require(type(search['attempts']) is list and 1 <= len(search['attempts']) <= LIMIT, 'retained attempt count')
    trace_cost, ticket_cost, selected_trace = 0, 0, None
    for nonce, attempt in enumerate(search['attempts']):
        exact(attempt, ('nonce', 'trace', 'ticket', 'selected', 'trace_ns', 'ticket_ns'), 'attempt')
        integer(attempt['nonce'], 'attempt nonce')
        require(attempt['nonce'] == nonce and selected_trace is None, 'no omitted or post-success attempts')
        trace = trace_for(challenge, nonce)
        ticket = h(b'ticket', challenge, trace)
        selected = ticket.hex() <= target
        require(attempt['trace'] == trace.hex() and attempt['ticket'] == ticket.hex(), 'independent ticket replay')
        require(type(attempt['selected']) is bool and attempt['selected'] is selected, 'exact selection truth')
        trace_cost += integer(attempt['trace_ns'], 'attempt trace duration')
        ticket_cost += integer(attempt['ticket_ns'], 'attempt ticket duration')
        if selected:
            selected_trace = trace
    require(search['trace_ns'] == trace_cost and search['ticket_ns'] == ticket_cost, 'all failed-search costs retained')
    require(search['wall_ns'] == trace_cost + ticket_cost + search['overhead_ns'], 'complete search wall accounting')
    expected_outcome = 'search-exhausted' if selected_trace is None else 'ticket-found'
    require(search['outcome'] == expected_outcome, 'search outcome')
    if selected_trace is None:
        require(len(search['attempts']) == LIMIT, 'exhaustion requires the entire fixed cap')
        require(row['proof'] is None and row['precheck'] is None and row['measurements'] == [],
                'exhaustion cannot acquire a proof or receiver measurements')
        encoding_ns = 0
    else:
        proof = row['proof']
        exact(proof, ('bytes', 'sha256', 'encoding_ns'), 'proof')
        integer(proof['bytes'], 'proof width')
        require(proof['bytes'] == PROOF_BYTES and proof['sha256'] == digest(prefix + selected_trace),
                'fresh proof byte identity')
        encoding_ns = integer(proof['encoding_ns'], 'proof encoding duration')
        require(selected_trace != independent_trace(class_name, challenge.hex()),
                'must independently establish Transcript, not assume every guess is invalid')
        exact(row['precheck'], ('actual_result', 'elapsed_ns'), 'precheck')
        require(row['precheck']['actual_result'] == 'FilterPassed', 'cheap rejection cannot stand in for full replay')
        integer(row['precheck']['elapsed_ns'], 'precheck duration')
        measurements = row['measurements']
        require(type(measurements) is list and len(measurements) == len(KERNELS), 'both receiver kernels')
        for position, measured in enumerate(measurements):
            exact(measured, ('position', 'kernel', 'elapsed_ns', 'actual_result', 'probe'), 'measurement')
            integer(measured['position'], 'measurement position')
            require(measured['position'] == position and measured['kernel'] == KERNELS[(position + sample) % 2],
                    'balanced fixed receiver order')
            integer(measured['elapsed_ns'], 'receiver duration', minimum=1)
            require(measured['actual_result'] == 'Transcript', 'full native Transcript refusal required')
            checked_probe(measured['probe'], challenge)
    acquisition = row['acquisition']
    exact(acquisition, ('wall_ns', 'accounted_ns', 'overhead_ns'), 'acquisition')
    for field in acquisition:
        integer(acquisition[field], 'acquisition ' + field, minimum=1 if field == 'wall_ns' else 0)
    require(acquisition['accounted_ns'] == setup['wall_ns'] + search['wall_ns'] + encoding_ns,
            'complete from-scratch acquisition cost')
    require(acquisition['wall_ns'] == acquisition['accounted_ns'] + acquisition['overhead_ns'],
            'enclosing attacker wall cost')
    return selected_trace is not None


def ratio(numerator, denominator):
    value = Fraction(numerator, denominator)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def summarize(raw):
    exact(raw, ('schema', 'profile', 'construction', 'valid_proof_preacquired', 'attempt_limit',
                'samples_per_group', 'kernels', 'metadata', 'samples', *FLAGS), 'raw campaign')
    require(raw['schema'] == SCHEMA and raw['profile'] == PROFILE, 'fixed schema/profile')
    require(raw['construction'] == 'public-inputs-zero-product-claim-fake-trace'
            and raw['valid_proof_preacquired'] is False, 'no honest proof acquisition')
    integer(raw['attempt_limit'], 'campaign cap'); integer(raw['samples_per_group'], 'campaign samples')
    require(raw['attempt_limit'] == LIMIT and raw['samples_per_group'] == SAMPLES, 'fixed campaign dimensions')
    require(raw['kernels'] == list(KERNELS), 'fixed receiver kernels')
    for flag in FLAGS:
        require(raw[flag] is False, 'diagnostic cannot grant ' + flag)
    metadata = raw['metadata']
    exact(metadata, ('arch', 'os', 'pointer_bits', 'process_id', 'debug_assertions', 'clock', 'identity_scope'), 'metadata')
    for field in ('arch', 'os'):
        require(type(metadata[field]) is str and re.fullmatch('[a-z0-9_]{1,32}', metadata[field]) is not None,
                'bounded platform ' + field)
    integer(metadata['pointer_bits'], 'pointer width')
    require(metadata['pointer_bits'] in (32, 64), 'known pointer width')
    integer(metadata['process_id'], 'process ID', minimum=1, maximum=(1 << 32) - 1)
    require(metadata['debug_assertions'] is False, 'release-mode cost diagnostic required')
    require(metadata['clock'] == 'std::time::Instant-wall-nanoseconds'
            and metadata['identity_scope'] == 'external-source-binary-resource-receipt-required', 'timing identity boundary')
    verify_reference_sources()
    require(type(raw['samples']) is list and len(raw['samples']) == len(CLASSES) * len(TARGETS) * SAMPLES,
            'complete fixed sample denominator')
    groups, cursor, replays, total_attempts = [], 0, 0, 0
    for class_name in CLASSES:
        for target in TARGETS:
            group = {'class': class_name, 'target': target, 'samples': SAMPLES, 'constructed': 0,
                     'exhausted': 0, 'all_search_attempts': 0, 'all_acquisition_wall_ns': 0,
                     'complete_acquisition_for_constructed_ns': 0, 'precheck_ns': 0,
                     'receiver_wall_ns': dict.fromkeys(KERNELS, 0)}
            for sample in range(SAMPLES):
                row = raw['samples'][cursor]; cursor += 1
                complete = validate_row(row, class_name, target, sample)
                group['all_search_attempts'] += len(row['search']['attempts'])
                group['all_acquisition_wall_ns'] += row['acquisition']['wall_ns']
                group['constructed' if complete else 'exhausted'] += 1
                if complete:
                    replays += 1
                    group['complete_acquisition_for_constructed_ns'] += row['acquisition']['wall_ns']
                    group['precheck_ns'] += row['precheck']['elapsed_ns']
                    for measured in row['measurements']:
                        group['receiver_wall_ns'][measured['kernel']] += measured['elapsed_ns']
            # Always retain exhausted acquisition cost in the campaign denominator.
            group['receiver_to_all_acquisition_ratio'] = {
                kernel: ratio(cost, group['all_acquisition_wall_ns'])
                for kernel, cost in group['receiver_wall_ns'].items()}
            group['complete_group'] = group['exhausted'] == 0
            total_attempts += group['all_search_attempts']; groups.append(group)
    return {'schema': 'pon-fresh-rejection-summary-v1', 'raw_schema': SCHEMA,
            'samples': cursor, 'independent_relation_replays': replays,
            'all_search_attempts': total_attempts, 'groups': groups,
            'complete_campaign': all(group['complete_group'] for group in groups),
            'reference_commit': REFERENCE_COMMIT, 'reference_files': REFERENCE_FILES,
            'native_source_binary_resource_authenticated': False,
            'reported_metadata': metadata, 'all_legal_strategy_cost_bound': None,
            'scope': 'reported wall timings and independent relation replay; external execution receipts required',
            **{flag: False for flag in FLAGS}}


def unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'duplicate JSON key ' + name)
        result[name] = value
    return result


def load_raw(path, expected_sha256):
    hash_text(expected_sha256, 'caller-pinned raw digest')
    data = read_regular(path.parent, path.name, RAW_LIMIT)
    require(len(data) <= RAW_LIMIT and digest(data) == expected_sha256, 'raw bytes must match caller pin')
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON ' + value)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw', type=Path)
    parser.add_argument('--raw-sha256', required=True)
    args = parser.parse_args()
    report = summarize(load_raw(args.raw, args.raw_sha256))
    report['raw_sha256'] = args.raw_sha256
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
