#!/usr/bin/env python3
"""Native negative-input costs, separate from honest-winner mutation accounting.

No honest proof is supplied to the constructor. Compare this specific bounded
constructor with actual verifier kernels, never with an asserted cheapest miner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
CLASSES = ('dense', 'zero', 'rank-one', 'sparse')
TARGETS = ('7f' + 'ff' * 31, '07' + 'ff' * 31, '00' * 31 + '01')
MODES = ('diagnose-production', 'diagnose-reference', 'diagnose-limb')
CELLS, PROOF_BYTES, SAMPLES = 4096, 49188, 9
CLOCKS = {'setup_ns', 'search_ns', 'total_ns', 'elapsed_ns', 'process_wall_ns', 'caller_material_ns'}


def require(condition, message):
    if not condition:
        raise ValueError('from-zero work: ' + message)


def natural(value):
    require(type(value) is int and 0 <= value < 1 << 128, 'nonnegative integer clock')
    return value


def h(tag, *parts):
    digest = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in parts:
        digest.update(len(part).to_bytes(4, 'little') + part)
    return digest.digest()


def material(name):
    require(name in CLASSES, 'known material')
    if name == 'zero':
        a = b = [0] * CELLS
    elif name == 'sparse':
        a = b = [int(i // 64 == i % 64) for i in range(CELLS)]
    elif name == 'rank-one':
        a = [(i // 64 + 1) * (i % 64 + 1) for i in range(CELLS)]
        b = [(i // 64 + 2) * (i % 64 + 1) for i in range(CELLS)]
    else:
        a = [i % 31 for i in range(CELLS)]
        b = [(7 * i) % 37 for i in range(CELLS)]
    return struct.pack('<4096I', *a), struct.pack('<4096I', *b)


def case(name, target, sample):
    a, b = material(name)
    task = h(b'task', a, b)
    challenge = h(b'from-zero-cost-challenge-v1', name.encode(), bytes.fromhex(target),
                  sample.to_bytes(8, 'little'))
    limit = 1 if target == TARGETS[2] else 4096
    return challenge, task, bytes.fromhex(target), a + b, limit


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field ' + key)
        result[key] = value
    return result


def load(raw):
    require(len(raw) <= 4 * 1024 * 1024, 'bounded native response')
    def invalid(value):
        raise ValueError('non-finite JSON ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def validate_construction(data, statement):
    challenge, task, target, matrices, limit = statement
    require(type(data) is dict and set(data) == {
        'schema', 'challenge', 'task', 'target', 'attempt_limit', 'setup_ns',
        'search_ns', 'total_ns', 'outcome', 'attempts', 'proof_hex',
        'honest_proof_acquired', 'acceptance_granted'}, 'construction exact fields')
    require(data['schema'] == 'pon-work-from-zero-construction-v1', 'construction schema')
    require((data['challenge'], data['task'], data['target']) ==
            (challenge.hex(), task.hex(), target.hex()), 'exact statement binding')
    require(type(data['attempt_limit']) is int and data['attempt_limit'] == limit, 'exact attempt limit')
    require(data['honest_proof_acquired'] is False and data['acceptance_granted'] is False,
            'negative input grants no acceptance')
    require(natural(data['total_ns']) >= natural(data['setup_ns']) + natural(data['search_ns']),
            'retain setup and complete search costs')
    attempts = data['attempts']
    require(type(attempts) is list and 1 <= len(attempts) <= limit, 'bounded nonempty attempts')
    selected = None
    for nonce, row in enumerate(attempts):
        trace = h(b'from-zero-fake-trace-v1', challenge, nonce.to_bytes(8, 'little'))
        ticket = h(b'ticket', challenge, trace)
        hit = target != bytes(32) and ticket <= target
        require(type(row) is dict and set(row) == {'nonce', 'trace', 'ticket', 'selected'},
                'attempt exact fields')
        require(type(row['nonce']) is int and row['nonce'] == nonce
                and row['trace'] == trace.hex() and row['ticket'] == ticket.hex()
                and row['selected'] is hit, 'all attempts independently replayed')
        if hit:
            require(nonce == len(attempts) - 1, 'stop exactly at first selected ticket')
            selected = trace
    if selected is None:
        require(len(attempts) == limit and data['outcome'] == 'exhausted'
                and data['proof_hex'] is None, 'retain exhaustion without invented proof')
        return None
    proof = b'PNW1' + matrices + bytes(4 * CELLS) + selected
    require(len(proof) == PROOF_BYTES and data['proof_hex'] == proof.hex()
            and data['outcome'] == 'prefilter-candidate', 'canonical invented-zero-C proof only')
    return proof


def validate_diagnosis(data, mode):
    require(type(data) is dict and set(data) == {'schema', 'mode', 'result', 'elapsed_ns'},
            'diagnosis exact fields')
    require(data['schema'] == 'pon-work-verifier-diagnostic-v1' and data['mode'] == mode,
            'same selected native verifier')
    natural(data['elapsed_ns'])
    # An accidental matching transcript, other error, or acceptance is retained
    # as a failed experiment, not reclassified to fit the expected cost category.
    require(data['result'] == 'Transcript', 'actual full replay must reject the false trace')


def projection(value):
    if isinstance(value, dict):
        return {key: projection(item) for key, item in value.items() if key not in CLOCKS}
    if isinstance(value, list):
        return [projection(item) for item in value]
    return value


def summarize(samples):
    groups = []
    for name in CLASSES:
        for target in TARGETS:
            rows = [row for row in samples if row['class'] == name and row['target'] == target]
            require(len(rows) == SAMPLES and {row['sample'] for row in rows} == set(range(SAMPLES)),
                    'complete cost cohort')
            candidates = sum(row['construction']['outcome'] == 'prefilter-candidate' for row in rows)
            construction = sum(row['construction']['total_ns'] for row in rows)
            verifiers = {}
            for mode in MODES:
                measured = [v for row in rows for v in row['verifications'] if v['mode'] == mode]
                require(len(measured) == candidates, 'every candidate checked by each native kernel')
                elapsed = sum(v['elapsed_ns'] for v in measured)
                # Exhausted attempts remain in construction, never in a fabricated
                # verifier denominator. Zero denominators stay unknown, not zero.
                verifiers[mode] = {'calls': len(measured), 'elapsed_ns': elapsed,
                    'verifier_to_native_construction_ratio':
                        {'numerator': elapsed, 'denominator': construction}
                        if candidates and construction else None}
            groups.append({'class': name, 'target': target, 'samples': len(rows),
                'candidates': candidates, 'exhausted': len(rows) - candidates,
                'attempts': sum(len(row['construction']['attempts']) for row in rows),
                'setup_ns': sum(row['construction']['setup_ns'] for row in rows),
                'search_ns': sum(row['construction']['search_ns'] for row in rows),
                'native_construction_ns': construction,
                'caller_material_ns': sum(row['caller_material_ns'] for row in rows),
                'constructor_process_wall_ns': sum(row['process_wall_ns'] for row in rows),
                'verifiers': verifiers})
    return groups


def invoke(binary, mode, request, directory, label, observations):
    start = time.monotonic_ns()
    observed = {'mode': mode, 'input_sha256': hashlib.sha256(request).hexdigest(),
                'exit_code': None, 'timed_out': False}
    observations.append(observed)
    (directory / (label + '.input')).write_bytes(request)
    try:
        result = subprocess.run([str(binary), mode], input=request, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
        out, err = result.stdout, result.stderr
        observed['exit_code'] = result.returncode
    except subprocess.TimeoutExpired as error:
        out, err = error.stdout or b'', error.stderr or b''
        observed['timed_out'] = True
    except OSError as error:
        out, err = b'', str(error).encode()
    observed['process_wall_ns'] = time.monotonic_ns() - start
    (directory / (label + '.stdout')).write_bytes(out)
    (directory / (label + '.stderr')).write_bytes(err)
    require(observed['exit_code'] == 0 and not observed['timed_out'], 'native operation failed: ' + label)
    return load(out), observed['process_wall_ns']


def run(args):
    # Existing collector primitives retain exact compiler, ELF, source and failure
    # identities. This companion has its own manifest; old reports are unchanged.
    from ci_observation import source, digest
    from check_cross_arch_cost import ARCHITECTURES, elf_machine
    spec = ARCHITECTURES[args.arch]
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'pon-work-from-zero-execution-v1', 'result': 'FAIL',
              'architecture': args.arch, 'observations': [], 'samples': [],
              'work_hardness_accepted': False, 'fastest_adversary_qualified': False,
              'worst_case_rejection_qualified': False, 'public_service_measured': False,
              'production_activation': False,
              'timing_scope': 'cold-native-construction-and-kernel; process-wall-separate; no-honest-acquisition',
              'source_before': None, 'scalar_relation_replayed': False,
              'binary_source_authenticity_established_by_collector': False,
              'runner': {key: os.environ.get(key) for key in
                         ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY',
                          'RUNNER_ARCH', 'TRNM_COST_RUNNER_LABEL')}}
    binary = None
    try:
        import platform
        require(platform.machine() == spec['machine'] and platform.system() == 'Linux', 'native host')
        report['source_before'] = source()
        require(report['source_before']['source_state'] == 'committed-clean', 'frozen source required')
        binary = args.binary.resolve()
        report['binary_sha256_before'] = digest(binary)
        require(elf_machine(binary) == spec['elf_machine'], 'native ELF architecture')
        sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
        from work_oracle import verify as scalar_verify
        for name in CLASSES:
            for target in TARGETS:
                for sample in range(SAMPLES):
                    started = time.monotonic_ns()
                    statement = case(name, target, sample)
                    caller_material_ns = time.monotonic_ns() - started
                    challenge, task, threshold, matrices, limit = statement
                    request = challenge + task + threshold + matrices + limit.to_bytes(8, 'little')
                    label = f'{name}-{target[:2]}-{sample}'
                    native, wall = invoke(binary, 'forge-transcript', request, output, label,
                                          report['observations'])
                    row = {'class': name, 'target': target, 'sample': sample,
                           'construction': native, 'process_wall_ns': wall,
                           'caller_material_ns': caller_material_ns, 'verifications': [],
                           'scalar_result': None}
                    report['samples'].append(row)
                    proof = validate_construction(native, statement)
                    if proof is None:
                        continue
                    request = challenge + task + threshold + proof
                    for position in range(3):
                        mode = MODES[(position + sample) % 3]
                        observed, wall = invoke(binary, mode, request, output, label + '-' + mode,
                                               report['observations'])
                        row['verifications'].append({**observed, 'process_wall_ns': wall})
                        validate_diagnosis(observed, mode)
                    try:
                        scalar_verify(challenge, task, threshold, proof)
                    except ValueError as error:
                        row['scalar_result'] = str(error)
                    else:
                        row['scalar_result'] = 'ACCEPTED'
                    require(row['scalar_result'] == 'TRANSCRIPT', 'independent scalar rejection')
        report['groups'] = summarize(report['samples'])
        report['scalar_rejection_count'] = sum(row['scalar_result'] == 'TRANSCRIPT' for row in report['samples'])
        report['scalar_relation_replayed'] = True
        report['result'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        try:
            report['source_after'] = source()
            report['binary_sha256_after'] = digest(binary) if binary is not None else None
            if (report['source_before'] != report['source_after'] or
                    report.get('binary_sha256_before') != report['binary_sha256_after']):
                report['result'] = 'FAIL'
                report['source_or_binary_changed'] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report['result'] = 'FAIL'
            report['final_identity_error'] = str(error)
        report['artifact_sha256'] = {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'result': report['result'], 'receipt': str(output),
                      'samples': len(report['samples']), 'error': report.get('error')}))
    return 0 if report['result'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--arch', choices=('x64', 'arm64'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
