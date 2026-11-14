#!/usr/bin/env python3
"""Replay pinned carry/packed full proofs through a guarded successor verifier.

Per profile: one positive, the original 11 ordinary controls, two typed late
arithmetic controls, and four arithmetic shape controls. This generates zero
new cryptographic proofs. A passing finite control set is not NI/PQ security,
Node qualification, or a global malicious-input resource bound.

Only Python's standard library and /usr/bin/time are required. Original proof
paths may differ from the source checkout. The statement defaults to the
proof directory's sibling prepared/statement.bin, as in the retained ABBA runs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback

Q = 4_294_967_291
GOLDILOCKS = 18_446_744_069_414_584_321
INPUT_BYTES = 49_506
PREFIX_BYTES = 131_072
PUBLIC_BYTES = 377_290
PUBLIC_SHA256 = 'd8b06f64c5e3ff0242e1fe30110280be56fe9eca9cfb55086f7ed7ab5bdb3b6c'
SHA_PROOF_SHA256 = 'ca4867c63de4f0d247930944d4c47d87342a4945a399abe9f8a57eba2502e33c'
FIXTURE_PINS = {
    '.expected-header.bin': (318, '7b96038f228a1eedccf7b29ffc54802aba691be7259e33937846c6bf6126d78f'),
    '.artifacts.bin': (64, '802adcdd951cfb4cd7271df22c3bca6af66fee9f40454c74f8b5ff2c98a1b683'),
    '.input.bin': (INPUT_BYTES, '67b74fa2f417c0240d974e5ecea410d2b68d97d6dde667603aeb4d7ce59036cb'),
    '.prefix.bin': (PREFIX_BYTES, '2d3876ae3aeaff654b373acf3ad71720428890fe4373a51ca93c9126b9fd5f96'),
}
PROFILES = {
    'carry': {
        'binary': 'carry_backend', 'magic': b'W1P3ACR2', 'degree_bits': 17,
        'arith_bytes': 306_213,
        'arith_sha256': '26a7d0848b436a547ea5add19cf882ffb5b5b4621993f5511b93542053d9ab68',
        'hash_bound_proof_source_commit': 'ac4927c52266e7bd1fae547f92a1d0753f4f96d6',
        'proofs': '/home/qian-qi/work/chain-w1-carry-measurements-20261108-f16ac/01-B/proof',
    },
    'packed': {
        'binary': 'packed_carry_backend', 'magic': b'W1P3APC3', 'degree_bits': 14,
        'arith_bytes': 453_861,
        'arith_sha256': '2b96cb7c32e34ab22ba39e1de424281b6d20b7811cff24ba769cf2e6cb67a988',
        'hash_bound_proof_source_commit': '9fe8aba32558e4f59c39b26c07ea1331b058762e',
        'proofs': '/home/qian-qi/work/chain-w1-packed-carry-measurements-20261108-f16ac/01-B/proof',
    },
}
PHASES = [
    'bounded_read_decode_and_proof_shape',
    'canonical_plans_and_public_only_sha_air',
    'sha_verifier_independent_preprocessing_setup',
    'sha_stark_verify',
    'arith_verifier_independent_preprocessing_setup',
    'arith_stark_verify',
]
LATE_MODES = [
    ('last-fold-query-value', 'FinalPolyMismatch'),
    ('last-fold-auth-sibling', 'CommitPhaseMmcsError(CapMismatch)'),
]
SHAPE_MODES = [
    'trace-width-short', 'last-input-row-short',
    'last-fold-extra-query', 'final-polynomial-extra',
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def save_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def binding(path):
    return {'bytes': path.stat().st_size, 'sha256': hash_file(path)}


def changed_word(data, offset):
    check(0 <= offset <= len(data) - 4, 'word mutation offset')
    value = int.from_bytes(data[offset:offset + 4], 'little')
    check(value < Q, 'word mutation input must be canonical')
    return data[:offset] + ((value + 1) % Q).to_bytes(4, 'little') + data[offset + 4:]


def flipped(data, offset):
    check(0 <= offset < len(data), 'byte mutation offset')
    return data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1:]


def changed_first_commitment(data):
    # Preserve the vector count and canonical field encoding: this is not shape corruption.
    check(len(data) >= 24 and int.from_bytes(data[8:16], 'little') == 1,
          'unexpected pinned first commitment layout')
    value = int.from_bytes(data[16:24], 'little')
    check(value < GOLDILOCKS, 'first commitment word is noncanonical')
    return data[:16] + ((value + 1) % GOLDILOCKS).to_bytes(8, 'little') + data[24:]


def execute(label, command, logs, env, timeout):
    """Retain every process outcome, including crashes/timeouts; callers classify it."""
    case = logs / label
    case.mkdir()
    stdout, stderr, usage = case / 'stdout.jsonl', case / 'stderr.txt', case / 'time.txt'
    wrapped = ['/usr/bin/time', '-v', '-o', str(usage), *map(str, command)]
    utc_start = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    timed_out = False
    print(json.dumps({'running': label, 'command': list(map(str, command))}), flush=True)
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(wrapped, stdout=out, stderr=err, env=env,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = process.wait()
    seconds = time.perf_counter() - start
    objects = []
    for line in stdout.read_text(encoding='utf-8', errors='replace').splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                objects.append(value)
        except json.JSONDecodeError:
            pass
    resource_text = usage.read_text(errors='replace') if usage.exists() else ''
    peak = re.search(r'Maximum resident set size \(kbytes\): (\d+)', resource_text)
    observation = {
        'label': label, 'command': list(map(str, command)), 'utc_start': utc_start,
        'exit_code': code, 'timed_out': timed_out, 'outer_wall_seconds': seconds,
        'final': next((value for value in reversed(objects) if 'qualification' in value), None),
        'phase_events': [value for value in objects if 'phase' in value],
        'peak_rss_kib': int(peak.group(1)) if peak else None,
        'resource_text': resource_text,
        'stdout_sha256': hash_file(stdout), 'stderr_sha256': hash_file(stderr),
        'resource_sha256': hash_file(usage) if usage.exists() else None,
    }
    save_new(case / 'observation.json', observation)
    print(json.dumps({'finished': label, 'exit_code': code, 'timed_out': timed_out,
                      'outer_wall_seconds': seconds}), flush=True)
    return observation


def phase_names(observation):
    return [event['phase'] for event in observation['phase_events']]


def require_final(observation, code, status=None):
    check(not observation['timed_out'] and observation['exit_code'] == code,
          f"wrong process outcome: exit={observation['exit_code']}, timeout={observation['timed_out']}")
    final = observation['final']
    check(isinstance(final, dict) and final.get('qualification') == 'HOLD_NO_GO',
          'missing independent HOLD_NO_GO final verdict')
    if status is not None:
        check(final.get('status') == status, 'wrong final status')
    return final


def require_rejection(observation, prefix, expected_phases, subtype=None):
    final = require_final(observation, 1, 'REJECTED_OR_FAILED')
    error = final.get('error', '')
    check(isinstance(error, str) and error.startswith(prefix), 'wrong rejection frontier: ' + str(error))
    check(phase_names(observation) == expected_phases,
          'wrong phase sequence: ' + repr(phase_names(observation)))
    if subtype is not None:
        check(subtype in error and 'SiblingCountMismatch' not in error,
              'wrong late subtype: ' + error)
    return error


def populate(case, retained, replacements=None, omitted=()):
    """Only mutation targets are new bytes; unchanged inputs are linked read-only by usage."""
    replacements = replacements or {}
    case.mkdir()
    for name, source in retained.items():
        if name in omitted or name in replacements:
            continue
        try:
            os.link(source, case / name)
        except OSError:
            with source.open('rb') as src, (case / name).open('xb') as dst:
                shutil.copyfileobj(src, dst)
    for name, data in replacements.items():
        with (case / name).open('xb') as stream:
            stream.write(data)


def ordinary_controls(public, sp, ap, header, artifacts):
    # Same names, offsets and semantics as run_successor_controls.py / run_campaign.py.
    return [
        ('public-extra-byte', {'statement.bin': public + b'\0'}, 'bounded file length', []),
        ('sha-proof-truncated', {'sha.proof.bin': sp[:-32]}, 'proof decoding: wire admission', []),
        ('sha-proof-trailing-byte', {'sha.proof.bin': sp + b'\0'}, 'proof decoding: wire admission', []),
        ('sha-commitment-changed', {'sha.proof.bin': changed_first_commitment(sp)}, 'sha proof rejected:', PHASES[:4]),
        ('arith-commitment-changed', {'arith.proof.bin': changed_first_commitment(ap)}, 'arithmetic proof rejected:', PHASES),
        ('last-C-changed', {'statement.bin': changed_word(public, 8 + INPUT_BYTES - 32 - 4)}, 'arithmetic proof rejected:', PHASES),
        ('last-prefix-changed', {'statement.bin': changed_word(public, 8 + INPUT_BYTES + PREFIX_BYTES - 4)}, 'sha proof rejected:', PHASES[:4]),
        ('last-AB-intermediate-changed', {'statement.bin': changed_word(public, PUBLIC_BYTES - 4)}, 'arithmetic proof rejected:', PHASES),
        ('unused-noise-tail-changed', {'statement.bin': flipped(public, 8 + INPUT_BYTES + PREFIX_BYTES + 32 + 4 * 128 * 32 - 1)}, 'sha proof rejected:', PHASES[:4]),
        ('wrong-independent-artifacts', {'expected-artifacts.bin': flipped(artifacts, 63)}, 'sha proof rejected:', PHASES[:4]),
        ('wrong-independent-header', {'expected-header.bin': flipped(header, 317)}, 'IndependentHeader', PHASES[:1]),
    ]


def validate_late_mutation(observation, profile, mode, original, mutated):
    final = require_final(observation, 0, 'MUTATED_RESEARCH_PROOF_ONLY')
    check(final.get('component') == profile['name'] and final.get('mode') == mode,
          'mutator selected a different component/mode')
    check(final.get('degree_bits') == profile['degree_bits'] and final.get('queries') == 64,
          'mutator selected a different FRI profile')
    check(final.get('transcript_fields_unchanged') is True and
          final.get('public_and_expected_inputs_must_remain_unchanged') is True,
          'typed mutation did not preserve transcript fields')
    check(len(original) == len(mutated) == final.get('proof_bytes_before') == final.get('proof_bytes_after'),
          'late control changed proof length')
    check(original[:8] == mutated[:8] == profile['magic'], 'late control changed envelope domain')
    difference = sum(a != b for a, b in zip(original, mutated))
    check(difference > 0 and difference == final.get('changed_byte_count'), 'late change count mismatch')
    check(final.get('proof_sha256_before') == profile['arith_sha256'] and
          final.get('proof_sha256_after') == sha(mutated), 'late mutation hash mismatch')
    mutation = final.get('mutation', {})
    if mode == 'last-fold-query-value':
        check(mutation.get('round_index_zero_based') == profile['degree_bits'] - 1 and
              mutation.get('query_index_zero_based') == 63 and
              mutation.get('sibling_value_index_zero_based') == 0,
              'mutation did not target the final fold of query 63')
    else:
        counts = mutation.get('sibling_hash_counts_by_round', [])
        check(len(counts) == profile['degree_bits'] and all(isinstance(n, int) and n >= 0 for n in counts),
              'bad shared multiproof frontier metadata')
        nonempty = [index for index, count in enumerate(counts) if count]
        check(bool(nonempty), 'missing shared authentication frontier')
        last = nonempty[-1]
        check(mutation.get('round_index_zero_based') == last and
              mutation.get('sibling_hash_index_zero_based') == counts[last] - 1 and
              mutation.get('digest_element_index_zero_based') == 3 and
              mutation.get('query_index_zero_based') is None,
              'mutation did not target the last shared authentication digest')


def source_snapshot(source, external_paths):
    files = {Path(__file__).resolve(), source / 'Cargo.toml', source / 'Cargo.lock'}
    for directory in ('src', 'tests', 'examples'):
        files.update((source / directory).rglob('*.rs'))
    files.update(external_paths)
    # Reference harnesses are pinned if present, but are not imported/executed.
    files.update(path for name in ('run_campaign.py', 'run_successor_controls.py',
                                  'run_wire_admission_campaign.py') if (path := source / name).is_file())
    bindings = {}
    for path in sorted(files):
        try:
            bindings[str(path)] = binding(path)
        except OSError as error:
            bindings[str(path)] = {'error': str(error)}
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    return {'source_git_head': head, 'files': bindings}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--source', type=Path, required=True, help='guarded successor standalone crate')
    result.add_argument('--output', type=Path, required=True, help='new directory; existing output is refused')
    result.add_argument('--fixture-stem', type=Path, help='defaults to SOURCE/fixtures/retained')
    result.add_argument('--late-mutator', type=Path)
    result.add_argument('--shape-mutator', type=Path)
    result.add_argument('--expected-source-head', help='optional exact 40-hex successor Git HEAD pin')
    result.add_argument('--timeout-seconds', type=float, default=60.0)
    result.add_argument('--threads', type=int, default=8)
    for name, profile in PROFILES.items():
        result.add_argument('--' + name + '-binary', type=Path)
        result.add_argument('--' + name + '-proofs', type=Path, default=Path(profile['proofs']))
        result.add_argument('--' + name + '-statement', type=Path)
    for name in ('carry', 'packed', 'late-mutator', 'shape-mutator'):
        result.add_argument('--expected-' + name + '-sha256', help='optional exact executable SHA256 pin')
    return result


def run(args):
    check(args.timeout_seconds > 0 and args.threads > 0, 'timeout and threads must be positive')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve(strict=True)
    executable_dir = source / 'target/release/examples'
    late_mutator = (args.late_mutator or executable_dir / 'mutate_last_query').resolve(strict=True)
    shape_mutator = (args.shape_mutator or executable_dir / 'mutate_structure').resolve(strict=True)
    stem = args.fixture_stem or source / 'fixtures/retained'
    fixtures = {suffix: Path(str(stem) + suffix).resolve(strict=True) for suffix in FIXTURE_PINS}
    header, artifacts = fixtures['.expected-header.bin'], fixtures['.artifacts.bin']
    profiles = []
    for name, definition in PROFILES.items():
        proofs = getattr(args, name + '_proofs').resolve(strict=True)
        statement = (getattr(args, name + '_statement') or proofs.parent / 'prepared/statement.bin').resolve(strict=True)
        binary = (getattr(args, name + '_binary') or executable_dir / definition['binary']).resolve(strict=True)
        profiles.append(dict(definition, name=name, binary_path=binary, proof_dir=proofs,
                             retained={'statement.bin': statement,
                                       'sha.proof.bin': (proofs / 'sha.proof.bin').resolve(strict=True),
                                       'arith.proof.bin': (proofs / 'arith.proof.bin').resolve(strict=True)}))
    executables = {'carry': profiles[0]['binary_path'], 'packed': profiles[1]['binary_path'],
                   'late_mutator': late_mutator, 'shape_mutator': shape_mutator}
    external = set(fixtures.values()) | set(executables.values())
    external.update(path for profile in profiles for path in profile['retained'].values())
    before = source_snapshot(source, external)
    save_new(output / 'source-before.json', before)
    records, failures = [], []
    env = dict(os.environ, RAYON_NUM_THREADS=str(args.threads), LC_ALL='C')
    counts = {'verifier_processes': 0, 'mutator_processes': 0, 'mutant_envelopes_written': 0}

    def case(label, category, body):
        record = {'label': label, 'category': category, 'passed': False}
        try:
            body(record)
            record['passed'] = True
        except Exception as error:
            record['failure'] = str(error)
            record['traceback'] = traceback.format_exc()
            failures.append({'label': label, 'error': str(error)})
        records.append(record)
        save_new(output / (label + '.result.json'), record)

    def launch(label, command, logs, kind):
        counts[kind + '_processes'] += 1
        return execute(label, command, logs, env, args.timeout_seconds)

    try:
        check(all('error' not in value for value in before['files'].values()), 'unreadable source/input/binary')
        if args.expected_source_head:
            check(re.fullmatch(r'[0-9a-f]{40}', args.expected_source_head) is not None and
                  before['source_git_head'] == args.expected_source_head, 'successor source HEAD mismatch')
        for name, path in executables.items():
            expected = getattr(args, 'expected_' + name + '_sha256')
            if expected:
                check(re.fullmatch(r'[0-9a-f]{64}', expected) is not None and hash_file(path) == expected,
                      'executable pin mismatch: ' + name)
        for suffix, (size, expected) in FIXTURE_PINS.items():
            check(binding(fixtures[suffix]) == {'bytes': size, 'sha256': expected}, 'independent fixture mismatch: ' + suffix)
        for profile in profiles:
            expected = {
                'statement.bin': (PUBLIC_BYTES, PUBLIC_SHA256),
                'sha.proof.bin': (4_356_101, SHA_PROOF_SHA256),
                'arith.proof.bin': (profile['arith_bytes'], profile['arith_sha256']),
            }
            for name, (size, digest) in expected.items():
                check(binding(profile['retained'][name]) == {'bytes': size, 'sha256': digest},
                      profile['name'] + ': historical input mismatch: ' + name)
            check(profile['retained']['arith.proof.bin'].read_bytes()[:8] == profile['magic'], 'arithmetic magic mismatch')
        save_new(output / 'provenance.json', {
            'schema': 'w1-carry-guarded-successor-controls-v1', 'qualification': 'HOLD_NO_GO',
            'source_git_head': before['source_git_head'], 'source_before': 'source-before.json',
            'machine': platform.uname()._asdict(), 'python': sys.version,
            'rayon_num_threads': args.threads, 'process_timeout_seconds': args.timeout_seconds,
            'cpu_affinity': sorted(os.sched_getaffinity(0)), 'host_exclusive': False,
            'historical_provenance_unchanged': True,
            'hash_bound_proof_source_commits': {p['name']: p['hash_bound_proof_source_commit'] for p in profiles},
            'retained_statement_sha256': PUBLIC_SHA256, 'retained_sha_proof_sha256': SHA_PROOF_SHA256,
            'retained_arith_proof_sha256': {p['name']: p['arith_sha256'] for p in profiles},
            'successor_binary_sha256': {name: hash_file(path) for name, path in executables.items()},
            'new_proofs_generated': 0, 'independent_input_tasks': 1,
            'planned_counts': {'positive': 2, 'ordinary': 22, 'late': 4, 'shape': 8,
                               'verifier_processes': 36, 'mutator_processes': 12},
            'scope': 'two finite arithmetic profiles; SHA late/shape controls are not repeated here',
            'global_malicious_rejection_cost_bound': False, 'production_node_admission': False,
            'complete_noninteractive_security_claim': False, 'PQ128_claim': False,
        })
        for profile in profiles:
            name, binary = profile['name'], profile['binary_path']
            retained = profile['retained']
            directory = output / name
            directory.mkdir()
            cases, logs = directory / 'cases', directory / 'processes'
            cases.mkdir()
            logs.mkdir()
            public, sp, ap = (retained[key].read_bytes() for key in ('statement.bin', 'sha.proof.bin', 'arith.proof.bin'))

            def positive(record):
                obs = launch('positive', [binary, 'verify', retained['statement.bin'], header, artifacts,
                                          profile['proof_dir']], logs, 'verifier')
                record['observation'] = obs
                final = require_final(obs, 0, 'VERIFIED_COMPLETE_W1_RESEARCH_ONLY')
                check(phase_names(obs) == PHASES, 'positive did not reach complete SHA+arithmetic verification')
                check(final.get('statement_sha256') == PUBLIC_SHA256 and
                      final.get('sha_proof_sha256') == SHA_PROOF_SHA256 and
                      final.get('arith_proof_sha256') == profile['arith_sha256'], 'positive reported wrong input hashes')
                wire = final.get('wire_admission', {})
                check(wire.get('schema') == 'w1-fixed-p3-wire-admission-v2' and
                      wire.get('structural_admission_only') is True and
                      wire.get('global_rejection_cost_bound') is False,
                      'positive lacks guarded fixed-profile admission evidence')
                check(final.get('preprocessing_source') == 'canonical public statement plus independent expected inputs; rebuilt in this process',
                      'positive preprocessing provenance changed')
            case(name + '-positive', 'positive', positive)

            for label, replacements, prefix, phases in ordinary_controls(public, sp, ap, header.read_bytes(), artifacts.read_bytes()):
                def ordinary(record):
                    folder = cases / label
                    populate(folder, retained, replacements)
                    ch = folder / 'expected-header.bin' if 'expected-header.bin' in replacements else header
                    ca = folder / 'expected-artifacts.bin' if 'expected-artifacts.bin' in replacements else artifacts
                    obs = launch(label, [binary, 'verify', folder / 'statement.bin', ch, ca, folder], logs, 'verifier')
                    record.update(expected_error_prefix=prefix, expected_phases=phases, observation=obs)
                    require_rejection(obs, prefix, phases)
                case(name + '-' + label, 'ordinary', ordinary)

            for mode, subtype in LATE_MODES:
                label = 'arith-' + mode
                def late(record):
                    folder = cases / label
                    populate(folder, retained, omitted=('arith.proof.bin',))
                    mutation = launch('mutate-' + label, [late_mutator, mode, retained['arith.proof.bin'],
                                                         folder / 'arith.proof.bin'], logs, 'mutator')
                    record['mutation'] = mutation
                    if (folder / 'arith.proof.bin').is_file():
                        counts['mutant_envelopes_written'] += 1
                    validate_late_mutation(mutation, profile, mode, ap, (folder / 'arith.proof.bin').read_bytes())
                    obs = launch(label, [binary, 'verify', folder / 'statement.bin', header, artifacts, folder], logs, 'verifier')
                    record.update(expected_error_prefix='arithmetic proof rejected:', expected_subtype=subtype,
                                  expected_phases=PHASES, observation=obs)
                    require_rejection(obs, 'arithmetic proof rejected:', PHASES, subtype)
                case(name + '-' + label, 'late', late)

            for mode in SHAPE_MODES:
                label = 'shape-' + mode
                def shape(record):
                    folder = cases / label
                    populate(folder, retained, omitted=('arith.proof.bin',))
                    mutation = launch('mutate-' + label, [shape_mutator, name, mode, retained['arith.proof.bin'],
                                                         folder / 'arith.proof.bin'], logs, 'mutator')
                    record['mutation'] = mutation
                    if (folder / 'arith.proof.bin').is_file():
                        counts['mutant_envelopes_written'] += 1
                    info = require_final(mutation, 0)
                    changed = folder / 'arith.proof.bin'
                    check(info.get('schema') == 'w1-fixed-wire-mutation-v1' and
                          info.get('component') == name and info.get('mode') == mode and
                          info.get('input_sha256') == profile['arith_sha256'] and
                          info.get('output_sha256') == hash_file(changed) and
                          info.get('input_bytes') == len(ap) and info.get('output_bytes') == changed.stat().st_size and
                          info.get('cryptographic_rejection_not_executed') is True,
                          'wrong shape mutation contract')
                    check(info['output_sha256'] != info['input_sha256'], 'shape mutator did not change bytes')
                    obs = launch(label, [binary, 'verify', folder / 'statement.bin', header, artifacts, folder], logs, 'verifier')
                    record.update(expected_phases=[], observation=obs)
                    error = require_rejection(obs, 'proof decoding: wire admission', [])
                    refusal = f"wire admission at {info['wire_refusal_offset']}: {info['wire_refusal_reason']}"
                    check(refusal in error, 'verifier did not refuse at the typed shape frontier')
                    check(not (obs['final'] or {}).get('timings'), 'shape refusal carried completed phase timings')
                case(name + '-' + label, 'shape', shape)
    except Exception as error:
        failures.append({'label': 'campaign-setup-or-dispatch', 'error': str(error),
                         'traceback': traceback.format_exc()})
    finally:
        try:
            after = source_snapshot(source, external)
        except Exception as error:
            after = {'error': str(error), 'traceback': traceback.format_exc()}
        save_new(output / 'source-after.json', after)
        intact = before == after
        if not intact:
            failures.append({'label': 'source-binary-input-integrity', 'error': 'pre/post source, binary or original input pins changed'})
        planned = {'positive': 2, 'ordinary': 22, 'late': 4, 'shape': 8}
        observed = {kind: sum(record['category'] == kind for record in records) for kind in planned}
        passed = {kind: sum(record['category'] == kind and record['passed'] for record in records) for kind in planned}
        all_pass = not failures and passed == planned and counts['verifier_processes'] == 36 and counts['mutator_processes'] == 12
        summary = {
            'schema': 'w1-carry-guarded-controls-summary-v1', 'qualification': 'HOLD_NO_GO',
            'control_campaign_status': 'PASS' if all_pass else 'FAILED',
            'planned_counts': planned, 'observed_counts': observed, 'passed_counts': passed,
            **counts, 'new_proofs_generated': 0, 'independent_input_tasks': 1,
            'source_before_after_equal': intact, 'records': records, 'failures': failures,
            'global_malicious_rejection_cost_bound': False, 'production_node_admission': False,
            'complete_noninteractive_security_claim': False, 'PQ128_claim': False,
            'warning': 'Finite successor replays and observed resource costs; no latest-rejection maximum, global budget or qualification.',
        }
        save_new(output / 'summary.json', summary)
        print(json.dumps({key: value for key, value in summary.items() if key not in ('records', 'failures')}, ensure_ascii=False), flush=True)
    return 0 if all_pass else 1


def main():
    args = parser().parse_args()
    try:
        return run(args)
    except Exception as error:
        # Failures before source-before.json exists cannot count as completed controls.
        print(json.dumps({'status': 'HARNESS_SETUP_FAILED', 'qualification': 'HOLD_NO_GO',
                          'error': str(error), 'new_proofs_generated': 0}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
