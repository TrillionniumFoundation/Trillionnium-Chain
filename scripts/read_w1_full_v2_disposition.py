#!/usr/bin/env python3
"""Read the complete retained W1-v2 observation without promoting qualification.

This reader performs byte/accounting checks, not cryptographic verification,
new proof generation, new timing, Cell replay, or Node admission. Its historical
inputs are fixed independently of the records being interpreted. The four-second
check is a necessary latency screen for the original confirmation contract,
not a newly chosen consensus block interval or a sufficient service test.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import stat
import statistics
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'config/pon/w1-retained-disposition-v1.json'
MANIFEST_SHA256 = '322420b8b58184fa5887770f76fb1f622a5a40afafbca8f5d2ca51e268a9846f'
PROOF = 'evidence/pon-w1-full-v2-20261105/'
FAILED = 'evidence/pon-w1-v2-deadline-20261105/'
INTERRUPTED = 'evidence/pon-w1-statement-v2-20261105/continuation/checkpoint-observation-20261105.json'
PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def reject(value):
        raise ValueError('nonfinite JSON number: ' + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def read_regular(path: Path, limit: int) -> bytes:
    # Repository ancestor directories are trusted; the opened leaf is checked.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                'input is not a bounded regular file: ' + str(path))
        value = source.read(limit + 1)
        after = os.fstat(source.fileno())
        require(len(value) == before.st_size and len(value) <= limit and
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'input changed while reading: ' + str(path))
        return value


def pinned_inputs(root: Path):
    manifest_raw = read_regular(root / MANIFEST, 65536)
    require(sha(manifest_raw) == MANIFEST_SHA256, 'historical input declaration changed')
    manifest = strict_json(manifest_raw)
    require(manifest['schema'] == 'trnm-w1-retained-disposition-inputs-v1' and
            type(manifest['original_confirmation_deadline_seconds']) is int and
            manifest['original_confirmation_deadline_seconds'] == 4,
            'original confirmation screen changed')
    values = {}
    for relative, expected in manifest['inputs'].items():
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                'input path escapes repository')
        value = read_regular(root / relative, expected['bytes'])
        require(len(value) == expected['bytes'] and sha(value) == expected['sha256'],
                'historical input digest or length mismatch: ' + relative)
        values[relative] = value
    return manifest, values


def observation_files(raw: bytes, index):
    expected = {row['path']: row for row in index['observation-3']}
    require(len(expected) == len(index['observation-3']), 'duplicate archived source index')
    files = {}
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            require(member.name not in names and len(names) < 512, 'duplicate/excess archive members')
            names.add(member.name)
            require('..' not in Path(member.name).parts and not member.name.startswith('/'),
                    'unsafe archive member')
            if member.isdir():
                continue
            require(member.isfile() and member.name.startswith('observation-3/'),
                    'nonregular or foreign archive member')
            name = member.name.removeprefix('observation-3/')
            require(name in expected and member.size == expected[name]['bytes'], 'archive index mismatch')
            total += member.size
            require(member.size <= 32 * 1024 * 1024 and total <= 128 * 1024 * 1024,
                    'archive expansion exceeds bounded input')
            stream = archive.extractfile(member)
            require(stream is not None, 'missing archive file')
            value = stream.read(member.size + 1)
            require(len(value) == member.size and sha(value) == expected[name]['sha256'],
                    'raw observation digest mismatch')
            files[name] = value
    require(set(files) == set(expected), 'missing original observation file')
    return files


def integer(value, expected=None):
    require(type(value) is int and value >= 0, 'expected an exact nonnegative integer')
    require(expected is None or value == expected, 'integer count mismatch')
    return value


def positive(value):
    require(type(value) in (int, float) and math.isfinite(value) and value > 0,
            'expected a positive finite number')
    return value


def evaluate(report, controls, timeout, interrupted, raw):
    require(report['schema'] == 'TRNM-W1-COMPLETE-STAGED-RUN2' and
            report['statement_version'] == 2, 'complete v2 statement required')
    require(report['complete_proof_claim'] is True and
            report['end_to_end_observation_complete'] is True and report['error'] is None,
            'complete proof observation missing')
    integer(report['independent_full_proof_trials_observed'], 1)
    integer(report['proof_randomness_tickets'], 0)
    expected_stages = ['prepare-full-execution', 'reverify-existing-prefix'] + [
        f'prove-{i:04}' for i in range(43)] + [
        'complete-recursive-compression', 'fresh-process-strict-verification',
        'serialize-local-payloads', 'observe-local-transfer-transparent',
        'observe-local-transfer-native', 'fixed-receipt-verifier-cost',
        'native-full-verifier-cost']
    require([stage['stage'] for stage in report['stages']] == expected_stages,
            'full W1 execution, ordered segments or original post-proof stages missing')
    require([row['index'] for row in report['manifest']['segments']] == list(range(43)),
            'full ordered segment manifest missing')
    for stage in report['stages']:
        result = stage['result']
        integer(result['returncode'], 0)
        require(result['stage_process_complete'] is True and result['timed_out'] is False and
                result['error'] is None, 'incomplete proof stage')
        require(result == strict_json(raw[stage['stage'] + '/result.json']),
                'reported stage differs from original process observation')
    identity = report['identity']
    native = strict_json(raw['native-full-verifier-cost/stdout.log'])
    repeated = strict_json(raw['fixed-receipt-verifier-cost/stdout.log'])
    fresh = strict_json(raw['fresh-process-strict-verification/stdout.log'])
    observations = {'native': native, 'transparent': repeated, 'fresh': fresh}
    samples = {}
    for name, expected_count in [('native', 1000), ('transparent', 100), ('fresh', 1)]:
        value = observations[name]
        require(value['profile_id'] == PROFILE and value['admission_authorized'] is False,
                'profile or authority changed')
        integer(value['iterations'], expected_count)
        values = value['native_replay_ns' if name == 'native' else 'decode_and_verify_ns']
        require(len(values) == expected_count and all(integer(x) > 0 for x in values),
                'missing/filtered/nonpositive timing samples')
        declared = report['benchmarks'][name]
        integer(declared['iterations'], expected_count)
        require(declared['samples_ns'] == values, 'benchmark does not retain every raw sample')
        for key in ('header_sha256', 'journal_sha256', 'work_id'):
            require(value[key] == identity[key], 'raw native/proof statement identity differs')
        require(value['expected_artifacts_sha256'] == identity['external_artifacts_sha256'],
                'external public material mismatch')
        if name == 'native':
            require(value['input_sha256'] == identity['input_sha256'], 'native input mismatch')
            integer(value['input_bytes'], 49506)
            integer(value['journal_bytes'], 16882)
            integer(value['full_replay_calls'], 1001)
        else:
            require(value['receipt_sha256'] == identity['receipt_sha256'] and
                    value['image_id'] == identity['image_id'], 'fixed full proof identity mismatch')
            integer(value['independent_proof_trials'], 1)
        samples[name] = values
    require(controls['schema'] == 'TRNM-W1-V2-RECEIPT-CONTROLS1' and
            controls['profile_id'] == PROFILE and controls['all_controls_passed'] is True,
            'saved-receipt controls missing')
    for key, value in [('planned_controls', 58), ('completed_controls', 58),
                       ('positive_controls_passed', 1), ('negative_controls_passed', 57),
                       ('new_proofs_generated', 0), ('unexpected_acceptances', 0)]:
        integer(controls[key], value)
    require(len(controls['controls']) == 58 and
            len({row['name'] for row in controls['controls']}) == 58 and
            all(row['passed'] is True for row in controls['controls']), 'incomplete receipt controls')
    require(timeout['schema'] == 'TRNM-W1-V2-DEADLINE-OBSERVATION1' and
            timeout['complete_proof_claim'] is False and timeout['new_proof_trials_success'] == 0 and
            timeout['succinct_exists'] is False and 'TIMEOUT' in timeout['termination_reasons'] and
            timeout['total_wall_budget_seconds'] == 7200,
            'original deadline failure omitted or relabelled')
    require(interrupted['run_state_after_disconnect'] == 'UNKNOWN' and
            interrupted['complete_proof_observed'] is False and
            interrupted['evidence_scope'].startswith('Reconstructed solely from tool outputs'),
            'disconnected unknown observation omitted or promoted')
    native_ns = statistics.median(samples['native'])
    proof_ns = statistics.median(samples['transparent'])
    seconds = positive(report['fresh_proof_pipeline_seconds'])
    require(seconds == report['fresh_verified_receipt_observed_seconds_from_start'],
            'fresh generation clock changed')
    payloads = report['local_observations']['serialization']['payloads']
    native_bytes = integer(payloads['native']['payload_bytes'])
    proof_bytes = integer(payloads['transparent']['payload_bytes'])
    require(native_bytes > 0 and proof_bytes > 0, 'missing complete payload bytes')
    return {
        'schema': 'trnm-w1-retained-disposition-v1',
        'disposition': 'HOLD_NO_GO',
        'scope': 'historical exact-byte readback and necessary-cost veto; not a new experiment',
        'observed_complete_w1_v2_proof': True,
        'new_proofs_generated': 0,
        'cryptographic_verification_performed_by_reader': False,
        'ordinary_cell_relation_proven': False,
        'identity': identity,
        'retained_attempts': {'complete_success': 1, 'complete_deadline_failure': 1,
                              'interrupted_outcome': 'UNKNOWN',
                              'attempt_population_complete': False,
                              'all_attempts_total_cost': None,
                              'note': 'retain unknown/interrupted and failed attempts; no success rate or amortized all-attempt claim'},
        'fresh_proof_pipeline_seconds': seconds,
        'original_confirmation_deadline_seconds': 4,
        'fresh_proof_to_original_deadline_ratio': seconds / 4,
        'native_replay_samples': len(samples['native']),
        'same_receipt_replay_samples': len(samples['transparent']),
        'independent_successful_proof_trials': 1,
        'native_median_ns': native_ns,
        'transparent_median_ns': proof_ns,
        'transparent_to_native_median_ratio': proof_ns / native_ns,
        'native_local_envelope_bytes': native_bytes,
        'transparent_local_envelope_bytes': proof_bytes,
        'local_envelope_ratio': proof_bytes / native_bytes,
        'gates': {
            'original_deadline_necessary_screen': 'FAIL' if seconds > 4 else 'UNQUALIFIED',
            'same_receipt_verification_cost': 'FAIL' if proof_ns >= native_ns else 'UNQUALIFIED',
            'local_envelope_cost': 'FAIL' if proof_bytes >= native_bytes else 'UNQUALIFIED',
            'all_attempt_economics': 'UNKNOWN',
            'prover_p99': 'UNKNOWN',
            'aggregate_process_tree_resources': 'UNKNOWN',
            'ordinary_encoder_router_state_cell': 'HOLD',
            'native_admission_wan_confirmation': 'HOLD',
        },
        'production_activation': False,
        'consensus_admission': False,
        'whole_chain_quantum_security_qualified': False,
    }


def analyze(root: Path = ROOT):
    manifest, values = pinned_inputs(root)
    report = strict_json(values[PROOF + 'proof-result.json'])
    raw = observation_files(values[PROOF + 'observation-3.tar.gz'],
                            strict_json(values[PROOF + 'raw-index.json']))
    require(raw['result.json'] == values[PROOF + 'proof-result.json'], 'raw result mismatch')
    for key, name in [('receipt_sha256', 'succinct.bin'), ('input_sha256', 'input.bin'),
                      ('header_sha256', 'header.bin'), ('external_artifacts_sha256', 'expected-artifacts.bin')]:
        require(report['identity'][key] == sha(values[PROOF + name]), 'proof statement byte mismatch')
    require(values[PROOF + 'input.bin'][:318] == values[PROOF + 'header.bin'] and
            len(values[PROOF + 'input.bin']) == 49506, 'native full W1 input missing')
    timeout_full = strict_json(gzip.decompress(values[FAILED + 'result.json.gz']))
    require(timeout_full['complete_proof_claim'] is False, 'failed raw proof result promoted')
    result = evaluate(report, strict_json(values[PROOF + 'controls-result.json']),
                      strict_json(values[FAILED + 'summary.json']), strict_json(values[INTERRUPTED]), raw)
    result['input_declaration_sha256'] = MANIFEST_SHA256
    result['input_files'] = manifest['inputs']
    result['historical_prover_source_commit'] = manifest['observation_source_commit']
    result['reader_sha256'] = sha(Path(__file__).read_bytes())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.source_root)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({'schema': 'trnm-w1-retained-disposition-v1', 'disposition': 'INVALID_EVIDENCE',
                          'error': str(error), 'production_activation': False}, allow_nan=False))
        return 2
    text = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n'
    if args.out is not None:
        with args.out.open('x') as output:
            output.write(text)
    else:
        print(text, end='')
    # A valid negative readback succeeds as a reader; disposition remains NO_GO.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
