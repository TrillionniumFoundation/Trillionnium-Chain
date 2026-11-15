"""Reproduce the complete source-router relation, retaining an independent input file.

The default admission state is an explicitly local research fixture. Neither the
fixture nor a generated expected.json authenticates a live Hepta owner. Real callers
must obtain the expected contract/context from their own admitting owner.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bounded_process import run_bounded
from contract_wire import ROOT, canonical, unique
from evaluation_bundle import (MAX_BUNDLE_BYTES, MAX_TASK_BYTES, artifact_id,
                               evaluate_bundle, read_bounded, verify_bundle)
from experiments import shared_cell_operator_v1 as cell
import useful_cell_relation_v1 as relation
from useful_cell_numeric_v1 import compare_behavior, evaluate_exact


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    with path.open('xb') as output:
        output.write(raw)
    return {'bytes': len(raw), 'sha256': relation.sha256(raw)}


def read_object(path, limit):
    return relation.strict_json(read_bounded(path, limit), limit, 'FILE')


def elapsed(call):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    value = call()
    return value, {'wall_ns': time.perf_counter_ns() - wall,
                   'process_cpu_ns': time.process_time_ns() - cpu}


def quality_replay(model_dir, bundle_hash):
    """Use the existing frozen evaluation protocol, never infer quality from proof validity."""
    raw = read_bounded(model_dir / 'evaluation-bundle.json', MAX_BUNDLE_BYTES)
    bundle = verify_bundle(raw, bundle_hash)
    calibration = json.loads(read_bounded(model_dir / 'calibration.json', MAX_TASK_BYTES),
                             object_pairs_hook=unique)
    results = {}
    for partition in ('consumer', 'evaluation_a', 'evaluation_b'):
        rows = json.loads(read_bounded(model_dir / (partition + '.json'), MAX_TASK_BYTES),
                          object_pairs_hook=unique)
        result = evaluate_bundle(raw, bundle_hash, rows, partition, calibration_rows=calibration)
        results[partition] = {
            'rows': len(rows), 'selected_reference': result['selected_reference'],
            'candidate_value': result['value_claim']['candidate_value'],
            'reference_value': result['value_claim']['reference_value'],
            'marginal_value': result['value_claim']['marginal_value'],
            'primary': result['primary'], 'marginal': result['marginal'],
        }
    return {
        'schema': 'useful-cell-int257-v1/retrospective-quality',
        'evaluation_bundle': bundle_hash, 'candidate': bundle['candidate_artifact'],
        'calibration_role': 'existing-strong-reference-selection-only',
        'partitions': results, 'independent_future_window': False,
        'confidence_calibration_evaluated': False, 'ood_evaluated': False,
        'old_task_retention_evaluated': False, 'model_reward': 0,
        'owner_adoption_authority': False,
        'scope': 'recomputed-original-retrospective-protocol; W1-proven rows are reported separately',
    }


def verify_directory(directory, expected_path):
    expected = read_object(expected_path, relation.CONTRACT_LIMIT)
    raw = read_bounded(directory / 'contract.json', relation.CONTRACT_LIMIT)
    before = read_object(directory / 'before-state.json', relation.CONTRACT_LIMIT)
    after = read_object(directory / 'after-state.json', relation.CONTRACT_LIMIT)
    output = read_object(directory / 'output.json', relation.CONTRACT_LIMIT)
    witness = read_bounded(directory / 'witness.json', relation.WITNESS_LIMIT)
    return relation.verify_relation(raw, before, output, after, witness, expected=expected)


def run(args):
    # The repository boundary is checked before creating an observation directory.
    preflight = run_bounded(['bash', 'scripts/project-preflight.sh'], b'', cwd=ROOT,
                            timeout=30, stdout_limit=8192, stderr_limit=8192)
    relation.require(preflight.returncode == 0, 'PROJECT_PREFLIGHT')
    output_dir = Path(args.out).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / 'admission').mkdir()
    records = {}
    records['preflight.json'] = save(output_dir / 'preflight.json',
                                    json.loads(preflight.stdout))
    started = time.time_ns() // 1_000_000
    model_dir = Path(args.model_dir).resolve()
    model, rows, provenance = cell.load_inputs(
        model_dir / 'model.json', model_dir / 'consumer.json',
        model_dir / 'evaluation-bundle.json', args.bundle_hash,
        'consumer', args.offset, args.batch_size)
    artifact = artifact_id(model)
    before = {'cell_id': args.cell_id, 'generation': args.generation,
              'state_root': args.state_root, 'model_artifact': artifact}
    # One deadline, frozen before any proof generation; failed work cannot renew it.
    deadline = args.deadline_ms if args.deadline_ms is not None else started + 600_000
    identity = relation.current_identity()
    raw, freeze_time = elapsed(lambda: relation.freeze_contract(
        model, rows, before, consumer=args.consumer, allowed_use='research-inference-only',
        candidate_artifact=artifact, deadline_ms=deadline, request_id=args.request_id,
        target=args.target))
    expected = {
        'contract_id': relation.contract_id(raw),
        'program_sha256': identity['program_sha256'],
        'parameters_sha256': identity['parameters_sha256'],
        'before_state': copy.deepcopy(before), 'consumer': args.consumer,
        'allowed_use': 'research-inference-only', 'candidate_artifact': artifact,
    }
    records['contract.json'] = save(output_dir / 'contract.json', raw)
    records['before-state.json'] = save(output_dir / 'before-state.json', before)
    records['admission/expected.json'] = save(output_dir / 'admission/expected.json', expected)
    records['program-identity.json'] = save(output_dir / 'program-identity.json', identity)
    records['input-provenance.json'] = save(output_dir / 'input-provenance.json', provenance)
    # Save the frozen admission first. A later failure leaves a reviewable failed attempt.
    save(output_dir / 'attempt.json', {
        'schema': 'useful-cell-int257-v1/attempt', 'started_ms': started,
        'deadline_ms': deadline, 'target': args.target, 'max_attempts': args.max_attempts,
        'admission_authority': 'local-reproduction-fixture', 'production_activation': False,
    })
    try:
        proved, prove_time = elapsed(lambda: relation.prove_reference(
            raw, model, rows, before, max_attempts=args.max_attempts))
        for name, value in (('witness.json', proved['witness']), ('output.json', proved['output']),
                            ('after-state.json', proved['after_state'])):
            records[name] = save(output_dir / name, value)
        verified, verify_time = elapsed(lambda: relation.verify_relation(
            raw, before, proved['output'], proved['after_state'], proved['witness'], expected=expected))
        records['verification.json'] = save(output_dir / 'verification.json', verified)
        # A fresh process independently reads the already frozen context and witness.
        independent, independent_time = elapsed(lambda: run_bounded(
            [sys.executable, str(Path(__file__).resolve()), '--verify-dir', str(output_dir),
             '--expected', str(output_dir / 'admission/expected.json')], b'', cwd=ROOT,
            timeout=60, stdout_limit=8192, stderr_limit=8192))
        relation.require(independent.returncode == 0, 'INDEPENDENT_PROCESS_REJECTION')
        independent_report = json.loads(independent.stdout, object_pairs_hook=unique)
        relation.require(independent_report['relation_valid'] is True and
                         independent_report['contract_id'] == expected['contract_id'],
                         'INDEPENDENT_PROCESS_CONTEXT')
        records['independent-verification.json'] = save(
            output_dir / 'independent-verification.json', independent_report)
        scalar = evaluate_exact(model, [row['x'] for row in rows])
        behavior = compare_behavior(
            scalar['logits'], proved['output']['logits'],
            reference_routes=scalar['routes'], candidate_routes=proved['output']['routes'],
            reference_stops=[False] * len(rows), candidate_stops=proved['output']['stop'])
        behavior.update({'comparison': 'same-frozen-integer-model',
                         'stop_policy': 'disabled; agreement is not a STOP-enabled-model experiment',
                         'bf16_equivalence': None})
        records['behavior.json'] = save(output_dir / 'behavior.json', behavior)
        quality, quality_time = elapsed(lambda: quality_replay(model_dir, args.bundle_hash))
        records['quality.json'] = save(output_dir / 'quality.json', quality)
        witness = json.loads(proved['witness'])
        report = {
            'schema': 'useful-cell-int257-v1/reproduction', 'status': 'reference-relation-verified',
            'contract_id': expected['contract_id'], 'program_sha256': identity['program_sha256'],
            'parameters_sha256': identity['parameters_sha256'],
            'source_commit': model['source'], 'repository_head': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'admission_authority': 'local-reproduction-fixture', 'batch_size': len(rows),
            'w1_transcripts_verified': len(witness['tiles']),
            'search_attempts_by_tile': [entry['nonce'] + 1 for entry in witness['tiles']],
            'target': args.target, 'witness_bytes': len(proved['witness']),
            'source_replayed': verified['upstream_verified'],
            'separate_process_verified': independent_report['relation_valid'],
            'timing_scope': 'local-Python-reference; parent-process CPU excludes child source replay',
            'timing': {'freeze': freeze_time, 'prove': prove_time, 'verify': verify_time,
                       'separate_process': independent_time, 'quality': quality_time},
            'behavior': behavior, 'files': records,
            'qualifications': {'ordinary_hepta': False, 'bf16': False, 'succinct_proof': False,
                               'work_security': False, 'production': False, 'public_reward': False},
        }
        save(output_dir / 'report.json', report)
        return {key: report[key] for key in ('status', 'contract_id', 'program_sha256', 'batch_size',
                'w1_transcripts_verified', 'search_attempts_by_tile', 'witness_bytes',
                'source_replayed', 'separate_process_verified', 'qualifications')}
    except Exception as error:
        save(output_dir / 'failure.json', {'status': 'failed', 'type': type(error).__name__,
                                         'error': str(error), 'contract_id': expected['contract_id'],
                                         'production_activation': False})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', help='new directory for an actual reference proof experiment')
    mode.add_argument('--verify-dir', help='existing proof directory to verify with external context')
    parser.add_argument('--expected', help='independently retained expected context, required for verification')
    parser.add_argument('--model-dir', default=str(cell.DEFAULT_MATERIAL))
    parser.add_argument('--bundle-hash', default=cell.DEFAULT_BUNDLE)
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--target', default='7f' + 'ff' * 31)
    parser.add_argument('--max-attempts', type=int, default=64)
    parser.add_argument('--consumer', default='research/source-owner-auditor-v1')
    parser.add_argument('--cell-id', default='11' * 32)
    parser.add_argument('--generation', type=int, default=0)
    parser.add_argument('--state-root', default='22' * 32)
    parser.add_argument('--request-id', default='44' * 32)
    parser.add_argument('--deadline-ms', type=int)
    args = parser.parse_args()
    if args.verify_dir:
        if not args.expected:
            parser.error('--verify-dir requires independently retained --expected')
        result = verify_directory(Path(args.verify_dir), Path(args.expected))
    else:
        if args.expected:
            parser.error('--expected is used only with --verify-dir')
        result = run(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
