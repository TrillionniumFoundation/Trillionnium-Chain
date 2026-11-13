"""Reproduce the complete source-router relation, retaining an independent input file.

The default admission state is an explicitly local research fixture. Neither the
fixture nor a generated expected.json authenticates a live Hepta owner. Real callers
must obtain the expected contract/context from their own admitting owner.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
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
from useful_cell_attempt_journal_v1 import (AttemptJournal, MAX_BYTES as JOURNAL_LIMIT,
                                          bind_delivered_witness, inspect_acknowledged_journal)
from useful_cell_numeric_v1 import compare_behavior, evaluate_exact

DIAGNOSTIC_PATHS = (Path(__file__).resolve(),
                    ROOT / 'formal/pon-nakamoto-v1/useful_cell_attempt_journal_v1.py')
_DIAGNOSTIC_SOURCE = {path: path.read_bytes() for path in DIAGNOSTIC_PATHS}


def diagnostic_identity():
    """Do not relabel loaded diagnostics with source bytes changed during a run."""
    relation.require(all(path.read_bytes() == raw for path, raw in _DIAGNOSTIC_SOURCE.items()),
                     'DIAGNOSTIC_SOURCE_CHANGED_RESTART_REQUIRED')
    return {str(path.relative_to(ROOT)): hashlib.sha256(raw).hexdigest()
            for path, raw in _DIAGNOSTIC_SOURCE.items()}


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


def inspect_search_directory(directory, expected_path, plan_path, acknowledgement_path):
    """Replay all recorded arithmetic, including misses, against frozen inputs.

    This is an archived search inspection, not renewed deadline authority. The
    ordinary complete relation is separately verified by verify_directory.
    """
    diagnostic_identity()
    expected = read_object(expected_path, relation.CONTRACT_LIMIT)
    raw = read_bounded(directory / 'contract.json', relation.CONTRACT_LIMIT)
    before = read_object(directory / 'before-state.json', relation.CONTRACT_LIMIT)
    inputs = read_object(directory / 'proof-search-input.json', relation.WITNESS_LIMIT)
    relation.require(set(inputs) == {'model', 'rows'}, 'SEARCH_INPUT_FIELDS')
    identity = relation.current_identity()
    value = relation._bound_contract(raw, inputs['model'], inputs['rows'], before, identity)
    observed_expected = {
        'contract_id': relation.contract_id(raw), 'program_sha256': identity['program_sha256'],
        'parameters_sha256': identity['parameters_sha256'], 'before_state': before,
        'consumer': value['output']['consumer'], 'allowed_use': value['output']['allowed_use'],
        'candidate_artifact': value['output']['candidate_artifact'],
    }
    relation.require(canonical(expected) == canonical(observed_expected), 'SEARCH_EXTERNAL_CONTEXT')
    retained_plan = read_object(plan_path, relation.CONTRACT_LIMIT)
    tiles, _ = cell.build_tiles(inputs['model'], inputs['rows'])
    rebuilt = relation.reference_search_plan(raw, before, tiles, len(inputs['rows']),
                                             retained_plan['max_attempts_per_tile'])
    relation.require(canonical(retained_plan) == canonical(rebuilt), 'SEARCH_FROZEN_PLAN')
    acknowledgement = read_object(acknowledgement_path, relation.CONTRACT_LIMIT)
    report = inspect_acknowledged_journal(
        read_bounded(directory / 'proof-search.jsonl', JOURNAL_LIMIT),
        expected_plan=rebuilt, acknowledgement=acknowledgement,
        materials={tile['index']: tile['material'] for tile in tiles})
    if report['status'] == 'complete':
        for name, field, limit in (
                ('witness.json', 'witness_sha256', relation.WITNESS_LIMIT),
                ('output.json', 'output_sha256', relation.CONTRACT_LIMIT),
                ('after-state.json', 'after_state_sha256', relation.CONTRACT_LIMIT)):
            relation.require(hashlib.sha256(read_bounded(directory / name, limit)).hexdigest() ==
                             report['ending'][field], 'SEARCH_FINAL_ARTIFACT_' + field.upper())
        witness_raw = read_bounded(directory / 'witness.json', relation.WITNESS_LIMIT)
        delivered = read_object(directory / 'witness.json', relation.WITNESS_LIMIT)
        relation.require(canonical(delivered['model']) == canonical(inputs['model']) and
                         canonical(delivered['rows']) == canonical(inputs['rows']), 'SEARCH_DELIVERED_INPUTS')
        bind_delivered_witness(report, witness_raw)
    relation.require(relation.current_identity() == identity, 'SEARCH_PROGRAM_CHANGED')
    diagnostic_identity()
    return report


def run(args):
    # The repository boundary is checked before creating an observation directory.
    diagnostic_identity()
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
    # Retain the request denominator even when loading, source replay or freeze
    # fails before there is an admitted contract or a started proof search.
    deadline = args.deadline_ms if args.deadline_ms is not None else started + 600_000
    records['attempt.json'] = save(output_dir / 'attempt.json', {
        'schema': 'useful-cell-int257-v1/attempt-v2', 'started_ms': started,
        'deadline_ms': deadline, 'target': args.target, 'max_attempts': args.max_attempts,
        'requested_batch_size': args.batch_size, 'planned_tiles': 5,
        'admission_authority': 'local-reproduction-fixture', 'production_activation': False,
    })
    execution = {}
    try:
        return run_admitted(args, output_dir, records, deadline, execution)
    except BaseException as error:
        failure = {'schema': 'useful-cell-int257-v1/failed-reproduction-v2',
                   'status': 'failed', 'type': type(error).__name__, 'error': str(error),
                   'planned_tiles': 5, 'requested_batch_size': args.batch_size,
                   'fully_completed_trial_outputs': 0, 'production_activation': False}
        if (output_dir / 'admission/proof-search-plan.json').is_file():
            plan = read_object(output_dir / 'admission/proof-search-plan.json', relation.CONTRACT_LIMIT)
            failure['contract_id'] = plan['contract_id']
            # A damaged or unavailable journal is an additional retained failure,
            # never a reason to claim zero work or a successful verification.
            try:
                raw = read_bounded(output_dir / 'proof-search.jsonl', JOURNAL_LIMIT)
                acknowledgement = execution.get('search_acknowledgement')
                failure['search_acknowledgement'] = acknowledgement
                relation.require(acknowledgement is not None, 'SEARCH_ACKNOWLEDGEMENT_UNAVAILABLE')
                ack_name = 'admission/proof-search-acknowledgement.json'
                if ack_name not in records:
                    records[ack_name] = save(output_dir / ack_name, acknowledgement)
                summary = inspect_acknowledged_journal(raw, expected_plan=plan,
                                                       acknowledgement=acknowledgement)
                records['proof-search-failure-inspection.json'] = save(
                    output_dir / 'proof-search-failure-inspection.json', summary)
                failure['search'] = summary
            except BaseException as inspection_error:
                failure['journal_inspection_failure'] = {
                    'type': type(inspection_error).__name__, 'error': str(inspection_error)}
        else:
            failure['search_status'] = 'not-started'
            failure['not_run_tiles'] = 5
        failure['files'] = records
        save(output_dir / 'failure.json', failure)
        raise


def run_admitted(args, output_dir, records, deadline, execution):
    model_dir = Path(args.model_dir).resolve()
    model, rows, provenance = cell.load_inputs(
        model_dir / 'model.json', model_dir / 'consumer.json',
        model_dir / 'evaluation-bundle.json', args.bundle_hash,
        'consumer', args.offset, args.batch_size)
    artifact = artifact_id(model)
    before = {'cell_id': args.cell_id, 'generation': args.generation,
              'state_root': args.state_root, 'model_artifact': artifact}
    # One deadline, frozen before any proof generation; failed work cannot renew it.
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
    tiles, _ = cell.build_tiles(model, rows)
    plan = relation.reference_search_plan(raw, before, tiles, len(rows), args.max_attempts)
    records['admission/proof-search-plan.json'] = save(output_dir / 'admission/proof-search-plan.json', plan)
    records['proof-search-input.json'] = save(output_dir / 'proof-search-input.json',
                                             {'model': model, 'rows': rows})
    journal = AttemptJournal(output_dir / 'proof-search.jsonl')
    try:
        with journal:
            proved, prove_time = elapsed(lambda: relation.prove_reference(
                raw, model, rows, before, max_attempts=args.max_attempts,
                attempt_sink=journal.append))
    finally:
        # File contents can include a flushed but unacknowledged final line.
        # The observed fsync prefix, not parseable bytes, controls completion.
        execution['search_acknowledgement'] = journal.acknowledgement()
    records['admission/proof-search-acknowledgement.json'] = save(
        output_dir / 'admission/proof-search-acknowledgement.json', execution['search_acknowledgement'])
    journal_raw = read_bounded(output_dir / 'proof-search.jsonl', JOURNAL_LIMIT)
    records['proof-search.jsonl'] = {'bytes': len(journal_raw),
                                    'sha256': hashlib.sha256(journal_raw).hexdigest()}
    for name, value in (('witness.json', proved['witness']), ('output.json', proved['output']),
                        ('after-state.json', proved['after_state'])):
        records[name] = save(output_dir / name, value)
    verified, verify_time = elapsed(lambda: relation.verify_relation(
        raw, before, proved['output'], proved['after_state'], proved['witness'], expected=expected))
    records['verification.json'] = save(output_dir / 'verification.json', verified)
    search, search_replay_time = elapsed(lambda: inspect_search_directory(
        output_dir, output_dir / 'admission/expected.json', output_dir / 'admission/proof-search-plan.json',
        output_dir / 'admission/proof-search-acknowledgement.json'))
    relation.require(search['status'] == 'complete' and search['full_arithmetic_replay'] is True and
                     search['delivered_witness_matches_first_hits'] is True,
                     'SEARCH_JOURNAL_INCOMPLETE')
    records['proof-search-inspection.json'] = save(output_dir / 'proof-search-inspection.json', search)
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
        'schema': 'useful-cell-int257-v1/reproduction-v2', 'status': 'reference-relation-verified',
        'contract_id': expected['contract_id'], 'program_sha256': identity['program_sha256'],
        'parameters_sha256': identity['parameters_sha256'],
        'source_commit': model['source'], 'repository_head': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'admission_authority': 'local-reproduction-fixture', 'batch_size': len(rows),
        'w1_transcripts_verified': len(witness['tiles']),
        'search_attempts_by_tile': [entry['nonce'] + 1 for entry in witness['tiles']],
        'proof_search': search,
        'target': args.target, 'witness_bytes': len(proved['witness']),
        'source_replayed': verified['upstream_verified'],
        'separate_process_verified': independent_report['relation_valid'],
        'component_scope': {
            'encoder': 'frozen-public-source-token-hash-extractor',
            'mask': 'no-request-or-expert-mask-in-this-fixed-profile',
            'routing': 'exact-three-expert-argmax-lowest-index-ties',
            'state': 'complete-read-only-equality; no mutable-neuron-state',
            'stop_and_abstention': 'disabled',
            'output': 'complete-bound-batch-output; no owner effect or future model adoption',
        },
        'measurement_scope': {
            'runtime': 'local-Python-reference', 'resource_isolation_enforced': False,
            'concurrent_host_load_observed': False, 'original_fixed_host_gate': False,
            'best_known_native_implementation_measured': False,
            'cheapest_legal_advantage_rho': None, 'invalid_input_rejection_measured': False,
        },
        'timing_scope': 'local-Python-reference; parent-process CPU excludes child source replay',
        'timing': {'freeze': freeze_time, 'prove': prove_time, 'verify': verify_time,
                   'all_attempt_math_replay': search_replay_time,
                   'separate_process': independent_time, 'quality': quality_time},
        'diagnostic_source_sha256': diagnostic_identity(),
        'behavior': behavior, 'files': records,
        'qualifications': {'ordinary_hepta': False, 'bf16': False, 'succinct_proof': False,
                           'work_security': False, 'production': False, 'public_reward': False},
    }
    save(output_dir / 'report.json', report)
    return {key: report[key] for key in ('status', 'contract_id', 'program_sha256', 'batch_size',
            'w1_transcripts_verified', 'search_attempts_by_tile', 'witness_bytes',
            'source_replayed', 'separate_process_verified', 'qualifications')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', help='new directory for an actual reference proof experiment')
    mode.add_argument('--verify-dir', help='existing proof directory to verify with external context')
    mode.add_argument('--inspect-search', help='replay every saved search attempt, including misses and failures')
    parser.add_argument('--expected', help='independently retained expected context, required for verification')
    parser.add_argument('--search-plan', help='independently retained complete search plan, required for --inspect-search')
    parser.add_argument('--search-acknowledgement', help='retained fsync acknowledgement, required for --inspect-search')
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
    if args.verify_dir or args.inspect_search:
        if not args.expected:
            parser.error('verification and search inspection require independently retained --expected')
        if args.inspect_search:
            if not args.search_plan or not args.search_acknowledgement:
                parser.error('--inspect-search requires retained --search-plan and --search-acknowledgement')
            result = inspect_search_directory(Path(args.inspect_search), Path(args.expected), Path(args.search_plan),
                                               Path(args.search_acknowledgement))
        else:
            if args.search_plan or args.search_acknowledgement:
                parser.error('search plan/acknowledgement are used only with --inspect-search')
            result = verify_directory(Path(args.verify_dir), Path(args.expected))
    else:
        if args.expected or args.search_plan or args.search_acknowledgement:
            parser.error('expected context/plan/acknowledgement are used only with verification or search inspection')
        result = run(args)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
