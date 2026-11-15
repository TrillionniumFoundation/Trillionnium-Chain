"""Retain real V2 source/W1/state/training replay and independent cold readback.

The admitting owner here is an explicitly local fixture, not a native chain or
Hepta authorization owner. No tool is dispatched, reward granted or model
installed. An updated model really feeds a subsequent reference task, but that
does not prove a production adoption or a quality gain.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contract_wire import H, canonical
from evaluation_bundle import artifact_id
from experiments import shared_cell_operator_v1 as cell
import useful_cell_execution_v2 as execution
import useful_cell_relation_v2 as relation


def write_new(path, value):
    raw = value if type(value) is bytes else canonical(value)
    with path.open('xb') as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def read_json(path, maximum):
    with path.open('rb') as handle:
        raw = handle.read(maximum + 1)
    return relation.v1.strict_json(raw, maximum, 'READBACK')


def verify_directory(directory, expected_path):
    expected = read_json(expected_path, relation.RESULT_LIMIT)
    before = read_json(directory / 'before.json', relation.RESULT_LIMIT)
    output = read_json(directory / 'output.json', relation.RESULT_LIMIT)
    after = read_json(directory / 'after.json', relation.RESULT_LIMIT)
    with (directory / 'contract.json').open('rb') as handle:
        raw = handle.read(relation.CONTRACT_LIMIT + 1)
    with (directory / 'witness.json').open('rb') as handle:
        witness = handle.read(relation.WITNESS_LIMIT + 1)
    return relation.verify_historical_relation(raw, before, output, after, witness,
                                               expected=expected)


def run_case(root, name, model, rows, before, policy):
    directory = root / name
    directory.mkdir()
    admission = directory / 'admission'
    admission.mkdir()
    started = time.perf_counter_ns()
    cpu = time.process_time_ns()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    observation = {'case': name, 'complete': False, 'admission_authority': 'local-fixture',
                   'work_attempts': None, 'error': None, 'files': {}}
    try:
        identity = relation.current_identity()
        now = time.time_ns() // 1_000_000
        request_id = H('useful-cell-v2/local-fixture-request', name.encode(),
                       bytes.fromhex(relation.v1.digest(before))).hex()
        # All context originates here, before producing a proof. The separately
        # retained expected file is never regenerated from a received package.
        context = {
            'network': H('useful-cell-v2/local-fixture-network').hex(),
            'parent_id': H('useful-cell-v2/local-fixture-parent').hex(),
            'parent_state_root': relation.v1.digest(before),
            'block_height': 1 + before['sequence'], 'consensus_time_ms': now}
        options = {'policy': policy, 'consumer': 'local-source-router-consumer',
                   'allowed_use': 'reference-replay-only', 'request_id': request_id,
                   'issued_at_ms': now, 'deadline_ms': now + 600_000,
                   'parent_context': context, 'target': 'ff' * 32}
        raw = relation.freeze_contract(model, rows, before, **options)
        expected = {'contract_id': relation.contract_id(raw),
                    'program_sha256': identity['program_sha256'],
                    'parameters_sha256': identity['parameters_sha256'],
                    'before_state': copy.deepcopy(before), 'consumer': options['consumer'],
                    'allowed_use': options['allowed_use'], 'candidate_artifact': artifact_id(model),
                    'parent_context': copy.deepcopy(context)}
        for filename, value in [('admission/expected.json', expected), ('contract.json', raw),
                                ('before.json', before)]:
            observation['files'][filename] = write_new(directory / filename, value)
        proved = relation.prove_reference(raw, model, rows, before, max_attempts=1)
        observation['work_attempts'] = proved['work_attempts']
        for filename, value in [('output.json', proved['output']), ('after.json', proved['after_state']),
                                ('witness.json', proved['witness']), ('after-model.json', proved['after_model'])]:
            observation['files'][filename] = write_new(directory / filename, value)
        historical = relation.verify_historical_relation(raw, before, proved['output'],
                                                         proved['after_state'], proved['witness'],
                                                         expected=expected)
        live = relation.verify_live_relation(raw, before, proved['output'], proved['after_state'],
                                             proved['witness'], expected=expected)
        observation['files']['historical.json'] = write_new(directory / 'historical.json', historical)
        observation['files']['live.json'] = write_new(directory / 'live.json', live)
        command = [sys.executable, str(Path(__file__).resolve()), '--verify-dir', str(directory),
                   '--expected', str(admission / 'expected.json')]
        cold = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60, check=False)
        observation['files']['cold.stdout'] = write_new(directory / 'cold.stdout', cold.stdout)
        observation['files']['cold.stderr'] = write_new(directory / 'cold.stderr', cold.stderr)
        observation['cold_command'] = command
        observation['cold_exit_code'] = cold.returncode
        relation.require(cold.returncode == 0, 'COLD_VERIFICATION_FAILED')
        replayed = relation.v1.strict_json(cold.stdout, relation.RESULT_LIMIT, 'COLD_REPORT')
        relation.require(replayed == historical, 'COLD_REPORT_MISMATCH')
        observation.update(
            complete=True, input_rows=len(rows), program_sha256=identity['program_sha256'],
            parameters_sha256=identity['parameters_sha256'],
            before_model=artifact_id(model), after_model=artifact_id(proved['after_model']),
            actions=proved['output']['execution']['actions'],
            training=proved['output']['execution']['training'],
            rng_before=before['rng_counter'], rng_after=proved['after_state']['rng_counter'],
            relation_report=historical, target=options['target'],
            target_scope='maximal-target-correctness-control-not-work-cost')
        return proved, observation
    except BaseException as error:
        observation['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        observation['wall_ns'] = time.perf_counter_ns() - started
        observation['controller_cpu_ns'] = time.process_time_ns() - cpu
        observation['waited_child_cpu_ns'] = int(1_000_000_000 * (
            child_after.ru_utime + child_after.ru_stime - child_before.ru_utime - child_before.ru_stime))
        write_new(directory / 'observation.json', observation)


def run(output, batch_size):
    output.mkdir(parents=True, exist_ok=False)
    summary = {'schema': relation.RELATION_ID + '/experiment', 'complete': False,
               'scope': 'local-source-router-reference-not-native-owner-or-adoption',
               'planned_cases': ['emit', 'masked-sampling-training', 'tool-proposal',
                                 'abstain', 'stopped', 'exhausted-prefix', 'successor-model-task'],
               'cases': [], 'error': None, 'production_qualified': False,
               'work_security_qualified': False, 'model_quality_qualified': False,
               'ordinary_hepta_use_verified': False, 'native_node_admission': False}
    try:
        model, rows, provenance = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE,
            'consumer', 0, batch_size)
        write_new(output / 'provenance.json', provenance)
        identity = relation.current_identity()
        write_new(output / 'source-identity.json', identity)
        before = execution.initial_state(model, cell_id='11' * 32, generation=1,
                                         scope='local-source-router-reference', rng_seed='22' * 32,
                                         remaining_steps=2 * len(rows))
        trained = None
        for name in summary['planned_cases'][:-1]:
            state = copy.deepcopy(before)
            policy = execution.default_policy(len(rows))
            if name == 'masked-sampling-training':
                policy['feature_mask'] = [index % 3 != 0 for index in range(256)] + [True]
                policy['expert_mask'] = [[False, True, True] for _ in rows]
                policy['sampler'] = 'sha256-positive-shift-v1'
                mask = {'base': [[False] * 257 for _ in range(3)],
                        'deltas': [[[False] * 257 for _ in range(3)] for _ in range(3)]}
                mask['base'][0][-1] = True
                policy['training'] = {'learning_rate_num': 1, 'learning_rate_den': 1,
                                      'momentum_num': 0, 'momentum_den': 1, 'clip_abs': 1,
                                      'trainable_mask': mask}
            elif name == 'tool-proposal':
                policy['tool_names'] = ['review.M00', 'review.M04', 'review.M10']
            elif name == 'abstain':
                policy['abstain_margin'] = 2 * execution.LOGIT_BOUND
                policy['sampler'] = 'sha256-positive-shift-v1'
            elif name == 'stopped':
                state['remaining_steps'] = 0
            elif name == 'exhausted-prefix':
                state['remaining_steps'] = 1
            proved, observation = run_case(output, name, model, rows, state, policy)
            summary['cases'].append(observation)
            if name == 'masked-sampling-training':
                trained = proved
        _, successor_rows, successor_provenance = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE,
            'consumer', len(rows), batch_size)
        relation.require(not ({row['id'] for row in rows} &
                              {row['id'] for row in successor_rows}), 'SUCCESSOR_INPUT_OVERLAP')
        write_new(output / 'successor-provenance.json', successor_provenance)
        successor_policy = execution.default_policy(len(successor_rows))
        successor, observation = run_case(output, 'successor-model-task', trained['after_model'], successor_rows,
                                          trained['after_state'], successor_policy)
        relation.require(observation['before_model'] == artifact_id(trained['after_model']) and
                         observation['before_model'] != artifact_id(model), 'SUCCESSOR_MODEL_NOT_USED')
        summary['cases'].append(observation)
        summary['successor_reference_model_used'] = True
        summary['successor_reference_inputs_disjoint'] = True
        summary['successor_reference_state_sequence'] = successor['after_state']['sequence']
        summary['complete'] = True
        relation.require(identity == relation.current_identity(), 'EXPERIMENT_SOURCE_CHANGED')
    except BaseException as error:
        summary['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        write_new(output / 'summary.json', summary)
    print(json.dumps({'complete': summary['complete'], 'cases': len(summary['cases']),
                      'summary': str(output / 'summary.json')}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path)
    mode.add_argument('--verify-dir', type=Path)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--batch-size', type=int, default=64)
    args = parser.parse_args()
    if args.verify_dir:
        if not args.expected:
            parser.error('--verify-dir requires separately retained --expected')
        sys.stdout.buffer.write(canonical(verify_directory(args.verify_dir, args.expected)))
    else:
        if args.expected or not 1 <= args.batch_size <= 64:
            parser.error('new experiments require batch size 1..64 and no --expected')
        run(args.out.resolve(), args.batch_size)


if __name__ == '__main__':
    main()
