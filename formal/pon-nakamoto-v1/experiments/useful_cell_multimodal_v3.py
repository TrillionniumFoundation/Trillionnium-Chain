#!/usr/bin/env python3
"""Retain full V3 arithmetic controls, including cold replay and next-model use.

Inputs and weights are deliberately generated arithmetic fixtures.  These runs
exercise the maximum four-row tensor packing, actual three-modality bytes and
full W1 transcripts; they are not a benchmark dataset, quality claim, native
admission, production use or work-cost qualification.  No network or GPU is used.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import resource
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import canonical
import useful_cell_multimodal_execution_v3 as execution
import useful_cell_multimodal_relation_v3 as relation


def _write(path, value):
    path.write_bytes(value if type(value) is bytes else canonical(value))


def _part(modality, raw, **fields):
    return {'modality': modality, 'payload_hex': raw.hex(),
            'source': {'origin': 'generated-arithmetic-fixture',
                       'object_id': hashlib.sha256(raw).hexdigest(),
                       'sha256': hashlib.sha256(raw).hexdigest()}, **fields}


def _inputs(offset):
    rows = []
    for index in range(4):
        number = offset + index
        raw_text = ('Cell ' + str(number) + '\r\n' + '\u591a\u6a21\u6001').encode('utf-8')
        normalized = raw_text.decode().replace('\r\n', '\n').encode()
        raw_image = bytes((number * 19 + pixel * 29) % 256 for pixel in range(5 * 3 * 3))
        samples = [((number * 1901 + sample * 1999) % 65536) - 32768 for sample in range(128)]
        raw_audio = struct.pack('<' + 'h' * len(samples), *samples)
        rows.append({'id': hashlib.sha256(('row/' + str(number)).encode()).hexdigest(),
                     'label': number % 3,
                     'parts': [_part('text-utf8', raw_text, mask=[True] * len(normalized)),
                               _part('image-rgb8', raw_image, width=5, height=3, mask=[True] * 16),
                               _part('audio-pcm16le', raw_audio, sample_rate_hz=16000, mask=[True] * 16)]})
    return rows


def _model():
    parameters = execution.zero_parameters()
    for ordinal, (name, vector) in enumerate(parameters.items()):
        span = 9 if name == 'text_embedding' else 5
        parameters[name] = [(index * 7 + ordinal * 3) % span - span // 2 for index in range(len(vector))]
    return {'schema': execution.MODEL_SCHEMA, 'classes': ['alpha', 'beta', 'gamma'], 'parameters': parameters}


def _state(model, steps=20):
    return execution.initial_state(model, cell_id='71' * 32, generation=3, scope='arithmetic/multimodal-v3',
                                   rng_seed='72' * 32, remaining_steps=steps)


def _training():
    mask = execution.zero_parameters(True)
    mask['router'] = [False] * len(mask['router'])
    return {'learning_rate_num': 1, 'learning_rate_den': 1, 'momentum_num': 1, 'momentum_den': 4,
            'clip_abs': 1, 'trainable_mask': mask}


def replay_case(directory):
    raw = (directory / 'contract.json').read_bytes()
    before = json.loads((directory / 'before-state.json').read_bytes())
    output = json.loads((directory / 'output.json').read_bytes())
    after = json.loads((directory / 'after-state.json').read_bytes())
    expected = json.loads((directory / 'owner-expected.json').read_bytes())
    report = relation.verify_historical_relation(raw, before, output, after,
                                                 (directory / 'witness.json').read_bytes(), expected=expected)
    print(json.dumps(report, sort_keys=True))
    return 0


def _case(root, name, model, inputs, before, policy):
    directory = root / name
    directory.mkdir()
    started_ns = time.time_ns()
    cpu_start = resource.getrusage(resource.RUSAGE_SELF)
    summary = {'schema': 'pon-useful-cell-multimodal-v3/arithmetic-control', 'case': name,
               'status': 'RUNNING', 'fixture_source': 'generated-arithmetic-fixture',
               'production_qualified': False, 'quality_qualified': False, 'work_cost_qualified': False}
    try:
        program = relation.current_identity()
        issued_ms = time.time_ns() // 1_000_000
        parent = {'network': '73' * 32, 'parent_id': '74' * 32, 'parent_state_root': '75' * 32,
                  'block_height': 42, 'consensus_time_ms': issued_ms}
        request_id = hashlib.sha256(('multimodal-control/' + name).encode()).hexdigest()
        raw = relation.freeze_contract(model, inputs, before, policy=policy,
                                       consumer='arithmetic-fixture-owner', allowed_use='research/classify',
                                       request_id=request_id, issued_at_ms=issued_ms,
                                       deadline_ms=issued_ms + 600_000, parent_context=parent, target='ff' * 32)
        # Owned data and admitted program pins exist before proof construction.
        expected = {'contract_id': relation.contract_id(raw), 'program_sha256': program['program_sha256'],
                    'parameters_sha256': program['parameters_sha256'], 'before_state': copy.deepcopy(before),
                    'consumer': 'arithmetic-fixture-owner', 'allowed_use': 'research/classify',
                    'request_id': request_id, 'candidate_artifact': execution.artifact(model),
                    'inputs_sha256': hashlib.sha256(canonical(inputs)).hexdigest(), 'parent_context': parent}
        for filename, value in (('contract.json', raw), ('model.json', model), ('inputs.json', inputs),
                                ('before-state.json', before), ('policy.json', policy), ('owner-expected.json', expected)):
            _write(directory / filename, value)
        prove_start = time.monotonic_ns()
        proof = relation.prove_reference(raw, model, inputs, before, max_attempts=1)
        prove_ns = time.monotonic_ns() - prove_start
        for filename, value in (('witness.json', proof['witness']), ('output.json', proof['output']),
                                ('after-state.json', proof['after_state']), ('after-model.json', proof['after_model']),
                                ('work-attempts.json', proof['work_attempts'])):
            _write(directory / filename, value)
        historical = relation.verify_historical_relation(raw, before, proof['output'], proof['after_state'],
                                                         proof['witness'], expected=expected)
        live = relation.verify_live_relation(raw, before, proof['output'], proof['after_state'],
                                             proof['witness'], expected=expected)
        _write(directory / 'historical-verification.json', historical)
        _write(directory / 'live-verification.json', live)
        command = [sys.executable, str(Path(__file__).resolve()), '--replay-case', str(directory)]
        with (directory / 'cold.stdout').open('wb') as stdout, (directory / 'cold.stderr').open('wb') as stderr:
            cold = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=180, check=False)
        _write(directory / 'cold-process.json', {'command': command, 'exit_code': cold.returncode})
        if cold.returncode != 0:
            raise ValueError('COLD_REPLAY_FAILED')
        cold_report = json.loads((directory / 'cold.stdout').read_bytes())
        if cold_report != historical:
            raise ValueError('COLD_REPLAY_MISMATCH')
        actions = proof['output']['execution']['actions']
        if name == 'abstain' and actions != ['abstain'] * 4:
            raise ValueError('ABSTAIN_CONTROL')
        if name == 'stopped' and actions != ['stop'] * 4:
            raise ValueError('STOP_CONTROL')
        if name == 'exhausted-prefix' and actions != ['emit', 'stop', 'stop', 'stop']:
            raise ValueError('PREFIX_CONTROL')
        if name == 'tool-proposals' and actions != ['propose_tool'] * 4:
            raise ValueError('TOOL_CONTROL')
        if name == 'training' and proof['after_model'] == model:
            raise ValueError('TRAINING_MODEL_UNCHANGED')
        summary.update(status='PASS', contract_id=expected['contract_id'], program=program,
                       rows=len(inputs), modalities=['text-utf8', 'image-rgb8', 'audio-pcm16le'],
                       complete_w1_transcripts=historical['complete_w1_transcripts_verified'],
                       work_attempts=proof['work_attempts'], proving_wall_ns=prove_ns,
                       witness_bytes=len(proof['witness']), actions=actions,
                       before_model_artifact=execution.artifact(model),
                       after_model_artifact=execution.artifact(proof['after_model']),
                       before_sequence=before['sequence'], after_sequence=proof['after_state']['sequence'],
                       source_origin_authenticated=False, parent_context_authenticated=False,
                       checkpoint_committed=False, final_use_granted=False, actual_production_model_use_verified=False)
        return summary, proof
    except Exception as error:
        summary.update(status='FAIL', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        cpu_end = resource.getrusage(resource.RUSAGE_SELF)
        summary.update(started_ns=started_ns, finished_ns=time.time_ns(),
                       self_cpu_user_us=int((cpu_end.ru_utime - cpu_start.ru_utime) * 1_000_000),
                       self_cpu_system_us=int((cpu_end.ru_stime - cpu_start.ru_stime) * 1_000_000))
        _write(directory / 'summary.json', summary)


def run_controls(root):
    root.mkdir(parents=True, exist_ok=False)
    model, inputs = _model(), _inputs(1)
    specifications = []
    policy = execution.default_policy(4)
    policy['sampler'] = 'sha256-positive-shift-v3'
    specifications.append(('sampled', model, inputs, _state(model), policy))
    policy = execution.default_policy(4)
    policy['feature_mask'] = [True, False, True, False, True, False, True, False]
    policy['expert_mask'] = [[False, True, True], [False, False, True], [True, True, True], [True, False, False]]
    masked = copy.deepcopy(inputs)
    for row in masked:
        for part in row['parts']:
            part['mask'] = [index % 2 == 0 for index in range(len(part['mask']))]
    specifications.append(('masked', model, masked, _state(model), policy))
    policy = execution.default_policy(4)
    policy['training'] = _training()
    specifications.append(('training', model, inputs, _state(model), policy))
    policy = execution.default_policy(4)
    policy['tool_names'] = ['review.alpha', 'review.beta', 'review.gamma']
    specifications.append(('tool-proposals', model, inputs, _state(model), policy))
    policy = execution.default_policy(4)
    policy['abstain_margin'] = 2 * execution.LOGIT_BOUND
    specifications.append(('abstain', model, inputs, _state(model), policy))
    policy = execution.default_policy(4)
    policy['training'] = _training()
    specifications.append(('stopped', model, inputs, _state(model, 0), policy))
    specifications.append(('exhausted-prefix', model, inputs, _state(model, 1), execution.default_policy(4)))
    summaries, training = [], None
    for name, current_model, rows, before, policy in specifications:
        try:
            summary, proof = _case(root, name, current_model, rows, before, policy)
            if name == 'training':
                training = proof
        except Exception:
            summary = json.loads((root / name / 'summary.json').read_bytes())
        summaries.append(summary)
    if training is not None:
        try:
            summary, _ = _case(root, 'successor-model-next-input', training['after_model'], _inputs(101),
                               training['after_state'], execution.default_policy(4))
        except Exception:
            summary = json.loads((root / 'successor-model-next-input' / 'summary.json').read_bytes())
        summaries.append(summary)
    else:
        summaries.append({'case': 'successor-model-next-input', 'status': 'DEPENDENCY_NOT_READY'})
    files = []
    for path in sorted(root.rglob('*')):
        if path.is_file():
            raw = path.read_bytes()
            files.append({'path': path.relative_to(root).as_posix(), 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()})
    summary = {'schema': 'pon-useful-cell-multimodal-v3/retained-arithmetic-controls',
               'status': 'PASS' if all(row['status'] == 'PASS' for row in summaries) else 'FAIL',
               'cases': summaries, 'files': files,
               'target': 'ff' * 32, 'target_semantics': 'maximal-correctness-control-not-work-hardness',
               'production_qualified': False, 'quality_qualified': False, 'work_cost_qualified': False}
    _write(root / 'summary.json', summary)
    print(json.dumps({key: summary[key] for key in ('status', 'target_semantics', 'production_qualified',
                                                  'quality_qualified', 'work_cost_qualified')}, sort_keys=True))
    return 0 if summary['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output', type=Path)
    group.add_argument('--replay-case', type=Path)
    args = parser.parse_args()
    return replay_case(args.replay_case.resolve()) if args.replay_case else run_controls(args.output.resolve())


if __name__ == '__main__':
    raise SystemExit(main())
