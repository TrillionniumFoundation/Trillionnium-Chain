"""Retain numeric controls from the unchanged Python V2 scalar implementation.

Only ASCII snippets are used for the cross-language equivalence claim. The new
native source profile intentionally has a different provenance/domain and does
not accept a Python V2 proof. This generator is never called by the native CLI.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from contract_wire import H, canonical
from ledger import FAMILY
from experiments.model_loop import features
import useful_cell_execution_v2 as execution
from useful_cell_numeric_v1 import evaluate_exact

PROFILE = 'pon-cell-stateful-native-int257-v1'


def model():
    return {'schema': 'hepta-source-owner-linear-256-v1', 'family': FAMILY.hex(),
            'scale': 1024, 'source': 'ab' * 20,
            'base': [[(11*j + 7*r) % 23 - 11 for j in range(257)] for r in range(3)],
            'router': [[(7*j + 3*r) % 17 - 8 for j in range(257)] for r in range(3)],
            'deltas': [[[(5*j + 3*r + 7*e) % 19 - 9 for j in range(257)]
                        for r in range(3)] for e in range(3)],
            'feature': 'signed-token-hash-256-clipped8-plus-bias-v1',
            'classes': ['M00', 'M04', 'M10']}


def training():
    return {'learning_rate_num': 1, 'learning_rate_den': 1024,
            'momentum_num': 2, 'momentum_den': 3, 'clip_abs': 8192,
            'trainable_mask': {
                'base': [[(r+j) % 5 != 0 for j in range(257)] for r in range(3)],
                'deltas': [[[(e+r+j) % 7 != 0 for j in range(257)] for r in range(3)]
                           for e in range(3)]}}


def old_optimizer():
    return {'schema': execution.OPTIMIZER_SCHEMA, 'step': 5,
            'base': [[(j + 3*r) % 199 - 99 for j in range(257)] for r in range(3)],
            'deltas': [[[(j + 3*r + 13*e) % 199 - 99 for j in range(257)]
                        for r in range(3)] for e in range(3)]}


def native_model(value):
    return {'schema': PROFILE + '/model', **{key: copy.deepcopy(value[key])
                                           for key in ('base', 'router', 'deltas')}}


def model_artifact(value):
    return H(PROFILE + '/model', canonical(value)).hex()


def numeric_state(value):
    value = copy.deepcopy(value)
    del value['schema'], value['model_artifact']
    if value['optimizer'] is not None:
        del value['optimizer']['schema']
    return value


def make_case(name):
    value = model()
    if name == 'negative_floor_and_ties':
        value['base'] = [[0] * 257 for _ in range(3)]
        value['router'] = [[0] * 257 for _ in range(3)]
        value['deltas'] = [[[0] * 257 for _ in range(3)] for _ in range(3)]
    if name == 'coefficient_boundary':
        for rows in [value['base'], value['router'], *value['deltas']]:
            for r, row in enumerate(rows):
                row[:] = [32767 if (r+j) % 2 else -32767 for j in range(257)]
    snippets = [
        b' \t fn Alpha(value:u64) { let result = value + 3; M00 TRNM_IGNORED; return result; }\r\n',
        b'async fn Beta() { delta Delta DELTA; gamma; atomic_load; m04 trnm_test; }',
        b'fn gamma() { matrix_route input_value output_value; checked_add; memory_update; }',
        b'fn repeated() { ' + b'clipped ' * 200 + b' }',
    ]
    inputs, rows = [], []
    for i, raw in enumerate(snippets):
        identity = hashlib.sha256(f'native-cell-fixture/{i}'.encode()).hexdigest()
        origin = f'fixture/module_{i}.rs'
        normalized = re.sub(rb'[\x09-\x0d ]+', b' ', raw).strip(b' ')
        inputs.append({'id': identity, 'origin': origin, 'content_hex': raw.hex(), 'label': i % 3})
        rows.append({'id': identity, 'file': origin,
                     'source_content_sha256': hashlib.sha256(normalized).hexdigest(),
                     'split': 'consumer', 'label': i % 3, 'x': features(normalized.decode())})
    before = execution.initial_state(value, cell_id='12' * 32, generation=9,
                                     scope='native-cell-fixture', rng_seed='34' * 32,
                                     remaining_steps=12)
    before.update(memory=[-1, 5, -7], rng_counter=3, sequence=11)
    policy = execution.default_policy(len(rows))
    if name == 'negative_floor_and_ties':
        before['memory'] = [-1, -1, -1]
        policy['expert_mask'] = [[False, True, True] for _ in rows]
    if name in ('masked_sampling_training', 'stop_prefix', 'all_stop_training_preserves'):
        policy['sampler'] = 'sha256-positive-shift-v1'
        policy['training'] = training()
    if name in ('masked_sampling_training', 'all_stop_training_preserves'):
        before['optimizer'] = old_optimizer()
    if name == 'masked_sampling_training':
        policy['feature_mask'] = [j % 7 != 0 or j == 256 for j in range(257)]
        policy['expert_mask'] = [[False, True, True], [True, False, True],
                                 [True, True, False], [False, False, True]]
    if name == 'abstain_before_rng':
        policy['sampler'] = 'sha256-positive-shift-v1'
        policy['abstain_margin'] = 2 * execution.LOGIT_BOUND
    if name == 'stop_prefix':
        before['remaining_steps'] = 2
        policy['tool_names'] = ['route.m00', None, 'route.m10']
    if name == 'all_stop_training_preserves':
        before['remaining_steps'] = 0
    if name == 'tool_proposal':
        policy['tool_names'] = ['route.m00', 'route.m04', 'route.m10']
    if name == 'coefficient_boundary':
        before['memory'] = [8192, -8192, 8192]
    result = execution.execute(value, rows, before, policy)
    native = native_model(value)
    state = copy.deepcopy(before)
    state['schema'] = PROFILE + '/state'
    state['model_artifact'] = model_artifact(native)
    if state['optimizer'] is not None:
        state['optimizer']['schema'] = PROFILE + '/momentum'
    admission = {'schema': PROFILE + '/owner-admission',
                 'input_profile': 'owner-utf8-ascii-token-snippet-v1',
                 'consumer': 'native-cell-test-owner', 'allowed_use': 'bounded-replay',
                 'request_id': hashlib.sha256(name.encode()).hexdigest(),
                 'issued_at_unix_seconds': 100, 'deadline_unix_seconds': 200,
                 'work_target': 'ff' * 32, 'model': native, 'inputs': inputs,
                 'before': state, 'policy': policy}
    output = copy.deepcopy(result['output'])
    del output['schema']
    training_values = []
    for stage in result['trace']:
        if not stage['stage'].startswith('training-'):
            continue
        out = copy.deepcopy(stage['outputs'])
        out.pop('model', None)
        out.pop('optimizer', None)
        training_values.append({'stage': stage['stage'], 'outputs': out})
    return {'name': name, 'admission': admission, 'oracle': {
        'source_features': [row['x'] for row in rows],
        'products': evaluate_exact(value, [r['x'] for r in execution.prepare_rows(rows, policy)])['products'],
        'output': output, 'after_state': numeric_state(result['after_state']),
        'after_model': {key: result['after_model'][key] for key in ('base', 'router', 'deltas')},
        'decisions': [stage['outputs'] for stage in result['trace'] if stage['stage'].startswith('decision/')],
        'training': training_values,
    }}


def main():
    names = ['masked_sampling_training', 'negative_floor_and_ties', 'abstain_before_rng',
             'stop_prefix', 'all_stop_training_preserves', 'tool_proposal', 'coefficient_boundary']
    source_paths = [
        'formal/pon-nakamoto-v1/useful_cell_execution_v2.py',
        'formal/pon-nakamoto-v1/useful_cell_numeric_v1.py',
        'formal/pon-nakamoto-v1/model_contract.py',
        'formal/pon-nakamoto-v1/experiments/model_loop.py',
    ]
    result = {'schema': PROFILE + '/python-v2-numeric-oracle',
              'scope': 'same-numeric-semantics-on-ASCII-snippets-not-same-proof-or-source-provenance',
              'source_sha256': {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                                for path in source_paths},
              'cases': [make_case(name) for name in names]}
    path = Path(sys.argv[1])
    path.write_bytes(canonical(result))
    print(json.dumps({'path': str(path), 'bytes': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'cases': len(names)}))


if __name__ == '__main__':
    main()
