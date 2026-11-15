"""Executed, bounded integer Cell semantics for the V2 research relation.

This module is a scalar execution reference, not a proof system or owner.  It
does not authenticate source rows, grant tool authority, install a checkpoint,
or qualify ordinary Hepta or native consensus.  The enclosing relation must
replay the source rows and bind the complete trace to its independent task.

The frozen model evaluates all rows before a single optional batch update.
Routing and recurrent sign updates have an explicit stop-gradient boundary;
the training rule below is not backpropagation through time.  Integer division
in the recurrent update is floor division; optimizer division truncates toward
zero.  Frozen parameters AND their existing moments remain unchanged.
"""
from __future__ import annotations

import copy
import hashlib
import re

from contract_wire import H, canonical
from model_contract import CLASSES, DIM, SCALE, load_model_bytes
from useful_cell_numeric_v1 import evaluate_exact


PROFILE_ID = 'pon-useful-cell-execution-v2'
STATE_SCHEMA = PROFILE_ID + '/state'
OPTIMIZER_SCHEMA = PROFILE_ID + '/momentum'
OUTPUT_SCHEMA = PROFILE_ID + '/output'
FEATURE_BOUND = 8
WEIGHT_BOUND = 32767
MEMORY_BOUND = 8192
TARGET_VALUE = 8192
MAX_BATCH = 64
PRODUCT_BOUND = DIM * FEATURE_BOUND * WEIGHT_BOUND
LOGIT_BOUND = 2 * PRODUCT_BOUND + MEMORY_BOUND
U64_MAX = (1 << 64) - 1
MOMENT_BOUND = (1 << 63) - 1
MAX_RNG_DRAWS = 64
RNG_DOMAIN = b'pon-useful-cell-execution-v2/positive-shift\x00'
ACTIONS = ('emit', 'stop', 'abstain', 'propose_tool')
SAMPLERS = ('argmax-lowest', 'sha256-positive-shift-v1')

# These are fixed semantics, not negotiable labels in an untrusted policy.
EXECUTION_PROFILE = {
    'id': PROFILE_ID,
    'features': 'source-features-then-explicit-zero-mask-bias-retained',
    'model_order': ['base', 'router', 'delta-0', 'delta-1', 'delta-2'],
    'router': 'masked-argmax-lowest-index',
    'recurrent_update': 'floor((3*memory+sign(logit)*8192)/4)',
    'sequence': 'one-per-execute-call-including-all-stop',
    'step_budget': 'one-per-nonstop-row-including-abstain',
    'abstention': 'top-two-margin-strictly-below-threshold-before-sampling',
    'sampling': 'sha256-u64le-counter-rejection-positive-shift',
    'rng_draw_cap_per_row': MAX_RNG_DRAWS,
    'rng_consumption': 'every-draw-including-rejected;none-for-stop-or-abstain',
    'loss': 'sum-squared-error-onehot8192-over-nonstop-rows',
    'backward': 'frozen-route-and-discrete-state-stop-gradient;not-bptt',
    'clip': 'trainable-mask-then-componentwise-absolute-clip',
    'optimizer': 'moment=trunc0(mu*old)+clipped;weight-=trunc0(lr*moment)',
    'frozen_parameters': 'weight-and-moment-both-unchanged',
    'overflow': 'reject-no-saturation-no-counter-wrap',
    'tool_effects': 'proposals-only-no-execution',
    'ordinary_hepta': False,
    'production_qualified': False,
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _integer(value, minimum, maximum, code):
    _require(type(value) is int and minimum <= value <= maximum, code)
    return value


def _hex(value, code):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, code)
    return value


def _identity(value, code, maximum=256):
    _require(type(value) is str and 1 <= len(value) <= maximum and
             re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._:/-]*', value) is not None, code)
    return value


def _matrix(value, *, boolean=False, bound=WEIGHT_BOUND, code='MATRIX'):
    _require(type(value) is list and len(value) == 3 and
             all(type(row) is list and len(row) == DIM for row in value), code + '_SHAPE')
    if boolean:
        _require(all(type(v) is bool for row in value for v in row), code + '_BOOLEAN')
    else:
        _require(all(type(v) is int and -bound <= v <= bound for row in value for v in row),
                 code + '_INTEGER')
    return [list(row) for row in value]


def _deltas(value, *, boolean=False, bound=WEIGHT_BOUND, code='DELTAS'):
    _require(type(value) is list and len(value) == 3, code + '_SHAPE')
    return [_matrix(matrix, boolean=boolean, bound=bound, code=code) for matrix in value]


def _model(model):
    fields = {'schema', 'family', 'scale', 'source', 'base', 'router',
              'deltas', 'feature', 'classes'}
    _require(type(model) is dict and set(model) == fields, 'EXECUTION_MODEL_FIELDS')
    for name in ('schema', 'family', 'feature'):
        _require(type(model[name]) is str and len(model[name]) <= 256, 'EXECUTION_MODEL_IDENTITY')
    _require(type(model['source']) is str and
             re.fullmatch('[0-9a-f]{40}', model['source']) is not None, 'EXECUTION_MODEL_SOURCE')
    _require(type(model['scale']) is int and model['scale'] == SCALE, 'EXECUTION_MODEL_SCALE')
    _require(type(model['classes']) is list and model['classes'] == CLASSES,
             'EXECUTION_MODEL_CLASSES')
    value = {key: model[key] for key in ('schema', 'family', 'scale', 'source', 'feature')}
    value.update(classes=list(CLASSES), base=_matrix(model['base']),
                 router=_matrix(model['router']), deltas=_deltas(model['deltas']))
    return load_model_bytes(canonical(value))


def _artifact(model):
    return H('artifact', canonical(model)).hex()


def _optimizer(value):
    if value is None:
        return None
    _require(type(value) is dict and set(value) == {'schema', 'step', 'base', 'deltas'},
             'OPTIMIZER_FIELDS')
    _require(value['schema'] == OPTIMIZER_SCHEMA, 'OPTIMIZER_SCHEMA')
    return {'schema': OPTIMIZER_SCHEMA,
            'step': _integer(value['step'], 0, U64_MAX, 'OPTIMIZER_STEP'),
            'base': _matrix(value['base'], bound=MOMENT_BOUND, code='MOMENT_BASE'),
            'deltas': _deltas(value['deltas'], bound=MOMENT_BOUND, code='MOMENT_DELTAS')}


def validate_state(state, model=None):
    """Return an independent, strictly validated state; authenticate it elsewhere."""
    fields = {'schema', 'cell_id', 'generation', 'scope', 'model_artifact', 'memory',
              'rng_seed', 'rng_counter', 'remaining_steps', 'sequence', 'optimizer'}
    _require(type(state) is dict and set(state) == fields, 'EXECUTION_STATE_FIELDS')
    _require(state['schema'] == STATE_SCHEMA, 'EXECUTION_STATE_SCHEMA')
    _require(type(state['memory']) is list and len(state['memory']) == 3 and
             all(type(v) is int and -MEMORY_BOUND <= v <= MEMORY_BOUND for v in state['memory']),
             'STATE_MEMORY')
    result = {'schema': STATE_SCHEMA,
              'cell_id': _hex(state['cell_id'], 'STATE_CELL_ID'),
              'scope': _identity(state['scope'], 'STATE_SCOPE'),
              'model_artifact': _hex(state['model_artifact'], 'STATE_MODEL_ARTIFACT'),
              'rng_seed': _hex(state['rng_seed'], 'STATE_RNG_SEED'),
              'memory': list(state['memory']), 'optimizer': _optimizer(state['optimizer'])}
    for name in ('generation', 'rng_counter', 'remaining_steps', 'sequence'):
        result[name] = _integer(state[name], 0, U64_MAX, 'STATE_' + name.upper())
    if model is not None:
        _require(result['model_artifact'] == _artifact(_model(model)), 'STATE_MODEL_ARTIFACT_MISMATCH')
    return result


def initial_state(model, *, cell_id, generation, scope, rng_seed, remaining_steps):
    model = _model(model)
    return validate_state({
        'schema': STATE_SCHEMA, 'cell_id': cell_id, 'generation': generation,
        'scope': scope, 'model_artifact': _artifact(model), 'memory': [0, 0, 0],
        'rng_seed': rng_seed, 'rng_counter': 0, 'remaining_steps': remaining_steps,
        'sequence': 0, 'optimizer': None,
    }, model)


def _training(value):
    if value is None:
        return None
    fields = {'learning_rate_num', 'learning_rate_den', 'momentum_num', 'momentum_den',
              'clip_abs', 'trainable_mask'}
    _require(type(value) is dict and set(value) == fields, 'TRAINING_FIELDS')
    result = {
        'learning_rate_num': _integer(value['learning_rate_num'], 0, 1 << 20, 'LEARNING_RATE_NUM'),
        'learning_rate_den': _integer(value['learning_rate_den'], 1, 1 << 32, 'LEARNING_RATE_DEN'),
        'momentum_num': _integer(value['momentum_num'], 0, 1 << 16, 'MOMENTUM_NUM'),
        'momentum_den': _integer(value['momentum_den'], 1, 1 << 16, 'MOMENTUM_DEN'),
        'clip_abs': _integer(value['clip_abs'], 1, 1 << 40, 'GRADIENT_CLIP'),
    }
    _require(result['momentum_num'] < result['momentum_den'], 'MOMENTUM_RANGE')
    mask = value['trainable_mask']
    _require(type(mask) is dict and set(mask) == {'base', 'deltas'}, 'TRAINABLE_MASK_FIELDS')
    result['trainable_mask'] = {
        'base': _matrix(mask['base'], boolean=True, code='TRAINABLE_BASE'),
        'deltas': _deltas(mask['deltas'], boolean=True, code='TRAINABLE_DELTAS'),
    }
    return result


def default_policy(batch_size):
    _integer(batch_size, 1, MAX_BATCH, 'EXECUTION_BATCH')
    return {'feature_mask': [True] * DIM,
            'expert_mask': [[True, True, True] for _ in range(batch_size)],
            'allowed_actions': list(ACTIONS), 'sampler': 'argmax-lowest',
            'abstain_margin': 0, 'tool_names': [None, None, None], 'training': None}


def validate_policy(policy, batch_size):
    _integer(batch_size, 1, MAX_BATCH, 'EXECUTION_BATCH')
    fields = {'feature_mask', 'expert_mask', 'allowed_actions', 'sampler',
              'abstain_margin', 'tool_names', 'training'}
    _require(type(policy) is dict and set(policy) == fields, 'EXECUTION_POLICY_FIELDS')
    feature_mask = policy['feature_mask']
    _require(type(feature_mask) is list and len(feature_mask) == DIM and
             all(type(v) is bool for v in feature_mask), 'FEATURE_MASK')
    _require(feature_mask[-1] is True, 'BIAS_MASK')
    expert_mask = policy['expert_mask']
    _require(type(expert_mask) is list and len(expert_mask) == batch_size and
             all(type(row) is list and len(row) == 3 and
                 all(type(v) is bool for v in row) and any(row) for row in expert_mask), 'EXPERT_MASK')
    actions = policy['allowed_actions']
    _require(type(actions) is list and 1 <= len(actions) <= len(ACTIONS) and
             all(type(v) is str and v in ACTIONS for v in actions) and
             len(set(actions)) == len(actions), 'ALLOWED_ACTIONS')
    _require(type(policy['sampler']) is str and policy['sampler'] in SAMPLERS, 'SAMPLER')
    tools = policy['tool_names']
    _require(type(tools) is list and len(tools) == 3, 'TOOL_NAMES')
    for name in tools:
        if name is not None:
            _identity(name, 'TOOL_NAME', 128)
    return {'feature_mask': list(feature_mask), 'expert_mask': [list(row) for row in expert_mask],
            'allowed_actions': list(actions), 'sampler': policy['sampler'],
            'abstain_margin': _integer(policy['abstain_margin'], 0, 2 * LOGIT_BOUND, 'ABSTAIN_MARGIN'),
            'tool_names': list(tools), 'training': _training(policy['training'])}


def _rows(rows):
    _require(type(rows) is list and 1 <= len(rows) <= MAX_BATCH, 'EXECUTION_BATCH')
    result = []
    for row in rows:
        _require(type(row) is dict and set(row) ==
                 {'id', 'file', 'source_content_sha256', 'split', 'label', 'x'}, 'EXECUTION_ROW_FIELDS')
        _hex(row['id'], 'EXECUTION_ROW_ID')
        _hex(row['source_content_sha256'], 'EXECUTION_SOURCE_CONTENT')
        _require(type(row['file']) is str and 1 <= len(row['file']) <= 1024 and
                 not row['file'].startswith('/') and '..' not in row['file'].split('/') and
                 '\x00' not in row['file'], 'EXECUTION_SOURCE_PATH')
        _require(type(row['split']) is str and row['split'] in
                 ('consumer', 'evaluation_a', 'evaluation_b'), 'EXECUTION_PARTITION')
        _integer(row['label'], 0, 2, 'EXECUTION_LABEL')
        _require(type(row['x']) is list and len(row['x']) == DIM and
                 all(type(v) is int and -FEATURE_BOUND <= v <= FEATURE_BOUND for v in row['x']) and
                 row['x'][-1] == FEATURE_BOUND, 'EXECUTION_FEATURES')
        result.append({key: list(value) if key == 'x' else value for key, value in row.items()})
    _require(len({row['id'] for row in result}) == len(result), 'EXECUTION_DUPLICATE_ROW')
    _require(len({row['split'] for row in result}) == 1, 'EXECUTION_MIXED_PARTITION')
    return result


def prepare_rows(rows, policy):
    """Execute the mask on source features; the caller must replay their source."""
    result = _rows(rows)
    policy = validate_policy(policy, len(result))
    for row in result:
        row['x'] = [value if allowed else 0 for value, allowed in
                    zip(row['x'], policy['feature_mask'])]
    return result


def _zero_matrix():
    return [[0] * DIM for _ in range(3)]


def _zero_parameters():
    return {'base': _zero_matrix(), 'deltas': [_zero_matrix() for _ in range(3)]}


def _trunc0(numerator, denominator):
    return numerator // denominator if numerator >= 0 else -((-numerator) // denominator)


def _sample(scores, seed, counter):
    minimum = min(scores)
    masses = [score - minimum + 1 for score in scores]
    total = sum(masses)
    limit = (1 << 256) - ((1 << 256) % total)
    draws = []
    for _ in range(MAX_RNG_DRAWS):
        _require(counter < U64_MAX, 'RNG_COUNTER_OVERFLOW')
        digest = hashlib.sha256(RNG_DOMAIN + bytes.fromhex(seed) + counter.to_bytes(8, 'little')).digest()
        value = int.from_bytes(digest, 'big')
        draws.append({'counter': counter, 'sha256': digest.hex(), 'accepted': value < limit})
        counter += 1
        if value < limit:
            ticket = value % total
            cumulative = 0
            for prediction, mass in enumerate(masses):
                cumulative += mass
                if ticket < cumulative:
                    return prediction, counter, {'masses': masses, 'total': total,
                                                 'limit_hex': format(limit, '065x'),
                                                 'ticket': ticket, 'draws': draws}
    raise ValueError('RNG_REJECTION_LIMIT')


def _train(model, active, optimizer, spec):
    gradients = _zero_parameters()
    loss_rows = []
    for row in active:
        target = [TARGET_VALUE if index == row['label'] else 0 for index in range(3)]
        errors = [value - wanted for value, wanted in zip(row['logits'], target)]
        derivative = [2 * error for error in errors]
        loss_rows.append({'row': row['row'], 'target': target, 'errors': errors,
                          'loss': sum(error * error for error in errors), 'd_logits': derivative})
        for index in range(3):
            for coordinate, feature in enumerate(row['features']):
                value = derivative[index] * feature
                gradients['base'][index][coordinate] += value
                gradients['deltas'][row['route']][index][coordinate] += value
    loss = sum(row['loss'] for row in loss_rows)
    traces = [
        {'stage': 'training-loss', 'inputs': {'active_rows': copy.deepcopy(active)},
         'outputs': {'rows': loss_rows, 'loss': loss}},
        {'stage': 'training-backward',
         'inputs': {'features': [row['features'] for row in active],
                    'routes': [row['route'] for row in active],
                    'd_logits': [row['d_logits'] for row in loss_rows],
                    'gradient_boundary': EXECUTION_PROFILE['backward']},
         'outputs': {'gradients': copy.deepcopy(gradients), 'router_gradients': _zero_matrix()}},
    ]
    if not active:
        summary = {'active_rows': 0, 'loss': 0, 'parameters_changed': False,
                   'optimizer_step': None if optimizer is None else optimizer['step']}
        traces.append({'stage': 'training-update',
                       'inputs': {'spec': copy.deepcopy(spec), 'optimizer': copy.deepcopy(optimizer)},
                       'outputs': {'applied': False, 'reason': 'no-active-rows',
                                   'optimizer': copy.deepcopy(optimizer), 'model': copy.deepcopy(model)}})
        return copy.deepcopy(model), copy.deepcopy(optimizer), summary, traces
    old = copy.deepcopy(optimizer)
    if old is None:
        old = dict(_zero_parameters(), schema=OPTIMIZER_SCHEMA, step=0)
    _require(old['step'] < U64_MAX, 'OPTIMIZER_STEP_OVERFLOW')
    updated = copy.deepcopy(model)
    moment = copy.deepcopy(old)
    moment['step'] += 1
    masked = _zero_parameters()
    clipped = _zero_parameters()
    updates = _zero_parameters()
    groups = [('base', None)] + [('deltas', index) for index in range(3)]
    for name, expert in groups:
        select = lambda mapping: mapping[name] if expert is None else mapping[name][expert]
        weights = select(updated)
        raw_gradient = select(gradients)
        mask = select(spec['trainable_mask'])
        old_moment = select(old)
        new_moment = select(moment)
        masked_gradient = select(masked)
        clipped_gradient = select(clipped)
        update = select(updates)
        for row in range(3):
            for coordinate in range(DIM):
                if not mask[row][coordinate]:
                    # Retain both the exact weight and its potentially nonzero
                    # old momentum; no hidden decay or update of frozen values.
                    continue
                value = raw_gradient[row][coordinate]
                masked_gradient[row][coordinate] = value
                value = max(-spec['clip_abs'], min(spec['clip_abs'], value))
                clipped_gradient[row][coordinate] = value
                value += _trunc0(spec['momentum_num'] * old_moment[row][coordinate], spec['momentum_den'])
                _require(-MOMENT_BOUND <= value <= MOMENT_BOUND, 'OPTIMIZER_MOMENT_OVERFLOW')
                new_moment[row][coordinate] = value
                change = _trunc0(spec['learning_rate_num'] * value, spec['learning_rate_den'])
                update[row][coordinate] = change
                value = weights[row][coordinate] - change
                _require(-WEIGHT_BOUND <= value <= WEIGHT_BOUND, 'TRAINED_WEIGHT_RANGE')
                weights[row][coordinate] = value
    updated = _model(updated)
    summary = {'active_rows': len(active), 'loss': loss,
               'parameters_changed': canonical(updated) != canonical(model), 'optimizer_step': moment['step']}
    traces.append({'stage': 'training-update',
                   'inputs': {'spec': copy.deepcopy(spec), 'model': copy.deepcopy(model),
                              'optimizer': copy.deepcopy(optimizer), 'gradients': gradients},
                   'outputs': {'applied': True, 'masked_gradients': masked,
                               'clipped_gradients': clipped, 'updates': updates,
                               'optimizer': copy.deepcopy(moment), 'model': copy.deepcopy(updated)}})
    return updated, moment, summary, traces


def execute(model, rows, before, policy, *, verified_products=None):
    """Replay a full bounded Cell call without mutating any caller-owned value.

    ``verified_products`` must be a Python list of 15 integer rows by batch,
    ordered base/router/delta-0/delta-1/delta-2 as in V1 ``evaluate_exact``.
    Every value must equal an independent scalar recomputation after the mask.
    Supplying these products never replaces any decision, state or training work.
    """
    model = _model(model)
    rows = _rows(rows)
    policy = validate_policy(policy, len(rows))
    before = validate_state(before, model)
    _require(before['sequence'] < U64_MAX, 'STATE_SEQUENCE_OVERFLOW')
    prepared = prepare_rows(rows, policy)
    scalar = evaluate_exact(model, [row['x'] for row in prepared])['products']
    if verified_products is not None:
        _require(type(verified_products) is list and len(verified_products) == 15 and
                 all(type(row) is list and len(row) == len(rows) and
                     all(type(v) is int and -PRODUCT_BOUND <= v <= PRODUCT_BOUND for v in row)
                     for row in verified_products), 'VERIFIED_PRODUCTS_SHAPE_OR_RANGE')
        _require(verified_products == scalar, 'VERIFIED_PRODUCTS_MISMATCH')
        products = copy.deepcopy(verified_products)
    else:
        products = scalar
    trace = [
        {'stage': 'preprocess', 'inputs': {'rows': rows, 'feature_mask': policy['feature_mask']},
         'outputs': {'rows': copy.deepcopy(prepared)}},
        {'stage': 'operator-products',
         'inputs': {'model': copy.deepcopy(model), 'features': [row['x'] for row in prepared]},
         'outputs': {'products': copy.deepcopy(products)}},
    ]
    after = copy.deepcopy(before)
    output = {'schema': OUTPUT_SCHEMA, 'row_ids': [row['id'] for row in rows],
              'routes': [], 'logits': [], 'predictions': [], 'labels': [], 'actions': [],
              'stop': [], 'abstain': [], 'tool_proposals': [], 'delivery_content': [], 'training': None}
    active = []
    for index, row in enumerate(prepared):
        memory_before = list(after['memory'])
        rng_before = after['rng_counter']
        remaining_before = after['remaining_steps']
        route = scores = prediction = label = proposal = delivery = None
        sample = None
        route_scores = None
        margin = None
        if remaining_before == 0:
            action = 'stop'
        else:
            route_scores = [products[3 + expert][index] for expert in range(3)]
            legal = [expert for expert in range(3) if policy['expert_mask'][index][expert]]
            route = max(legal, key=lambda expert: route_scores[expert])
            scores = [products[cls][index] + products[6 + 3 * route + cls][index] + memory_before[cls]
                      for cls in range(3)]
            _require(all(-LOGIT_BOUND <= value <= LOGIT_BOUND for value in scores), 'EXECUTION_LOGIT_BOUND')
            ranked = sorted(range(3), key=lambda cls: (-scores[cls], cls))
            margin = scores[ranked[0]] - scores[ranked[1]]
            if margin < policy['abstain_margin']:
                action = 'abstain'
            else:
                if policy['sampler'] == 'argmax-lowest':
                    prediction = ranked[0]
                else:
                    prediction, after['rng_counter'], sample = _sample(scores, after['rng_seed'], rng_before)
                label = CLASSES[prediction]
                tool = policy['tool_names'][prediction]
                if tool is None:
                    action = 'emit'
                    delivery = {'kind': 'classification', 'source_id': row['id'], 'label': label}
                else:
                    action = 'propose_tool'
                    proposal = {'name': tool, 'arguments': {'source_id': row['id'], 'label': label,
                                                           'logits': list(scores)}}
            after['memory'] = [(3 * old + (1 if value > 0 else -1 if value < 0 else 0) * MEMORY_BOUND) // 4
                               for old, value in zip(memory_before, scores)]
            after['remaining_steps'] -= 1
            active.append({'row': index, 'route': route, 'logits': list(scores),
                           'features': list(row['x']), 'label': row['label']})
        _require(action in policy['allowed_actions'], 'ACTION_NOT_ALLOWED')
        for key, value in (
                ('routes', route), ('logits', scores), ('predictions', prediction), ('labels', label),
                ('actions', action), ('stop', action == 'stop'), ('abstain', action == 'abstain'),
                ('tool_proposals', proposal), ('delivery_content', delivery)):
            output[key].append(copy.deepcopy(value))
        trace.append({'stage': 'decision/' + str(index),
                      'inputs': {'source_id': row['id'], 'products': [values[index] for values in products],
                                 'expert_mask': policy['expert_mask'][index], 'memory': memory_before,
                                 'rng_seed': after['rng_seed'], 'rng_counter': rng_before,
                                 'remaining_steps': remaining_before, 'sampler': policy['sampler'],
                                 'abstain_margin': policy['abstain_margin'], 'tool_names': policy['tool_names'],
                                 'allowed_actions': policy['allowed_actions']},
                      'outputs': {'route_scores': route_scores, 'route': route, 'logits': scores,
                                  'margin': margin, 'sampling': sample, 'prediction': prediction,
                                  'action': action, 'tool_proposal': proposal, 'delivery_content': delivery,
                                  'memory': list(after['memory']), 'rng_counter': after['rng_counter'],
                                  'remaining_steps': after['remaining_steps']}})
    if policy['training'] is None:
        after_model = copy.deepcopy(model)
        trace.append({'stage': 'training-disabled', 'inputs': {'training': None},
                      'outputs': {'model': copy.deepcopy(model), 'optimizer': copy.deepcopy(after['optimizer'])}})
    else:
        after_model, after['optimizer'], output['training'], training_trace = _train(
            model, active, before['optimizer'], policy['training'])
        trace.extend(training_trace)
    after['sequence'] += 1
    after['model_artifact'] = _artifact(after_model)
    after = validate_state(after, after_model)
    trace.append({'stage': 'state-transition', 'inputs': {'before': before},
                  'outputs': {'after': copy.deepcopy(after)}})
    return {'output': output, 'after_state': after, 'after_model': after_model, 'trace': trace}
