"""Bounded multimodal integer Cell execution, in a fresh research namespace.

This executes raw-byte preprocessing, learned encoders, a residual MLP, routed
low-rank adapters, a head, recurrent decisions and an optional integer training
surrogate.  It neither authenticates an input's claimed origin nor owns a task,
FinalUse, checkpoint or tool.  The accompanying relation checks every forward
dense product with its own complete W1 transcript and replays the other steps.

The three codecs and graph below are finite, fixed profiles, not arbitrary
multimodal models.  Quantized adjoints are explicitly specified integer rules;
they are not derivatives of the discontinuous integer function or BPTT.
"""
from __future__ import annotations

import copy
import hashlib
import re
import struct

from contract_wire import H, canonical


PROFILE_ID = 'pon-useful-cell-multimodal-execution-v3'
MODEL_SCHEMA = PROFILE_ID + '/model'
STATE_SCHEMA = PROFILE_ID + '/state'
OPTIMIZER_SCHEMA = PROFILE_ID + '/momentum'
OUTPUT_SCHEMA = PROFILE_ID + '/output'
MAX_BATCH = 4
HIDDEN = 8
EXPANSION = 12
RANK = 2
EXPERTS = 3
CLASSES = 3
ACTIVATION_BOUND = 64
MEMORY_BOUND = 64
QUANT_DIVISOR = 8
TARGET_VALUE = 64
LOGIT_BOUND = 4224
U64_MAX = (1 << 64) - 1
GRADIENT_BOUND = (1 << 55) - 1
MOMENT_BOUND = (1 << 60) - 1
MAX_RNG_DRAWS = 64
RNG_DOMAIN = b'pon-useful-cell-multimodal-execution-v3/positive-shift\x00'
MODALITIES = ('text-utf8', 'image-rgb8', 'audio-pcm16le')
ACTIONS = ('emit', 'stop', 'abstain', 'propose_tool')
SAMPLERS = ('argmax-lowest', 'sha256-positive-shift-v3')

# Every entry is a row-major tensor.  The complete bundle, including every
# unselected adapter and every encoder, is bound by the artifact identity.
PARAMETER_SHAPES = {
    'text_embedding': [256, 8],
    'image_projection': [8, 12], 'image_bias': [8],
    'audio_projection': [8, 4], 'audio_bias': [8],
    'base_up': [12, 8], 'base_up_bias': [12],
    'base_down': [8, 12], 'base_down_bias': [8],
    'router': [3, 8],
    'adapter_0_down': [2, 8], 'adapter_0_up': [8, 2],
    'adapter_1_down': [2, 8], 'adapter_1_up': [8, 2],
    'adapter_2_down': [2, 8], 'adapter_2_up': [8, 2],
    'head': [3, 8], 'head_bias': [3],
}
EXECUTION_PROFILE = {
    'id': PROFILE_ID,
    'max_batch': MAX_BATCH,
    'input_codecs': ['text-utf8', 'image-rgb8', 'audio-pcm16le'],
    'text': 'strict-utf8;CRLF-and-CR-to-LF;utf8-byte-tokenizer;1..64-raw-bytes',
    'image': 'RGB8;1..16-per-axis;nearest-floor-resize-8x8;trunc0((pixel-128)/16);2x2x3-patches',
    'audio': 'mono-s16le;8000-or-16000-Hz;pair-mean-trunc0-at-16k;at-most-64-8k-samples;trunc0(sample/4096);zero-pad-4-sample-frames',
    'encoder': 'learned-byte-embedding-or-affine-patch/frame;clamp64;masked-trunc0-mean',
    'fusion': 'trunc0-mean-of-present-modalities;then-eight-coordinate-boolean-mask',
    'model_order': ['encoder', 'base-up-relu64', 'base-down-residual-clamp64',
                    'router', 'all-three-low-rank-adapters', 'selected-add-clamp64', 'head'],
    'linear': 'exact-signed-dot;projection-rescale-trunc0-by-8;bias-after-rescale',
    'router': 'masked-argmax-lowest-index;frozen-parameters-and-route-stop-gradient',
    'memory': 'floor((3*old+sign(logit)*64)/4);state-stop-gradient-not-bptt',
    'sequence': 'one-per-call-including-all-stop',
    'steps': 'one-per-nonstop-row-including-abstain',
    'sampling': 'sha256-counter-rejection-positive-shift;every-draw-consumed;cap64',
    'loss': 'sum-squared-error-onehot64-over-nonstop-rows',
    'backward': 'integer-surrogate;clamp/relu-gate-strict-interior;trunc0-adjoint-at-each-rescale-and-mean;route-and-memory-stop-gradient',
    'update': 'trainable-mask;component-clip;trunc0-rational-momentum;trunc0-rational-learning-rate',
    'frozen_parameters': 'weight-and-existing-moment-unchanged',
    'overflow': 'reject;no-weight-saturation;no-counter-wrap',
    'tool_effects': 'proposal-only',
    'source_origin_authentication': False,
    'ordinary_hepta': False,
    'arbitrary_encoder_or_graph': False,
    'production_qualified': False,
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def integer(value, minimum, maximum, code):
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def hex_value(value, code, length=64):
    require(type(value) is str and len(value) == length and
            re.fullmatch('[0-9a-f]+', value) is not None, code)
    return value


def identity(value, code, maximum=256):
    require(type(value) is str and 1 <= len(value) <= maximum and
            re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/-]*', value) is not None, code)
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def trunc0(numerator, denominator):
    return numerator // denominator if numerator >= 0 else -((-numerator) // denominator)


def _size(shape):
    result = 1
    for value in shape:
        result *= value
    return result


def parameter_bound(name):
    return ACTIVATION_BOUND if name == 'text_embedding' or name.endswith('_bias') else 8


def zero_parameters(value=0):
    return {name: [value] * _size(shape) for name, shape in PARAMETER_SHAPES.items()}


def _parameters(value, *, boolean=False, moment=False):
    require(type(value) is dict and set(value) == set(PARAMETER_SHAPES), 'MM3_PARAMETER_FIELDS')
    result = {}
    for name, shape in PARAMETER_SHAPES.items():
        vector = value[name]
        require(type(vector) is list and len(vector) == _size(shape), 'MM3_PARAMETER_SHAPE')
        bound = MOMENT_BOUND if moment else parameter_bound(name)
        require(all(type(item) is bool for item in vector) if boolean else
                all(type(item) is int and -bound <= item <= bound for item in vector),
                'MM3_PARAMETER_BOOLEAN' if boolean else 'MM3_PARAMETER_RANGE')
        result[name] = list(vector)
    return result


def validate_model(model):
    require(type(model) is dict and set(model) == {'schema', 'classes', 'parameters'}, 'MM3_MODEL_FIELDS')
    require(model['schema'] == MODEL_SCHEMA, 'MM3_MODEL_SCHEMA')
    classes = model['classes']
    require(type(classes) is list and len(classes) == CLASSES and
            all(type(value) is str for value in classes), 'MM3_MODEL_CLASSES')
    for name in classes:
        identity(name, 'MM3_MODEL_CLASS', 64)
    require(len(set(classes)) == CLASSES, 'MM3_DUPLICATE_CLASS')
    return {'schema': MODEL_SCHEMA, 'classes': list(classes),
            'parameters': _parameters(model['parameters'])}


def artifact(model):
    return H(PROFILE_ID + '/artifact', canonical(validate_model(model))).hex()


def _optimizer(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == {'schema', 'step', 'moments'}, 'MM3_OPTIMIZER_FIELDS')
    require(value['schema'] == OPTIMIZER_SCHEMA, 'MM3_OPTIMIZER_SCHEMA')
    return {'schema': OPTIMIZER_SCHEMA,
            'step': integer(value['step'], 0, U64_MAX, 'MM3_OPTIMIZER_STEP'),
            'moments': _parameters(value['moments'], moment=True)}


def validate_state(state, model=None):
    fields = {'schema', 'cell_id', 'generation', 'scope', 'model_artifact', 'memory',
              'rng_seed', 'rng_counter', 'remaining_steps', 'sequence', 'optimizer'}
    require(type(state) is dict and set(state) == fields, 'MM3_STATE_FIELDS')
    require(state['schema'] == STATE_SCHEMA, 'MM3_STATE_SCHEMA')
    require(type(state['memory']) is list and len(state['memory']) == CLASSES and
            all(type(value) is int and -MEMORY_BOUND <= value <= MEMORY_BOUND
                for value in state['memory']), 'MM3_STATE_MEMORY')
    result = {'schema': STATE_SCHEMA, 'cell_id': hex_value(state['cell_id'], 'MM3_CELL_ID'),
              'scope': identity(state['scope'], 'MM3_SCOPE'),
              'model_artifact': hex_value(state['model_artifact'], 'MM3_MODEL_ARTIFACT'),
              'memory': list(state['memory']), 'rng_seed': hex_value(state['rng_seed'], 'MM3_RNG_SEED'),
              'optimizer': _optimizer(state['optimizer'])}
    for name in ('generation', 'rng_counter', 'remaining_steps', 'sequence'):
        result[name] = integer(state[name], 0, U64_MAX, 'MM3_' + name.upper())
    if model is not None:
        require(result['model_artifact'] == artifact(model), 'MM3_STATE_MODEL_MISMATCH')
    return result


def initial_state(model, *, cell_id, generation, scope, rng_seed, remaining_steps):
    return validate_state({'schema': STATE_SCHEMA, 'cell_id': cell_id,
                           'generation': generation, 'scope': scope,
                           'model_artifact': artifact(model), 'memory': [0] * CLASSES,
                           'rng_seed': rng_seed, 'rng_counter': 0,
                           'remaining_steps': remaining_steps, 'sequence': 0,
                           'optimizer': None}, model)


def _source(value, raw):
    require(type(value) is dict and set(value) == {'origin', 'object_id', 'sha256'}, 'MM3_SOURCE_FIELDS')
    identity(value['origin'], 'MM3_SOURCE_ORIGIN')
    identity(value['object_id'], 'MM3_SOURCE_OBJECT', 1024)
    hex_value(value['sha256'], 'MM3_SOURCE_SHA256')
    require(hashlib.sha256(raw).hexdigest() == value['sha256'], 'MM3_SOURCE_CONTENT_MISMATCH')


def _raw(value, maximum):
    require(type(value) is str and 0 < len(value) <= 2 * maximum and len(value) % 2 == 0 and
            re.fullmatch('[0-9a-f]+', value) is not None, 'MM3_PAYLOAD_HEX')
    return bytes.fromhex(value)


def _mask(value, length):
    require(type(value) is list and len(value) == length and all(type(v) is bool for v in value),
            'MM3_INPUT_MASK')
    return list(value)


def _prepare_part(part):
    require(type(part) is dict and type(part.get('modality')) is str and
            part['modality'] in MODALITIES, 'MM3_MODALITY')
    modality = part['modality']
    fields = {'modality', 'source', 'payload_hex', 'mask'}
    if modality == 'image-rgb8':
        fields |= {'width', 'height'}
    elif modality == 'audio-pcm16le':
        fields |= {'sample_rate_hz'}
    require(set(part) == fields, 'MM3_PART_FIELDS')
    raw = _raw(part['payload_hex'], 768 if modality == 'image-rgb8' else 256)
    _source(part['source'], raw)
    if modality == 'text-utf8':
        require(len(raw) <= 64, 'MM3_TEXT_LIMIT')
        try:
            decoded = raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError as error:
            raise ValueError('MM3_UTF8') from error
        normalized = decoded.replace('\r\n', '\n').replace('\r', '\n')
        tokens = list(normalized.encode('utf-8'))
        mask = _mask(part['mask'], len(tokens))
        return {'modality': modality, 'mask': mask, 'tokens': tokens,
                'decoded': decoded, 'normalized': normalized, 'raw_features': None}
    if modality == 'image-rgb8':
        width = integer(part['width'], 1, 16, 'MM3_IMAGE_WIDTH')
        height = integer(part['height'], 1, 16, 'MM3_IMAGE_HEIGHT')
        require(len(raw) == width * height * 3, 'MM3_IMAGE_BYTE_SHAPE')
        mask = _mask(part['mask'], 16)
        resized = []
        for y in range(8):
            for x in range(8):
                offset = ((y * height // 8) * width + x * width // 8) * 3
                resized.extend(raw[offset:offset + 3])
        quantized = [trunc0(value - 128, 16) for value in resized]
        patches = []
        for py in range(0, 8, 2):
            for px in range(0, 8, 2):
                patches.append([quantized[((py + dy) * 8 + px + dx) * 3 + channel]
                                for dy in range(2) for dx in range(2) for channel in range(3)])
        return {'modality': modality, 'mask': mask, 'raw_rgb8': list(raw),
                'resized_rgb8': resized, 'quantized_rgb': quantized,
                'raw_features': patches, 'tokens': None}
    require(type(part['sample_rate_hz']) is int and part['sample_rate_hz'] in (8000, 16000),
            'MM3_AUDIO_RATE')
    require(len(raw) % 2 == 0, 'MM3_AUDIO_BYTE_SHAPE')
    samples = list(struct.unpack('<' + 'h' * (len(raw) // 2), raw))
    if part['sample_rate_hz'] == 16000:
        require(len(samples) % 2 == 0, 'MM3_AUDIO_PAIR_SHAPE')
        resampled = [trunc0(samples[index] + samples[index + 1], 2)
                     for index in range(0, len(samples), 2)]
    else:
        resampled = samples
    require(1 <= len(resampled) <= 64, 'MM3_AUDIO_SAMPLE_LIMIT')
    mask = _mask(part['mask'], 16)
    valid_frames = (len(resampled) + 3) // 4
    require(not any(mask[valid_frames:]), 'MM3_AUDIO_PADDING_MASK')
    quantized = [trunc0(value, 4096) for value in resampled]
    padded = quantized + [0] * (64 - len(quantized))
    return {'modality': modality, 'mask': mask, 'raw_s16le': samples,
            'resampled_8khz': list(resampled), 'quantized_audio': quantized,
            'raw_features': [padded[index:index + 4] for index in range(0, 64, 4)],
            'valid_frames': valid_frames, 'tokens': None}


def prepare_inputs(inputs):
    """Check bytes and actually preprocess them; origin authority is external."""
    require(type(inputs) is list and 1 <= len(inputs) <= MAX_BATCH, 'MM3_BATCH')
    prepared = []
    ids = []
    for row in inputs:
        require(type(row) is dict and set(row) == {'id', 'label', 'parts'}, 'MM3_INPUT_FIELDS')
        ids.append(hex_value(row['id'], 'MM3_INPUT_ID'))
        integer(row['label'], 0, CLASSES - 1, 'MM3_INPUT_LABEL')
        parts = row['parts']
        require(type(parts) is list and 1 <= len(parts) <= len(MODALITIES), 'MM3_PART_COUNT')
        values = [_prepare_part(part) for part in parts]
        order = [MODALITIES.index(part['modality']) for part in values]
        require(order == sorted(set(order)), 'MM3_MODALITY_ORDER_OR_DUPLICATE')
        prepared.append({'id': row['id'], 'label': row['label'], 'parts': values})
    require(len(set(ids)) == len(ids), 'MM3_DUPLICATE_INPUT')
    return prepared


def _training(value):
    if value is None:
        return None
    fields = {'learning_rate_num', 'learning_rate_den', 'momentum_num', 'momentum_den',
              'clip_abs', 'trainable_mask'}
    require(type(value) is dict and set(value) == fields, 'MM3_TRAINING_FIELDS')
    result = {
        'learning_rate_num': integer(value['learning_rate_num'], 0, 1 << 16, 'MM3_LEARNING_RATE_NUM'),
        'learning_rate_den': integer(value['learning_rate_den'], 1, 1 << 32, 'MM3_LEARNING_RATE_DEN'),
        'momentum_num': integer(value['momentum_num'], 0, 1 << 16, 'MM3_MOMENTUM_NUM'),
        'momentum_den': integer(value['momentum_den'], 1, 1 << 16, 'MM3_MOMENTUM_DEN'),
        'clip_abs': integer(value['clip_abs'], 1, 1 << 40, 'MM3_GRADIENT_CLIP'),
        'trainable_mask': _parameters(value['trainable_mask'], boolean=True),
    }
    require(result['momentum_num'] < result['momentum_den'], 'MM3_MOMENTUM_RANGE')
    require(not any(result['trainable_mask']['router']), 'MM3_ROUTER_FROZEN')
    return result


def default_policy(batch_size):
    integer(batch_size, 1, MAX_BATCH, 'MM3_BATCH')
    return {'feature_mask': [True] * HIDDEN,
            'expert_mask': [[True] * EXPERTS for _ in range(batch_size)],
            'allowed_actions': list(ACTIONS), 'sampler': 'argmax-lowest',
            'abstain_margin': 0, 'tool_names': [None] * CLASSES, 'training': None}


def validate_policy(policy, batch_size):
    integer(batch_size, 1, MAX_BATCH, 'MM3_BATCH')
    require(type(policy) is dict and set(policy) == {'feature_mask', 'expert_mask', 'allowed_actions',
            'sampler', 'abstain_margin', 'tool_names', 'training'}, 'MM3_POLICY_FIELDS')
    feature_mask = _mask(policy['feature_mask'], HIDDEN)
    expert_mask = policy['expert_mask']
    require(type(expert_mask) is list and len(expert_mask) == batch_size and
            all(type(row) is list and len(row) == EXPERTS and
                all(type(value) is bool for value in row) and any(row) for row in expert_mask),
            'MM3_EXPERT_MASK')
    actions = policy['allowed_actions']
    require(type(actions) is list and 1 <= len(actions) <= len(ACTIONS) and
            all(type(value) is str and value in ACTIONS for value in actions) and
            len(set(actions)) == len(actions), 'MM3_ALLOWED_ACTIONS')
    require(type(policy['sampler']) is str and policy['sampler'] in SAMPLERS, 'MM3_SAMPLER')
    tools = policy['tool_names']
    require(type(tools) is list and len(tools) == CLASSES, 'MM3_TOOL_NAMES')
    for name in tools:
        if name is not None:
            identity(name, 'MM3_TOOL_NAME', 128)
    return {'feature_mask': feature_mask, 'expert_mask': copy.deepcopy(expert_mask),
            'allowed_actions': list(actions), 'sampler': policy['sampler'],
            'abstain_margin': integer(policy['abstain_margin'], 0, 2 * LOGIT_BOUND, 'MM3_ABSTAIN_MARGIN'),
            'tool_names': list(tools), 'training': _training(policy['training'])}


def _tensor(rows):
    require(type(rows) is list and rows and type(rows[0]) is list and rows[0], 'MM3_INTERNAL_TENSOR')
    width = len(rows[0])
    require(all(type(row) is list and len(row) == width and all(type(v) is int for v in row)
                for row in rows), 'MM3_INTERNAL_TENSOR')
    return {'dtype': 'i64', 'shape': [len(rows), width], 'values': [v for row in rows for v in row]}


def _weights(parameters, name):
    shape = PARAMETER_SHAPES[name]
    require(len(shape) == 2, 'MM3_INTERNAL_LINEAR_SHAPE')
    return [parameters[name][offset:offset + shape[1]]
            for offset in range(0, len(parameters[name]), shape[1])]


def _linear(parameters, name, rows, operations, trace):
    weight = _weights(parameters, name)
    require(1 <= len(rows) <= 64 and all(len(row) == len(weight[0]) for row in rows),
            'MM3_INTERNAL_LINEAR_INPUT')
    result = [[sum(a * b for a, b in zip(weights, row)) for weights in weight] for row in rows]
    operation = {'id': name, 'weight': _tensor(weight), 'input': _tensor(rows), 'output': _tensor(result)}
    operations.append(operation)
    trace.append({'stage': 'dense/' + name,
                  'inputs': {'weight': copy.deepcopy(operation['weight']),
                             'input': copy.deepcopy(operation['input'])},
                  'outputs': {'output': copy.deepcopy(operation['output'])}})
    return result


def _clamp(value):
    return max(-ACTIVATION_BOUND, min(ACTIVATION_BOUND, value))


def _relu(value):
    return max(0, min(ACTIVATION_BOUND, value))


def _pooled(vectors, mask):
    count = sum(mask)
    return ([0] * HIDDEN if count == 0 else
            [trunc0(sum(vector[column] for vector, allowed in zip(vectors, mask) if allowed), count)
             for column in range(HIDDEN)])


def _encode(parameters, prepared, feature_mask, operations, trace):
    encoded = [[] for _ in prepared]
    for modality in MODALITIES:
        members = [(index, part) for index, row in enumerate(prepared)
                   for part in row['parts'] if part['modality'] == modality]
        if not members:
            continue
        projected = None
        if modality != 'text-utf8':
            key = 'image' if modality == 'image-rgb8' else 'audio'
            projected = _linear(parameters, key + '_projection',
                                [unit for _, part in members for unit in part['raw_features']], operations, trace)
        offset = 0
        for row_index, part in members:
            if modality == 'text-utf8':
                preactivation = None
                vectors = [parameters['text_embedding'][token * HIDDEN:(token + 1) * HIDDEN]
                           for token in part['tokens']]
            else:
                count = len(part['raw_features'])
                preactivation = [[trunc0(value, QUANT_DIVISOR) + bias for value, bias in
                                  zip(vector, parameters[key + '_bias'])]
                                 for vector in projected[offset:offset + count]]
                vectors = [[_clamp(value) for value in vector] for vector in preactivation]
                offset += count
            pooled = _pooled(vectors, part['mask'])
            record = {'modality': modality, 'prepared': copy.deepcopy(part),
                      'preactivation': preactivation, 'vectors': vectors, 'pooled': pooled}
            encoded[row_index].append(record)
            trace.append({'stage': 'encoder/' + str(row_index) + '/' + modality,
                          'inputs': {'prepared': copy.deepcopy(part), 'preactivation': preactivation,
                                     'embedding': parameters['text_embedding'] if modality == 'text-utf8' else None},
                          'outputs': {'vectors': copy.deepcopy(vectors), 'pooled': list(pooled)}})
    fused, unmasked = [], []
    for parts in encoded:
        value = [trunc0(sum(part['pooled'][index] for part in parts), len(parts)) for index in range(HIDDEN)]
        unmasked.append(value)
        fused.append([item if allowed else 0 for item, allowed in zip(value, feature_mask)])
    trace.append({'stage': 'fusion-mask',
                  'inputs': {'components': [[part['pooled'] for part in parts] for parts in encoded],
                             'feature_mask': feature_mask},
                  'outputs': {'unmasked': _tensor(unmasked), 'masked': _tensor(fused)}})
    return fused, encoded


def _sample(scores, seed, counter):
    masses = [score - min(scores) + 1 for score in scores]
    total = sum(masses)
    limit = (1 << 256) - (1 << 256) % total
    draws = []
    for _ in range(MAX_RNG_DRAWS):
        require(counter < U64_MAX, 'MM3_RNG_COUNTER_OVERFLOW')
        raw = hashlib.sha256(RNG_DOMAIN + bytes.fromhex(seed) + counter.to_bytes(8, 'little')).digest()
        value = int.from_bytes(raw, 'big')
        draws.append({'counter': counter, 'sha256': raw.hex(), 'accepted': value < limit})
        counter += 1
        if value < limit:
            ticket = value % total
            cumulative = 0
            for index, mass in enumerate(masses):
                cumulative += mass
                if ticket < cumulative:
                    return index, counter, {'masses': masses, 'total': total,
                                            'limit_hex': format(limit, '065x'),
                                            'ticket': ticket, 'draws': draws}
    raise ValueError('MM3_RNG_REJECTION_LIMIT')


def _linear_backward(parameters, name, vector, derivative, gradients):
    weights = _weights(parameters, name)
    width = len(vector)
    for row, value in enumerate(derivative):
        for column, feature in enumerate(vector):
            gradients[name][row * width + column] += value * feature
    return [sum(weights[row][column] * derivative[row] for row in range(len(weights)))
            for column in range(width)]


def _add(left, right):
    return [a + b for a, b in zip(left, right)]


def _gated(derivative, preactivation, *, relu=False):
    low = 0 if relu else -ACTIVATION_BOUND
    return [value if low < point < ACTIVATION_BOUND else 0
            for value, point in zip(derivative, preactivation)]


def _backward(parameters, cache, active, policy):
    gradients = zero_parameters()
    losses, adjoints = [], []
    for record in active:
        index = record['row']
        target = [TARGET_VALUE if cls == record['label'] else 0 for cls in range(CLASSES)]
        errors = [score - desired for score, desired in zip(record['logits'], target)]
        dlogits = [2 * value for value in errors]
        losses.append({'row': index, 'target': target, 'errors': errors,
                       'd_logits': dlogits, 'loss': sum(value * value for value in errors)})
        gradients['head_bias'] = _add(gradients['head_bias'], dlogits)
        dz = _linear_backward(parameters, 'head', cache['head_input'][index], dlogits, gradients)
        dz = _gated(dz, cache['head_preactivation'][index])
        route = cache['routes'][index]
        adapter = cache['adapters'][route]
        down_name, up_name = 'adapter_' + str(route) + '_down', 'adapter_' + str(route) + '_up'
        da = _linear_backward(parameters, up_name, adapter['low'][index],
                              [trunc0(value, QUANT_DIVISOR) for value in dz], gradients)
        da = _gated(da, adapter['low_preactivation'][index])
        dh = _linear_backward(parameters, down_name, cache['fused'][index],
                              [trunc0(value, QUANT_DIVISOR) for value in da], gradients)
        db = _gated(dz, cache['base_preactivation'][index])
        dh = _add(dh, db)  # The base residual uses the actual encoder output.
        gradients['base_down_bias'] = _add(gradients['base_down_bias'], db)
        du = _linear_backward(parameters, 'base_down', cache['up'][index],
                              [trunc0(value, QUANT_DIVISOR) for value in db], gradients)
        du = _gated(du, cache['up_preactivation'][index], relu=True)
        gradients['base_up_bias'] = _add(gradients['base_up_bias'], du)
        dh = _add(dh, _linear_backward(parameters, 'base_up', cache['fused'][index],
                                      [trunc0(value, QUANT_DIVISOR) for value in du], gradients))
        dh = [value if allowed else 0 for value, allowed in zip(dh, policy['feature_mask'])]
        parts = cache['encoded'][index]
        dcomponent = [trunc0(value, len(parts)) for value in dh]
        component_adjoints = []
        for part in parts:
            prepared = part['prepared']
            count = sum(prepared['mask'])
            dunit = [0] * HIDDEN if count == 0 else [trunc0(value, count) for value in dcomponent]
            propagated = []
            for unit, allowed in enumerate(prepared['mask']):
                derivative = list(dunit) if allowed else [0] * HIDDEN
                if part['modality'] == 'text-utf8':
                    token = prepared['tokens'][unit]
                    for column, value in enumerate(derivative):
                        gradients['text_embedding'][token * HIDDEN + column] += value
                else:
                    key = 'image' if part['modality'] == 'image-rgb8' else 'audio'
                    derivative = _gated(derivative, part['preactivation'][unit])
                    gradients[key + '_bias'] = _add(gradients[key + '_bias'], derivative)
                    _linear_backward(parameters, key + '_projection', prepared['raw_features'][unit],
                                     [trunc0(value, QUANT_DIVISOR) for value in derivative], gradients)
                propagated.append(derivative)
            component_adjoints.append({'modality': part['modality'], 'unit_adjoints': propagated})
        adjoints.append({'row': index, 'route': route, 'd_head_preactivation': dz,
                         'd_adapter_low': da, 'd_base_preactivation': db,
                         'd_base_up_preactivation': du, 'd_fused': dh,
                         'component_adjoints': component_adjoints})
    require(all(-GRADIENT_BOUND <= value <= GRADIENT_BOUND for vector in gradients.values()
                for value in vector), 'MM3_GRADIENT_OVERFLOW')
    return gradients, losses, adjoints


def _train(model, cache, active, optimizer, policy):
    spec = policy['training']
    gradients, losses, adjoints = _backward(model['parameters'], cache, active, policy)
    trace = [
        {'stage': 'training-loss', 'inputs': {'active': copy.deepcopy(active)},
         'outputs': {'rows': losses, 'loss': sum(row['loss'] for row in losses)}},
        {'stage': 'training-backward',
         'inputs': {'rule': EXECUTION_PROFILE['backward'], 'forward_cache': copy.deepcopy(cache),
                    'd_logits': [row['d_logits'] for row in losses]},
         'outputs': {'gradients': copy.deepcopy(gradients), 'adjoints': adjoints}},
    ]
    if not active:
        summary = {'active_rows': 0, 'loss': 0, 'parameters_changed': False,
                   'optimizer_step': None if optimizer is None else optimizer['step']}
        trace.append({'stage': 'training-update', 'inputs': {'spec': spec, 'optimizer': optimizer},
                      'outputs': {'applied': False, 'model': model, 'optimizer': optimizer}})
        return copy.deepcopy(model), copy.deepcopy(optimizer), summary, trace
    old = copy.deepcopy(optimizer)
    if old is None:
        old = {'schema': OPTIMIZER_SCHEMA, 'step': 0, 'moments': zero_parameters()}
    require(old['step'] < U64_MAX, 'MM3_OPTIMIZER_STEP_OVERFLOW')
    updated, moment = copy.deepcopy(model), copy.deepcopy(old)
    moment['step'] += 1
    masked, clipped, changes = zero_parameters(), zero_parameters(), zero_parameters()
    for name, vector in gradients.items():
        for index, value in enumerate(vector):
            if not spec['trainable_mask'][name][index]:
                continue
            masked[name][index] = value
            value = max(-spec['clip_abs'], min(spec['clip_abs'], value))
            clipped[name][index] = value
            value += trunc0(spec['momentum_num'] * old['moments'][name][index], spec['momentum_den'])
            require(-MOMENT_BOUND <= value <= MOMENT_BOUND, 'MM3_MOMENT_OVERFLOW')
            moment['moments'][name][index] = value
            change = trunc0(spec['learning_rate_num'] * value, spec['learning_rate_den'])
            changes[name][index] = change
            weight = updated['parameters'][name][index] - change
            require(-parameter_bound(name) <= weight <= parameter_bound(name), 'MM3_TRAINED_WEIGHT_RANGE')
            updated['parameters'][name][index] = weight
    updated = validate_model(updated)
    summary = {'active_rows': len(active), 'loss': sum(row['loss'] for row in losses),
               'parameters_changed': canonical(updated) != canonical(model), 'optimizer_step': moment['step']}
    trace.append({'stage': 'training-update',
                  'inputs': {'model': model, 'optimizer': optimizer, 'spec': spec, 'gradients': gradients},
                  'outputs': {'applied': True, 'masked_gradients': masked, 'clipped_gradients': clipped,
                              'updates': changes, 'model': copy.deepcopy(updated), 'optimizer': copy.deepcopy(moment)}})
    return updated, moment, summary, trace


def execute(model, inputs, before, policy):
    """Execute the complete finite graph; no witness tensor drives this call."""
    model = validate_model(model)
    prepared = prepare_inputs(inputs)
    before = validate_state(before, model)
    policy = validate_policy(policy, len(prepared))
    require(before['sequence'] < U64_MAX, 'MM3_SEQUENCE_OVERFLOW')
    parameters = model['parameters']
    operations, trace = [], []
    trace.append({'stage': 'raw-preprocessing', 'inputs': {'rows': copy.deepcopy(inputs)},
                  'outputs': {'rows': copy.deepcopy(prepared)}})
    fused, encoded = _encode(parameters, prepared, policy['feature_mask'], operations, trace)
    up_product = _linear(parameters, 'base_up', fused, operations, trace)
    up_pre = [[trunc0(value, QUANT_DIVISOR) + bias for value, bias in zip(row, parameters['base_up_bias'])]
              for row in up_product]
    up = [[_relu(value) for value in row] for row in up_pre]
    trace.append({'stage': 'base-up-activation', 'inputs': {'product': _tensor(up_product), 'bias': parameters['base_up_bias']},
                  'outputs': {'preactivation': _tensor(up_pre), 'relu': _tensor(up)}})
    down_product = _linear(parameters, 'base_down', up, operations, trace)
    base_pre = [[residual + trunc0(value, QUANT_DIVISOR) + bias for residual, value, bias in
                 zip(source, row, parameters['base_down_bias'])] for source, row in zip(fused, down_product)]
    base = [[_clamp(value) for value in row] for row in base_pre]
    trace.append({'stage': 'base-residual',
                  'inputs': {'product': _tensor(down_product), 'residual': _tensor(fused), 'bias': parameters['base_down_bias']},
                  'outputs': {'preactivation': _tensor(base_pre), 'clamped': _tensor(base)}})
    router = _linear(parameters, 'router', fused, operations, trace)
    routes = [max([index for index in range(EXPERTS) if mask[index]], key=lambda index: scores[index])
              for scores, mask in zip(router, policy['expert_mask'])]
    trace.append({'stage': 'routing', 'inputs': {'scores': _tensor(router), 'expert_mask': policy['expert_mask']},
                  'outputs': {'routes': list(routes)}})
    adapters = []
    for expert in range(EXPERTS):
        down_name, up_name = 'adapter_' + str(expert) + '_down', 'adapter_' + str(expert) + '_up'
        product = _linear(parameters, down_name, fused, operations, trace)
        low_pre = [[trunc0(value, QUANT_DIVISOR) for value in row] for row in product]
        low = [[_clamp(value) for value in row] for row in low_pre]
        trace.append({'stage': down_name + '-activation', 'inputs': {'product': _tensor(product)},
                      'outputs': {'preactivation': _tensor(low_pre), 'clamped': _tensor(low)}})
        product = _linear(parameters, up_name, low, operations, trace)
        high = [[trunc0(value, QUANT_DIVISOR) for value in row] for row in product]
        adapters.append({'low_preactivation': low_pre, 'low': low, 'high': high})
        trace.append({'stage': up_name + '-rescale', 'inputs': {'product': _tensor(product)},
                      'outputs': {'rescaled': _tensor(high)}})
    head_pre = [[a + b for a, b in zip(base[index], adapters[route]['high'][index])]
                for index, route in enumerate(routes)]
    head_input = [[_clamp(value) for value in row] for row in head_pre]
    trace.append({'stage': 'selected-adapter-residual',
                  'inputs': {'base': _tensor(base), 'routes': routes,
                             'adapter_outputs': [_tensor(adapter['high']) for adapter in adapters]},
                  'outputs': {'preactivation': _tensor(head_pre), 'head_input': _tensor(head_input)}})
    head_product = _linear(parameters, 'head', head_input, operations, trace)
    after = copy.deepcopy(before)
    output = {'schema': OUTPUT_SCHEMA, 'row_ids': [row['id'] for row in prepared],
              'routes': [], 'logits': [], 'predictions': [], 'labels': [], 'actions': [],
              'stop': [], 'abstain': [], 'tool_proposals': [], 'delivery_content': [], 'training': None}
    active = []
    for index, row in enumerate(prepared):
        memory_before = list(after['memory'])
        rng_before, remaining_before = after['rng_counter'], after['remaining_steps']
        scores = prediction = label = proposal = delivery = sample = margin = route = None
        if remaining_before == 0:
            action = 'stop'
        else:
            route = routes[index]
            scores = [product + bias + memory for product, bias, memory in
                      zip(head_product[index], parameters['head_bias'], memory_before)]
            require(all(-LOGIT_BOUND <= value <= LOGIT_BOUND for value in scores), 'MM3_LOGIT_BOUND')
            ranked = sorted(range(CLASSES), key=lambda cls: (-scores[cls], cls))
            margin = scores[ranked[0]] - scores[ranked[1]]
            if margin < policy['abstain_margin']:
                action = 'abstain'
            else:
                if policy['sampler'] == 'argmax-lowest':
                    prediction = ranked[0]
                else:
                    prediction, after['rng_counter'], sample = _sample(scores, after['rng_seed'], rng_before)
                label = model['classes'][prediction]
                tool = policy['tool_names'][prediction]
                if tool is None:
                    action = 'emit'
                    delivery = {'kind': 'classification', 'input_id': row['id'], 'label': label}
                else:
                    action = 'propose_tool'
                    proposal = {'name': tool, 'arguments': {'input_id': row['id'], 'label': label,
                                                           'logits': list(scores)}}
            after['memory'] = [(3 * old + (1 if value > 0 else -1 if value < 0 else 0) * MEMORY_BOUND) // 4
                               for old, value in zip(memory_before, scores)]
            after['remaining_steps'] -= 1
            active.append({'row': index, 'route': route, 'label': row['label'], 'logits': list(scores)})
        require(action in policy['allowed_actions'], 'MM3_ACTION_NOT_ALLOWED')
        for name, value in (('routes', route), ('logits', scores), ('predictions', prediction), ('labels', label),
                            ('actions', action), ('stop', action == 'stop'), ('abstain', action == 'abstain'),
                            ('tool_proposals', proposal), ('delivery_content', delivery)):
            output[name].append(copy.deepcopy(value))
        trace.append({'stage': 'decision/' + str(index),
                      'inputs': {'input_id': row['id'], 'head_product': list(head_product[index]),
                                 'head_bias': parameters['head_bias'], 'selected_route': routes[index],
                                 'memory': memory_before, 'rng_seed': after['rng_seed'],
                                 'rng_counter': rng_before, 'remaining_steps': remaining_before,
                                 'policy': {name: policy[name] for name in
                                            ('sampler', 'abstain_margin', 'tool_names', 'allowed_actions')}},
                      'outputs': {'route': route, 'logits': scores, 'margin': margin,
                                  'sampling': sample, 'prediction': prediction, 'action': action,
                                  'tool_proposal': proposal, 'delivery_content': delivery,
                                  'memory': list(after['memory']), 'rng_counter': after['rng_counter'],
                                  'remaining_steps': after['remaining_steps']}})
    cache = {'fused': fused, 'encoded': encoded, 'up_preactivation': up_pre, 'up': up,
             'base_preactivation': base_pre, 'routes': routes, 'adapters': adapters,
             'head_preactivation': head_pre, 'head_input': head_input}
    if policy['training'] is None:
        after_model = copy.deepcopy(model)
        trace.append({'stage': 'training-disabled', 'inputs': {'training': None},
                      'outputs': {'model': copy.deepcopy(model), 'optimizer': copy.deepcopy(after['optimizer'])}})
    else:
        after_model, after['optimizer'], output['training'], training_trace = _train(
            model, cache, active, before['optimizer'], policy)
        trace.extend(training_trace)
    after['sequence'] += 1
    after['model_artifact'] = artifact(after_model)
    after = validate_state(after, after_model)
    trace.append({'stage': 'state-transition', 'inputs': {'before': before},
                  'outputs': {'after_state': copy.deepcopy(after), 'after_model_artifact': artifact(after_model)}})
    require(len({operation['id'] for operation in operations}) == len(operations), 'MM3_OPERATION_ID_COLLISION')
    return {'output': output, 'after_state': after, 'after_model': after_model,
            'operations': operations, 'trace': trace}
