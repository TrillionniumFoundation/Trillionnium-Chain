"""Full replay plus complete forward-dense W1 checks for the finite V3 Cell.

Every matrix receives its own W1 statement built from the actual encoder/graph
inputs.  Text lookup, masks, rescaling, nonlinearities, pooling, state and the
integer backward/update rule are independently replayed, not claimed to have a
succinct or W1 proof.  Producer-supplied tensors never drive the replay.

The caller must retain expected context from its task owner or verified parent
state.  No function derives expected context from a producer claim.  Historical
and live time checks are separate; neither API grants authority or consumes a
request.  Origin signatures, FinalUse, production adoption, external delivery,
model quality and work-cost security remain outside this reference relation.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import time

from contract_wire import H, ROOT, canonical, unique, u64
import useful_cell_multimodal_execution_v3 as execution
import useful_cell_source_guard_v2 as source_guard
import work_oracle as work


RELATION_ID = 'pon-useful-cell-multimodal-int-v3'
VERIFIER_ID = 'pon-useful-cell-multimodal-python-reference-v3'
CHALLENGE_DOMAIN = RELATION_ID + '/forward-dense-challenge'
CONTRACT_LIMIT = 256 * 1024
WITNESS_LIMIT = 16 * 1024 * 1024
RESULT_LIMIT = 4 * 1024 * 1024
WORK_PROFILE = 'pon-matmul-transcript-64-v1'
SCOPE = {
    'research_only': True,
    'fixed_multimodal_codecs_and_graph': True,
    'arbitrary_encoder_or_graph': False,
    'source_origin_authentication': False,
    'ordinary_hepta_product': False,
    'native_node_admission': False,
    'public_reward_eligible': False,
    'production_activation': False,
    'training': 'explicit-integer-surrogate-not-true-discrete-derivative-or-bptt',
    'nonlinear_and_backward_proof': 'full-scalar-replay',
    'forward_dense_proof': 'separate-complete-w1-for-every-executed-dense-operator',
    'tool_effects': 'proposals-only',
}
SOURCE_FILES = (
    'formal/pon-nakamoto-v1/useful_cell_multimodal_relation_v3.py',
    'formal/pon-nakamoto-v1/useful_cell_multimodal_execution_v3.py',
    'formal/pon-nakamoto-v1/useful_cell_source_guard_v2.py',
    'formal/pon-nakamoto-v1/work_oracle.py',
    'formal/pon-nakamoto-v1/contract_wire.py',
    'config/pon/ledger-v1.json', 'config/pon/work-profile-v1.json',
    'config/pon/model-family-v1.json', 'config/pon/devnet-v1.json',
    'config/pon/evaluation-round-v1.json',
)
_IMPORT_SOURCE = {path: (ROOT / path).read_bytes() for path in SOURCE_FILES}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def strict_json(raw, maximum, code):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, code + '_LIMIT')
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError(code)))
        require(canonical(value) == raw, code + '_CANONICAL')
    except (UnicodeError, TypeError, RecursionError, OverflowError, json.JSONDecodeError) as error:
        raise ValueError(code) from error
    return value


def _object(value, maximum, code):
    try:
        raw = canonical(value)
    except (ValueError, TypeError, RecursionError, OverflowError) as error:
        raise ValueError(code) from error
    return strict_json(raw, maximum, code)


def current_identity():
    # Reuse the corrected source-name/code/import/default guard, not V1's
    # historical __module__-based filtering.  This is local consistency only.
    source_guard.verify_sources(ROOT, _IMPORT_SOURCE)
    manifest = {path: hashlib.sha256(raw).hexdigest() for path, raw in _IMPORT_SOURCE.items()}
    runtime = {'implementation': sys.implementation.name, 'version': list(sys.version_info[:3]),
               'byteorder': sys.byteorder, 'cache_tag': sys.implementation.cache_tag}
    parameters = {
        'relation': RELATION_ID, 'verifier': VERIFIER_ID, 'work_profile': WORK_PROFILE,
        'challenge': CHALLENGE_DOMAIN, 'execution': execution.EXECUTION_PROFILE,
        'tensor_shapes': execution.PARAMETER_SHAPES,
        'dense_w1': {'width': work.N, 'noise_rank': work.R, 'prime': work.Q,
                     'proof_bytes': work.PROOF_BYTES, 'packing': 'zero-pad-weights-times-transposed-input',
                     'decode': 'centered-integer-with-strict-double-bound-and-zero-padding'},
        'contract_limit': CONTRACT_LIMIT, 'witness_limit': WITNESS_LIMIT, 'result_limit': RESULT_LIMIT,
        'historical_time': 'independent-parent-state-and-protocol-milliseconds',
        'live_time': 'consumer-milliseconds-before-and-after-complete-verification',
        'segment_binding': 'contract-ordinal-kind-predecessor-dtype-shape-and-actual-values-v3',
        'scope': SCOPE,
    }
    return {'program_sha256': execution.digest({'source_manifest': manifest, 'runtime': runtime,
                                               'parameters': parameters}),
            'parameters_sha256': execution.digest(parameters), 'source_manifest': manifest,
            'runtime': runtime}


def contract_id(raw):
    strict_json(raw, CONTRACT_LIMIT, 'MM3_CONTRACT')
    return H(RELATION_ID + '/contract', raw).hex()


def _parent_context(value):
    require(type(value) is dict and set(value) == {'network', 'parent_id', 'parent_state_root',
            'block_height', 'consensus_time_ms'}, 'MM3_PARENT_FIELDS')
    for name in ('network', 'parent_id', 'parent_state_root'):
        execution.hex_value(value[name], 'MM3_PARENT_' + name.upper())
    execution.integer(value['block_height'], 1, execution.U64_MAX, 'MM3_PARENT_HEIGHT')
    execution.integer(value['consensus_time_ms'], 0, execution.U64_MAX, 'MM3_PARENT_TIME')
    return copy.deepcopy(value)


def _assemble(model, inputs, before, *, policy, consumer, allowed_use, request_id,
              issued_at_ms, deadline_ms, parent_context, target, program):
    model = execution.validate_model(model)
    prepared = execution.prepare_inputs(inputs)
    before = execution.validate_state(before, model)
    policy = execution.validate_policy(policy, len(inputs))
    parent = _parent_context(parent_context)
    execution.identity(consumer, 'MM3_CONSUMER')
    execution.identity(allowed_use, 'MM3_ALLOWED_USE')
    execution.hex_value(request_id, 'MM3_REQUEST_ID')
    execution.hex_value(target, 'MM3_TARGET')
    require(target != '00' * 32, 'MM3_TARGET_ZERO')
    execution.integer(issued_at_ms, 0, execution.U64_MAX, 'MM3_ISSUED_AT')
    execution.integer(deadline_ms, 0, execution.U64_MAX, 'MM3_DEADLINE')
    require(issued_at_ms <= parent['consensus_time_ms'] <= deadline_ms, 'MM3_PROTOCOL_TIME_WINDOW')
    return {
        'schema': RELATION_ID,
        'task': {'consumer': consumer, 'allowed_use': allowed_use, 'request_id': request_id,
                 'issued_at_ms': issued_at_ms, 'deadline_ms': deadline_ms,
                 'candidate_artifact': execution.artifact(model)},
        'parent_context': parent,
        'before': {'state_sha256': execution.digest(before), 'cell_id': before['cell_id'],
                   'generation': before['generation'], 'scope': before['scope'], 'sequence': before['sequence']},
        'model': {'artifact': execution.artifact(model), 'schema': execution.MODEL_SCHEMA,
                  'ordered_bundle': execution.EXECUTION_PROFILE['model_order'],
                  'parameter_tensor_shapes': copy.deepcopy(execution.PARAMETER_SHAPES),
                  'classes': list(model['classes'])},
        'inputs': {'raw_inputs_sha256': execution.digest(inputs),
                   'preprocessed_sha256': execution.digest(prepared),
                   'rows': [{'id': row['id'], 'label': row['label'],
                             'parts': [{'modality': part['modality'], 'source': copy.deepcopy(part['source'])}
                                       for part in row['parts']]} for row in inputs]},
        'policy': policy,
        'proof': {'relation': RELATION_ID, 'verifier': VERIFIER_ID,
                  'program_sha256': program['program_sha256'], 'parameters_sha256': program['parameters_sha256'],
                  'source_manifest_sha256': execution.digest(program['source_manifest']),
                  'work_profile': WORK_PROFILE, 'target': target, 'challenge_domain': CHALLENGE_DOMAIN},
        'scope': copy.deepcopy(SCOPE),
    }


def freeze_contract(model, inputs, before_state, *, policy, consumer, allowed_use,
                    request_id, issued_at_ms, deadline_ms, parent_context, target):
    """Admit the caller's actual bytes/state; not a source of caller authority."""
    program = current_identity()
    raw = canonical(_assemble(model, inputs, before_state, policy=policy, consumer=consumer,
                              allowed_use=allowed_use, request_id=request_id, issued_at_ms=issued_at_ms,
                              deadline_ms=deadline_ms, parent_context=parent_context, target=target, program=program))
    require(len(raw) <= CONTRACT_LIMIT, 'MM3_CONTRACT_LIMIT')
    require(current_identity() == program, 'MM3_PROGRAM_CHANGED_DURING_FREEZE')
    return raw


def _contract(raw):
    value = strict_json(raw, CONTRACT_LIMIT, 'MM3_CONTRACT')
    require(type(value) is dict and set(value) == {'schema', 'task', 'parent_context', 'before', 'model',
            'inputs', 'policy', 'proof', 'scope'}, 'MM3_CONTRACT_FIELDS')
    require(value['schema'] == RELATION_ID, 'MM3_RELATION_VERSION')
    require(type(value['task']) is dict and set(value['task']) == {'consumer', 'allowed_use', 'request_id',
            'issued_at_ms', 'deadline_ms', 'candidate_artifact'}, 'MM3_TASK_FIELDS')
    require(type(value['proof']) is dict and set(value['proof']) == {'relation', 'verifier', 'program_sha256',
            'parameters_sha256', 'source_manifest_sha256', 'work_profile', 'target', 'challenge_domain'},
            'MM3_PROOF_FIELDS')
    return value


def _bound_contract(raw, model, inputs, before, program):
    value = _contract(raw)
    task = value['task']
    rebuilt = _assemble(model, inputs, before, policy=value['policy'], consumer=task['consumer'],
                        allowed_use=task['allowed_use'], request_id=task['request_id'],
                        issued_at_ms=task['issued_at_ms'], deadline_ms=task['deadline_ms'],
                        parent_context=value['parent_context'], target=value['proof']['target'], program=program)
    require(canonical(rebuilt) == raw, 'MM3_EXECUTED_CONTRACT_MISMATCH')
    return value


def _tile(operation):
    """Pack a replay-generated dense operation, including every padding cell."""
    weights, inputs, outputs = operation['weight'], operation['input'], operation['output']
    rows, width = weights['shape']
    batch, input_width = inputs['shape']
    require(width == input_width and outputs['shape'] == [batch, rows] and
            1 <= rows <= work.N and 1 <= width <= work.N and 1 <= batch <= work.N and
            weights['dtype'] == inputs['dtype'] == outputs['dtype'] == 'i64', 'MM3_DENSE_SHAPE')
    a, b = [0] * work.CELLS, [0] * work.CELLS
    for row in range(rows):
        for coordinate in range(width):
            a[row * work.N + coordinate] = weights['values'][row * width + coordinate] % work.Q
    for request in range(batch):
        for coordinate in range(width):
            b[coordinate * work.N + request] = inputs['values'][request * width + coordinate] % work.Q
    bounds = [sum(abs(weights['values'][row * width + coordinate]) *
                  max(abs(inputs['values'][request * width + coordinate]) for request in range(batch))
                  for coordinate in range(width)) for row in range(rows)]
    require(all(2 * bound < work.Q for bound in bounds), 'MM3_DENSE_SIGNED_BOUND')
    return {'operation_id': operation['id'], 'a': a, 'b': b, 'rows': rows, 'batch': batch,
            'bounds': bounds, 'task': work.task_id(a, b),
            'material': work.field_bytes(a) + work.field_bytes(b)}


def _check_product(operation, tile, product):
    require(type(product) is list and len(product) == work.CELLS and
            all(type(value) is int and 0 <= value < work.Q for value in product), 'MM3_DENSE_PRODUCT_FIELD')
    for row in range(work.N):
        for request in range(work.N):
            value = product[row * work.N + request]
            if row >= tile['rows'] or request >= tile['batch']:
                require(value == 0, 'MM3_DENSE_PRODUCT_PADDING')
                continue
            signed = value - work.Q if 2 * value > work.Q else value
            require(abs(signed) <= tile['bounds'][row], 'MM3_DENSE_PRODUCT_RANGE')
            require(signed == operation['output']['values'][request * tile['rows'] + row],
                    'MM3_DENSE_PRODUCT_MISMATCH')


def _challenge(cid, before, ordinal, tile, nonce):
    execution.integer(nonce, 0, execution.U64_MAX, 'MM3_WORK_NONCE')
    return H(CHALLENGE_DOMAIN, bytes.fromhex(cid), bytes.fromhex(execution.digest(before)), u64(ordinal),
             tile['operation_id'].encode('ascii'), tile['task'], u64(nonce))


def _segments(cid, result):
    prior = H(RELATION_ID + '/segment-start', bytes.fromhex(cid)).hex()
    linked = []
    for ordinal, stage in enumerate(result['trace']):
        require(type(stage) is dict and set(stage) == {'stage', 'inputs', 'outputs'}, 'MM3_TRACE_SHAPE')
        item = {'schema': RELATION_ID + '/segment', 'contract_id': cid,
                'ordinal': ordinal, 'predecessor': prior, **copy.deepcopy(stage)}
        prior = H(RELATION_ID + '/segment', canonical(item)).hex()
        linked.append(dict(item, segment_id=prior))
    return linked


def _output(value, cid, result, segments):
    return {'schema': RELATION_ID + '/output', 'contract_id': cid,
            'request_id': value['task']['request_id'], 'consumer': value['task']['consumer'],
            'allowed_use': value['task']['allowed_use'],
            'before_model_artifact': value['task']['candidate_artifact'],
            'after_model_artifact': execution.artifact(result['after_model']),
            'execution': copy.deepcopy(result['output']), 'segment_root': segments[-1]['segment_id'],
            'tools_executed': False, 'external_delivery_verified': False}


def prove_reference(contract_raw, model, inputs, before_state, *, max_attempts=64):
    execution.integer(max_attempts, 1, 4096, 'MM3_SEARCH_BUDGET')
    program = current_identity()
    value = _bound_contract(contract_raw, model, inputs, before_state, program)
    result = execution.execute(model, inputs, before_state, value['policy'])
    cid = contract_id(contract_raw)
    target = bytes.fromhex(value['proof']['target'])
    entries, attempts = [], []
    for ordinal, operation in enumerate(result['operations']):
        tile = _tile(operation)
        for nonce in range(max_attempts):
            challenge = _challenge(cid, before_state, ordinal, tile, nonce)
            proof = work.prove(challenge, tile['a'], tile['b'])
            if H('ticket', challenge, proof[-32:]) <= target:
                break
        else:
            raise ValueError('MM3_SEARCH_EXHAUSTED:operation=' + operation['id'] +
                             ':all_attempts=' + str(sum(attempts) + max_attempts))
        product = list(struct.unpack('<' + 'I' * work.CELLS, proof[4 + 8 * work.CELLS:-32]))
        _check_product(operation, tile, product)
        attempts.append(nonce + 1)
        entries.append({'ordinal': ordinal, 'operation_id': operation['id'], 'nonce': nonce, 'proof_hex': proof.hex()})
    segments = _segments(cid, result)
    witness = canonical({'schema': RELATION_ID + '/witness', 'model': model, 'inputs': inputs,
                         'dense_proofs': entries, 'segments': segments, 'after_model': result['after_model']})
    require(len(witness) <= WITNESS_LIMIT, 'MM3_WITNESS_LIMIT')
    require(current_identity() == program, 'MM3_PROGRAM_CHANGED_DURING_PROVING')
    return {'output': _output(value, cid, result, segments), 'after_state': result['after_state'],
            'after_model': result['after_model'], 'witness': witness, 'work_attempts': attempts}


def _expected(raw, before, expected):
    expected = _object(expected, RESULT_LIMIT, 'MM3_EXPECTED_CONTEXT')
    require(type(expected) is dict and set(expected) == {'contract_id', 'program_sha256', 'parameters_sha256',
            'before_state', 'consumer', 'allowed_use', 'request_id', 'candidate_artifact',
            'inputs_sha256', 'parent_context'}, 'MM3_EXPECTED_FIELDS')
    for name in ('contract_id', 'program_sha256', 'parameters_sha256', 'request_id',
                 'candidate_artifact', 'inputs_sha256'):
        execution.hex_value(expected[name], 'MM3_EXPECTED_' + name.upper())
    require(contract_id(raw) == expected['contract_id'], 'MM3_EXPECTED_CONTRACT')
    require(canonical(execution.validate_state(before)) == canonical(execution.validate_state(expected['before_state'])),
            'MM3_EXPECTED_STATE')
    value = _contract(raw)
    for name in ('consumer', 'allowed_use', 'request_id', 'candidate_artifact'):
        require(value['task'][name] == expected[name], 'MM3_EXPECTED_' + name.upper())
    require(type(value['inputs']) is dict and value['inputs'].get('raw_inputs_sha256') == expected['inputs_sha256'],
            'MM3_EXPECTED_INPUTS')
    parent = _parent_context(expected['parent_context'])
    require(canonical(value['parent_context']) == canonical(parent), 'MM3_EXPECTED_PARENT')
    issued = execution.integer(value['task']['issued_at_ms'], 0, execution.U64_MAX, 'MM3_ISSUED_AT')
    deadline = execution.integer(value['task']['deadline_ms'], 0, execution.U64_MAX, 'MM3_DEADLINE')
    require(issued <= parent['consensus_time_ms'] <= deadline, 'MM3_PROTOCOL_TIME_WINDOW')
    return value, expected


def _verify(raw, before, output, after, witness_raw, *, expected):
    value, expected = _expected(raw, before, expected)
    # _expected canonicalized an independent owner snapshot.  Use that stable
    # value throughout a long proof check instead of rereading a caller's
    # mutable state object between replay and the per-operator challenges.
    before = execution.validate_state(expected['before_state'])
    program = current_identity()
    for name in ('program_sha256', 'parameters_sha256'):
        require(program[name] == expected[name], 'MM3_EXPECTED_' + name.upper())
    output = _object(output, RESULT_LIMIT, 'MM3_OUTPUT')
    after = execution.validate_state(after)
    witness = strict_json(witness_raw, WITNESS_LIMIT, 'MM3_WITNESS')
    require(type(witness) is dict and set(witness) == {'schema', 'model', 'inputs', 'dense_proofs',
            'segments', 'after_model'}, 'MM3_WITNESS_FIELDS')
    require(witness['schema'] == RELATION_ID + '/witness', 'MM3_WITNESS_SCHEMA')
    _bound_contract(raw, witness['model'], witness['inputs'], before, program)
    result = execution.execute(witness['model'], witness['inputs'], before, value['policy'])
    require(type(witness['dense_proofs']) is list and len(witness['dense_proofs']) == len(result['operations']),
            'MM3_DENSE_PROOF_COUNT')
    for ordinal, (operation, entry) in enumerate(zip(result['operations'], witness['dense_proofs'])):
        require(type(entry) is dict and set(entry) == {'ordinal', 'operation_id', 'nonce', 'proof_hex'},
                'MM3_DENSE_PROOF_FIELDS')
        require(type(entry['ordinal']) is int and entry['ordinal'] == ordinal and
                entry['operation_id'] == operation['id'], 'MM3_DENSE_PROOF_ORDER')
        execution.hex_value(entry['proof_hex'], 'MM3_DENSE_PROOF_HEX', 2 * work.PROOF_BYTES)
        proof = bytes.fromhex(entry['proof_hex'])
        tile = _tile(operation)
        require(proof[4:4 + 8 * work.CELLS] == tile['material'], 'MM3_DENSE_MATERIAL')
        challenge = _challenge(expected['contract_id'], before, ordinal, tile, entry['nonce'])
        _, product = work.verify(challenge, tile['task'], bytes.fromhex(value['proof']['target']), proof)
        _check_product(operation, tile, product)
    require(canonical(after) == canonical(result['after_state']), 'MM3_AFTER_STATE_RELATION')
    require(canonical(witness['after_model']) == canonical(result['after_model']), 'MM3_AFTER_MODEL_RELATION')
    segments = _segments(expected['contract_id'], result)
    require(canonical(witness['segments']) == canonical(segments), 'MM3_SEGMENT_DATAFLOW_RELATION')
    require(canonical(output) == canonical(_output(value, expected['contract_id'], result, segments)),
            'MM3_OUTPUT_RELATION')
    require(current_identity() == program, 'MM3_PROGRAM_CHANGED_DURING_VERIFICATION')
    return {
        'schema': RELATION_ID + '/verification', 'contract_id': expected['contract_id'],
        'relation_valid': True, 'raw_content_replayed': True, 'source_origin_authenticated': False,
        'fixed_multimodal_preprocessing_verified': True, 'learned_encoder_replayed': True,
        'all_forward_dense_products_verified': True,
        'complete_w1_transcripts_verified': len(result['operations']),
        'nonlinear_and_backward_verification': 'full-scalar-replay', 'backward_w1_proven': False,
        'state_transition_verified': True, 'sampler_state_verified': True,
        'training_step_verified': value['policy']['training'] is not None,
        'segments_verified': len(segments), 'segment_root': segments[-1]['segment_id'],
        'before_state_sha256': execution.digest(before), 'after_state_sha256': execution.digest(after),
        'before_model_artifact': execution.artifact(witness['model']),
        'after_model_artifact': execution.artifact(result['after_model']),
        'external_context_matched': True, 'owner_authorization_verified': False,
        'request_consumed': False, 'checkpoint_committed': False, 'final_use_granted': False,
        'actual_production_model_use_verified': False, 'arbitrary_encoder_or_graph': False,
        'ordinary_hepta_product': False, 'native_node_admission': False,
        'tools_executed': False, 'external_delivery_verified': False,
        'succinct_proof': False, 'work_security_qualified': False, 'model_quality_qualified': False,
        'production_qualified': False, 'public_reward_eligible': False,
    }


def verify_historical_relation(contract_raw, before_state, output, after_state, witness_raw, *, expected):
    """Use only independent protocol parent/time; never today's wall clock."""
    report = _verify(contract_raw, before_state, output, after_state, witness_raw, expected=expected)
    return dict(report, time_semantics='historical-parent-protocol-time',
                consensus_time_ms=_contract(contract_raw)['parent_context']['consensus_time_ms'])


def verify_live_relation(contract_raw, before_state, output, after_state, witness_raw, *, expected,
                         clock_ms=lambda: time.time_ns() // 1_000_000):
    """Check current time only; a real owner must still recheck and consume."""
    started = execution.integer(clock_ms(), 0, execution.U64_MAX, 'MM3_CLOCK')
    value, _ = _expected(contract_raw, before_state, expected)
    require(value['task']['issued_at_ms'] <= started <= value['task']['deadline_ms'], 'MM3_LIVE_START_WINDOW')
    report = _verify(contract_raw, before_state, output, after_state, witness_raw, expected=expected)
    finished = execution.integer(clock_ms(), 0, execution.U64_MAX, 'MM3_CLOCK')
    require(started <= finished <= value['task']['deadline_ms'], 'MM3_LIVE_COMPLETION_WINDOW')
    return dict(report, time_semantics='live-consumer-clock', clock_start_ms=started, clock_finish_ms=finished)
