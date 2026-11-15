"""Full replay relation for a bounded, stateful integer source-routing Cell.

The relation executes preprocessing, all five W1 products, recurrent decisions
and an optional exact training step. It is a reference verifier, not a succinct
proof or an activated native consensus rule. Historical validation never reads
wall time or today's revocations. Live validation checks time but grants no
authority: the existing Hepta owner must retain expected context independently
and perform its current-generation, FinalUse and atomic journal checks.
"""
from __future__ import annotations

import copy
import struct
import time

from contract_wire import H, ROOT, canonical, u64
from evaluation_bundle import artifact_id
from experiments import shared_cell_operator_v1 as cell
from model_contract import DIM, load_model_bytes
import useful_cell_execution_v2 as execution
import useful_cell_relation_v1 as v1
import useful_cell_source_guard_v2 as source_guard
import work_oracle as work

RELATION_ID = 'pon-useful-cell-stateful-int257-v2'
VERIFIER_ID = 'pon-useful-cell-stateful-python-reference-v2'
CHALLENGE_DOMAIN = 'useful-cell-stateful-int257-v2/challenge'
CONTRACT_LIMIT = 128 * 1024
WITNESS_LIMIT = 4 * 1024 * 1024
RESULT_LIMIT = 2 * 1024 * 1024
SCOPE = {
    'research_only': True,
    'ordinary_hepta_product': False,
    'native_node_admission': False,
    'public_reward_eligible': False,
    'production_activation': False,
    'upstream': 'frozen-public-source-token-extractor',
    'training': 'integer-surrogate-with-discrete-state-stop-gradient',
    'tool_effects': 'proposals-only',
}
SOURCE_FILES = (
    'formal/pon-nakamoto-v1/useful_cell_relation_v2.py',
    'formal/pon-nakamoto-v1/useful_cell_execution_v2.py',
    'formal/pon-nakamoto-v1/useful_cell_source_guard_v2.py',
)
_IMPORT_SOURCE = {path: (ROOT / path).read_bytes() for path in SOURCE_FILES}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def _canonical_object(value, limit, code):
    """Bound untrusted Python objects as strictly as the canonical wire form."""
    try:
        raw = canonical(value)
    except (ValueError, TypeError, RecursionError, OverflowError) as error:
        raise ValueError(code) from error
    return v1.strict_json(raw, limit, code)


def _loaded_source_guard():
    source_guard.verify_sources(ROOT, {**v1._IMPORT_SOURCE, **_IMPORT_SOURCE})


def current_identity():
    # V1 owns the executed source/feature/work closure; its loaded-source guard
    # is retained rather than relabeling that implementation with V2 source.
    _loaded_source_guard()
    upstream = v1.current_identity()
    manifest = {**upstream['source_manifest'],
                **{name: v1.sha256(raw) for name, raw in _IMPORT_SOURCE.items()}}
    parameters = {
        'relation': RELATION_ID, 'verifier': VERIFIER_ID,
        'challenge': CHALLENGE_DOMAIN, 'work_profile': cell.PROFILE,
        'tile_widths': [64, 64, 64, 64, 1],
        'contract_limit': CONTRACT_LIMIT, 'witness_limit': WITNESS_LIMIT,
        'result_limit': RESULT_LIMIT, 'scope': SCOPE,
        'execution': execution.EXECUTION_PROFILE,
        'source_relation_parameters': upstream['parameters_sha256'],
        'historical_time': 'independently-verified-parent-and-protocol-time',
        'live_time': 'consumer-clock-before-and-after-complete-verification',
        'segment_binding': 'contract-ordinal-kind-predecessor-and-actual-values-v2',
    }
    return {
        'program_sha256': v1.digest({'source_manifest': manifest,
                                    'runtime': upstream['runtime'],
                                    'parameters': parameters}),
        'parameters_sha256': v1.digest(parameters),
        'source_manifest': manifest, 'runtime': upstream['runtime'],
        'source_relation_program': upstream['program_sha256'],
    }


def contract_id(raw):
    v1.strict_json(raw, CONTRACT_LIMIT, 'V2_CONTRACT')
    return H('useful-cell-stateful-int257-v2/contract', raw).hex()


def _parent_context(value):
    require(type(value) is dict and set(value) ==
            {'network', 'parent_id', 'parent_state_root', 'block_height',
             'consensus_time_ms'}, 'PARENT_CONTEXT_FIELDS')
    for name in ('network', 'parent_id', 'parent_state_root'):
        v1.hex_value(value[name], code='PARENT_' + name.upper())
    for name in ('block_height', 'consensus_time_ms'):
        v1.unsigned(value[name], 'PARENT_' + name.upper())
    require(value['block_height'] > 0, 'PARENT_BLOCK_HEIGHT')
    return copy.deepcopy(value)


def _source_rows(model, rows, identity):
    # This is the real Git-source replay, including inventory, normalized raw
    # text, tokenization and clipping. No witness flag can replace it.
    v1._verify_upstream(model, rows, {
        'program_sha256': identity['source_relation_program']})


def _assemble(model, rows, before, *, policy, consumer, allowed_use,
              request_id, issued_at_ms, deadline_ms, parent_context, target,
              identity):
    require(type(model) is dict, 'MODEL_OBJECT')
    load_model_bytes(canonical(model))
    v1._rows(rows)
    before = execution.validate_state(before, model)
    policy = execution.validate_policy(policy, len(rows))
    parent = _parent_context(parent_context)
    v1.identity_text(consumer, 'CONSUMER')
    v1.identity_text(allowed_use, 'ALLOWED_USE')
    v1.hex_value(request_id, code='REQUEST_ID')
    v1.hex_value(target, code='WORK_TARGET')
    require(target != '00' * 32, 'WORK_TARGET_ZERO')
    v1.unsigned(issued_at_ms, 'ISSUED_AT')
    v1.unsigned(deadline_ms, 'DEADLINE')
    require(issued_at_ms <= parent['consensus_time_ms'] <= deadline_ms,
            'PROTOCOL_TIME_WINDOW')
    prepared = execution.prepare_rows(rows, policy)
    weights = model['base'] + model['router'] + [r for d in model['deltas'] for r in d]
    return {
        'schema': RELATION_ID,
        'task': {'consumer': consumer, 'allowed_use': allowed_use,
                 'request_id': request_id, 'issued_at_ms': issued_at_ms,
                 'deadline_ms': deadline_ms, 'candidate_artifact': artifact_id(model)},
        'parent_context': parent,
        'before': {'state_sha256': v1.digest(before), 'cell_id': before['cell_id'],
                   'generation': before['generation'], 'scope': before['scope'],
                   'sequence': before['sequence']},
        'model': {
            'artifact': artifact_id(model), 'schema': model['schema'],
            'source_commit': model['source'],
            'ordered_bundle': ['base', 'router', 'delta-0', 'delta-1', 'delta-2'],
            'composition': 'base-plus-one-masked-router-selected-delta-plus-memory',
            'weight_tensor_sha256': v1.digest(weights),
            'encoder': {'kind': 'source-token-hash-extractor', 'feature': model['feature'],
                        'source_sha256': identity['source_manifest'][
                            'formal/pon-nakamoto-v1/experiments/model_loop.py']},
        },
        'inputs': {
            'modality': 'public-git-rust-source', 'source_rows_sha256': v1.digest(rows),
            'masked_rows_sha256': v1.digest(prepared),
            'members': [{'id': row['id'], 'file': row['file'],
                         'source_content_sha256': row['source_content_sha256']}
                        for row in rows],
            'tensor_shape': [len(rows), DIM], 'tensor_type': 'signed-int-feature-v1',
        },
        'policy': policy,
        'proof': {'relation': RELATION_ID, 'verifier': VERIFIER_ID,
                  'program_sha256': identity['program_sha256'],
                  'parameters_sha256': identity['parameters_sha256'],
                  'source_manifest_sha256': v1.digest(identity['source_manifest']),
                  'work_profile': cell.PROFILE, 'target': target,
                  'challenge_domain': CHALLENGE_DOMAIN},
        'scope': copy.deepcopy(SCOPE),
    }


def freeze_contract(model, rows, before_state, *, policy, consumer, allowed_use,
                    request_id, issued_at_ms, deadline_ms, parent_context, target):
    """Called by an admitting consumer with its own task/state, never authority."""
    identity = current_identity()
    value = _assemble(model, rows, before_state, policy=policy, consumer=consumer,
                      allowed_use=allowed_use, request_id=request_id,
                      issued_at_ms=issued_at_ms, deadline_ms=deadline_ms,
                      parent_context=parent_context, target=target, identity=identity)
    _source_rows(model, rows, identity)
    raw = canonical(value)
    require(len(raw) <= CONTRACT_LIMIT, 'V2_CONTRACT_LIMIT')
    require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_FREEZE')
    return raw


def _contract(raw):
    value = v1.strict_json(raw, CONTRACT_LIMIT, 'V2_CONTRACT')
    require(type(value) is dict and set(value) ==
            {'schema', 'task', 'parent_context', 'before', 'model', 'inputs',
             'policy', 'proof', 'scope'}, 'V2_CONTRACT_FIELDS')
    require(value['schema'] == RELATION_ID, 'V2_RELATION_VERSION')
    require(type(value['task']) is dict and set(value['task']) ==
            {'consumer', 'allowed_use', 'request_id', 'issued_at_ms',
             'deadline_ms', 'candidate_artifact'}, 'V2_TASK_FIELDS')
    require(type(value['proof']) is dict and set(value['proof']) ==
            {'relation', 'verifier', 'program_sha256', 'parameters_sha256',
             'source_manifest_sha256', 'work_profile', 'target', 'challenge_domain'},
            'V2_PROOF_FIELDS')
    return value


def _bound_contract(raw, model, rows, before, identity):
    value = _contract(raw)
    task = value['task']
    rebuilt = _assemble(model, rows, before, policy=value['policy'],
                        consumer=task['consumer'], allowed_use=task['allowed_use'],
                        request_id=task['request_id'], issued_at_ms=task['issued_at_ms'],
                        deadline_ms=task['deadline_ms'], parent_context=value['parent_context'],
                        target=value['proof']['target'], identity=identity)
    require(canonical(rebuilt) == raw, 'V2_EXECUTED_CONTRACT_MISMATCH')
    _source_rows(model, rows, identity)
    return value


def _challenge(raw, before, tile, nonce):
    v1.unsigned(nonce, 'WORK_NONCE')
    return H(CHALLENGE_DOMAIN, bytes.fromhex(contract_id(raw)),
             bytes.fromhex(v1.digest(before)), bytes.fromhex(tile['task']),
             u64(tile['index']), u64(nonce))


def _segments(cid, model, rows, before, policy, products, result):
    """Recompute an ordered dataflow transcript from actual consumed values.

    Every stage has values, not an asserted digest. A next-stage input includes
    the predecessor identity and the exact tensors passed by this execution.
    Even equal-valued tensors belonging to another admitted task have different
    segment identities. None of the witness's segments drive computation.
    """
    prepared = execution.prepare_rows(rows, policy)
    stages = [
        {'stage': 'source-replay',
         'inputs': {'source': model['source'], 'members': [row['id'] for row in rows]},
         'outputs': {'shape': [len(rows), DIM], 'dtype': 'signed-integer',
                     'values': [row['x'] for row in rows]}},
        {'stage': 'feature-mask',
         'inputs': {'values': [row['x'] for row in rows], 'mask': policy['feature_mask']},
         'outputs': {'shape': [len(rows), DIM], 'dtype': 'signed-integer',
                     'values': [row['x'] for row in prepared]}},
        {'stage': 'five-w1-products',
         'inputs': {'values': [row['x'] for row in prepared], 'model': artifact_id(model)},
         'outputs': {'shape': [15, len(rows)], 'dtype': 'signed-integer', 'values': products}},
        *result['trace'],
        {'stage': 'checkpoint',
         'inputs': {'before': before, 'decisions': result['output']},
         'outputs': {'after_state': result['after_state'],
                     'after_model': artifact_id(result['after_model'])}},
    ]
    prior = H('useful-cell-stateful-int257-v2/segment-start', bytes.fromhex(cid)).hex()
    linked = []
    for index, stage in enumerate(stages):
        require(type(stage) is dict and set(stage) == {'stage', 'inputs', 'outputs'},
                'EXECUTION_TRACE_SHAPE')
        item = {'schema': RELATION_ID + '/segment', 'contract_id': cid,
                'ordinal': index, 'predecessor': prior, **copy.deepcopy(stage)}
        identity = H('useful-cell-stateful-int257-v2/segment', canonical(item)).hex()
        linked.append(dict(item, segment_id=identity))
        prior = identity
    return linked


def _output(value, cid, result, segments):
    return {
        'schema': RELATION_ID + '/output', 'contract_id': cid,
        'request_id': value['task']['request_id'], 'consumer': value['task']['consumer'],
        'allowed_use': value['task']['allowed_use'],
        'before_model_artifact': value['task']['candidate_artifact'],
        'after_model_artifact': artifact_id(result['after_model']),
        'execution': result['output'],
        'segment_root': segments[-1]['segment_id'],
        'tools_executed': False, 'external_delivery_verified': False,
    }


def prove_reference(contract_raw, model, rows, before_state, *, max_attempts=64):
    require(type(max_attempts) is int and 1 <= max_attempts <= 4096, 'SEARCH_BUDGET')
    identity = current_identity()
    value = _bound_contract(contract_raw, model, rows, before_state, identity)
    prepared = execution.prepare_rows(rows, value['policy'])
    tiles, _ = cell.build_tiles(model, prepared)
    entries, products, attempts = [], {}, []
    target = bytes.fromhex(value['proof']['target'])
    for tile in tiles:
        words = list(struct.unpack('<' + 'I' * (2 * work.CELLS), tile['material']))
        for nonce in range(max_attempts):
            challenge = _challenge(contract_raw, before_state, tile, nonce)
            proof = work.prove(challenge, words[:work.CELLS], words[work.CELLS:])
            if H('ticket', challenge, proof[-32:]) <= target:
                break
        else:
            raise ValueError('SEARCH_EXHAUSTED:tile=' + str(tile['index']) +
                             ':all_attempts=' + str(sum(attempts) + max_attempts))
        attempts.append(nonce + 1)
        entries.append({'index': tile['index'], 'nonce': nonce, 'proof_hex': proof.hex()})
        products[tile['index']] = proof[4 + 2 * work.CELLS * 4:-32]
    observed = cell.consume_products(tiles, products, len(rows))['products'].tolist()
    result = execution.execute(model, rows, before_state, value['policy'],
                               verified_products=observed)
    cid = contract_id(contract_raw)
    segments = _segments(cid, model, rows, before_state, value['policy'], observed, result)
    witness = canonical({'schema': RELATION_ID + '/witness', 'model': model,
                         'rows': rows, 'tiles': entries, 'segments': segments,
                         'after_model': result['after_model']})
    require(len(witness) <= WITNESS_LIMIT, 'V2_WITNESS_LIMIT')
    require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_PROVING')
    return {'output': _output(value, cid, result, segments),
            'after_state': result['after_state'], 'after_model': result['after_model'],
            'witness': witness, 'work_attempts': attempts}


def _expected(raw, before, expected):
    expected = _canonical_object(expected, RESULT_LIMIT, 'V2_EXPECTED_CONTEXT')
    require(type(expected) is dict and set(expected) ==
            {'contract_id', 'program_sha256', 'parameters_sha256', 'before_state',
             'consumer', 'allowed_use', 'candidate_artifact', 'parent_context'},
            'V2_EXPECTED_FIELDS')
    for name in ('contract_id', 'program_sha256', 'parameters_sha256', 'candidate_artifact'):
        v1.hex_value(expected[name], code='EXPECTED_' + name.upper())
    require(contract_id(raw) == expected['contract_id'], 'EXPECTED_CONTRACT')
    expected_state = execution.validate_state(expected['before_state'])
    require(canonical(execution.validate_state(before)) == canonical(expected_state),
            'EXPECTED_STATE')
    value = _contract(raw)
    for name in ('consumer', 'allowed_use', 'candidate_artifact'):
        require(value['task'][name] == expected[name], 'EXPECTED_' + name.upper())
    parent = _parent_context(expected['parent_context'])
    require(canonical(value['parent_context']) == canonical(parent), 'EXPECTED_PARENT_CONTEXT')
    require(value['task']['issued_at_ms'] <= parent['consensus_time_ms'] <=
            value['task']['deadline_ms'], 'PROTOCOL_TIME_WINDOW')
    return value, expected


def _verify(raw, before, output, after, witness_raw, *, expected):
    value, expected = _expected(raw, before, expected)
    identity = current_identity()
    for name in ('program_sha256', 'parameters_sha256'):
        require(expected[name] == identity[name], 'EXPECTED_' + name.upper())
    output = _canonical_object(output, RESULT_LIMIT, 'V2_OUTPUT')
    after = execution.validate_state(after)
    witness = v1.strict_json(witness_raw, WITNESS_LIMIT, 'V2_WITNESS')
    require(type(witness) is dict and set(witness) ==
            {'schema', 'model', 'rows', 'tiles', 'segments', 'after_model'}, 'V2_WITNESS_FIELDS')
    require(witness['schema'] == RELATION_ID + '/witness', 'V2_WITNESS_SCHEMA')
    model, rows = witness['model'], witness['rows']
    _bound_contract(raw, model, rows, before, identity)
    tiles, _ = cell.build_tiles(model, execution.prepare_rows(rows, value['policy']))
    require(type(witness['tiles']) is list and len(witness['tiles']) == len(tiles),
            'WITNESS_TILE_COUNT')
    products = {}
    for tile, entry in zip(tiles, witness['tiles']):
        require(type(entry) is dict and set(entry) == {'index', 'nonce', 'proof_hex'},
                'WITNESS_TILE_FIELDS')
        require(type(entry['index']) is int and entry['index'] == tile['index'],
                'WITNESS_TILE_ORDER')
        v1.hex_value(entry['proof_hex'], 2 * work.PROOF_BYTES, 'WITNESS_PROOF_BYTES')
        proof = bytes.fromhex(entry['proof_hex'])
        require(proof[4:4 + 2 * work.CELLS * 4] == tile['material'], 'WITNESS_MATERIAL')
        challenge = _challenge(raw, before, tile, entry['nonce'])
        _, product = work.verify(challenge, bytes.fromhex(tile['task']),
                                 bytes.fromhex(value['proof']['target']), proof)
        products[tile['index']] = work.field_bytes(product)
    observed = cell.consume_products(tiles, products, len(rows))['products'].tolist()
    result = execution.execute(model, rows, before, value['policy'],
                               verified_products=observed)
    require(canonical(after) == canonical(result['after_state']), 'AFTER_STATE_RELATION')
    require(canonical(witness['after_model']) == canonical(result['after_model']),
            'AFTER_MODEL_RELATION')
    cid = expected['contract_id']
    segments = _segments(cid, model, rows, before, value['policy'], observed, result)
    require(canonical(witness['segments']) == canonical(segments), 'SEGMENT_DATAFLOW_RELATION')
    require(canonical(output) == canonical(_output(value, cid, result, segments)),
            'OUTPUT_RELATION')
    require(current_identity() == identity, 'PROGRAM_CHANGED_DURING_VERIFICATION')
    return {
        'schema': RELATION_ID + '/verification', 'contract_id': cid,
        'relation_valid': True, 'source_replay_verified': True,
        'feature_mask_verified': True, 'complete_w1_transcripts_verified': len(tiles),
        'state_transition_verified': True, 'sampler_state_verified': True,
        'segments_verified': len(segments), 'segment_root': segments[-1]['segment_id'],
        'training_step_verified': value['policy']['training'] is not None,
        'before_state_sha256': v1.digest(before), 'after_state_sha256': v1.digest(after),
        'before_model_artifact': artifact_id(model),
        'after_model_artifact': artifact_id(result['after_model']),
        'external_context_matched': True, 'owner_authorization_verified': False,
        'request_consumed': False, 'checkpoint_committed': False,
        'final_use_granted': False, 'actual_model_use_verified': False,
        'ordinary_hepta_encoder_verified': False, 'native_node_admission': False,
        'tools_executed': False, 'external_delivery_verified': False,
        'succinct_proof': False, 'work_security_qualified': False,
        'model_quality_qualified': False, 'production_qualified': False,
        'public_reward_eligible': False,
    }


def verify_historical_relation(contract_raw, before_state, output, after_state,
                               witness_raw, *, expected):
    """Validate at independent parent state/protocol time, never today's time.

    The caller must obtain expected from already verified chain state/task owner.
    This API has no current-clock, current-revocation or authority parameter.
    It does not claim that the supplied parent context has been authenticated.
    """
    report = _verify(contract_raw, before_state, output, after_state, witness_raw,
                     expected=expected)
    return dict(report, time_semantics='historical-parent-protocol-time',
                consensus_time_ms=_contract(contract_raw)['parent_context']['consensus_time_ms'])


def verify_live_relation(contract_raw, before_state, output, after_state,
                         witness_raw, *, expected,
                         clock_ms=lambda: time.time_ns() // 1_000_000):
    """Current-time computation check only; real owner/FinalUse remains required."""
    started = v1.unsigned(clock_ms(), 'CLOCK')
    value, _ = _expected(contract_raw, before_state, expected)
    require(value['task']['issued_at_ms'] <= started <= value['task']['deadline_ms'],
            'LIVE_START_WINDOW')
    report = _verify(contract_raw, before_state, output, after_state, witness_raw,
                     expected=expected)
    finished = v1.unsigned(clock_ms(), 'CLOCK')
    require(started <= finished <= value['task']['deadline_ms'], 'LIVE_COMPLETION_WINDOW')
    return dict(report, time_semantics='live-consumer-clock',
                clock_start_ms=started, clock_finish_ms=finished)
