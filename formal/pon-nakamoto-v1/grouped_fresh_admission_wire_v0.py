"""Independent, dependency-free parser for the controlled native admission wire.

This checks bytes and externally supplied fixture pins, never Ed25519 authority,
live Node state, genuine demand, or reward eligibility. The body uses big-endian
integers; pon_wire hashes use LITTLE-endian length frames. The fixed seal profile
and grouped model commitments have two other, deliberately separate hash frames.
"""
from __future__ import annotations

import hashlib
import json

PROFILE = 'pon-grouped-int257-sealed-research-v0'
OPERATOR_PROFILE = 'pon-routed-int257-grouped-research-v0'
REQUEST_PROFILE = 'pon-grouped-int257-lottery-audit-v0'
NUMERIC = 'signed-i32-coeff-i64-accum-bias8-lowest-argmax'
STEPS, BATCH_SIZE, DIM = 64, 16, 257
BODY_BYTES, CAPSULE_BYTES, CANDIDATE_BYTES = 728, 862, 742
MAX_NONCES, MAX_LIFETIME_NS = 4096, 3_600_000_000_000
BODY_MAGIC, CAPSULE_MAGIC, CANDIDATE_MAGIC = b'PGAB\0\0', b'PGAC\0\0', b'PGCE\0\0'
BRANCH_HASHES = ('network', 'parameters', 'genesis', 'parent', 'prior_state', 'target')
BRANCH_INTS = ('height', 'generation')
INTENT_HASHES = (
    'registry_id', 'registry_digest', 'previous_registry_digest', 'demand_id',
    'source_record', 'authorization_scope', 'withdrawal_head', 'model_commitment',
    'request_precommitment', 'batch_id', 'transactions_commitment', 'payee', 'operation_id')
INTENT_INTS = ('registry_sequence', 'model_generation', 'timestamp_ms', 'not_before_ns',
               'expires_ns', 'available_until_ns', 'nonce_first', 'nonce_count')
REQUEST_HASHES = ('model_commitment', 'request_precommitment', 'batch_id',
                  'authorization_scope', 'demand_id', 'source_record', 'withdrawal_head', 'payee')
REQUEST_INTS = (*INTENT_INTS[1:], 'now_ns')
LAYOUT = {
    'magic': BODY_MAGIC.hex(), 'profile_hash_bytes': 32, 'steps_u16_be': STEPS,
    'branch_hashes': list(BRANCH_HASHES), 'branch_u64_be': list(BRANCH_INTS),
    'intent_hashes': list(INTENT_HASHES), 'intent_u64_be': list(INTENT_INTS)}
POLICY_FIELDS = frozenset((
    'schema', 'requester_public_key', 'source_public_key', 'latest_sequence', 'latest_digest',
    'expected_capsule_sha256', 'expected_body_hex', 'policy_id', 'fixture_keys_public',
    'external_demand_authenticated', 'independent_operators'))
TIMINGS = ('native_node_startup', 'policy_prepare_and_fixture_signatures',
           'native_signature_and_parent_verification', 'initial_artifact_and_journal_persistence')
RESULT_FIELDS = frozenset((
    'schema', 'profile', 'profile_hash', 'steps', 'numeric', 'batch_size', 'branch',
    'body_hex', 'body_bytes', 'capsule_hex', 'capsule_bytes', 'capsule_sha256',
    'external_policy', 'expected_policy_file_sha256', 'candidates', 'canonical_body_layout',
    'challenge_formula', *TIMINGS, 'controlled_fixture_authority', 'native_parent_target_checked',
    'fixture_signature_algorithm', 'external_demand_authenticated', 'independent_operators',
    'native_w1_admission', 'chainwork_awarded', 'production_activation'))


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _keys(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)


def _uint(value, code='UINT64'):
    require(type(value) is int and 0 <= value < 1 << 64, code)
    return value


def _hex(value, size, code='HEX'):
    require(type(value) is str and len(value) == 2 * size and
            all(c in '0123456789abcdef' for c in value), code)
    return bytes.fromhex(value)


def _json(value):
    """Strict JSON subset: bool/int aliases and floating-point numbers differ."""
    def visit(x):
        if x is None or type(x) in (str, bool):
            return
        if type(x) is int:
            require(-(1 << 63) <= x < 1 << 64, 'JSON_INTEGER')
        elif type(x) is list:
            for item in x:
                visit(item)
        elif type(x) is dict and all(type(k) is str for k in x):
            for item in x.values():
                visit(item)
        else:
            raise ValueError('JSON_TYPE')
    visit(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _equal(actual, expected, code):
    require(_json(actual) == _json(expected), code)


def pon_hash(tag, *parts):
    require(type(tag) is bytes and len(tag) < 1 << 16, 'HASH_TAG')
    require(all(type(p) is bytes and len(p) < 1 << 32 for p in parts), 'HASH_PART')
    raw = b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag
    raw += b''.join(len(p).to_bytes(4, 'little') + p for p in parts)
    return hashlib.sha256(raw).digest()


def profile_hash():
    tag = b'profile'
    parts = (PROFILE.encode(), OPERATOR_PROFILE.encode(), NUMERIC.encode(),
             STEPS.to_bytes(2, 'big'), BATCH_SIZE.to_bytes(2, 'big'))
    raw = b'TRNM-GROUPED-FRESH-SEAL0\0' + len(tag).to_bytes(2, 'big') + tag
    return hashlib.sha256(raw + b''.join(len(p).to_bytes(4, 'big') + p for p in parts)).digest()


def _grouped_hash(domain, *parts):
    tag = domain.encode()
    raw = b'trnm.domain.hash.v1' + len(tag).to_bytes(8, 'big') + tag
    return hashlib.sha256(raw + b''.join(len(p).to_bytes(8, 'big') + p for p in parts)).hexdigest()


def material_commitments(model_init, requests, *, now_ns=None):
    """Reconstruct commitments from full supplied coefficients and ordered inputs.

    The caller owns the provenance/authorization of this supplied material. A
    matching commitment establishes consistency with it, not corpus provenance.
    """
    _keys(model_init, {'type', 'model_version', 'base', 'router', 'deltas'}, 'MODEL_FIELDS')
    require(model_init['type'] == 'init', 'MODEL_TYPE')
    raw_model = _hex(model_init['model_version'], 32, 'MODEL_VERSION')
    raw_model += b''.join(v.to_bytes(8, 'big') for v in (DIM, 3, 3))
    deltas = model_init['deltas']
    require(type(deltas) is list and len(deltas) == 3, 'MODEL_DELTAS')
    for matrix in (model_init['base'], model_init['router'], *deltas):
        require(type(matrix) is list and len(matrix) == 3, 'MODEL_ROWS')
        for row in matrix:
            require(type(row) is list and len(row) == DIM, 'MODEL_COLUMNS')
            for x in row:
                require(type(x) is int and -32767 <= x <= 32767, 'MODEL_COEFFICIENT')
                raw_model += x.to_bytes(8, 'big', signed=True)
    model = _grouped_hash('pon-routed-int257-grouped-model-v0',
                          OPERATOR_PROFILE.encode(), NUMERIC.encode(), raw_model)
    require(type(requests) is list and len(requests) == BATCH_SIZE, 'WORK_UNIT_16')
    if now_ns is not None:
        _uint(now_ns, 'NOW_NS')
    raw_requests, seen = BATCH_SIZE.to_bytes(8, 'big'), set()
    for row in requests:
        _keys(row, {'id', 'scope', 'arrival_ns', 'deadline_ns', 'x'}, 'REQUEST_FIELDS')
        raw_requests += _hex(row['id'], 32, 'REQUEST_ID') + _hex(row['scope'], 32, 'REQUEST_SCOPE')
        require(row['id'] not in seen, 'DUPLICATE_REQUEST')
        seen.add(row['id'])
        start, end = _uint(row['arrival_ns']), _uint(row['deadline_ns'])
        require(start < end, 'REQUEST_INTERVAL')
        if now_ns is not None:
            require(start <= now_ns < end, 'REQUEST_NOT_CURRENT')
        raw_requests += start.to_bytes(8, 'big') + end.to_bytes(8, 'big')
        require(type(row['x']) is list and len(row['x']) == DIM, 'REQUEST_DIM')
        require(all(type(x) is int and -8 <= x <= 8 for x in row['x']), 'REQUEST_FEATURE')
        require(row['x'][-1] == 8, 'REQUEST_BIAS')
        raw_requests += b''.join(x.to_bytes(8, 'big', signed=True) for x in row['x'])
    preinput = _grouped_hash('pon-grouped-preinput-audit-v0', REQUEST_PROFILE.encode(),
                             NUMERIC.encode(), bytes.fromhex(model), raw_requests)
    return {'model_commitment': model, 'request_precommitment': preinput}


def _branch(value):
    _keys(value, (*BRANCH_HASHES, *BRANCH_INTS), 'BRANCH_FIELDS')
    for key in BRANCH_HASHES:
        _hex(value[key], 32, 'BRANCH_' + key.upper())
    for key in BRANCH_INTS:
        _uint(value[key], 'BRANCH_' + key.upper())
    require(value['height'] > 0 and value['target'] != '00' * 32, 'BRANCH_CONTEXT')


def decode_body(raw):
    require(type(raw) is bytes and len(raw) == BODY_BYTES, 'BODY_LENGTH')
    require(raw[:6] == BODY_MAGIC, 'BODY_MAGIC')
    require(raw[6:38] == profile_hash(), 'BODY_PROFILE')
    require(int.from_bytes(raw[38:40], 'big') == STEPS, 'BODY_STEPS')
    position, branch, intent = 40, {}, {}
    for target, names, size in ((branch, BRANCH_HASHES, 32), (branch, BRANCH_INTS, 8),
                                (intent, INTENT_HASHES, 32), (intent, INTENT_INTS, 8)):
        for key in names:
            part = raw[position:position + size]
            target[key] = part.hex() if size == 32 else int.from_bytes(part, 'big')
            position += size
    require(position == BODY_BYTES, 'BODY_END')
    _branch(branch)
    require(all(intent[k] != '00' * 32 for k in INTENT_HASHES if k != 'previous_registry_digest'),
            'INTENT_ZERO_HASH')
    require(intent['registry_sequence'] > 0 and intent['model_generation'] > 0 and
            intent['timestamp_ms'] > 0, 'INTENT_GENERATION')
    require((intent['registry_sequence'] == 1) == (intent['previous_registry_digest'] == '00' * 32),
            'REGISTRY_PREVIOUS')
    require(intent['not_before_ns'] > 0 and
            1 <= intent['expires_ns'] - intent['not_before_ns'] <= MAX_LIFETIME_NS and
            intent['available_until_ns'] >= intent['expires_ns'], 'INTENT_WINDOW')
    require(intent['nonce_first'] > 0 and 1 <= intent['nonce_count'] <= MAX_NONCES and
            intent['nonce_first'] + intent['nonce_count'] <= 1 << 64, 'INTENT_NONCES')
    return {'profile_hash': raw[6:38].hex(), 'steps': STEPS, 'branch': branch, 'intent': intent}


def decode_capsule(raw):
    require(type(raw) is bytes and len(raw) == CAPSULE_BYTES, 'CAPSULE_LENGTH')
    require(raw[:6] == CAPSULE_MAGIC, 'CAPSULE_MAGIC')
    body = decode_body(raw[6:6 + BODY_BYTES])
    return {'body': body, 'requester_signature': raw[-128:-64].hex(),
            'source_signature': raw[-64:].hex(), 'signatures_verified': False}


def candidate_bytes(body, nonce):
    decoded = decode_body(body)
    intent = decoded['intent']
    _uint(nonce, 'NONCE')
    require(intent['nonce_first'] <= nonce < intent['nonce_first'] + intent['nonce_count'], 'NONCE_RANGE')
    return CANDIDATE_MAGIC + body + nonce.to_bytes(8, 'big')


def inspect_freeze(freeze_result, freeze_request, model_init, requests, *, expected_native=None):
    """Crosscheck native ``result`` against the caller's exact controlled fixture.

    ``expected_native`` may pin body/capsule/policy-file SHA256 and an exact branch
    snapshot, read separately from retained native artifacts. All three SHA pins
    are required for ``pins_checked=True``. These are local fixture pins, not
    independent network authority. Native verify_capsule owns Ed25519 and live
    Node rechecks. This function neither verifies signatures nor awards work.
    """
    _keys(freeze_result, RESULT_FIELDS, 'FREEZE_RESULT_FIELDS')
    request_keys = set((*REQUEST_HASHES, *REQUEST_INTS))
    require(type(freeze_request) is dict, 'FREEZE_REQUEST_FIELDS')
    if 'op' in freeze_request:
        require(freeze_request['op'] == 'freeze', 'FREEZE_OPERATION')
        request_keys.add('op')
    _keys(freeze_request, request_keys, 'FREEZE_REQUEST_FIELDS')
    for key in REQUEST_HASHES:
        _hex(freeze_request[key], 32, 'FREEZE_' + key.upper())
    for key in REQUEST_INTS:
        _uint(freeze_request[key], 'FREEZE_' + key.upper())
    result, f = freeze_result, freeze_request
    _equal([result[k] for k in ('schema', 'profile', 'profile_hash', 'steps', 'numeric', 'batch_size')],
           ['pon-grouped-fresh-controlled-freeze-v0', PROFILE, profile_hash().hex(), STEPS, NUMERIC, BATCH_SIZE],
           'FREEZE_PROFILE')
    _equal(result['canonical_body_layout'], LAYOUT, 'BODY_LAYOUT')
    _equal([result['body_bytes'], result['capsule_bytes']], [BODY_BYTES, CAPSULE_BYTES], 'WIRE_SIZES')
    body_raw = _hex(result['body_hex'], BODY_BYTES, 'BODY_HEX')
    body = decode_body(body_raw)
    capsule_raw = _hex(result['capsule_hex'], CAPSULE_BYTES, 'CAPSULE_HEX')
    capsule = decode_capsule(capsule_raw)
    require(capsule_raw[6:6 + BODY_BYTES] == body_raw, 'CAPSULE_BODY')
    _branch(result['branch'])
    _equal(body['branch'], result['branch'], 'BRANCH_BODY')
    material = material_commitments(model_init, requests, now_ns=f['now_ns'])
    for key, expected in material.items():
        require(f[key] == expected, 'MATERIAL_' + key.upper())
    require(all(row['scope'] == f['authorization_scope'] for row in requests), 'AUTHORIZATION_SCOPE')
    registry = pon_hash(b'pon-grouped-fresh-controlled-registry-v0', profile_hash())
    request, batch = bytes.fromhex(f['request_precommitment']), bytes.fromhex(f['batch_id'])
    expected_intent = {key: f[key] for key in (*REQUEST_HASHES, *INTENT_INTS[1:])}
    expected_intent.update(
        registry_id=registry.hex(), registry_digest=pon_hash(
            b'pon-grouped-fresh-controlled-registry-entry-v0', registry, request, batch).hex(),
        previous_registry_digest='00' * 32, registry_sequence=1,
        transactions_commitment=pon_hash(b'transactions-empty').hex(),
        operation_id=pon_hash(b'pon-grouped-fresh-controlled-operation-v0', registry, request,
                              batch, f['nonce_first'].to_bytes(8, 'big'),
                              f['nonce_count'].to_bytes(8, 'big')).hex())
    _equal(body['intent'], expected_intent, 'BODY_INTENT')
    require(f['not_before_ns'] <= f['now_ns'] < f['expires_ns'], 'ADMISSION_NOT_CURRENT')
    capsule_sha = hashlib.sha256(capsule_raw).hexdigest()
    require(result['capsule_sha256'] == capsule_sha, 'CAPSULE_SHA256')
    policy = result['external_policy']
    _keys(policy, POLICY_FIELDS, 'POLICY_FIELDS')
    require(policy['schema'] == 'pon-grouped-fresh-controlled-external-policy-v0', 'POLICY_SCHEMA')
    requester = _hex(policy['requester_public_key'], 32, 'REQUESTER_KEY')
    source = _hex(policy['source_public_key'], 32, 'SOURCE_KEY')
    require(requester != bytes(32) and source != bytes(32) and requester != source, 'POLICY_KEYS')
    _equal(policy['latest_sequence'], body['intent']['registry_sequence'], 'POLICY_SEQUENCE')
    require(policy['latest_digest'] == body['intent']['registry_digest'] and
            policy['expected_capsule_sha256'] == capsule_sha and
            policy['expected_body_hex'] == body_raw.hex(), 'POLICY_BINDING')
    policy_id = pon_hash(b'pon-grouped-fresh-external-policy-v0', requester, source,
                         policy['latest_sequence'].to_bytes(8, 'big'),
                         bytes.fromhex(policy['latest_digest']), bytes.fromhex(capsule_sha), body_raw).hex()
    require(policy['policy_id'] == policy_id, 'POLICY_ID')
    require(policy['fixture_keys_public'] is True and policy['external_demand_authenticated'] is False
            and policy['independent_operators'] is False, 'POLICY_SCOPE')
    policy_sha = hashlib.sha256(_json(policy)).hexdigest()
    require(result['expected_policy_file_sha256'] == policy_sha, 'POLICY_FILE_SHA256')
    pin_values = {'expected_body_sha256': hashlib.sha256(body_raw).hexdigest(),
                  'expected_capsule_sha256': capsule_sha, 'expected_policy_file_sha256': policy_sha}
    pins = {} if expected_native is None else expected_native
    require(type(pins) is dict and set(pins) <= set(pin_values) | {'branch'}, 'EXPECTED_NATIVE_FIELDS')
    for key, expected in pin_values.items():
        if key in pins:
            _hex(pins[key], 32, 'EXTERNAL_PIN_ENCODING')
            require(pins[key] == expected, 'EXTERNAL_PIN_' + key.upper())
    if 'branch' in pins:
        _branch(pins['branch'])
        _equal(body['branch'], pins['branch'], 'EXTERNAL_BRANCH')
    rows = result['candidates']
    require(type(rows) is list and len(rows) == f['nonce_count'], 'CANDIDATE_COUNT')
    candidates = {}
    for index, row in enumerate(rows):
        _keys(row, {'nonce', 'candidate_hex', 'challenge', 'work_id'}, 'CANDIDATE_FIELDS')
        nonce = _uint(row['nonce'], 'CANDIDATE_NONCE')
        require(nonce == f['nonce_first'] + index, 'CANDIDATE_ORDER')
        raw = candidate_bytes(body_raw, nonce)
        require(_hex(row['candidate_hex'], CANDIDATE_BYTES, 'CANDIDATE_HEX') == raw, 'CANDIDATE_BODY')
        challenge = pon_hash(b'pon-grouped-fresh-challenge-v0', raw).hex()
        work_id = pon_hash(b'pon-grouped-fresh-work-id-v0', raw).hex()
        require(row['challenge'] == challenge and row['work_id'] == work_id, 'CANDIDATE_HASH')
        candidates[nonce] = dict(row, context={'chain': body['branch']['network'],
            'parent': body['branch']['parent'], 'batch_id': f['batch_id'], 'challenge': challenge})
    require(result['challenge_formula'] ==
            'pon_wire.hash(pon-grouped-fresh-challenge-v0, [PGCE\\0\\0 || body || nonce_u64_be])',
            'CHALLENGE_FORMULA')
    for key in TIMINGS:
        _keys(result[key], {'wall_ns', 'thread_cpu_ns'}, 'TIMING_FIELDS')
        for value in result[key].values():
            if value is not None:
                _uint(value, 'TIMING_UINT')
    for key in ('controlled_fixture_authority', 'native_parent_target_checked'):
        require(result[key] is True, 'FIXTURE_OBSERVATION')
    require(result['fixture_signature_algorithm'] == 'native-strict-Ed25519', 'SIGNATURE_OBSERVATION')
    for key in ('external_demand_authenticated', 'independent_operators', 'native_w1_admission', 'production_activation'):
        require(result[key] is False, 'QUALIFICATION_FLAGS')
    _equal(result['chainwork_awarded'], 0, 'CHAINWORK')
    return {'schema': 'pon-grouped-fresh-independent-wire-check-v0', 'body': body,
            'candidates_by_nonce': candidates, **material,
            'body_sha256': pin_values['expected_body_sha256'], 'capsule_sha256': capsule_sha,
            'policy_file_sha256': policy_sha, 'policy_id': policy_id,
            'pins_checked': all(k in pins for k in pin_values), 'branch_pin_checked': 'branch' in pins,
            'binding_checks': {'full_body': True, 'supplied_material': True, 'all_request_scopes': True,
                               'request_and_admission_clock': True, 'candidate_identity': True,
                               'signature_carrier_excluded_from_candidate': True},
            'signature_verified_by_this_parser': capsule['signatures_verified'],
            'native_branch_authenticated_by_this_parser': False,
            'external_demand_authenticated': False, 'production_activation': False,
            'chainwork_awarded': 0}
