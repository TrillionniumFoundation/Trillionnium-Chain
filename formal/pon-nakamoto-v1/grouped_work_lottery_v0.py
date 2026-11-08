"""Canonical grouped-Cell lottery *audit*, deliberately granting zero chainwork.

This freezes a single 16-request, 3x257 signed-integer research relation. It
models prechallenge binding and a classical ideal-ticket experiment, not a
registered work profile. The existing grouped arithmetic is challenge invariant:
the cached-product counterexample is a reason this profile MUST NOT earn work.
Full reference recomputation establishes correctness, never producer cost.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import time

from contract_wire import canonical, unique
from experiments.grouped_cell_operator_v0 import (
    PROFILE as OPERATOR_PROFILE, context_bytes, digest, i64, input_commitment, model_commitment,
    native_hash, scalar_product, statement_commitment, u64, uint,
)
from work_query_bound import expected_first_query_credit, parameters

PROFILE = 'pon-grouped-int257-lottery-audit-v0'
SCHEMA = 'pon-grouped-int257-lottery-audit-package-v0'
NUMERIC = 'signed-i32-coeff-i64-accum-bias8-lowest-argmax'
BATCH_SIZE = 16
DIM = 257
MAGIC = b'PGLA\x00\x00'
HEADER_HASH_FIELDS = (
    'network', 'parameters', 'parent', 'target', 'payee', 'task',
    'model_commitment', 'request_precommitment', 'batch_id',
    'transactions_commitment', 'prior_state_root',
)
HEADER_INT_FIELDS = ('height', 'timestamp_ms', 'nonce')
HEADER_FIELDS = frozenset((*HEADER_HASH_FIELDS, *HEADER_INT_FIELDS, 'profile'))
ENVELOPE_FIELDS = frozenset((*HEADER_HASH_FIELDS, *HEADER_INT_FIELDS)) - {
    'model_commitment', 'request_precommitment'}
PRODUCT_FIELDS = frozenset((
    'router_outputs', 'routes', 'groups', 'logits', 'predictions',
    'useful_dense_macs', 'padded_macs', 'nonempty_expert_groups',
))
PACKAGE_FIELDS = frozenset((
    'schema', 'header', 'context', 'model_commitment', 'input_commitment',
    'statement_commitment', 'product', 'ticket', 'receipt_id', 'transport_aux_hex',
))
WIRE_SIZE = len(MAGIC) + 32 + 32 * len(HEADER_HASH_FIELDS) + 8 * len(HEADER_INT_FIELDS)
MAX_PACKAGE_BYTES = 128 * 1024


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _keys(value, fields, code):
    require(type(value) is dict and set(value) == fields, code)


def _matrix(value, rows, columns, bound, code):
    require(type(value) is list and len(value) == rows, code)
    for row in value:
        require(type(row) is list and len(row) == columns, code)
        require(all(type(x) is int and -bound <= x <= bound for x in row), code)


def validate_init(init):
    _keys(init, {'type', 'model_version', 'base', 'router', 'deltas'}, 'MODEL_FIELDS')
    require(init['type'] == 'init', 'MODEL_TYPE')
    digest(init['model_version'], 'MODEL_VERSION')
    for key in ('base', 'router'):
        _matrix(init[key], 3, DIM, 32767, 'MODEL_' + key.upper())
    require(type(init['deltas']) is list and len(init['deltas']) == 3, 'MODEL_DELTAS')
    for matrix in init['deltas']:
        _matrix(matrix, 3, DIM, 32767, 'MODEL_DELTA')


def validate_requests(requests, *, now_ns=None):
    require(type(requests) is list and len(requests) == BATCH_SIZE, 'WORK_UNIT_16')
    ids = set()
    if now_ns is not None:
        uint(now_ns, 'NOW')
    for row in requests:
        _keys(row, {'id', 'scope', 'arrival_ns', 'deadline_ns', 'x'}, 'REQUEST_FIELDS')
        digest(row['id'], 'REQUEST_ID')
        digest(row['scope'], 'REQUEST_SCOPE')
        require(row['id'] not in ids, 'DUPLICATE_REQUEST')
        ids.add(row['id'])
        start, end = uint(row['arrival_ns']), uint(row['deadline_ns'])
        require(start < end, 'REQUEST_INTERVAL')
        if now_ns is not None:
            require(start <= now_ns < end, 'REQUEST_NOT_CURRENT')
        _matrix([row['x']], 1, DIM, 8, 'REQUEST_FEATURES')
        require(row['x'][-1] == 8, 'REQUEST_BIAS')


def request_precommitment(init, requests):
    """No challenge, output, state-after, proof or ticket can enter these bytes."""
    validate_init(init)
    validate_requests(requests)
    raw = u64(BATCH_SIZE)
    for row in requests:
        raw += digest(row['id']) + digest(row['scope'])
        raw += u64(row['arrival_ns']) + u64(row['deadline_ns'])
        raw += b''.join(i64(x) for x in row['x'])
    return native_hash('pon-grouped-preinput-audit-v0', PROFILE.encode(),
                       NUMERIC.encode(), digest(model_commitment(init)), raw)


def encode_header(header):
    _keys(header, HEADER_FIELDS, 'HEADER_FIELDS')
    require(header['profile'] == PROFILE, 'PROFILE')
    values = [digest(header[key], 'HEADER_' + key.upper()) for key in HEADER_HASH_FIELDS]
    # Match the existing conditional query model: zero target is not legal.
    parameters(int(header['target'], 16))
    integers = [u64(header[key]) for key in HEADER_INT_FIELDS]
    identity = digest(native_hash('pon-grouped-audit-profile-v0', PROFILE.encode(),
                                  OPERATOR_PROFILE.encode(), NUMERIC.encode(), u64(BATCH_SIZE)))
    return MAGIC + identity + b''.join(values) + b''.join(integers)


def decode_header(raw):
    require(type(raw) is bytes and len(raw) == WIRE_SIZE, 'HEADER_WIRE_LENGTH')
    require(raw[:len(MAGIC)] == MAGIC, 'HEADER_WIRE_MAGIC')
    pos = len(MAGIC) + 32
    header = {'profile': PROFILE}
    for key in HEADER_HASH_FIELDS:
        header[key] = raw[pos:pos + 32].hex()
        pos += 32
    for key in HEADER_INT_FIELDS:
        header[key] = int.from_bytes(raw[pos:pos + 8], 'big')
        pos += 8
    require(encode_header(header) == raw, 'HEADER_WIRE_CANONICAL')
    return header


def make_candidate(init, requests, envelope):
    """An external owner supplies this envelope; the helper grants no authority."""
    _keys(envelope, ENVELOPE_FIELDS, 'ENVELOPE_FIELDS')
    header = dict(envelope, profile=PROFILE, model_commitment=model_commitment_checked(init),
                  request_precommitment=request_precommitment(init, requests))
    encode_header(header)
    return header


def model_commitment_checked(init):
    validate_init(init)
    return model_commitment(init)


def derive_challenge(header):
    return native_hash('pon-grouped-challenge-audit-v0', encode_header(header))


def context_for(header):
    return {'chain': header['network'], 'parent': header['parent'],
            'challenge': derive_challenge(header), 'batch_id': header['batch_id']}


def reference_product(init, requests):
    validate_init(init)
    validate_requests(requests)
    # Existing independent scalar control uses the original matrices, not producer caches.
    return scalar_product(init, requests)


def _validate_product(product):
    _keys(product, PRODUCT_FIELDS, 'PRODUCT_FIELDS')
    for key, bound in (('router_outputs', 257 * 32767 * 8),
                       ('logits', 257 * 65534 * 8)):
        _matrix(product[key], BATCH_SIZE, 3, bound, 'PRODUCT_' + key.upper())
    for key in ('routes', 'predictions'):
        row = product[key]
        require(type(row) is list and len(row) == BATCH_SIZE and
                all(type(x) is int and 0 <= x < 3 for x in row), 'PRODUCT_' + key.upper())
    groups = product['groups']
    require(type(groups) is list and len(groups) == 3, 'PRODUCT_GROUPS')
    for group in groups:
        require(type(group) is list and len(group) <= BATCH_SIZE and
                all(type(x) is int and 0 <= x < BATCH_SIZE for x in group), 'PRODUCT_GROUPS')
    for key in ('useful_dense_macs', 'padded_macs', 'nonempty_expert_groups'):
        uint(product[key], 'PRODUCT_COUNT')


def _auxiliary(value):
    require(type(value) is str and len(value) <= 8192 and len(value) % 2 == 0 and
            all(c in '0123456789abcdef' for c in value), 'TRANSPORT_AUX')


@dataclass(frozen=True, slots=True)
class PreparedReticket:
    """Immutable local producer cache, not a verified receipt or authority token."""
    model_hash: str
    request_precommitment: str
    request_tail: bytes
    product_tail: bytes
    product_json: bytes


def prepare_reticket(init, requests):
    """Pay original arithmetic and canonical material preparation once."""
    product = reference_product(init, requests)
    model_hash = model_commitment_checked(init)
    request_hash = request_precommitment(init, requests)
    request_tail = u64(BATCH_SIZE)
    for row in requests:
        request_tail += digest(row['id']) + digest(row['scope'])
        request_tail += u64(row['arrival_ns']) + u64(row['deadline_ns'])
        request_tail += b''.join(i64(x) for x in row['x'])
    # This is a separately encoded cached producer; verify_package still uses
    # the original grouped statement implementation and full scalar reference.
    product_tail = u64(BATCH_SIZE)
    product_tail += b''.join(i64(x) for row in product['router_outputs'] for x in row)
    product_tail += b''.join(u64(x) for x in product['routes'])
    for group in product['groups']:
        product_tail += u64(len(group)) + b''.join(u64(x) for x in group)
    product_tail += b''.join(i64(x) for row in product['logits'] for x in row)
    product_tail += b''.join(u64(x) for x in product['predictions'])
    product_tail += b''.join(u64(product[k]) for k in
                            ('useful_dense_macs', 'padded_macs', 'nonempty_expert_groups'))
    return PreparedReticket(model_hash, request_hash, request_tail, product_tail, canonical(product))


def bind_cached(prepared, header, *, transport_aux_hex=''):
    """A lawful producer reuses invariant bytes; every final hash is fresh.

    Output equality and an external current expected policy must still be checked
    by verify_package. This helper does no fresh neural contractions and makes no
    claim that its total cost beats every native implementation at a small shape.
    """
    require(type(prepared) is PreparedReticket, 'PREPARED_RETICKET')
    encode_header(header)
    _auxiliary(transport_aux_hex)
    require(header['model_commitment'] == prepared.model_hash and
            header['request_precommitment'] == prepared.request_precommitment,
            'PREPARED_MATERIAL_BINDING')
    context = context_for(header)
    context_raw = context_bytes(context)
    inputs = native_hash('pon-routed-int257-grouped-input-v0', OPERATOR_PROFILE.encode(),
                         digest(prepared.model_hash), context_raw + prepared.request_tail)
    statement = native_hash('pon-routed-int257-grouped-statement-v0', OPERATOR_PROFILE.encode(),
                            digest(prepared.model_hash), digest(inputs), context_raw + prepared.product_tail)
    ticket = native_hash('pon-grouped-ticket-audit-v0', digest(context['challenge']), digest(statement))
    receipt = native_hash('pon-grouped-receipt-audit-v0', encode_header(header),
                          digest(statement), digest(ticket))
    return {'schema': SCHEMA, 'header': copy.deepcopy(header), 'context': context,
            'model_commitment': prepared.model_hash, 'input_commitment': inputs,
            'statement_commitment': statement, 'product': json.loads(prepared.product_json),
            'ticket': ticket, 'receipt_id': receipt, 'transport_aux_hex': transport_aux_hex}


def package_claim(init, requests, header, product, *, transport_aux_hex=''):
    """Construct an untrusted claim. Auxiliary transport bytes are not a proof.

    There is no succinct verifier here: verify_package recomputes the entire
    relation. Reordering JSON or adding carrier randomness earns no extra ticket.
    """
    encode_header(header)
    validate_requests(requests)
    model_hash = model_commitment_checked(init)
    require(header['model_commitment'] == model_hash and
            header['request_precommitment'] == request_precommitment(init, requests),
            'MATERIAL_BINDING')
    _validate_product(product)
    _auxiliary(transport_aux_hex)
    context = context_for(header)
    inputs = input_commitment(model_hash, {'context': context, 'requests': requests})
    statement = statement_commitment(model_hash, inputs, context, product)
    ticket = native_hash('pon-grouped-ticket-audit-v0', digest(derive_challenge(header)),
                         digest(statement))
    receipt = native_hash('pon-grouped-receipt-audit-v0', encode_header(header),
                          digest(statement), digest(ticket))
    return {'schema': SCHEMA, 'header': copy.deepcopy(header), 'context': context,
            'model_commitment': model_hash, 'input_commitment': inputs,
            'statement_commitment': statement, 'product': copy.deepcopy(product),
            'ticket': ticket, 'receipt_id': receipt, 'transport_aux_hex': transport_aux_hex}


def decode_package(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PACKAGE_BYTES, 'PACKAGE_SIZE')
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON_CONSTANT')))
    except (UnicodeDecodeError, RecursionError) as exc:
        raise ValueError('PACKAGE_JSON') from exc
    _keys(value, PACKAGE_FIELDS, 'PACKAGE_FIELDS')
    return value


def verify_package(package, *, expected_header, init, requests, now_ns):
    """Full correctness reference plus expected pre-query context, zero admission.

    The caller must obtain expected_header independently. Passing an attacker's
    own envelope as policy is not target/current-parent/demand authentication.
    This local API cannot establish external chronological commitment.
    """
    _keys(package, PACKAGE_FIELDS, 'PACKAGE_FIELDS')
    require(package['schema'] == SCHEMA, 'PACKAGE_SCHEMA')
    require(encode_header(package['header']) == encode_header(expected_header),
            'EXPECTED_HEADER_BINDING')
    uint(now_ns, 'NOW')
    validate_requests(requests, now_ns=now_ns)
    _validate_product(package['product'])
    expected_product = reference_product(init, requests)
    require(canonical(package['product']) == canonical(expected_product), 'PRODUCT_RELATION')
    expected = package_claim(init, requests, expected_header, expected_product,
                             transport_aux_hex=package['transport_aux_hex'])
    require(canonical(package) == canonical(expected), 'PACKAGE_BINDING')
    target = int(expected_header['target'], 16)
    _, weight = parameters(target)
    eta = expected_first_query_credit(target)
    return {'correct_relation': True, 'target_hit': int(package['ticket'], 16) <= target,
            'nominal_conditional_weight_decimal': str(weight),
            'conditional_mean_credit': {'numerator': str(eta.numerator), 'denominator': str(eta.denominator)},
            'chainwork_awarded': 0, 'business_credit': 0, 'model_reward': 0,
            'pow_qualified': False, 'production_activation': False,
            'minimum_fresh_work_proved': False,
            'verdict': 'HOLD_CHALLENGE_INVARIANT_ARITHMETIC',
            'receipt_id': package['receipt_id']}


def cached_reticket_audit(init, requests, envelope, *, nonces, now_ns, on_attempt=None):
    """Retain every attempted cached-product ticket, including misses/failures.

    Timings are Python CPU observations, not native/GPU benchmarks. Preparation,
    producer binding, full independent verifier and total supervisor are distinct
    denominators. No success-conditioned stopping or uncounted discarded attempt.
    """
    require(type(nonces) is list and 1 <= len(nonces) <= 256, 'AUDIT_ATTEMPTS')
    require(on_attempt is None or callable(on_attempt), 'AUDIT_CALLBACK')
    for nonce in nonces:
        uint(nonce, 'AUDIT_NONCE')
    started, cpu = time.perf_counter_ns(), time.process_time_ns()
    product_started = time.process_time_ns()
    prepared = prepare_reticket(init, requests)
    original_header = make_candidate(init, requests, envelope)
    prepare_cpu = time.process_time_ns() - product_started
    attempts, seen = [], set()
    for index, nonce in enumerate(nonces):
        attempt_cpu = time.process_time_ns()
        row = {'index': index, 'nonce': nonce, 'producer_new_matrix_contractions': 0,
               'producer_cpu_ns': None, 'verifier_cpu_ns': None}
        verify_started = None
        try:
            candidate = dict(original_header, nonce=nonce)
            claim = bind_cached(prepared, candidate)
            row['producer_cpu_ns'] = time.process_time_ns() - attempt_cpu
            # The ticket has already been evaluated even if semantic/clock
            # verification later refuses it. Never discard failed-query cost.
            identity = (claim['context']['challenge'], claim['statement_commitment'])
            row.update(challenge=identity[0], statement=identity[1], ticket=claim['ticket'],
                       first_ticket_input=identity not in seen)
            seen.add(identity)
            verify_started = time.process_time_ns()
            checked = verify_package(claim, expected_header=candidate, init=init,
                                     requests=requests, now_ns=now_ns)
            row['verifier_cpu_ns'] = time.process_time_ns() - verify_started
            row.update(status='verified_research', **checked)
        except ValueError as exc:
            if verify_started is not None:
                row['verifier_cpu_ns'] = time.process_time_ns() - verify_started
            row.update(status='rejected', error=str(exc), chainwork_awarded=0)
        row['attempt_cpu_ns'] = time.process_time_ns() - attempt_cpu
        attempts.append(row)
        if on_attempt is not None:
            # Write errors are never swallowed. The caller retains its written
            # prefix and labels unobserved remainder instead of rerunning it.
            on_attempt(copy.deepcopy(row))
    return {'schema': 'pon-grouped-cached-reticket-audit-v0', 'profile': PROFILE,
            'model_commitment': model_commitment_checked(init),
            'request_precommitment': request_precommitment(init, requests),
            'one_prepared_arithmetic_product': json.loads(prepared.product_json),
            'preparation_cpu_ns': prepare_cpu,
            'producer_binding_scope': 'immutable_encoded_material_and_product_cache; fresh hashes; no fresh neural contractions',
            'attempt_callback_scope': 'included in whole audit time; excluded from per-attempt phase times',
            'planned_attempts': len(nonces), 'attempts': attempts,
            'distinct_ticket_inputs': len(seen),
            'total_cpu_ns': time.process_time_ns() - cpu,
            'total_wall_ns': time.perf_counter_ns() - started,
            'chainwork_awarded': 0, 'pow_qualified': False, 'production_activation': False,
            'fresh_matrix_work_per_ticket_required': False,
            'scope': 'finite_python_cpu_counterexample_not_W1_not_real_demand_not_hardware_lower_bound'}
