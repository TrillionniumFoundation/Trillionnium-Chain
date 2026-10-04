"""Independent signed application replay for checked account execution fixtures.

This module derives the complete development genesis and the complete successor
State for transaction tags 1--5, 10 and 11.  It never calls a native executable,
uses observed post-State/deltas as input, or changes the existing archive oracle.
The full State remains available for aggregates.  Semantic account point reads
must additionally have a verified witness against the exact parent checkpoint.

Packet commitments are checked, but W1, difficulty and fork selection are NOT
independently reexecuted here.  These are fixture application semantics, not a
new consensus authority, partial-State executor, or data-availability acceptance.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import traceback

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import account_archive_oracle as archive
from strict_signature import verify as verify_signature


ROOT = Path(__file__).resolve().parents[2]
NATIVE_SCHEMA = 'pon-account-execution-native-observation-v1'
SCHEMA = 'pon-account-execution-oracle-observation-v1'
EVALUATION = 'native-public-evaluation-dev-v1'
PROFILE = 'consensus-maintenance-continuity-dev-v1'
MODEL = 'linear-expert-dev-v1'
SUPPORTED_TAGS = (1, 2, 3, 4, 5, 10, 11)
U64_MAX = (1 << 64) - 1
ZERO = bytes(32)
HASH_FIELDS = ('network', 'parameters', 'parent', 'target', 'miner',
               'transactions', 'state', 'receipts', 'work_task')
SCOPE = {
    'independent_genesis_derivation': True,
    'independent_signed_application_transitions': True,
    'complete_state_and_account_roots': True,
    'account_access_witnesses_checked': True,
    'native_consensus_admission_reexecuted': False,
    'work_relation_reverified': False,
    'fork_choice_reverified': False,
    'production_activation': False,
    'protocol_capacity_changed': False,
    'public_data_availability_accepted': False,
}
NATIVE_SCOPE = {
    'complete_state_retained': True,
    'research_account_access_execution': True,
    'serial_execution_only': True,
    'production_backend_changed': False,
    'protocol_capacity_changed': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}


class RelationError(ValueError):
    """Stable independent relation failure; not a native error authority."""


def require(condition, code):
    if not condition:
        raise RelationError(code)


def uint(value, code='RANGE'):
    require(type(value) is int and 0 <= value <= U64_MAX, code)
    return value


def add(left, right):
    return uint(uint(left) + uint(right))


def mul(left, right):
    return uint(uint(left) * uint(right))


def u64(value):
    return uint(value).to_bytes(8, 'little')


def h(tag, *parts):
    return archive.digest(tag.encode() if type(tag) is str else tag, *parts)


def hex_bytes(value, size=None):
    require(type(value) is str and len(value) % 2 == 0
            and all(char in '0123456789abcdef' for char in value), 'ENCODING')
    raw = bytes.fromhex(value)
    require(size is None or len(raw) == size, 'LENGTH')
    return raw


def hash_value(value):
    if type(value) is bytes:
        require(len(value) == 32, 'LENGTH')
        return value
    if type(value) is str:
        return hex_bytes(value, 32)
    return archive.hash_bytes(value)


def canonical(value):
    return archive.canonical(value)


def equal(actual, expected, code):
    require(canonical(actual) == canonical(expected), code)


def config(path):
    return archive.load_json(ROOT / path)


def development_key(number):
    """Only fixed, publicly known development seeds; no external key input."""
    return Ed25519PrivateKey.from_private_bytes(h('DEV-ONLY-KEY', u64(number)))


def development_public(number):
    return development_key(number).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def matrix_bytes(values):
    require(len(values) == 4096 and all(type(v) is int and 0 <= v < 4294967291
                                      for v in values), 'FIELD')
    return struct.pack('<4096I', *values)


@dataclass(frozen=True)
class Context:
    params: dict
    network: bytes
    parameters: bytes
    fees: dict
    maintenance: dict
    genesis: bytes
    genesis_state: dict

    def as_json(self):
        return dict(network=list(self.network), parameters=list(self.parameters),
                    genesis=list(self.genesis))


def bootstrap_lifecycle(network, parameters):
    """Independent serialization of the fixed public QDL2/QWT1/QWA2 genesis."""
    source, requester = development_public(0), development_public(1)
    model_raw = matrix_bytes([i % 31 for i in range(4096)])
    input_raw = matrix_bytes([(7 * i) % 37 for i in range(4096)])
    model = h('artifact', model_raw)
    inputs = h('qualified-task-input-v1', input_raw)
    task = h('task', model_raw, input_raw)
    demand = h('qualified-demand-id-v2', network, parameters, requester, u64(1))
    source_record = h('qualified-bootstrap-source-record-v2', network, parameters,
                      model, inputs, b'public-fixture-not-user-demand')
    authorization = h('qualified-bootstrap-authorization-v2', network, parameters,
                      b'development-attestation-not-local-permission')
    availability_manifest = h('qualified-bootstrap-da-manifest-v2', model, inputs)
    availability_root = h('qualified-bootstrap-da-attestation-v2', model, inputs)
    lease_hashes = (network, parameters, demand, requester, source, source_record,
                    authorization, availability_manifest, availability_root)
    lease = (b'QDL2\x02\x00\x00\x01' + b''.join(lease_hashes)
             + b''.join(u64(v) for v in (1, 1, 0, 1000, 1100)) + b'\x01' + bytes(7))
    require(len(lease) == 344, 'GENESIS_LEASE_BYTES')
    lease_id = h('qualified-demand-lease-v2', lease)
    work_profile = h('qualified-task-profile-v1', b'pon-matmul-transcript-64-v1')
    recipe = h('qualified-task-recipe-v1', b'canonical-field-matrix64-product-v1')
    layer = h('qualified-task-layer-v1', model, b'entire-row-major-field-layer-64x64')
    bound_source = h('qualified-demand-source-record-v2', lease_id, source_record)
    frontier = h('qualified-demand-frontier-v2', lease_id)
    meter = h('qualified-task-output-meter-v1', network, parameters, demand,
              model, layer, inputs, recipe, task)
    manifest_hashes = (network, parameters, work_profile, source, demand, bound_source,
                       model, layer, inputs, recipe, task, availability_manifest,
                       availability_root, authorization, frontier, meter)
    manifest = (b'QWT1\x01\x00\x01\x01\x01\x00\x01\x00'
                + b''.join(manifest_hashes) + struct.pack('<4H', 64, 64, 64, 0)
                + b''.join(u64(v) for v in (1, 0, 1000, 1100, 64 ** 3))
                + struct.pack('<3I', 16384, 16384, 0))
    require(len(manifest) == 584, 'GENESIS_MANIFEST_BYTES')
    unsigned = b'QWA2' + lease_id + manifest
    message = h('qualified-task-source-sign-v2', unsigned)
    signature = development_key(0).sign(message)
    verify_signature(source, signature, message)
    statement = unsigned + signature
    require(len(statement) == 684, 'GENESIS_STATEMENT_BYTES')
    return {
        'qualified-demand-generation-v2': 1,
        'qualified-demand-slot-v2:00': dict(
            schema='qualified-demand-slot-record-v2', lease=lease.hex(), status='active',
            opened_height=0, source_sequence=1, statement=statement.hex(),
            statement_id=h('qualified-task-manifest-v2', unsigned).hex(),
            registered_height=0, bound_model=model.hex(), bound_input=inputs.hex(),
            bound_task=task.hex(), bound_meter=meter.hex(), output_count=0,
            output_product=None, output_height=None),
    }


def derive_context(genesis_timestamp=1):
    require(type(genesis_timestamp) is int and 0 < genesis_timestamp <= (1 << 63) - 1,
            'GENESIS_TIME')
    params = config('config/pon/devnet-v1.json')
    evaluation = config('config/pon/public-evaluation-native-v1.json')
    continuity = config('config/pon/continuity-v1.json')
    registry = config('config/pon/qualified-task-lifecycle-v4.json')
    wire = config('config/pon/ledger-v1.json')
    work = config('config/pon/work-profile-v1.json')
    model = config('config/pon/model-family-v1.json')
    require(params['consensus_revision'] == 3 and params['production_activation'] is False,
            'CONFIG')
    require(evaluation['id'] == EVALUATION and evaluation['storage_revision'] == 2
            and evaluation['production_activation'] is False, 'CONFIG')
    require(continuity['id'] == PROFILE and continuity['consensus_revision'] == 12
            and continuity['production_eligible'] is False
            and continuity['hardness_accepted'] is False
            and continuity['useful_model_work_accepted'] is False
            and continuity['capacity']['maximum_keys'] == 65536, 'CONFIG')
    require(registry['id'] == 'signed-task-lifecycle-dev-v4'
            and registry['consensus_revision'] == 9
            and registry['atomic_overlap_window'] is True
            and registry['standalone_renew_disabled'] is True, 'CONFIG')
    params.update(evaluation['genesis_overrides'])
    params.update(
        evaluation_policy_hash=h('evaluation-policy', canonical(evaluation)).hex(),
        consensus_revision=12, work_task_profile=PROFILE,
        continuity_policy_hash=h('consensus-maintenance-continuity-policy-v1',
                                 canonical(continuity)).hex(),
        qualified_task_registry_hash=h('qualified-task-registry-v4', canonical(registry)).hex(),
        genesis_timestamp=genesis_timestamp,
        chain_label=f'trnm-pon-task-lifecycle-wall-devnet-12-{EVALUATION}-{genesis_timestamp}-evaluation-storage2')
    require(params['reward_maturity_blocks'] == 20 and params['max_state_keys'] == 65536,
            'CONFIG')
    network = h('network', params['chain_label'].encode('ascii'))
    parameters = h('parameters', canonical(params), canonical(wire), canonical(work), canonical(model))
    a = matrix_bytes([(13 * i + 17) % 257 for i in range(4096)])
    b = matrix_bytes([(29 * i + 31) % 263 for i in range(4096)])
    maintenance = dict(
        schema='genesis-consensus-maintenance-v1', network=network.hex(),
        parameters=parameters.hex(), policy=params['continuity_policy_hash'],
        matrix_task=h('task', a, b).hex(), model=h('artifact', a).hex(),
        input=h('qualified-task-input-v1', b).hex(),
        source='genesis-public-deterministic-maintenance-v1',
        purpose='ledger-continuity-maintenance', useful_output_credit=0,
        hardness_accepted=False, useful_model_work_accepted=False)
    state = {'meta:issued': mul(params['genesis_accounts'], params['genesis_funding_units_per_account']),
             'model:current': ZERO.hex(), 'consensus-maintenance-v1': maintenance}
    state.update(bootstrap_lifecycle(network, parameters))
    for index in range(params['genesis_accounts']):
        state['account:' + development_public(index).hex()] = dict(
            balance=params['genesis_funding_units_per_account'], nonce=0)
    root = archive.source_state_root(state)
    genesis = h('genesis', network, parameters, root, u64(genesis_timestamp))
    fees = {row['tag']: uint(row['base_fee_units']) for row in wire['commands']}
    return Context(params, network, parameters, fees, maintenance, genesis, state)


def derive_genesis(context):
    return copy.deepcopy(context.genesis_state)


def account_value(value):
    require(type(value) is dict and set(value) == {'balance', 'nonce'}, 'ACCOUNT_FIELDS')
    return dict(balance=uint(value['balance']), nonce=uint(value['nonce']))


def named_hash(key, prefix):
    require(type(key) is str and key.startswith(prefix), 'STATE_NAMESPACE')
    return hex_bytes(key[len(prefix):], 32)


def validate_state(state, context):
    """Reject unsupported mutable namespaces rather than silently preserving them."""
    require(type(state) is dict, 'STATE')
    immutable = {key: value for key, value in context.genesis_state.items()
                 if key != 'meta:issued' and not key.startswith('account:')}
    for key, expected in immutable.items():
        equal(state.get(key), expected, 'IMMUTABLE_GENESIS_RECORD')
    uint(state.get('meta:issued'))
    for key, value in state.items():
        if key in immutable or key == 'meta:issued':
            continue
        if key.startswith('account:'):
            named_hash(key, 'account:')
            account_value(value)
        elif key.startswith('reward:'):
            named_hash(key, 'reward:')
            require(type(value) is dict and set(value) == {'owner', 'amount', 'maturity'}, 'STATE')
            hex_bytes(value['owner'], 32)
            uint(value['amount'])
            uint(value['maturity'])
        elif key.startswith('task:'):
            named_hash(key, 'task:')
            require(type(value) is dict and set(value) == {
                'owner', 'provider', 'remaining', 'deadline', 'status', 'output'}, 'STATE')
            for name in ('owner', 'provider'):
                hex_bytes(value[name], 32)
            for name in ('remaining', 'deadline'):
                uint(value[name])
            require(value['status'] in ('reserved', 'receipt', 'cancelled', 'settled', 'expired'), 'STATE')
            if value['output'] is not None:
                hex_bytes(value['output'], 32)
        elif key.startswith('quota:'):
            named_hash(key, 'quota:')
            require(type(value) is dict and set(value) == {
                'owner', 'consumer', 'provider', 'remaining', 'units', 'deadline', 'status'}, 'STATE')
            for name in ('owner', 'consumer', 'provider'):
                hex_bytes(value[name], 32)
            for name in ('remaining', 'units', 'deadline'):
                uint(value[name])
            require(value['status'] in ('reserved', 'spent', 'expired'), 'STATE')
        else:
            raise RelationError('UNSUPPORTED_STATE_NAMESPACE')
    # Existing root bounds are part of this full-State contract, unchanged.
    archive.source_state_root(state)


class AccountAccess:
    """Full immutable parent binding plus authenticated semantic point access."""
    def __init__(self, parent, checked=None):
        self.parent = parent
        self.checked = checked
        self.used = set()

    def gate(self, owner):
        owner = hash_value(owner)
        if self.checked is not None:
            require(owner in self.checked, 'MISSING_WITNESS:' + owner.hex())
            observed = self.parent.get('account:' + owner.hex())
            expected = self.checked[owner]
            equal(observed, None if expected is None else expected.as_json(), 'PARENT_ACCOUNT_BINDING')
        self.used.add(owner)
        return owner.hex()

    def read(self, state, owner):
        key = 'account:' + self.gate(owner)
        return account_value(state[key]) if key in state else dict(balance=0, nonce=0)

    def exists(self, state, owner):
        return 'account:' + self.gate(owner) in state

    def credit(self, state, owner, amount):
        value = self.read(state, owner)
        value['balance'] = add(value['balance'], amount)
        state['account:' + hash_value(owner).hex()] = value

    def debit(self, state, owner, amount):
        value = self.read(state, owner)
        require(uint(amount) > 0 and value['balance'] >= amount, 'FUNDS')
        value['balance'] -= amount
        state['account:' + hash_value(owner).hex()] = value


def capacity(state, height, context, access=None):
    uint(height)
    access = access if access is not None else AccountAccess(state)
    equal(state.get('consensus-maintenance-v1'), context.maintenance, 'CONTINUITY_MAINTENANCE')
    maturity = uint(context.params['reward_maturity_blocks'])
    maximum = add(height, maturity)
    future = set()
    recipients = set()
    for key in sorted(state):
        value = state[key]
        if key.startswith('reward:'):
            due = uint(value['maturity'])
            require(height < due <= maximum and due not in future, 'CONTINUITY_REWARD_QUEUE')
            future.add(due)
            uint(value['amount'])
            owner = hex_bytes(value['owner'], 32)
            if not access.exists(state, owner):
                recipients.add(owner)
        elif key.startswith(('task:', 'quota:')) and uint(value['remaining']) > 0:
            owner = hex_bytes(value['owner'], 32)
            if not access.exists(state, owner):
                recipients.add(owner)
        elif key.startswith('contribution:'):
            raise RelationError('UNSUPPORTED_STATE_NAMESPACE')
    expected_count = min(height, maturity)
    require(future == set(range(max(height, maturity) + 1, maximum + 1))
            and len(future) == expected_count, 'CONTINUITY_REWARD_QUEUE')
    queue = maturity - expected_count
    required = len(state) + len(recipients) + queue
    require(required <= context.params['max_state_keys'], 'STATE_CAPACITY')
    return dict(actual_keys=len(state), credit_account_reserve=len(recipients),
                archive_reserve=0, reward_queue_reserve=queue, required_keys=required)


def total_funds(state):
    total = 0
    for key in sorted(state):
        value = state[key]
        amount = value['balance'] if key.startswith('account:') else (
            value['remaining'] if key.startswith(('task:', 'quota:')) else (
                value['amount'] if key.startswith('reward:') else 0))
        total = add(total, amount)
    return total


def mandatory(parent, height, context, access):
    state = copy.deepcopy(parent)
    # These fixtures have no contribution, release, factor or evidence namespace;
    # validate_state refuses those inputs before an incomplete cleanup can run.
    for key in sorted(parent):
        value = state[key]
        if key.startswith(('task:', 'quota:')) and value['remaining'] == 0 and value['deadline'] < height:
            del state[key]
    due = sorted((value['deadline'], key) for key, value in state.items()
                 if key.startswith(('task:', 'quota:')) and value['remaining'] > 0
                 and value['deadline'] <= height)
    receipts = []
    for _, key in due[:context.params['mandatory_expiry_per_block']]:
        record = state[key]
        access.credit(state, hex_bytes(record['owner'], 32), record['remaining'])
        record.update(remaining=0, status='expired')
        receipts.append(canonical(dict(expiry=key)))
    for key in sorted(tuple(state)):
        if key.startswith('reward:') and state[key]['maturity'] <= height:
            record = state.pop(key)
            access.credit(state, hex_bytes(record['owner'], 32), record['amount'])
    return state, receipts


def decode_transaction(raw, context):
    require(type(raw) is bytes and len(raw) <= context.params['max_transaction_bytes'], 'ENCODING')
    require(len(raw) >= 159 and raw[:4] == b'PNX1', 'ENCODING')
    nonce, expiry, fee_limit = struct.unpack_from('<QQQ', raw, 68)
    tag, length = raw[92], int.from_bytes(raw[93:95], 'little')
    require(len(raw) == 159 + length and nonce > 0
            and fee_limit <= context.params['max_fee_limit'], 'ENCODING')
    require(tag in SUPPORTED_TAGS, 'UNSUPPORTED_TRANSACTION_TAG')
    require(length == {1: 40, 2: 80, 3: 32, 4: 64, 5: 64, 10: 112, 11: 136}[tag], 'ENCODING')
    return dict(network=raw[4:36], sender=raw[36:68], nonce=nonce, expiry=expiry,
                fee_limit=fee_limit, tag=tag, payload=raw[95:-64], signature=raw[-64:],
                unsigned=raw[:-64], raw=raw)


def signed_transaction(context, sender, nonce, tag, payload, expiry=2000, fee_limit=1_000_000):
    """Public fixture helper, independently encoded and signed."""
    require(tag in SUPPORTED_TAGS and type(payload) is bytes, 'UNSUPPORTED_TRANSACTION_TAG')
    unsigned = (b'PNX1' + context.network + development_public(sender) + u64(nonce)
                + u64(expiry) + u64(fee_limit) + bytes([tag]) + len(payload).to_bytes(2, 'little')
                + payload)
    return unsigned + development_key(sender).sign(h('tx-sign', unsigned))


def deadline(state, due, height, context):
    require(height < due <= add(height, context.params['max_task_lifetime_blocks']), 'EXPIRED')
    active = [value for key, value in state.items()
              if key.startswith(('task:', 'quota:')) and value['remaining'] > 0]
    require(len(active) < context.params['max_pending_tasks']
            and sum(value['deadline'] == due for value in active)
            < context.params['mandatory_expiry_per_block'], 'LIMIT')


def apply_transaction(state, raw, height, context, access):
    tx = decode_transaction(raw, context)
    require(tx['network'] == context.network, 'NETWORK')
    require(height <= tx['expiry'], 'EXPIRED')
    try:
        verify_signature(tx['sender'], tx['signature'], h('tx-sign', tx['unsigned']))
    except ValueError as error:
        raise RelationError('SIGNATURE') from error
    sender, tag, payload = tx['sender'], tx['tag'], tx['payload']
    account = access.read(state, sender)
    require(tx['nonce'] == add(account['nonce'], 1), 'NONCE')
    fee = add(context.fees[tag], mul(len(raw), context.params['byte_fee_units']))
    require(tx['fee_limit'] >= fee, 'FEE')
    if tag == 11:
        state['account:' + sender.hex()] = account
    else:
        access.debit(state, sender, fee)

    def number(offset):
        return int.from_bytes(payload[offset:offset + 8], 'little')

    def fetch(prefix, identifier):
        name = prefix + identifier.hex()
        require(name in state, 'STATE')
        return state[name]

    if tag == 1:
        recipient, amount = payload[:32], number(32)
        access.debit(state, sender, amount)
        access.credit(state, recipient, amount)
    elif tag == 2:
        identifier, provider, budget, due = payload[:32], payload[32:64], number(64), number(72)
        require(identifier == h('task-instance-v3', context.network, context.parameters,
                sender, u64(tx['nonce']), provider, u64(budget), u64(due)), 'RESOURCE_ID')
        name = 'task:' + identifier.hex()
        require(name not in state, 'DUPLICATE')
        deadline(state, due, height, context)
        access.debit(state, sender, budget)
        state[name] = dict(owner=sender.hex(), provider=provider.hex(), remaining=budget,
                           deadline=due, status='reserved', output=None)
    elif tag == 3:
        record = fetch('task:', payload[:32])
        require(record['owner'] == sender.hex(), 'AUTHORITY')
        require(record['status'] == 'reserved', 'STATE')
        access.credit(state, sender, record['remaining'])
        record.update(remaining=0, status='cancelled')
    elif tag == 4:
        record, output = fetch('task:', payload[:32]), payload[32:64]
        require(record['provider'] == sender.hex(), 'AUTHORITY')
        require(record['status'] == 'reserved' and height < record['deadline'], 'STATE')
        require(output != ZERO, 'EVIDENCE')
        record.update(output=output.hex(), status='receipt')
    elif tag == 5:
        record, output = fetch('task:', payload[:32]), payload[32:64]
        require(record['owner'] == sender.hex(), 'AUTHORITY')
        require(record['status'] == 'receipt' and height < record['deadline']
                and record['output'] == output.hex(), 'STATE')
        access.credit(state, hex_bytes(record['provider'], 32), record['remaining'])
        record.update(remaining=0, status='settled')
    elif tag == 10:
        identifier, consumer, provider = payload[:32], payload[32:64], payload[64:96]
        units, due = number(96), number(104)
        require(identifier == h('quota-instance-v3', context.network, context.parameters,
                sender, u64(tx['nonce']), consumer, provider, u64(units), u64(due)), 'RESOURCE_ID')
        name = 'quota:' + identifier.hex()
        require(name not in state, 'DUPLICATE')
        deadline(state, due, height, context)
        require(0 < units <= context.params['max_quota_units'], 'LIMIT')
        cost = mul(units, context.params['quota_unit_price'])
        access.debit(state, sender, cost)
        state[name] = dict(owner=sender.hex(), consumer=consumer.hex(), provider=provider.hex(),
                           remaining=cost, units=units, deadline=due, status='reserved')
    elif tag == 11:
        identifier, units, result = payload[:32], number(32), payload[40:72]
        record = fetch('quota:', identifier)
        require(record['provider'] == sender.hex(), 'AUTHORITY')
        require(record['status'] == 'reserved' and height < record['deadline'], 'STATE')
        require(0 < units <= record['units'] and result != ZERO, 'LIMIT')
        message = h('use', context.network, context.parameters, identifier, sender,
                    u64(tx['nonce']), u64(units), result)
        try:
            verify_signature(hex_bytes(record['consumer'], 32), payload[72:136], message)
        except ValueError as error:
            raise RelationError('SIGNATURE') from error
        cost = mul(units, context.params['quota_unit_price'])
        require(cost >= fee and record['remaining'] >= cost, 'FUNDS')
        record['remaining'] -= cost
        record['units'] -= units
        access.credit(state, sender, cost - fee)
        if record['units'] == 0:
            record['status'] = 'spent'
    value = access.read(state, sender)
    value['nonce'] = tx['nonce']
    state['account:' + sender.hex()] = value
    return fee, canonical(dict(tx=h('tx-id', raw).hex(), fee=fee, status='applied'))


def transition(parent, transactions, height, miner, parent_id, context, checked=None):
    """Pure canonical block relation; neither success nor failure mutates parent."""
    require(type(transactions) is list and len(transactions) <= context.params['max_transactions'], 'LIMIT')
    uint(height)
    require(height > 0, 'HEIGHT')
    miner, parent_id = hash_value(miner), hash_value(parent_id)
    validate_state(parent, context)
    access = AccountAccess(parent, checked)
    before = capacity(parent, height - 1, context, access)
    state, receipts = mandatory(parent, height, context, access)
    fees = 0
    for raw in transactions:
        fee, receipt = apply_transaction(state, raw, height, context, access)
        fees = add(fees, fee)
        receipts.append(receipt)
    halvings = min(height // context.params['subsidy_halving_interval'], 64)
    subsidy = context.params['block_subsidy_units'] >> halvings
    reward = 'reward:' + h('reward', parent_id, u64(height), miner).hex()
    state[reward] = dict(owner=miner.hex(), amount=add(fees, subsidy),
                         maturity=add(height, context.params['reward_maturity_blocks']))
    state['meta:issued'] = add(state['meta:issued'], subsidy)
    require(total_funds(state) == state['meta:issued'], 'CONSERVATION')
    after = capacity(state, height, context, access)
    validate_state(state, context)
    root = archive.source_state_root(state)
    accounts = archive.accounts_from_state(state)
    account_root = archive.full_sparse(accounts)[0]
    if checked is not None:
        unused = sorted(set(checked) - access.used)
        require(not unused, 'UNUSED_WITNESS:' + ','.join(owner.hex() for owner in unused))
    return dict(state=state, root=list(root), account_root=list(account_root),
                account_count=len(accounts), receipts_hex=[raw.hex() for raw in receipts],
                used_owners=[list(owner) for owner in sorted(access.used)],
                fees=fees, subsidy=subsidy, capacity_before=before, capacity_after=after)


def checked_witnesses(context, checkpoint, parent, parent_id, height, requested, witnesses):
    """Bind the checkpoint to the full parent before interpreting any account proof."""
    equal(checkpoint['context'], context.as_json(), 'CHECKPOINT_CONTEXT')
    require(hash_value(checkpoint['branch']) == hash_value(parent_id)
            and checkpoint['height'] == height, 'CHECKPOINT_PARENT')
    require(hash_value(checkpoint['source_state_root']) == archive.source_state_root(parent),
            'CHECKPOINT_SOURCE_ROOT')
    accounts = archive.accounts_from_state(parent)
    details = archive.full_sparse_details(accounts)
    require(hash_value(checkpoint['account_root']) == details['root']
            and checkpoint['account_count'] == len(accounts)
            and checkpoint['root_node'] == (None if details['root_node'] is None else list(details['root_node'])),
            'CHECKPOINT_ACCOUNT_ROOT')
    archive.checkpoint_record(checkpoint)
    require(type(requested) is list and type(witnesses) is list
            and len(requested) == len(witnesses) <= archive.MAX_VIEW_ACCOUNTS, 'WITNESS_BUDGET')
    owners = [hash_value(owner) for owner in requested]
    require(len(set(owners)) == len(owners), 'INVALID_WITNESS')
    result = {}
    for witness in witnesses:
        owner = hash_value(witness['owner'])
        require(owner in owners and owner not in result, 'INVALID_WITNESS')
        result[owner] = archive.verify_witness(witness, hash_value(checkpoint['id']), details['root'], owner)
        require(result[owner] == accounts.get(owner), 'PARENT_ACCOUNT_BINDING')
    return result


def sequence_root(tag, items):
    leaves = [h(tag + '-leaf', u64(index), raw) for index, raw in enumerate(items)]
    if not leaves:
        return h(tag + '-empty')
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [h(tag + '-node', left, right) for left, right in zip(leaves[::2], leaves[1::2])]
    return leaves[0]


def decode_packet(raw):
    require(type(raw) is bytes and 318 + 2 + 49188 <= len(raw) <= 1048576, 'PACKET_LENGTH')
    header = raw[:318]
    require(header[:6] == b'PNH1\x01\x00', 'HEADER_ENCODING')
    fields, position = {}, 6
    layout = ('network', 'parameters', 'parent', 'height', 'timestamp', 'target',
              'miner', 'transactions', 'state', 'receipts', 'work_task', 'nonce')
    for name in layout:
        size = 32 if name in HASH_FIELDS else 8
        chunk = header[position:position + size]
        fields[name] = chunk if size == 32 else int.from_bytes(chunk, 'little')
        position += size
    count, position = int.from_bytes(raw[318:320], 'little'), 320
    require(count <= 256, 'PACKET_TRANSACTIONS')
    transactions = []
    for _ in range(count):
        require(position + 2 <= len(raw), 'PACKET_LENGTH')
        size = int.from_bytes(raw[position:position + 2], 'little')
        position += 2
        require(159 <= size <= 2048 and position + size <= len(raw), 'PACKET_LENGTH')
        transactions.append(raw[position:position + size])
        position += size
    proof = raw[position:]
    require(len(proof) == 49188 and proof[:4] == b'PNW1', 'PACKET_WORK_ENCODING')
    return fields, transactions, h('block', header, proof[-32:])


def verify_packet(raw, transactions, output, context, parent, height, miner):
    fields, body, identity = decode_packet(raw)
    require(body == transactions, 'PACKET_TRANSACTION_BYTES')
    require(fields['network'] == context.network and fields['parameters'] == context.parameters,
            'PACKET_CONTEXT')
    require(fields['parent'] == hash_value(parent) and fields['height'] == height
            and fields['miner'] == hash_value(miner), 'PACKET_PARENT')
    require(fields['transactions'] == sequence_root('transactions', transactions), 'PACKET_TRANSACTION_ROOT')
    require(fields['state'] == hash_value(output['root']), 'PACKET_STATE_ROOT')
    receipts = [hex_bytes(value) for value in output['receipts_hex']]
    require(fields['receipts'] == sequence_root('receipts', receipts), 'PACKET_RECEIPT_ROOT')
    require(fields['work_task'] == hex_bytes(context.maintenance['matrix_task'], 32), 'PACKET_WORK_TASK')
    return identity


def fixture_transactions(context, height, parent):
    """The independently specified twenty-transaction fixture, including signatures."""
    def transfer(sender, nonce, recipient, amount):
        return signed_transaction(context, sender, nonce, 1,
                                  development_public(recipient) + u64(amount))

    def fee(raw):
        return add(context.fees[raw[92]], mul(len(raw), context.params['byte_fee_units']))

    def task(sender, nonce, budget, due):
        identity = h('task-instance-v3', context.network, context.parameters,
                     development_public(sender), u64(nonce), development_public(3),
                     u64(budget), u64(due))
        raw = signed_transaction(context, sender, nonce, 2,
                                 identity + development_public(3) + u64(budget) + u64(due))
        return identity, raw

    settled, reserve_settled = task(2, 1, 5000, 12)
    cancelled, reserve_cancelled = task(2, 2, 3000, 12)
    _, reserve_expired = task(2, 3, 7000, 5)
    _, reserve_refund = task(11, 2, 7000, 5)
    quota = h('quota-instance-v3', context.network, context.parameters,
              development_public(1), u64(2), development_public(2), development_public(12),
              u64(10), u64(6))
    quota_payload = quota + development_public(2) + development_public(12) + u64(10) + u64(6)
    output = h('checked-account-execution-fixture-output-v1', b'settlement')
    result = h('checked-account-execution-fixture-output-v1', b'quota-use')
    message = h('use', context.network, context.parameters, quota, development_public(12),
                u64(1), u64(5), result)
    use_payload = quota + u64(5) + result + development_key(2).sign(message)
    spend10, spend11, later10 = transfer(10, 1, 2, 37), transfer(11, 1, 2, 19), transfer(10, 2, 2, 7)
    if height == 1:
        return [transfer(0, 1, 10, fee(spend10) + 37),
                transfer(0, 2, 11, fee(spend11) + 19), spend11,
                transfer(1, 1, 1, 5), reserve_settled, reserve_cancelled, reserve_expired,
                signed_transaction(context, 1, 2, 10, quota_payload)]
    if height == 2:
        return [spend10, signed_transaction(context, 3, 1, 4, settled + output),
                signed_transaction(context, 2, 4, 5, settled + output),
                signed_transaction(context, 2, 5, 3, cancelled),
                signed_transaction(context, 12, 1, 11, use_payload)]
    if height == 3:
        return [transfer(0, 3, 10, fee(later10) + 7),
                transfer(0, 4, 11, 7000 + fee(reserve_refund)), reserve_refund]
    if height == 4:
        return [later10]
    if height == 5:
        return [transfer(11, 3, 2, 7000 - fee(transfer(11, 3, 2, 1)))]
    if height == 6:
        return [transfer(1, 3, 2, 9)]
    if height == 21:
        miner = development_public(79999).hex()
        require('account:' + miner not in parent, 'FIXTURE_MINER_ALREADY_PRESENT')
        rewards = [value for key, value in parent.items()
                   if key.startswith('reward:') and value['owner'] == miner]
        require(len(rewards) == 1 and rewards[0]['maturity'] == 21, 'FIXTURE_MATURITY_REWARD')
        amount = rewards[0]['amount'] - fee(transfer(79999, 1, 2, 1))
        require(amount > 0, 'FIXTURE_MATURITY_BUDGET')
        return [transfer(79999, 1, 2, amount)]
    return []


def strict_scope(actual, expected, code):
    require(type(actual) is dict and set(actual) == set(expected)
            and all(type(value) is bool for value in actual.values()), code)
    equal(actual, expected, code)


def expected_execution_observation(context, parent_checkpoint, parent_state, block, output):
    parent_accounts = archive.accounts_from_state(parent_state)
    return dict(
        schema='pon-checked-account-execution-v1', network=list(context.network),
        parameters=list(context.parameters), genesis=list(context.genesis),
        parent_checkpoint=parent_checkpoint['id'], parent_id=block['parent'], height=block['height'],
        parent_state_root=list(archive.source_state_root(parent_state)),
        successor_state_root=output['root'], parent_account_root=parent_checkpoint['account_root'],
        successor_account_root=output['account_root'], parent_account_count=len(parent_accounts),
        successor_account_count=output['account_count'], requested_owners=block['requested'],
        used_owners=output['used_owners'], parent_capacity=output['capacity_before'],
        successor_capacity=output['capacity_after'], workers=1, complete_state_required=True,
        aggregate_account_scans_are_full=True, consensus_admission=False, archive_mutated=False)


def check_positive_observation(observation):
    """Return independently derived branch states; observed State is comparison-only."""
    require(type(observation) is dict and observation.get('schema') == NATIVE_SCHEMA,
            'OBSERVATION_SCHEMA')
    require(not set(observation).intersection({'error', 'errors', 'failure', 'exception', 'timeout'}),
            'OBSERVATION_FAILURE')
    context = derive_context(observation['genesis_timestamp'])
    equal(observation['context'], context.as_json(), 'NATIVE_CONTEXT')
    equal(observation['params'], context.params, 'NATIVE_PARAMETERS')
    equal(observation['genesis_state'], context.genesis_state, 'NATIVE_GENESIS_STATE')
    strict_scope(observation['scope'], NATIVE_SCOPE, 'NATIVE_SCOPE')
    genesis_root = archive.source_state_root(context.genesis_state)
    genesis_accounts = archive.accounts_from_state(context.genesis_state)
    genesis_checkpoint, genesis_tree = archive.derive_checkpoint(
        context.as_json(), context.genesis, None, 0, genesis_root, genesis_accounts)
    equal(observation['genesis_checkpoint'], genesis_checkpoint, 'NATIVE_GENESIS_CHECKPOINT')
    states = {context.genesis: derive_genesis(context)}
    checkpoints = {context.genesis: genesis_checkpoint}
    trees = {context.genesis: genesis_tree}
    labels = {'genesis': context.genesis}
    records = dict(genesis_tree['records'])
    checkpoint_records = {hash_value(genesis_checkpoint['id']): archive.checkpoint_record(genesis_checkpoint)}
    selected, generation = context.genesis, 1
    active = dict(checkpoint=genesis_checkpoint['id'], generation=generation)
    detail_rows, selected_reopens = [], {}
    expected_labels = ([f'main-{height:02}' for height in range(1, 22)]
        + [f'fork-{height:02}' for height in range(3, 23)] + ['restored-22', 'restored-23'])
    blocks = observation['blocks']
    require(type(blocks) is list and [row['label'] for row in blocks] == expected_labels,
            'FIXTURE_BLOCK_SET')
    transactions_checked, reorganizations, witness_count = 0, 0, 0
    for block in blocks:
        label = block['label']
        height = int(label.rsplit('-', 1)[1])
        if label.startswith('main-'):
            parent_label = 'genesis' if height == 1 else f'main-{height-1:02}'
        elif label.startswith('fork-'):
            parent_label = 'main-02' if height == 3 else f'fork-{height-1:02}'
        else:
            parent_label = 'main-21' if height == 22 else 'restored-22'
        parent_id = labels[parent_label]
        parent = states[parent_id]
        parent_checkpoint = checkpoints[parent_id]
        require(type(block['height']) is int and block['height'] == height
                and hash_value(block['parent']) == parent_id,
                'FIXTURE_PARENT')
        equal(block['parent_state'], parent, 'NATIVE_PARENT_STATE')
        equal(block['parent_checkpoint'], parent_checkpoint, 'NATIVE_PARENT_CHECKPOINT')
        miner = development_public(79999 if label == 'main-01' else 0)
        require(hash_value(block['miner']) == miner, 'FIXTURE_MINER')
        transactions = fixture_transactions(context, height, parent) if label.startswith('main-') else []
        equal(block['transactions_hex'], [raw.hex() for raw in transactions], 'FIXTURE_SIGNED_TRANSACTION_BYTES')
        checked = checked_witnesses(context, parent_checkpoint, parent, parent_id, height-1,
                                   block['requested'], block['witnesses'])
        owners = [hash_value(owner) for owner in block['requested']]
        require(owners == sorted(owners), 'NATIVE_REQUESTED_ORDER')
        equal(block['witnesses_hex'], [archive.encode_witness(witness).hex()
                                      for witness in block['witnesses']], 'NATIVE_WITNESS_ENCODING')
        require([hash_value(witness['owner']) for witness in block['witnesses']] == owners,
                'NATIVE_WITNESS_ORDER')
        equal(block['witness_node_reads'], [archive.point_reads(trees[parent_id], owner)
                                           for owner in owners], 'NATIVE_WITNESS_NODE_READS')
        output = transition(parent, transactions, height, miner, parent_id, context, checked)
        equal(block['requested'], output['used_owners'], 'NATIVE_EXACT_ACCOUNT_COVERAGE')
        native = block['native_output']
        for field in ('state', 'root', 'receipts_hex', 'used_owners'):
            equal(native[field], output[field], 'NATIVE_OUTPUT_' + field.upper())
        equal(block['capacity_before'], output['capacity_before'], 'NATIVE_PARENT_CAPACITY')
        equal(block['capacity_after'], output['capacity_after'], 'NATIVE_SUCCESSOR_CAPACITY')
        equal(native['observation'], expected_execution_observation(context, parent_checkpoint,
              parent, block, output), 'NATIVE_EXECUTION_OBSERVATION')
        packet = hex_bytes(block['packet_hex'])
        require(hex_bytes(block['header_hex'], 318) == packet[:318], 'NATIVE_HEADER_BYTES')
        identity = verify_packet(packet, transactions, output, context, parent_id, height, miner)
        require(identity == hash_value(block['id']) and identity not in states, 'NATIVE_BLOCK_ID')
        accounts = archive.accounts_from_state(output['state'])
        successor, tree = archive.derive_checkpoint(context.as_json(), identity,
            hash_value(parent_checkpoint['id']), height, hash_value(output['root']), accounts)
        equal(block['successor_checkpoint'], successor, 'NATIVE_SUCCESSOR_CHECKPOINT')
        # Derive each persisted COW prefix from leaves, never imitate Rust insert.
        partial = archive.accounts_from_state(parent)
        for owner, value in sorted(accounts.items()):
            if partial.get(owner) != value:
                partial[owner] = value
                archive.merge_records(records, archive.full_sparse_details(partial)['records'])
        archive.merge_records(records, tree['records'])
        checkpoint_records[hash_value(successor['id'])] = archive.checkpoint_record(successor)
        states[identity], checkpoints[identity], trees[identity], labels[label] = (
            output['state'], successor, tree, identity)
        require(hash_value(block['selected_before']) == selected, 'NATIVE_ACTIVE_CHAIN')
        next_selected = hash_value(block['selected_after'])
        require(next_selected in states, 'NATIVE_UNKNOWN_SELECTED_BRANCH')
        if next_selected != selected:
            reorganizations += int(selected != parent_id)
            generation += 1
        selected = next_selected
        active = dict(checkpoint=checkpoints[selected]['id'], generation=generation)
        equal(block['archive_active_after'], active, 'NATIVE_ARCHIVE_ACTIVE')
        storage = archive.storage_counts(records, len(checkpoint_records))
        equal(block['archive_storage_after'], storage, 'NATIVE_ARCHIVE_STORAGE')
        for flag, expected in [('native_admitted', True), ('normal_worker4_equal', True),
                               ('checked_execution_mutated_archive', False)]:
            require(block.get(flag) is expected, 'NATIVE_BLOCK_SCOPE')
        if label in ('main-21', 'fork-22', 'restored-23'):
            require(selected == identity, 'FIXTURE_SELECTED_REOPEN_BRANCH')
            selected_reopens[label] = dict(active=identity, height=height, state=output['state'],
                                           archive_active=active, archive_storage=storage)
        transactions_checked += len(transactions)
        witness_count += len(owners)
        detail_rows.append(dict(label=label, id=identity.hex(), parent=parent_id.hex(), height=height,
            transaction_envelopes=len(transactions), state_root=hash_value(output['root']).hex(),
            account_root=hash_value(output['account_root']).hex(), account_count=len(accounts),
            receipts=len(output['receipts_hex']), fees=output['fees'], subsidy=output['subsidy'],
            used_owners=[owner.hex() for owner in owners], capacity_before=output['capacity_before'],
            capacity_after=output['capacity_after'], selected=selected.hex(),
            archive_storage=storage))
    require(transactions_checked == 20 and reorganizations == 2, 'FIXTURE_EXECUTION_COUNTS')
    reopens = observation['reopens']
    require(type(reopens) is list and [row['label'] for row in reopens]
            == ['main-21', 'fork-22', 'restored-23'], 'FIXTURE_REOPEN_SET')
    reopen_rows = []
    for row in reopens:
        wanted = selected_reopens[row['label']]
        require(hash_value(row['active']) == wanted['active'] and type(row['height']) is int
                and row['height'] == wanted['height'],
                'NATIVE_REOPEN_BRANCH')
        for field in ('state', 'archive_active', 'archive_storage'):
            equal(row[field], wanted[field], 'NATIVE_REOPEN_' + field.upper())
        require(hash_value(row['checkpoint']) == hash_value(wanted['archive_active']['checkpoint'])
                and row.get('unchanged') is True, 'NATIVE_REOPEN_CHECKPOINT')
        reopen_rows.append(dict(label=row['label'], active=wanted['active'].hex(), height=wanted['height'],
                                state_root=archive.source_state_root(wanted['state']).hex(),
                                checkpoint=hash_value(row['checkpoint']).hex()))
    for count, expected in [('accepted_native_packets', 43), ('accepted_signed_transactions', 20),
                            ('native_reorganizations', 2), ('cold_reopens', 3), ('final_native_height', 23)]:
        require(type(observation[count]) is int and observation[count] == expected, 'NATIVE_COUNTS')
    require(hash_value(observation['final_native_active']) == labels['restored-23'] == selected,
            'NATIVE_FINAL_BRANCH')
    equal(observation['final_native_state'], states[selected], 'NATIVE_FINAL_STATE')
    equal(observation['final_active'], active, 'NATIVE_FINAL_ACTIVE')
    equal(observation['final_storage'], archive.storage_counts(records, len(checkpoint_records)),
          'NATIVE_FINAL_STORAGE')
    equal(observation['final_rows'], archive.row_snapshot(context.as_json(), records, checkpoint_records, active),
          'NATIVE_FINAL_ROWS')
    for label, nonces in [('main-21', {10:2, 11:3, 79999:1}),
                          ('fork-22', {10:1, 11:1}), ('restored-23', {10:2, 11:3, 79999:1})]:
        state = states[labels[label]]
        for number, nonce in nonces.items():
            value = state['account:' + development_public(number).hex()]
            require(value['nonce'] == nonce, 'FIXTURE_BRANCH_NONCE')
            if label != 'fork-22':
                require(value['balance'] == 0, 'FIXTURE_PRESENT_ZERO')
    report = dict(schema=SCHEMA, native_schema=NATIVE_SCHEMA,
        supported_transaction_tags=list(SUPPORTED_TAGS), genesis_checked=True,
        genesis_state_root=genesis_root.hex(), genesis=context.genesis.hex(),
        blocks_checked=43, transaction_envelopes_checked=transactions_checked,
        reorganizations_checked=reorganizations, reopen_observations_checked=len(reopen_rows),
        account_witnesses_checked=witness_count, complete_archive_rows_from_observation_checked=True,
        sqlite_database_opened=False, block_observations=detail_rows, reopen_observations=reopen_rows,
        final_state_root=archive.source_state_root(states[selected]).hex(),
        final_account_root=hash_value(checkpoints[selected]['account_root']).hex(),
        archive_records_checked=len(records), archive_checkpoints_checked=len(checkpoint_records),
        scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE))
    return report, context, states, checkpoints, labels


NEGATIVE_LABELS = (
    'missing-sender', 'missing-new-recipient', 'missing-intrablock-owner',
    'missing-future-reward-recipient', 'missing-quota-provider', 'missing-expiry-recipient',
    'missing-matured-reward-recipient', 'unused-witness', 'duplicate-witness',
    'forged-account-value', 'forged-account-absence', 'witness-from-old-branch',
    'forged-witness-root', 'malformed-witness', 'witness-budget', 'wrong-parent',
    'wrong-height', 'wrong-context', 'wrong-source-state-root',
    'wrong-nonaccount-source-state-root', 'missing-checkpoint', 'main-signature',
    'recredited-nonce-replay', 'fee-limit', 'insufficient-funds', 'consumer-signature',
    'resource-id', 'canonical-nonce-before-later-signature', 'cancel-before-output',
)


def witness_for(checkpoint, state, owner):
    accounts = archive.accounts_from_state(state)
    tree = archive.full_sparse_details(accounts, [owner])
    return archive.witness_json(hash_value(checkpoint['id']), owner, accounts.get(owner),
                                tree['proofs'][owner])


def resign(raw, sender, *, nonce=None, fee_limit=None, edit_payload=None):
    unsigned = bytearray(raw[:-64])
    if nonce is not None:
        unsigned[68:76] = u64(nonce)
    if fee_limit is not None:
        unsigned[84:92] = u64(fee_limit)
    if edit_payload is not None:
        payload = bytearray(unsigned[95:])
        edit_payload(payload)
        unsigned[95:] = payload
    unsigned = bytes(unsigned)
    return unsigned + development_key(sender).sign(h('tx-sign', unsigned))


def negative_inputs(observation, context, states, checkpoints, labels):
    """Derive exact mutations from authenticated positives; observed negatives are not inputs."""
    positives = {row['label']: row for row in observation['blocks']}

    def base(source, label):
        row = positives[source]
        parent_id = hash_value(row['parent'])
        state, checkpoint = states[parent_id], checkpoints[parent_id]
        owners = [hash_value(owner) for owner in row['requested']]
        return dict(label=label, source_positive_label=source,
            settings_context=context.as_json(), parent=list(parent_id), height=row['height'],
            miner=list(hash_value(row['miner'])), parent_state=copy.deepcopy(state),
            parent_checkpoint_id=checkpoint['id'], parent_checkpoint=checkpoint,
            requested=[list(owner) for owner in owners],
            witnesses=[witness_for(checkpoint, state, owner) for owner in owners],
            transactions_hex=list(row['transactions_hex']), cancel_at=None)

    cases = []
    for source, label, number in (
        ('main-01', 'missing-sender', 0), ('main-01', 'missing-new-recipient', 10),
        ('main-01', 'missing-intrablock-owner', 11),
        ('main-02', 'missing-future-reward-recipient', 79999),
        ('main-02', 'missing-quota-provider', 12), ('main-05', 'missing-expiry-recipient', 11),
        ('main-21', 'missing-matured-reward-recipient', 79999)):
        case = base(source, label)
        owner = development_public(number)
        case['witnesses'] = [row for row in case['witnesses'] if hash_value(row['owner']) != owner]
        cases.append(case)
    case = base('main-01', 'unused-witness')
    case['witnesses'].append(witness_for(case['parent_checkpoint'], case['parent_state'],
                                        development_public(99999)))
    cases.append(case)
    case = base('main-01', 'duplicate-witness')
    case['witnesses'].append(copy.deepcopy(case['witnesses'][0]))
    cases.append(case)
    case = base('main-01', 'forged-account-value')
    next(row for row in case['witnesses'] if hash_value(row['owner']) == development_public(0))['account']['balance'] += 1
    cases.append(case)
    case = base('main-04', 'forged-account-absence')
    next(row for row in case['witnesses'] if hash_value(row['owner']) == development_public(10))['account'] = None
    cases.append(case)
    case = base('main-04', 'witness-from-old-branch')
    old_id = labels['main-02']
    for index, row in enumerate(case['witnesses']):
        if hash_value(row['owner']) == development_public(10):
            case['witnesses'][index] = witness_for(checkpoints[old_id], states[old_id], development_public(10))
    cases.append(case)
    case = base('main-01', 'forged-witness-root')
    case['witnesses'][0]['siblings'][0][0] ^= 1
    cases.append(case)
    case = base('main-01', 'malformed-witness')
    case['witnesses'][0]['siblings'].pop()
    cases.append(case)
    case = base('main-01', 'witness-budget')
    case['witnesses'] = [witness_for(case['parent_checkpoint'], case['parent_state'],
                                   development_public(number)) for number in range(100000, 100033)]
    cases.append(case)
    case = base('main-01', 'wrong-parent')
    case['parent'] = [9] * 32
    cases.append(case)
    case = base('main-01', 'wrong-height')
    case['height'] += 1
    cases.append(case)
    case = base('main-01', 'wrong-context')
    case['settings_context'] = derive_context(2).as_json()
    cases.append(case)
    case = base('main-01', 'wrong-source-state-root')
    case['parent_state']['account:' + development_public(0).hex()]['nonce'] = 1
    cases.append(case)
    case = base('main-01', 'wrong-nonaccount-source-state-root')
    case['parent_state']['meta:issued'] += 1
    cases.append(case)
    case = base('main-01', 'missing-checkpoint')
    case['parent_checkpoint_id'], case['parent_checkpoint'] = [8]*32, None
    cases.append(case)
    case = base('main-01', 'main-signature')
    raw = bytearray(hex_bytes(case['transactions_hex'][0]))
    raw[-1] ^= 1
    case['transactions_hex'][0] = raw.hex()
    cases.append(case)
    case = base('main-04', 'recredited-nonce-replay')
    case['transactions_hex'][0] = resign(hex_bytes(case['transactions_hex'][0]), 10, nonce=1).hex()
    cases.append(case)
    case = base('main-04', 'fee-limit')
    case['transactions_hex'][0] = resign(hex_bytes(case['transactions_hex'][0]), 10, fee_limit=0).hex()
    cases.append(case)
    case = base('main-04', 'insufficient-funds')
    case['transactions_hex'][0] = signed_transaction(context, 10, 2, 1,
        development_public(2) + u64(U64_MAX)).hex()
    cases.append(case)

    def flip_last(payload):
        payload[-1] ^= 1

    case = base('main-02', 'consumer-signature')
    case['transactions_hex'][4] = resign(hex_bytes(case['transactions_hex'][4]), 12,
                                        edit_payload=flip_last).hex()
    cases.append(case)

    def flip_first(payload):
        payload[0] ^= 1

    case = base('main-01', 'resource-id')
    case['transactions_hex'][4] = resign(hex_bytes(case['transactions_hex'][4]), 2,
                                        edit_payload=flip_first).hex()
    cases.append(case)
    case = base('main-04', 'canonical-nonce-before-later-signature')
    case['transactions_hex'][0] = resign(hex_bytes(case['transactions_hex'][0]), 10, nonce=1).hex()
    later = bytearray(signed_transaction(context, 0, 5, 1, development_public(10) + u64(1)))
    later[-1] ^= 1
    case['transactions_hex'].append(later.hex())
    cases.append(case)
    case = base('main-01', 'cancel-before-output')
    case['cancel_at'] = 'BeforeOutput'
    cases.append(case)
    for case in cases:
        case['requested'] = [list(owner) for owner in sorted(hash_value(row['owner'])
                                                            for row in case['witnesses'])]
    require(tuple(case['label'] for case in cases) == NEGATIVE_LABELS, 'INTERNAL_NEGATIVE_FIXTURE')
    return cases


def derive_checked_outcome(case, context, checkpoints):
    """Independent checked-input and application relation, returning a typed observation."""
    if len(case['witnesses']) > archive.MAX_VIEW_ACCOUNTS:
        return dict(kind='checked', code='Budget')
    by_id = {hash_value(checkpoint['id']): checkpoint for checkpoint in checkpoints.values()}
    checkpoint = by_id.get(hash_value(case['parent_checkpoint_id']))
    if checkpoint is None:
        return dict(kind='archive', code='MissingCheckpoint')
    if hash_value(checkpoint['branch']) != hash_value(case['parent']):
        return dict(kind='checked', code='Parent')
    if checkpoint['height'] + 1 != case['height']:
        return dict(kind='checked', code='Height')
    if hash_value(checkpoint['source_state_root']) != archive.source_state_root(case['parent_state']):
        return dict(kind='checked', code='SourceRoot')
    if canonical(case['settings_context']) != canonical(context.as_json()):
        return dict(kind='checked', code='Context')
    try:
        checked = checked_witnesses(context, checkpoint, case['parent_state'], case['parent'],
            case['height']-1, case['requested'], case['witnesses'])
    except ValueError:
        return dict(kind='archive', code='InvalidWitness')
    before = canonical(case['parent_state'])
    try:
        transition(case['parent_state'], [hex_bytes(raw) for raw in case['transactions_hex']],
            case['height'], case['miner'], case['parent'], context, checked)
    except RelationError as error:
        code = str(error)
        if code.startswith('MISSING_WITNESS:'):
            return dict(kind='account', code='MissingWitness', owner=list(hex_bytes(code.split(':', 1)[1], 32)))
        if code.startswith('UNUSED_WITNESS:'):
            return dict(kind='account', code='UnusedWitness',
                        owners=[list(hex_bytes(owner, 32)) for owner in code.split(':', 1)[1].split(',')])
        return dict(kind='relation', code=code)
    finally:
        require(canonical(case['parent_state']) == before, 'ORACLE_PARENT_MUTATED')
    if case['cancel_at'] == 'BeforeOutput':
        # The relation is otherwise valid. Native progress must show this exact
        # final cancellation point and unchanged inputs/durable observations.
        return dict(kind='checked', code='Cancelled')
    raise RelationError('NEGATIVE_CASE_UNEXPECTEDLY_ACCEPTED')


def expected_negative_progress(case):
    """Serial public progress contract, separately checked from monetary arithmetic."""
    label = case['label']
    if label == 'witness-budget':
        return []
    result = ['BeforeParentBinding']
    binding = {'duplicate-witness', 'forged-account-value', 'forged-account-absence',
               'witness-from-old-branch', 'forged-witness-root', 'malformed-witness',
               'wrong-parent', 'wrong-height', 'wrong-context', 'wrong-source-state-root',
               'wrong-nonaccount-source-state-root', 'missing-checkpoint'}
    if label in binding:
        return result
    result.append('BeforeStateClone')
    if label in {'missing-future-reward-recipient', 'missing-expiry-recipient',
                  'missing-matured-reward-recipient'}:
        return result
    result.append('AfterMandatory')
    for index in range(len(case['transactions_hex'])):
        result += [f'BeforePrepare {{ index: {index} }}', f'AfterPrepare {{ index: {index} }}']
    stop = {'missing-sender':0, 'missing-new-recipient':0, 'missing-intrablock-owner':1,
            'missing-quota-provider':4, 'main-signature':0, 'recredited-nonce-replay':0,
            'fee-limit':0, 'insufficient-funds':0, 'consumer-signature':4, 'resource-id':4,
            'canonical-nonce-before-later-signature':0}.get(label)
    for index in range(len(case['transactions_hex'])):
        result.append(f'BeforeApply {{ index: {index} }}')
        if stop == index:
            return result
        result.append(f'AfterApply {{ index: {index} }}')
    result += ['BeforeReward', 'BeforeCommitment', 'AfterCommitment', 'BeforeOutput']
    return result


def check_negative_observations(observation, context, states, checkpoints, labels):
    cases = negative_inputs(observation, context, states, checkpoints, labels)
    observed = observation['negative_cases']
    require(type(observed) is list and [row['label'] for row in observed] == list(NEGATIVE_LABELS),
            'NATIVE_NEGATIVE_SET')
    final_state = states[labels['restored-23']]
    binding = dict(native_active=list(labels['restored-23']), native_height=23,
        native_state_root=list(archive.source_state_root(final_state)),
        archive_active=observation['final_active'], archive_storage=observation['final_storage'],
        archive_rows_hash=list(h('account-execution-observed-rows-v1', canonical(observation['final_rows']))))
    details = []
    for native, case in zip(observed, cases):
        equal({key: native[key] for key in case}, case, 'NATIVE_NEGATIVE_INPUT')
        wanted = derive_checked_outcome(case, context, checkpoints)
        equal(native['outcome'], wanted, 'NATIVE_NEGATIVE_OUTCOME')
        preview = wanted['code'] if wanted['kind'] == 'relation' else None
        equal(native['node_preview_code'], preview, 'NATIVE_NEGATIVE_PREVIEW')
        equal(native['progress'], expected_negative_progress(case), 'NATIVE_NEGATIVE_PROGRESS')
        equal(native['before'], binding, 'NATIVE_NEGATIVE_BEFORE')
        equal(native['after'], binding, 'NATIVE_NEGATIVE_AFTER')
        require(native.get('parent_unchanged') is True and native.get('archive_unchanged') is True,
                'NATIVE_NEGATIVE_MUTATION')
        details.append(dict(label=case['label'], source_positive_label=case['source_positive_label'],
            input_sha256=sha256(canonical(case)).hexdigest(), outcome=wanted,
            node_preview_code=preview, progress=expected_negative_progress(case),
            parent_input_unchanged=True, durable_observation_unchanged=True,
            durable_observation_sha256=sha256(canonical(binding)).hexdigest()))
    return details


def check_observation(native_json):
    before = file_digest(native_json)
    observed = archive.load_json(native_json)
    observation_bytes = canonical(observed)
    report, context, states, checkpoints, labels = check_positive_observation(observed)
    negatives = check_negative_observations(observed, context, states, checkpoints, labels)
    require(canonical(observed) == observation_bytes, 'ORACLE_OBSERVATION_MUTATED')
    require(file_digest(native_json) == before, 'NATIVE_JSON_MUTATED')
    report.update(result='PASS', native_json_sha256=before,
                  negative_observations_checked=len(negatives), negative_observations=negatives)
    return report


def file_digest(path):
    value = sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-json', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = check_observation(args.native_json)
    except Exception as error:
        report = dict(schema=SCHEMA, result='FAIL', error_type=type(error).__name__,
                      error=str(error), scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE))
        traceback.print_exc(file=sys.stderr)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
