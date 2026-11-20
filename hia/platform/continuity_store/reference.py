"""Independent hosted qualification oracle; never used by the native runtime."""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[3]
MAX = (1 << 64) - 1
MAINTENANCE = 'consensus-maintenance-v1'

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        allow_nan=False).encode()

def domain(name, *parts):
    material = b'TRNM-PON1\0' + struct.pack('<H', len(name)) + name
    for part in parts:
        material += struct.pack('<I', len(part)) + part
    return hashlib.sha256(material).digest()

@lru_cache(maxsize=4)
def configuration(variant):
    if variant not in range(4):
        raise ValueError('Outside the four finite installed constructors')
    def load(name):
        return json.loads((ROOT / 'config/pon' / name).read_bytes())
    params = load('devnet-v1.json')
    policy_hash = domain(b'consensus-maintenance-continuity-policy-v1', canonical(load('continuity-v1.json')))
    registry = domain(b'qualified-task-registry-v4', canonical(load('qualified-task-lifecycle-v4.json')))
    growth = domain(b'native-growth-reference-policy-v2', canonical(load('growth-reference-v2.json'))) if variant >= 2 else bytes(32)
    evaluation = domain(b'evaluation-policy', canonical(load('public-evaluation-native-v1.json'))) if variant & 1 else bytes(32)
    policy = 'native-public-evaluation-dev-v1' if variant & 1 else 'legacy-first-two-v3'
    if variant & 1:
        params.update(load('public-evaluation-native-v1.json')['genesis_overrides'])
        params['evaluation_policy_hash'] = evaluation.hex()
    params.update(consensus_revision=12, work_task_profile='consensus-maintenance-continuity-dev-v1',
        chain_label='trnm-pon-continuity-devnet-12-' + policy, continuity_policy_hash=policy_hash.hex(),
        qualified_task_registry_hash=registry.hex())
    if variant >= 2:
        params.update(consensus_revision=17, work_task_profile='consensus-maintenance-growth-reference-dev-v2',
            chain_label='trnm-pon-growth-reference-v2-17-' + policy,
            state_commitment_profile='native-permanent-account-state-v2', growth_reference_policy_hash=growth.hex(),
            maximum_permanent_accounts=1000000, maximum_working_keys=65536, maximum_total_state_keys=1065536,
            growth_validation='complete-state-reference-not-bounded-witness')
    if variant & 1:
        params['chain_label'] += '-evaluation-storage2'
    network = domain(b'network', params['chain_label'].encode())
    parameters = domain(b'parameters', canonical(params), canonical(load('ledger-v1.json')),
        canonical(load('work-profile-v1.json')), canonical(load('model-family-v1.json')))
    a = b''.join(struct.pack('<I', (13 * i + 17) % 257) for i in range(4096))
    b = b''.join(struct.pack('<I', (29 * i + 31) % 263) for i in range(4096))
    task, model, input_hash = domain(b'task', a, b), domain(b'artifact', a), domain(b'qualified-task-input-v1', b)
    record = dict(schema='genesis-consensus-maintenance-v1', network=network.hex(), parameters=parameters.hex(),
        policy=policy_hash.hex(), matrix_task=task.hex(), model=model.hex(), input=input_hash.hex(),
        source='genesis-public-deterministic-maintenance-v1', purpose='ledger-continuity-maintenance',
        useful_output_credit=0, hardness_accepted=False, useful_model_work_accepted=False)
    return {'params': params, 'record': record, 'context': dict(network=network.hex(), parameters=parameters.hex(),
        policy=policy_hash.hex(), task=task.hex(), model=model.hex(), input=input_hash.hex(), registry=registry.hex(),
        growth=growth.hex(), evaluation=evaluation.hex())}

class Refusal(Exception):
    def __init__(self, code):
        self.code = code

def number(value, name):
    item = value.get(name) if isinstance(value, dict) else None
    if type(item) is not int or not 0 <= item <= MAX:
        raise Refusal(92)
    return item

def root_grammar(rows):
    def visit(value):
        if type(value) is float:
            return 85
        if isinstance(value, str):
            return 0 if value.isascii() else 86
        if isinstance(value, list):
            for item in value:
                code = visit(item)
                if code:
                    return code
        if isinstance(value, dict):
            for key, item in sorted(value.items()):
                if not key.isascii():
                    return 86
                code = visit(item)
                if code:
                    return code
        return 0
    for _, value in rows:
        code = visit(json.loads(value))
        if code:
            return code
    return 0

def relation(rows, height, variant):
    """Check only the finite-context relation, after complete canonical State."""
    state = {key.decode(): json.loads(value) for key, value in rows}
    wanted = configuration(variant)['record']
    # Here all expected fields have fixed integer, boolean or string types.
    # Canonical bytes distinguish integer zero from serde's floating zeros.
    if MAINTENANCE not in state or canonical(state[MAINTENANCE]) != canonical(wanted):
        return 91, None
    recipients, dues, archives = set(), set(), 0
    def reserve(value):
        owner = value.get('owner') if isinstance(value, dict) else None
        if not isinstance(owner, str) or len(owner.encode()) != 64 or any(ch not in '0123456789abcdef' for ch in owner):
            raise Refusal(92)
        key = 'account:' + owner
        if key not in state:
            recipients.add(key)
    try:
        for key, value in sorted(state.items()):
            if key.startswith('reward:'):
                due = number(value, 'maturity')
                if due <= height:
                    raise Refusal(93)
                if height > MAX - 20:
                    raise Refusal(94)
                if due > height + 20 or due in dues:
                    raise Refusal(93)
                dues.add(due)
                number(value, 'amount')
                reserve(value)
            elif key.startswith(('task:', 'quota:', 'release:')):
                if number(value, 'remaining') > 0:
                    reserve(value)
            elif variant & 1 and key.startswith('contribution:'):
                if 'evaluation-archive:' + key[len('contribution:'):] not in state:
                    archives += 1
        expected = min(height, 20)
        if len(dues) != expected:
            raise Refusal(93)
        for offset in range(expected):
            if height > MAX - 20:
                raise Refusal(94)
            if height + 20 - offset not in dues:
                raise Refusal(93)
        queue = 20 - expected
        accounts = sum(key.startswith('account:') for key in state)
        working = len(state) - accounts
        required = len(state) + len(recipients) + archives + queue
        if variant >= 2:
            if accounts + len(recipients) > 1000000 or working + archives + queue > 65536:
                raise Refusal(95)
        elif required > 65536:
            raise Refusal(95)
    except Refusal as error:
        return error.code, None
    return 0, dict(variant=variant, height=height, actual_keys=len(state), credit_account_reserve=len(recipients),
        archive_reserve=archives, reward_queue_reserve=queue, required_keys=required, accounts=accounts,
        working_keys=working, reward_heights=len(dues), maturity=20)
