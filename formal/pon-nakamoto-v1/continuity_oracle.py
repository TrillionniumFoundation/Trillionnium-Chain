"""Independent revision12 state-key potential and deterministic maintenance oracle.

Only the fresh explicit profile uses these rules. This is not a substitute native
executor, source signature, useful-work classification or full-chain proof.
"""
from __future__ import annotations
import copy
from contract_wire import H, canonical, read_config, development_parameters, state_root, u64
from work_oracle import task_id

PROFILE = 'consensus-maintenance-continuity-dev-v1'
MAINTENANCE_KEY = 'consensus-maintenance-v1'
CAP = 65536
MATURITY = 20

def context():
    params = development_parameters()
    rule = read_config('config/pon/continuity-v1.json')
    assert rule['id'] == PROFILE and rule['consensus_revision'] == 12
    params.update(consensus_revision=12, work_task_profile=PROFILE,
                  chain_label='trnm-pon-continuity-devnet-12-legacy-first-two-v3',
                  continuity_policy_hash=H('consensus-maintenance-continuity-policy-v1', canonical(rule)).hex())
    params['qualified_task_registry_hash'] = H('qualified-task-registry-v4',
        canonical(read_config('config/pon/qualified-task-lifecycle-v4.json'))).hex()
    network = H('network', params['chain_label'].encode())
    parameters = H('parameters', canonical(params), canonical(read_config('config/pon/ledger-v1.json')),
                   canonical(read_config('config/pon/work-profile-v1.json')),
                   canonical(read_config('config/pon/model-family-v1.json')))
    return params, network, parameters

def maintenance_record():
    params, network, parameters = context()
    a = [(13*i+17)%257 for i in range(4096)]
    b = [(29*i+31)%263 for i in range(4096)]
    model = b''.join(i.to_bytes(4,'little') for i in a)
    inputs = b''.join(i.to_bytes(4,'little') for i in b)
    return dict(schema='genesis-consensus-maintenance-v1', network=network.hex(), parameters=parameters.hex(),
                policy=params['continuity_policy_hash'], matrix_task=task_id(a,b).hex(),
                model=H('artifact',model).hex(), input=H('qualified-task-input-v1',inputs).hex(),
                source='genesis-public-deterministic-maintenance-v1', purpose='ledger-continuity-maintenance',
                useful_output_credit=0, hardness_accepted=False, useful_model_work_accepted=False)

def capacity(state, height, public_evaluation=False):
    recipients = set()
    rewards = []
    archives = 0
    for key,value in state.items():
        if key.startswith('reward:'):
            rewards.append(value['maturity'])
            recipients.add('account:'+value['owner'])
        elif key.startswith(('task:','quota:','release:')) and value['remaining'] > 0:
            recipients.add('account:'+value['owner'])
        elif public_evaluation and key.startswith('contribution:'):
            archives += 'evaluation-archive:'+key[len('contribution:'):] not in state
    expected = list(range(max(height,MATURITY)+1, height+MATURITY+1))
    if sorted(rewards) != expected:
        raise ValueError('CONTINUITY_REWARD_QUEUE')
    credits = len(recipients-set(state))
    queue = MATURITY-len(expected)
    return dict(actual_keys=len(state), credit_reserve=credits, archive_reserve=archives,
                queue_reserve=queue, required_keys=len(state)+credits+archives+queue)

def check(state, height, public_evaluation=False):
    if state.get(MAINTENANCE_KEY) != maintenance_record():
        raise ValueError('CONTINUITY_MAINTENANCE')
    value = capacity(state,height,public_evaluation)
    if value['required_keys'] > CAP:
        raise ValueError('STATE_CAPACITY')
    return value

def empty(parent, height, miner):
    check(parent,height-1)
    state = copy.deepcopy(parent)
    for name,record in list(state.items()):
        if name.startswith('reward:') and record['maturity'] <= height:
            del state[name]
            account = state.setdefault('account:'+record['owner'],dict(balance=0,nonce=0))
            account['balance'] += record['amount']
    subsidy = 1000 >> min(height//100000,64)
    key = 'reward:'+H('reward',bytes([7])*32,u64(height),bytes.fromhex(miner)).hex()
    state[key] = dict(owner=miner,amount=subsidy,maturity=height+MATURITY)
    state['meta:issued'] += subsidy
    funds = sum(v['balance'] if k.startswith('account:') else v['amount'] if k.startswith('reward:') else 0
                for k,v in state.items())
    assert funds == state['meta:issued']
    check(state,height)
    return state
