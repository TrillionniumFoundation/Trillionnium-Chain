"""Independent small-state mandatory-transition oracle for revision12.

Fixtures are explicit application-state inputs, not histories of signed admission.
This computes expected bytes without importing or executing the native bridge.
"""
from __future__ import annotations
import copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from contract_wire import H, canonical, read_config, state_root, u64
from continuity_oracle import CAP, MAINTENANCE_KEY, MATURITY, capacity, context, maintenance_record

LEGACY = 'legacy-first-two-v3'
PUBLIC = 'native-public-evaluation-dev-v1'


def identity(number):
    return bytes([number]).hex() * 32


def funds(state):
    return sum(value['balance'] if key.startswith('account:') else
               value['remaining'] if key.startswith(('task:', 'quota:', 'release:')) else
               value['amount'] if key.startswith('reward:') else 0
               for key, value in state.items())


def check(state, height, policy):
    if state.get(MAINTENANCE_KEY) != maintenance_record(policy):
        raise ValueError('CONTINUITY_MAINTENANCE')
    result = capacity(state, height, policy == PUBLIC)
    if result['required_keys'] > CAP:
        raise ValueError('STATE_CAPACITY')
    return result


def close_candidate(state, key, height):
    """Independent missing-reveal/commit-record closure for these seeded cases."""
    value = state[key]
    evaluation = value['public_evaluation']
    if evaluation['closed'] is not None or height <= evaluation['plan']['reveal_end']:
        return
    cid = key.removeprefix('contribution:')
    maps = {name: {} for name in ('commits', 'reveals', 'conflicts', 'appeals')}
    kinds = dict(c='commits', r='reveals', f='conflicts', a='appeals')
    prefix = 'evaluation-record-v2:' + cid + ':'
    for name, row in state.items():
        if name.startswith(prefix):
            kind, identifier = name[len(prefix):].split(':', 1)
            maps[kinds[kind]][identifier] = row['value']
    if {name: len(rows) for name, rows in maps.items()} != evaluation['record_counts']:
        raise ValueError('PUBLIC_EVAL_RECORD_COUNT')
    missing = set(evaluation['plan']['roster']) - set(maps['reveals'])
    aborted = bool(missing or maps['conflicts'])
    score = None if aborted else min(row['score'] for row in maps['reveals'].values())
    snapshot = {name: maps[name] for name in ('commits', 'reveals', 'conflicts')}
    evaluation['closed'] = dict(schema='pon-native-closed-evaluation-v2', round=evaluation['round'],
        candidate=cid, status='aborted' if aborted else 'complete-scored', score=score,
        missing_reveal_count=len(missing), conflict_count_before_close=len(maps['conflicts']),
        records_digest=H('native-public-evaluation-closure-records-v2', canonical(snapshot)).hex(),
        closed_height=height, objective_model_quality=False, independent_governance_accepted=False)
    value['score'] = 0 if aborted else score
    value['status'] = 'evaluation-aborted' if aborted else 'evaluated'


def transition(parent, height, miner, parent_id, policy):
    """No transactions: exact cleanup, refund, maturity and subsidy semantics."""
    check(parent, height - 1, policy)
    params, _, _ = context(policy)
    state = copy.deepcopy(parent)
    original_keys = set(state)
    current = state['model:current']
    if policy == PUBLIC:
        for key in sorted(k for k in original_keys if k.startswith('contribution:')):
            close_candidate(state, key, height)
            value = state[key]
            if value['public_evaluation']['closed'] is not None:
                state['evaluation-archive:' + key.removeprefix('contribution:')] = copy.deepcopy(value)
    for key in sorted(original_keys):
        value = state[key]
        if key.startswith('contribution:'):
            if value['parent'] != current or value.get('submission_round', 0) != height // params['candidate_round_blocks']:
                del state[key]
            elif height > value.get('submitted_height', height) + params['candidate_lifetime_blocks'] and value['status'] in ('submitted', 'evaluated'):
                value.update(status='expired', votes={}, score=0)
        elif key.startswith('evaluation-archive:'):
            if height - value['public_evaluation']['closed']['closed_height'] > 256:
                del state[key]
        elif key.startswith(('task:', 'quota:')):
            if value['remaining'] == 0 and value['deadline'] < height:
                del state[key]
        elif key.startswith('artifact:'):
            parts = key.split(':')
            if len(parts) != 4 or parts[1] != current or parts[2] != str(height // params['candidate_round_blocks']):
                del state[key]
    if policy == PUBLIC:
        for key in list(state):
            if key.startswith('evaluation-record-v2:'):
                candidate = key.split(':', 2)[1]
                if 'contribution:' + candidate not in state and 'evaluation-archive:' + candidate not in state:
                    del state[key]
    for key in list(state):
        if key.startswith('release:') and key[8:] != current and state[key]['remaining'] == 0:
            del state[key]

    def credit(owner, amount):
        account = state.setdefault('account:' + owner, dict(balance=0, nonce=0))
        account['balance'] += amount

    due = sorted((value['deadline'], key) for key, value in state.items()
                 if key.startswith(('task:', 'quota:', 'release:'))
                 and value['remaining'] > 0 and value['deadline'] <= height)
    receipts = []
    for _, key in due[:params['mandatory_expiry_per_block']]:
        record = state[key]
        credit(record['owner'], record['remaining'])
        record.update(remaining=0, status='expired')
        receipts.append(canonical(dict(expiry=key)))
    for key, record in list(state.items()):
        if key.startswith('reward:') and record['maturity'] <= height:
            del state[key]
            credit(record['owner'], record['amount'])
    subsidy = params['block_subsidy_units'] >> min(height // params['subsidy_halving_interval'], 64)
    key = 'reward:' + H('reward', bytes.fromhex(parent_id), u64(height), bytes.fromhex(miner)).hex()
    state[key] = dict(owner=miner, amount=subsidy, maturity=height + MATURITY)
    state['meta:issued'] += subsidy
    if funds(state) != state['meta:issued']:
        raise ValueError('CONSERVATION')
    cap = check(state, height, policy)
    return dict(height=height, status='accepted', state=state, root=state_root(state).hex(),
                receipts=[raw.hex() for raw in receipts], capacity=cap)


def base(height, policy=LEGACY):
    state = {MAINTENANCE_KEY: maintenance_record(policy), 'meta:issued': 1_000_000,
             'model:current': identity(0), 'account:' + identity(1): dict(balance=1_000_000, nonce=17)}
    for due in range(height + 1, height + MATURITY + 1):
        state['reward:' + H('continuity-oracle-queue', u64(due)).hex()] = dict(owner=identity(1), amount=0, maturity=due)
    return state


def case(name, state, height, steps, policy=LEGACY):
    return dict(name=name, evaluation_policy=policy, state=state, first_height=height,
                steps=steps, miner=identity(1), parent=identity(7))


def fixtures():
    state = base(20)
    for index in range(20):
        prefix = ('task', 'quota', 'release')[index % 3]
        owner = identity((1, 2, 3)[index % 3])
        state[f'{prefix}:{index:064x}'] = dict(owner=owner, remaining=11, budget=11, deadline=21, status='open')
    for reward in state.values():
        if isinstance(reward, dict) and reward.get('maturity') in (21, 22):
            reward['owner'] = identity(2 if reward['maturity'] == 21 else 4)
    state['meta:issued'] = funds(state)
    result = [case('funded-16-plus-4-shared-owners-and-zero-reward', state, 21, 3)]

    state = base(20)
    for prefix, number, remaining, deadline in [('quota', 30, 0, 20), ('task', 31, 0, 21),
                                               ('quota', 32, 9, 20), ('release', 33, 0, 999)]:
        state[f'{prefix}:{number:064x}'] = dict(owner=identity(2), remaining=remaining, deadline=deadline, status='open')
    state['release:' + identity(0)] = dict(owner=identity(1), remaining=0, deadline=999, status='open')
    state['meta:issued'] = funds(state)
    result.append(case('cleanup-precedes-refund-and-strict-deadline', state, 21, 3))

    policy = PUBLIC
    state = base(46, policy)
    params, network, parameters = context(policy)
    family = H('family', canonical(read_config('config/pon/model-family-v1.json'))).hex()
    roster = sorted(Ed25519PrivateKey.from_private_bytes(H('DEV-ONLY-KEY', u64(i))).public_key()
                    .public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for i in range(3))
    owner, roster = roster[0], roster[1:]
    cid = H('contribution-v3', bytes.fromhex(owner), bytes.fromhex(family), bytes(32),
            bytes([8])*32, bytes([9])*32, u64(0)).hex()
    plan = dict(schema='pon-native-frozen-evaluation-v1', network=network.hex(), parameters=parameters.hex(),
        candidate=cid, artifact=identity(8), components_root=identity(9), parent=identity(0), family=family,
        model_and_task_contract=H('plan', b'public-source-file-disjoint-v1', bytes.fromhex(params['evaluation_policy_hash'])).hex(),
        roster=roster, start=0, candidate_end=15, commit_end=31, reveal_end=47, adoption_start=56,
        max_score=params['max_evidence_score'], independent_governance_accepted=False, objective_model_quality=False)
    evaluation = dict(storage_revision=2, plan=plan, round=H('native-public-evaluation-round-v1', canonical(plan)).hex(),
                      record_counts=dict(commits=1, reveals=0, conflicts=0, appeals=0), closed=None)
    candidate = 'contribution:' + cid
    artifact = 'artifact:' + identity(0) + ':0:' + identity(8)
    record = 'evaluation-record-v2:' + cid + ':c:' + roster[0]
    state[candidate] = dict(owner=owner, artifact=identity(8), components_root=identity(9), family=family,
        parent=identity(0), votes={}, score=0, status='submitted', submitted_height=1, submission_round=0,
        public_evaluation=evaluation)
    state[artifact] = cid
    state[record] = dict(schema='pon-native-evaluation-record-v2', candidate=cid, kind='c', id=roster[0], value=identity(8))
    result.append(case('public-closure-at-reveal-end-plus-one', state, 47, 2, policy))
    closed = transition(transition(state, 47, identity(1), identity(7), policy)['state'],
                        48, identity(1), identity(7), policy)['state']
    retained = base(303, policy)
    retained['evaluation-archive:' + cid] = copy.deepcopy(closed['evaluation-archive:' + cid])
    retained[record] = copy.deepcopy(closed[record])
    result.append(case('archive-256-retained-257-removed-with-records', retained, 304, 2, policy))
    old_round = base(127, policy)
    old_round.update({key: copy.deepcopy(closed[key]) for key in (candidate, artifact, record, 'evaluation-archive:' + cid)})
    result.append(case('old-round-candidate-artifact-remove-archive-record-retain', old_round, 128, 1, policy))
    broken = base(20)
    del broken[next(key for key in broken if key.startswith('reward:'))]
    result.append(case('missing-maturity-rejected-before-transition', broken, 21, 1))
    return result


def expected(case):
    params, network, parameters = context(case['evaluation_policy'])
    state = copy.deepcopy(case['state'])
    rows = []
    for height in range(case['first_height'], case['first_height'] + case['steps']):
        try:
            row = transition(state, height, case['miner'], case['parent'], case['evaluation_policy'])
        except ValueError as error:
            rows.append(dict(height=height, status='rejected', error=str(error), unchanged_parent=state))
            break
        rows.append(row)
        state = row['state']
    return dict(name=case['name'], network=network.hex(), parameters=parameters.hex(), params=params, rows=rows)
