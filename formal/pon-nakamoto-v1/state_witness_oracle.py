"""Independent full-state witness relation for an explicit research companion.

The account update algorithm combines authenticated sibling boundaries bottom-up;
it does not call Rust, reopen its database, or copy its compressed-tree insertion.
The companion fixture is checked against independently replayed signed application
states. Complete non-account disclosure and an authenticated full-parent anchor
remain required. This is not a partial-State backend or work/availability proof.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback

import account_archive_oracle as archive
import account_execution_oracle as application


COMMITMENT_SCHEMA = 'pon-authenticated-state-commitment-v1'
EXECUTION_SCHEMA = 'pon-authenticated-state-execution-v1'
COMMITMENT_HASHES = ('network', 'parameters', 'genesis', 'state_root', 'account_root',
                    'non_account_root')
COMMITMENT_NUMBERS = ('account_count', 'account_balance', 'non_account_count',
                      'escrow_balance', 'reward_balance', 'issued')
NATIVE_SCHEMA = 'pon-state-witness-native-observation-v1'
SCHEMA = 'pon-state-witness-oracle-observation-v1'
NATIVE_SCOPE = {
    'complete_state_required': True,
    'complete_non_account_disclosure': True,
    'account_root_updates_from_original_proofs': True,
    'research_only': True,
    'consensus_admission_by_research_wrapper': False,
    'production_backend_changed': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}
SCOPE = {
    'independent_genesis_and_signed_application_replay': True,
    'complete_state_partition_roots_and_aggregates': True,
    'mandatory_and_final_changes_independently_derived': True,
    'post_account_root_derived_from_original_parent_proofs': True,
    'complete_non_account_disclosure_required': True,
    'native_consensus_admission_reexecuted': False,
    'sqlite_database_opened': False,
    'work_relation_reverified': False,
    'fork_choice_reverified': False,
    'storage_recovery_reexecuted': False,
    'partial_state_backend_accepted': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}
NEGATIVE_LABELS = (
    'witness-parent-checkpoint', 'witness-parent-id', 'witness-parent-height',
    'commitment-id', 'commitment-account-count', 'commitment-account-balance',
    'commitment-issued', 'commitment-context', 'missing-future-reward',
    'missing-future-task', 'missing-cleanup-task', 'missing-maintenance',
    'changed-non-account-value', 'duplicate-non-account', 'reordered-non-accounts',
    'injected-account-row', 'extra-non-account', 'cancel-before-mandatory',
    'cancel-after-mandatory', 'cancel-before-successor', 'cancel-after-successor',
    'cancel-before-output',
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def uint(value):
    require(type(value) is int and 0 <= value <= archive.U64_MAX, 'STATE_WITNESS_INTEGER')
    return value


def account_delta_updates(expected_checkpoint, expected_root, parent_count, parent_balance,
                          witnesses, changes):
    """Derive post root/count/balance using only checked original-parent proofs.

    The count and balance inputs require a separately authenticated full-parent
    commitment. Membership paths alone never establish those global aggregates.
    Canonical changes are strictly owner-ordered, nonempty differences, with no
    deletion or nonce rollback. Unchanged semantic reads may still have proofs.
    """
    archive.owner_bytes(expected_checkpoint)
    archive.owner_bytes(expected_root)
    uint(parent_count)
    uint(parent_balance)
    require(type(witnesses) is list and len(witnesses) <= archive.MAX_VIEW_ACCOUNTS,
            'STATE_WITNESS_BUDGET')
    require(type(changes) is list, 'STATE_WITNESS_CHANGES')
    proofs, proof_paths = {}, set()
    for witness in witnesses:
        checkpoint, owner, value, siblings = archive.witness_fields(witness)
        require(owner not in proofs, 'STATE_WITNESS_DUPLICATE_PROOF')
        path = archive.key_path(owner)
        require(path not in proof_paths, 'STATE_WITNESS_PATH_COLLISION')
        proof_paths.add(path)
        archive.verify_witness(witness, expected_checkpoint, expected_root, owner)
        proofs[owner] = (value, siblings)

    original, changed = {}, {}
    removed_balance = added_balance = created_count = 0
    previous = None

    def original_node(depth, position, value):
        key = (depth, position)
        require(key not in original or original[key] == value,
                'STATE_WITNESS_BOUNDARY_CONFLICT')
        original[key] = value

    for change in changes:
        require(type(change) is dict and set(change) == {'owner', 'before', 'after'},
                'STATE_WITNESS_CHANGE_FIELDS')
        owner = archive.hash_bytes(change['owner'])
        require(previous is None or previous < owner, 'STATE_WITNESS_CHANGE_ORDER')
        previous = owner
        require(owner in proofs, 'STATE_WITNESS_MISSING_CHANGE_PROOF')
        before, siblings = proofs[owner]
        expected_before = None if before is None else before.as_json()
        require(archive.canonical(change['before']) == archive.canonical(expected_before),
                'STATE_WITNESS_CHANGE_BEFORE')
        require(change['after'] is not None, 'STATE_WITNESS_ACCOUNT_DELETION')
        after = archive.account(change['after'])
        require(before != after, 'STATE_WITNESS_UNCHANGED_DELTA')
        require(before is None or after.nonce >= before.nonce, 'STATE_WITNESS_NONCE_ROLLBACK')
        removed_balance = uint(removed_balance + (0 if before is None else before.balance))
        added_balance = uint(added_balance + after.balance)
        created_count += int(before is None)
        path = int.from_bytes(archive.key_path(owner), 'big')
        require(path not in changed, 'STATE_WITNESS_PATH_COLLISION')
        changed[path] = archive.leaf(owner, after)
        position = path
        current = archive.EMPTY[archive.TREE_BITS] if before is None else archive.leaf(owner, before)
        for depth in range(archive.TREE_BITS, 0, -1):
            original_node(depth, position, current)
            original_node(depth, position ^ 1, siblings[depth - 1])
            pair = ((siblings[depth - 1], current) if position & 1
                    else (current, siblings[depth - 1]))
            current = archive.digest(archive.BRANCH_DOMAIN, *pair)
            position //= 2
        original_node(0, 0, current)

    require(removed_balance <= parent_balance, 'STATE_WITNESS_BALANCE_UNDERFLOW')
    require(sum(value is not None for value, _ in proofs.values()) <= parent_count,
            'STATE_WITNESS_COUNT_UNDERFLOW')
    count = uint(parent_count + created_count)
    balance = uint(parent_balance - removed_balance + added_balance)
    if not changed:
        return dict(root=expected_root, count=count, balance=balance)
    for depth in range(archive.TREE_BITS, 0, -1):
        parents = {position // 2 for position in changed}
        next_level = {}
        for parent in parents:
            children = []
            for position in (parent * 2, parent * 2 + 1):
                if position in changed:
                    children.append(changed[position])
                else:
                    require((depth, position) in original, 'STATE_WITNESS_INCOMPLETE_BOUNDARY')
                    children.append(original[(depth, position)])
            next_level[parent] = archive.digest(archive.BRANCH_DOMAIN, *children)
        changed = next_level
    require(set(changed) == {0}, 'STATE_WITNESS_ROOT_POSITION')
    return dict(root=changed[0], count=count, balance=balance)


def account_changes(parent, successor):
    """Full reference derivation; native reported changes are comparison-only."""
    before, after = archive.accounts_from_state(parent), archive.accounts_from_state(successor)
    require(set(before) <= set(after), 'STATE_WITNESS_ACCOUNT_DELETION')
    return [dict(owner=list(owner),
                 before=None if owner not in before else before[owner].as_json(),
                 after=after[owner].as_json())
            for owner in sorted(after) if before.get(owner) != after[owner]]


def ordered_deltas(parent, successor):
    """Derive the complete key-sorted net delta from two independently held states."""
    require(type(parent) is dict and type(successor) is dict, 'STATE_WITNESS_STATE')
    return [dict(key=key, before=None if key not in parent else dict(value=copy.deepcopy(parent[key])),
                 after=None if key not in successor else dict(value=copy.deepcopy(successor[key])))
            for key in sorted(set(parent) | set(successor))
            if (key in parent) != (key in successor)
            or archive.canonical(parent.get(key)) != archive.canonical(successor.get(key))]


def non_accounts(state):
    require(type(state) is dict and all(type(key) is str for key in state), 'STATE_WITNESS_STATE')
    return {key: copy.deepcopy(value) for key, value in sorted(state.items())
            if not key.startswith('account:')}


def state_root(state):
    """Existing consensus tree with UTF-8 top-level keys and canonical ASCII values.

    The old fixture oracle deliberately keeps its ASCII-key scope. This fresh
    primitive follows M06's actual key-byte boundary without changing that API.
    """
    require(type(state) is dict and len(state) <= 65536, 'STATE_WITNESS_STATE_LIMIT')
    nodes = {}
    for key, value in state.items():
        require(type(key) is str, 'STATE_WITNESS_STATE_KEY')
        encoded = key.encode('utf-8')
        body = archive.canonical(value)
        require(len(encoded) <= 160 and len(body) <= 4096, 'STATE_WITNESS_STATE_LIMIT')
        position = int.from_bytes(archive.digest(b'state-key', encoded), 'big')
        require(position not in nodes, 'STATE_WITNESS_KEY_COLLISION')
        nodes[position] = archive.digest(b'state-leaf', encoded, body)
    empty = archive.digest(b'state-empty')
    for _ in range(256):
        parents = {position // 2 for position in nodes}
        nodes = {parent: archive.digest(b'state-node', nodes.get(2 * parent, empty),
                                         nodes.get(2 * parent + 1, empty)) for parent in parents}
        empty = archive.digest(b'state-node', empty, empty)
    return nodes.get(0, empty)


def non_account_row_bytes(rows):
    """Exact compact Vec<StateRow> JSON, including UTF-8 key bytes."""
    require(type(rows) is list, 'STATE_WITNESS_NON_ACCOUNT_ROWS')
    for row in rows:
        require(type(row) is dict and set(row) == {'key', 'value'} and type(row['key']) is str,
                'STATE_WITNESS_NON_ACCOUNT_ROW')
        row['key'].encode('utf-8')
        archive.canonical(row['value'])
    return json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def commitment_identity(value):
    """The fresh research digest; it does not replace the existing consensus root."""
    require(type(value) is dict and set(value) == set(COMMITMENT_HASHES + COMMITMENT_NUMBERS)
            | {'schema', 'id'} and value['schema'] == COMMITMENT_SCHEMA,
            'STATE_WITNESS_COMMITMENT_FIELDS')
    for name in COMMITMENT_NUMBERS:
        uint(value[name])
    hashes = {name: archive.hash_bytes(value[name]) for name in COMMITMENT_HASHES}
    archive.hash_bytes(value['id'])
    parts = [hashes[name] for name in ('network', 'parameters', 'genesis', 'state_root', 'account_root')]
    parts += [value[name].to_bytes(8, 'little') for name in ('account_count', 'account_balance')]
    parts += [hashes['non_account_root']]
    parts += [value[name].to_bytes(8, 'little') for name in
              ('non_account_count', 'escrow_balance', 'reward_balance', 'issued')]
    return archive.digest(b'checked-state-commitment-v1', *parts)


def derive_commitment(state, context):
    """Recompute every aggregate and both partitions from the complete reference State."""
    accounts = archive.accounts_from_state(state)
    other = non_accounts(state)
    account_balance = uint(sum(value.balance for value in accounts.values()))
    escrow_balance = uint(sum(uint(value['remaining']) for key, value in other.items()
                              if key.startswith(('task:', 'quota:', 'release:'))))
    reward_balance = uint(sum(uint(value['amount']) for key, value in other.items()
                              if key.startswith('reward:')))
    issued = uint(other.get('meta:issued'))
    require(uint(account_balance + escrow_balance + reward_balance) == issued,
            'STATE_WITNESS_CONSERVATION')
    value = dict(schema=COMMITMENT_SCHEMA, network=list(context.network),
        parameters=list(context.parameters), genesis=list(context.genesis),
        state_root=list(state_root(state)),
        account_root=list(archive.full_sparse(accounts)[0]), account_count=len(accounts),
        account_balance=account_balance, non_account_root=list(state_root(other)),
        non_account_count=len(other), escrow_balance=escrow_balance,
        reward_balance=reward_balance, issued=issued, id=list(bytes(32)))
    value['id'] = list(commitment_identity(value))
    return value


def verify_complete_partition(witness, expected, checkpoint, parent, height):
    """Authenticate the entire submitted non-account set, not just today's due keys.

    `expected` is derived from the independently known complete parent. Accepting a
    self-consistent untrusted digest in its place would not authenticate aggregates.
    """
    require(type(witness) is dict and set(witness) == {
        'parent_checkpoint', 'parent_id', 'parent_height', 'commitment', 'non_accounts'},
        'STATE_WITNESS_FIELDS')
    require(archive.hash_bytes(witness['parent_checkpoint']) == checkpoint,
            'STATE_WITNESS_PARENT_CHECKPOINT')
    require(archive.hash_bytes(witness['parent_id']) == parent, 'STATE_WITNESS_PARENT_ID')
    require(uint(witness['parent_height']) == uint(height), 'STATE_WITNESS_PARENT_HEIGHT')
    identity = commitment_identity(witness['commitment'])
    require(archive.hash_bytes(witness['commitment']['id']) == identity,
            'STATE_WITNESS_COMMITMENT_ID')
    require(archive.canonical(witness['commitment']) == archive.canonical(expected),
            'STATE_WITNESS_PARENT_COMMITMENT')
    rows = witness['non_accounts']
    require(type(rows) is list, 'STATE_WITNESS_NON_ACCOUNT_ROWS')
    values, previous = {}, None
    for row in rows:
        require(type(row) is dict and set(row) == {'key', 'value'}, 'STATE_WITNESS_NON_ACCOUNT_ROW')
        key = row['key']
        require(type(key) is str and not key.startswith('account:'),
                'STATE_WITNESS_NON_ACCOUNT_KEY')
        require(previous is None or previous < key, 'STATE_WITNESS_NON_ACCOUNT_ORDER')
        previous = key
        values[key] = copy.deepcopy(row['value'])
    require(len(values) == expected['non_account_count'], 'STATE_WITNESS_NON_ACCOUNT_COUNT')
    require(state_root(values) == archive.hash_bytes(expected['non_account_root']),
            'STATE_WITNESS_NON_ACCOUNT_ROOT')
    return values


def derive_state_witness(state, context, checkpoint, parent, height):
    return dict(parent_checkpoint=list(checkpoint), parent_id=list(parent), parent_height=uint(height),
        commitment=derive_commitment(state, context),
        non_accounts=[dict(key=key, value=value) for key, value in non_accounts(state).items()])


def derive_transition(parent, successor, receipts, context, checkpoint, witnesses):
    """Both prologue and final transitions use original-parent proofs and aggregates."""
    before = derive_commitment(parent, context)
    after = derive_commitment(successor, context)
    changes = account_changes(parent, successor)
    updated = account_delta_updates(checkpoint, archive.hash_bytes(before['account_root']),
        before['account_count'], before['account_balance'], witnesses, changes)
    require(updated == dict(root=archive.hash_bytes(after['account_root']),
                           count=after['account_count'], balance=after['account_balance']),
            'STATE_WITNESS_FULL_REFERENCE_DISAGREEMENT')
    return dict(commitment=after, account_changes=changes,
        non_account_changes=ordered_deltas(non_accounts(parent), non_accounts(successor)),
        receipts=[list(item) for item in receipts])


def expected_execution(context, parent, successor, block, witness):
    checkpoint = archive.hash_bytes(block['parent_checkpoint']['id'])
    parent_id = archive.hash_bytes(block['parent'])
    parent_commitment = derive_commitment(parent, context)
    verified = verify_complete_partition(witness, parent_commitment, checkpoint,
                                          parent_id, block['height'] - 1)
    application.equal(verified, non_accounts(parent), 'STATE_WITNESS_REFERENCE_PARTITION')
    # This independently implemented prologue rejects unsupported fixture state
    # namespaces instead of assuming that their omitted cleanup is correct.
    application.validate_state(parent, context)
    mandatory, mandatory_receipts = application.mandatory(parent, block['height'], context,
                                                          application.AccountAccess(parent))
    receipts = [application.hex_bytes(raw) for raw in block['native_output']['receipts_hex']]
    # The supplied receipt bytes have already been compared with independent
    # complete signed replay by check_positive_observation before this function.
    return dict(schema=EXECUTION_SCHEMA, parent_checkpoint=list(checkpoint),
        parent_id=list(parent_id), height=block['height'], miner=block['miner'],
        parent=parent_commitment,
        mandatory=derive_transition(parent, mandatory, mandatory_receipts, context,
                                    checkpoint, block['witnesses']),
        successor=derive_transition(parent, successor, receipts, context,
                                    checkpoint, block['witnesses']),
        non_account_witness_count=len(verified),
        non_account_witness_bytes=len(non_account_row_bytes(witness['non_accounts'])),
        complete_non_account_partition=True, account_roots_from_merged_proofs=True,
        full_state_reference_checked=True, complete_state_required=True,
        consensus_admission=False, archive_mutated=False)


def check_positive_companion(native, companion, native_digest):
    """Reconstruct the entire fixture before comparing companion claimed outputs."""
    require(type(companion) is dict and set(companion) == {
        'schema', 'result', 'source_native_schema', 'native_json_sha256', 'context',
        'blocks', 'negative_cases', 'scope'}, 'STATE_WITNESS_NATIVE_FIELDS')
    require(companion['schema'] == NATIVE_SCHEMA and companion['result'] == 'PASS'
            and companion['source_native_schema'] == application.NATIVE_SCHEMA,
            'STATE_WITNESS_NATIVE_SCHEMA')
    require(companion['native_json_sha256'] == native_digest, 'STATE_WITNESS_NATIVE_SOURCE')
    application.strict_scope(companion['scope'], NATIVE_SCOPE, 'STATE_WITNESS_NATIVE_SCOPE')
    reference, context, states, checkpoints, labels = application.check_positive_observation(native)
    old_negatives = application.check_negative_observations(native, context, states, checkpoints, labels)
    application.equal(companion['context'], context.as_json(), 'STATE_WITNESS_NATIVE_CONTEXT')
    rows = companion['blocks']
    require(type(rows) is list and len(rows) == len(native['blocks'])
            and all(type(row) is dict for row in rows), 'STATE_WITNESS_NATIVE_BLOCKS')
    require([row.get('label') for row in rows] == [row['label'] for row in native['blocks']],
            'STATE_WITNESS_NATIVE_BLOCK_ORDER')
    observations = []
    for row, block in zip(rows, native['blocks']):
        require(set(row) == {'label', 'id', 'state_witness', 'observation',
                             'parent_unchanged', 'archive_unchanged',
                             'checked_execution_matches_native_output'},
                'STATE_WITNESS_NATIVE_BLOCK_FIELDS')
        identity = archive.hash_bytes(block['id'])
        require(archive.hash_bytes(row['id']) == identity, 'STATE_WITNESS_NATIVE_BLOCK_ID')
        parent = states[archive.hash_bytes(block['parent'])]
        output = states[identity]
        expected = expected_execution(context, parent, output, block, row['state_witness'])
        application.equal(row['observation'], expected, 'STATE_WITNESS_NATIVE_EXECUTION')
        require(row['parent_unchanged'] is True and row['archive_unchanged'] is True
                and row['checked_execution_matches_native_output'] is True,
                'STATE_WITNESS_NATIVE_MUTATION')
        observations.append(dict(label=row['label'], id=identity.hex(),
            parent_commitment=archive.hash_bytes(expected['parent']['id']).hex(),
            mandatory_commitment=archive.hash_bytes(expected['mandatory']['commitment']['id']).hex(),
            successor_commitment=archive.hash_bytes(expected['successor']['commitment']['id']).hex(),
            mandatory_account_changes=len(expected['mandatory']['account_changes']),
            mandatory_non_account_changes=len(expected['mandatory']['non_account_changes']),
            successor_account_changes=len(expected['successor']['account_changes']),
            successor_non_account_changes=len(expected['successor']['non_account_changes']),
            non_account_witness_count=expected['non_account_witness_count'],
            non_account_witness_bytes=expected['non_account_witness_bytes'],
            successor_account_count=expected['successor']['commitment']['account_count'],
            successor_account_balance=expected['successor']['commitment']['account_balance'],
            successor_issued=expected['successor']['commitment']['issued']))
    return (dict(schema=SCHEMA, native_schema=NATIVE_SCHEMA, result='PASS',
        native_json_sha256=native_digest, genesis_checked=True,
        blocks_checked=len(observations), state_transitions_checked=2 * len(observations),
        signed_transaction_envelopes_checked=reference['transaction_envelopes_checked'],
        source_application_negative_observations_checked=len(old_negatives),
        complete_non_account_partitions_checked=len(observations),
        block_observations=observations, scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE)),
        context, states, checkpoints, labels)


def negative_inputs(native, context, states, checkpoints):
    """Recreate mutations from independently reconstructed parents, never claims."""
    positives = {block['label']: block for block in native['blocks']}

    def base(label, source='main-01'):
        block = positives[source]
        parent = archive.hash_bytes(block['parent'])
        checkpoint = archive.hash_bytes(checkpoints[parent]['id'])
        return dict(label=label, source_positive_label=source,
            state_witness=derive_state_witness(states[parent], context, checkpoint,
                                               parent, block['height'] - 1), cancel_at=None)

    cases = []
    for field, label in [('parent_checkpoint', 'witness-parent-checkpoint'),
                         ('parent_id', 'witness-parent-id'), ('parent_height', 'witness-parent-height')]:
        case = base(label)
        if field == 'parent_height':
            case['state_witness'][field] += 1
        else:
            case['state_witness'][field][0] ^= 1
        cases.append(case)
    case = base('commitment-id')
    case['state_witness']['commitment']['id'][0] ^= 1
    cases.append(case)
    for field, label in [('account_count', 'commitment-account-count'),
                         ('account_balance', 'commitment-account-balance'), ('issued', 'commitment-issued'),
                         ('parameters', 'commitment-context')]:
        case = base(label)
        commitment = case['state_witness']['commitment']
        if field == 'parameters':
            commitment[field][0] ^= 1
        else:
            commitment[field] += 1
        commitment['id'] = list(commitment_identity(commitment))
        cases.append(case)
    for source, label, prefix, zero in [
        ('main-02', 'missing-future-reward', 'reward:', None),
        ('main-02', 'missing-future-task', 'task:', False),
        ('main-13', 'missing-cleanup-task', 'task:', True),
        ('main-01', 'missing-maintenance', 'consensus-maintenance-v1', None),
    ]:
        case = base(label, source)
        rows = case['state_witness']['non_accounts']
        position = next(index for index, row in enumerate(rows) if row['key'].startswith(prefix)
                        and (zero is None or (row['value']['remaining'] == 0) is zero))
        removed = rows.pop(position)
        if label == 'missing-future-reward':
            require(removed['value']['maturity'] > 2, 'STATE_WITNESS_NEGATIVE_FIXTURE')
        if label == 'missing-future-task':
            require(removed['value']['deadline'] > 2, 'STATE_WITNESS_NEGATIVE_FIXTURE')
        if label == 'missing-cleanup-task':
            require(removed['value']['deadline'] < 13, 'STATE_WITNESS_NEGATIVE_FIXTURE')
        cases.append(case)
    case = base('changed-non-account-value')
    next(row for row in case['state_witness']['non_accounts'] if row['key'] == 'meta:issued')['value'] += 1
    cases.append(case)
    case = base('duplicate-non-account')
    case['state_witness']['non_accounts'].append(copy.deepcopy(case['state_witness']['non_accounts'][-1]))
    cases.append(case)
    case = base('reordered-non-accounts')
    rows = case['state_witness']['non_accounts']
    rows[0], rows[1] = rows[1], rows[0]
    cases.append(case)
    case = base('injected-account-row')
    owner_key = 'account:' + application.development_public(0).hex()
    case['state_witness']['non_accounts'].insert(0,
        dict(key=owner_key, value=copy.deepcopy(context.genesis_state[owner_key])))
    cases.append(case)
    case = base('extra-non-account')
    case['state_witness']['non_accounts'].append(dict(key='unrecognized-retained-key', value=None))
    cases.append(case)
    for label, point in [('cancel-before-mandatory', 'BeforeMandatoryVerification'),
                         ('cancel-after-mandatory', 'AfterMandatoryVerification'),
                         ('cancel-before-successor', 'BeforeSuccessorVerification'),
                         ('cancel-after-successor', 'AfterSuccessorVerification'),
                         ('cancel-before-output', 'BeforeOutput')]:
        case = base(label)
        case['cancel_at'] = point
        cases.append(case)
    require(tuple(case['label'] for case in cases) == NEGATIVE_LABELS, 'STATE_WITNESS_NEGATIVE_FIXTURE')
    return cases


def negative_outcome(case, expected):
    """Independent bound-input refusal, including complete set and exact claims."""
    witness = case['state_witness']
    outcome = lambda code: dict(kind='state_witness', code=code)
    if any(archive.canonical(witness[name]) != archive.canonical(expected[name]) for name in
           ('parent_checkpoint', 'parent_id', 'parent_height')):
        return outcome('Context')
    rows = witness['non_accounts']
    if len(rows) > 65536:
        return dict(kind='checked', code='Budget')
    previous = None
    for row in rows:
        if row['key'].startswith('account:'):
            return outcome('AccountRow')
        if previous is not None and previous >= row['key']:
            return outcome('CanonicalOrder')
        previous = row['key']
    if archive.canonical(rows) != archive.canonical(expected['non_accounts']):
        return outcome('Partition')
    if archive.canonical(witness['commitment']) != archive.canonical(expected['commitment']):
        return outcome('Commitment')
    require(case['cancel_at'] is not None, 'STATE_WITNESS_NEGATIVE_UNEXPECTED_SUCCESS')
    return dict(kind='checked', code='Cancelled')


def negative_progress(case, block, expected):
    """Observed cooperative callback sequence, separate from state correctness.

    BeforeMandatoryVerification means before checking the already executed M06 prologue.
    No callback here promises preemption inside that earlier native scan.
    """
    progress = ['BeforeBinding', 'Execution(BeforeParentBinding)']
    stop = case['cancel_at']
    if stop is None:
        return progress

    def point(name):
        progress.append(name)
        return name == stop

    point('AfterBinding')
    point('Execution(BeforeStateClone)')
    if point('BeforeMandatoryVerification'):
        return progress
    for index in range(len(block['witnesses'])):
        point(f'AccountProof {{ phase: Mandatory, index: {index} }}')
    for index in range(len(expected['mandatory']['account_changes'])):
        point(f'AccountUpdate {{ phase: Mandatory, index: {index} }}')
    if point('AfterMandatoryVerification'):
        return progress
    point('Execution(AfterMandatory)')
    for index in range(len(block['transactions_hex'])):
        point(f'Execution(BeforePrepare {{ index: {index} }})')
        point(f'Execution(AfterPrepare {{ index: {index} }})')
    for index in range(len(block['transactions_hex'])):
        point(f'Execution(BeforeApply {{ index: {index} }})')
        point(f'Execution(AfterApply {{ index: {index} }})')
    for name in ('BeforeReward', 'BeforeCommitment', 'AfterCommitment', 'BeforeOutput'):
        point(f'Execution({name})')
    if point('BeforeSuccessorVerification'):
        return progress
    for index in range(len(block['witnesses'])):
        point(f'AccountProof {{ phase: Successor, index: {index} }}')
    for index in range(len(expected['successor']['account_changes'])):
        point(f'AccountUpdate {{ phase: Successor, index: {index} }}')
    if point('AfterSuccessorVerification'):
        return progress
    require(point('BeforeOutput'), 'STATE_WITNESS_NEGATIVE_CANCELLATION_POINT')
    return progress


def check_negative_companion(native, companion, context, states, checkpoints, labels):
    cases = negative_inputs(native, context, states, checkpoints)
    rows = companion['negative_cases']
    require(type(rows) is list and all(type(row) is dict for row in rows)
            and [row.get('label') for row in rows] == list(NEGATIVE_LABELS),
            'STATE_WITNESS_NATIVE_NEGATIVE_ORDER')
    blocks = {row['label']: row for row in native['blocks']}
    positives = {row['label']: row for row in companion['blocks']}
    state = states[labels['restored-23']]
    # These exact observations were independently reconstructed by the source
    # account oracle. They remain JSON comparisons; no SQLite is opened here.
    binding = dict(native_active=list(labels['restored-23']), native_height=23,
        native_state_root=list(archive.source_state_root(state)),
        archive_active=native['final_active'], archive_storage=native['final_storage'],
        archive_rows_hash=list(archive.digest(b'account-execution-observed-rows-v1',
                                              archive.canonical(native['final_rows']))))
    observations = []
    for row, case in zip(rows, cases):
        require(set(row) == set(case) | {'outcome', 'progress', 'before', 'after',
            'parent_unchanged', 'archive_unchanged', 'input_witness_unchanged'},
            'STATE_WITNESS_NATIVE_NEGATIVE_FIELDS')
        application.equal({key: row[key] for key in case}, case, 'STATE_WITNESS_NATIVE_NEGATIVE_INPUT')
        positive = positives[case['source_positive_label']]
        block = blocks[case['source_positive_label']]
        parent = archive.hash_bytes(block['parent'])
        expected = derive_state_witness(states[parent], context,
            archive.hash_bytes(checkpoints[parent]['id']), parent, block['height'] - 1)
        outcome = negative_outcome(case, expected)
        progress = negative_progress(case, block, positive['observation'])
        application.equal(row['outcome'], outcome, 'STATE_WITNESS_NATIVE_NEGATIVE_OUTCOME')
        application.equal(row['progress'], progress, 'STATE_WITNESS_NATIVE_NEGATIVE_PROGRESS')
        application.equal(row['before'], binding, 'STATE_WITNESS_NATIVE_NEGATIVE_BEFORE')
        application.equal(row['after'], binding, 'STATE_WITNESS_NATIVE_NEGATIVE_AFTER')
        require(row['parent_unchanged'] is True and row['archive_unchanged'] is True
                and row['input_witness_unchanged'] is True, 'STATE_WITNESS_NATIVE_NEGATIVE_MUTATION')
        observations.append(dict(label=case['label'], source_positive_label=case['source_positive_label'],
            input_sha256=sha256(archive.canonical(case)).hexdigest(), outcome=outcome,
            progress=progress, unchanged_durable_observation_sha256=sha256(archive.canonical(binding)).hexdigest()))
    return observations


def check_observation(native_json, state_witness_json):
    native_before, witness_before = application.file_digest(native_json), application.file_digest(state_witness_json)
    native = archive.load_json(native_json, max_bytes=32 * 1024 * 1024)
    companion = archive.load_json(state_witness_json, max_bytes=32 * 1024 * 1024)
    native_bytes, witness_bytes = archive.canonical(native), archive.canonical(companion)
    report, context, states, checkpoints, labels = check_positive_companion(native, companion, native_before)
    negatives = check_negative_companion(native, companion, context, states, checkpoints, labels)
    require(archive.canonical(native) == native_bytes and archive.canonical(companion) == witness_bytes,
            'STATE_WITNESS_ORACLE_INPUT_MUTATED')
    require(application.file_digest(native_json) == native_before
            and application.file_digest(state_witness_json) == witness_before,
            'STATE_WITNESS_ORIGINAL_FILE_MUTATED')
    report.update(state_witness_json_sha256=witness_before,
        negative_observations_checked=len(negatives), negative_observations=negatives)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-json', type=Path, required=True)
    parser.add_argument('--state-witness-json', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = check_observation(args.native_json, args.state_witness_json)
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        report = dict(schema=SCHEMA, result='FAIL', error_type=type(error).__name__,
                      error=str(error), scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE))
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
