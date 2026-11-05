"""Independent full-level reference for canonical AAM1 account multiproofs.

The native constructor walks a compressed database trie.  This reference instead
places every account at its integer leaf position and folds all 256 sparse-tree
levels.  At each level, the siblings outside the queried positions determine the
unique nonempty boundary.  Native roots, frontier rows and update summaries are
observations to check, never inputs to that construction.

The binary decoder establishes canonical structure, not checkpoint authority.
The signed fixture checker additionally derives genesis and replays complete
application states using the separately implemented Python M06 reference.  This
does not independently verify native W1 admission, fork choice, data availability
or a production backend migration.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback

import account_archive_oracle as archive


SCHEMA = 'pon-account-multiproof-oracle-observation-v1'
NATIVE_SCHEMA = 'pon-account-multiproof-native-observation-v1'
PROOF_SCHEMA = 'pon-account-multiproof-v1'
MAX_ACCOUNTS = 66_049
MAX_FRONTIER_NODES = 65_536
HEADER_BYTES = 44
MAX_ACCOUNT_BYTES = 49
FRONTIER_BYTES = 66
MAX_ENCODED_BYTES = HEADER_BYTES + MAX_ACCOUNT_BYTES * MAX_ACCOUNTS + FRONTIER_BYTES * MAX_FRONTIER_NODES
SCOPE = {
    'independent_full_sparse_account_roots': True,
    'independent_canonical_aam1_boundary_and_bytes': True,
    'original_parent_update_roots_checked': True,
    'native_consensus_admission_reexecuted': False,
    'work_relation_reverified': False,
    'fork_choice_reverified': False,
    'production_backend_migration_accepted': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}
NATIVE_SCOPE = {
    'actual_signed_node_admission': True,
    'complete_state_reference_required': True,
    'direct_archive_collection': True,
    'production_activation': False,
    'public_availability_accepted': False,
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def hash_value(value):
    """Only native serde hash arrays are accepted in the observation schema."""
    return archive.hash_bytes(value)


def hex_bytes(value):
    require(type(value) is str and len(value) % 2 == 0
            and all(char in '0123456789abcdef' for char in value), 'MULTIPROOF_HEX')
    return bytes.fromhex(value)


def equal(actual, expected, code):
    require(archive.canonical(actual) == archive.canonical(expected), code)


def dimension(proof):
    require(type(proof) is dict and set(proof) == {'checkpoint', 'accounts', 'frontier'},
            'MULTIPROOF_FIELDS')
    hash_value(proof['checkpoint'])
    accounts, frontier = proof['accounts'], proof['frontier']
    require(type(accounts) is list and type(frontier) is list, 'MULTIPROOF_LIST')
    require(len(accounts) <= MAX_ACCOUNTS and len(frontier) <= MAX_FRONTIER_NODES,
            'MULTIPROOF_BUDGET')
    length = HEADER_BYTES + FRONTIER_BYTES * len(frontier)
    for row in accounts:
        require(type(row) is dict and set(row) == {'owner', 'account'}, 'MULTIPROOF_ACCOUNT_FIELDS')
        hash_value(row['owner'])
        if row['account'] is not None:
            archive.account(row['account'])
        length += 33 + (16 if row['account'] is not None else 0)
    for row in frontier:
        require(type(row) is dict and set(row) == {'depth', 'prefix', 'digest'},
                'MULTIPROOF_FRONTIER_FIELDS')
        require(type(row['depth']) is int and 1 <= row['depth'] <= 256, 'MULTIPROOF_FRONTIER_DEPTH')
        hash_value(row['prefix'])
        hash_value(row['digest'])
    require(length <= MAX_ENCODED_BYTES, 'MULTIPROOF_BUDGET')
    return length


def structure(proof):
    """Check exact boundary slots by integer levels, without nearest-path search."""
    dimension(proof)
    paths = [int.from_bytes(archive.key_path(hash_value(row['owner'])), 'big')
             for row in proof['accounts']]
    require(all(left < right for left, right in zip(paths, paths[1:])), 'MULTIPROOF_ACCOUNT_ORDER')
    by_depth = {}
    previous = -1
    for row in proof['frontier']:
        depth = row['depth']
        prefix = int.from_bytes(hash_value(row['prefix']), 'big')
        require(prefix > previous, 'MULTIPROOF_FRONTIER_ORDER')
        require(prefix % (1 << (256 - depth)) == 0, 'MULTIPROOF_FRONTIER_PREFIX')
        require(hash_value(row['digest']) != archive.EMPTY[depth], 'MULTIPROOF_EMPTY_FRONTIER')
        by_depth.setdefault(depth, []).append(prefix >> (256 - depth))
        previous = prefix
    positions = set(paths)
    for depth in range(256, 0, -1):
        parents = {position // 2 for position in positions}
        for slot in by_depth.get(depth, ()):
            require(slot not in positions and slot // 2 in parents, 'MULTIPROOF_BOUNDARY')
        positions = parents
    return paths


def encode_proof(proof):
    length = dimension(proof)
    structure(proof)
    out = bytearray(b'AAM1' + hash_value(proof['checkpoint'])
                    + len(proof['accounts']).to_bytes(4, 'little')
                    + len(proof['frontier']).to_bytes(4, 'little'))
    for row in proof['accounts']:
        out.extend(hash_value(row['owner']))
        out.append(int(row['account'] is not None))
        if row['account'] is not None:
            value = archive.account(row['account'])
            out.extend(value.balance.to_bytes(8, 'little'))
            out.extend(value.nonce.to_bytes(8, 'little'))
    for row in proof['frontier']:
        out.extend(row['depth'].to_bytes(2, 'little'))
        out.extend(hash_value(row['prefix']))
        out.extend(hash_value(row['digest']))
    require(len(out) == length, 'MULTIPROOF_ENCODING_LENGTH')
    return bytes(out)


def decode_proof(raw):
    require(type(raw) is bytes, 'MULTIPROOF_ENCODING')
    require(len(raw) <= MAX_ENCODED_BYTES, 'MULTIPROOF_BUDGET')
    require(len(raw) >= HEADER_BYTES and raw[:4] == b'AAM1', 'MULTIPROOF_ENCODING')
    account_count = int.from_bytes(raw[36:40], 'little')
    frontier_count = int.from_bytes(raw[40:44], 'little')
    require(account_count <= MAX_ACCOUNTS and frontier_count <= MAX_FRONTIER_NODES,
            'MULTIPROOF_BUDGET')
    require(len(raw) - HEADER_BYTES >= 33 * account_count + FRONTIER_BYTES * frontier_count,
            'MULTIPROOF_ENCODING')
    cursor = HEADER_BYTES

    def take(length):
        nonlocal cursor
        value = raw[cursor:cursor + length]
        require(len(value) == length, 'MULTIPROOF_ENCODING')
        cursor += length
        return value

    accounts = []
    for _ in range(account_count):
        owner, flag = take(32), take(1)[0]
        require(flag in (0, 1), 'MULTIPROOF_ENCODING')
        value = (dict(balance=int.from_bytes(take(8), 'little'), nonce=int.from_bytes(take(8), 'little'))
                 if flag == 1 else None)
        accounts.append(dict(owner=list(owner), account=value))
    frontier = [dict(depth=int.from_bytes(take(2), 'little'), prefix=list(take(32)), digest=list(take(32)))
                for _ in range(frontier_count)]
    require(cursor == len(raw), 'MULTIPROOF_ENCODING')
    result = dict(checkpoint=list(raw[4:36]), accounts=accounts, frontier=frontier)
    structure(result)
    require(encode_proof(result) == raw, 'MULTIPROOF_ENCODING')
    return result


def from_full_accounts(accounts, checkpoint, requested):
    """Derive all frontier bytes from complete leaves and level-wise set differences.

    The queried trie and full account trie are folded together, with only the
    current level retained.  No native proof, root or compressed record is read.
    """
    require(type(accounts) is dict, 'MULTIPROOF_FULL_ACCOUNTS')
    archive.owner_bytes(checkpoint)
    requested = tuple(requested)
    require(len(requested) <= MAX_ACCOUNTS, 'MULTIPROOF_BUDGET')
    require(len(set(requested)) == len(requested), 'MULTIPROOF_DUPLICATE_QUERY')
    queries = sorted((int.from_bytes(archive.key_path(owner), 'big'), owner) for owner in requested)
    require(len({position for position, _ in queries}) == len(queries), 'MULTIPROOF_KEY_COLLISION')
    nodes = {}
    for owner, value in accounts.items():
        position = int.from_bytes(archive.key_path(owner), 'big')
        require(position not in nodes, 'MULTIPROOF_KEY_COLLISION')
        nodes[position] = archive.leaf(owner, value)
    positions = {position for position, _ in queries}
    frontier = []
    for depth in range(256, 0, -1):
        outside = {position ^ 1 for position in positions} - positions
        for position in outside & nodes.keys():
            frontier.append(dict(depth=depth,
                prefix=list((position << (256 - depth)).to_bytes(32, 'big')),
                digest=list(nodes[position])))
        parents = {position // 2 for position in nodes}
        nodes = {parent: archive.digest(archive.BRANCH_DOMAIN,
                    nodes.get(2 * parent, archive.EMPTY[depth]),
                    nodes.get(2 * parent + 1, archive.EMPTY[depth])) for parent in parents}
        positions = {position // 2 for position in positions}
    proof = dict(checkpoint=list(checkpoint),
        accounts=[dict(owner=list(owner), account=accounts[owner].as_json() if owner in accounts else None)
                  for _, owner in queries],
        frontier=sorted(frontier, key=lambda row: bytes(row['prefix'])))
    structure(proof)
    return proof, nodes.get(0, archive.EMPTY[0])


def from_full_state(state, checkpoint, requested):
    return from_full_accounts(archive.accounts_from_state(state), checkpoint, requested)


def proof_values(proof):
    return {hash_value(row['owner']): (archive.account(row['account']) if row['account'] is not None else None)
            for row in proof['accounts']}


def fold(proof, replacements=None):
    """Fold uncompressed integer levels; metrics count real sparse branch slots.

    A frontier node is inserted at its declared level.  An absent queried leaf
    remains an explicit empty slot so it can later be created by an update.
    Empty queries make no root claim: their result is None, not an empty root.
    """
    paths = structure(proof)
    replacements = replacements or {}
    nodes = {}
    changed = set()
    for position, row in zip(paths, proof['accounts']):
        owner = hash_value(row['owner'])
        value = replacements.get(owner, archive.account(row['account']) if row['account'] is not None else None)
        nodes[position] = archive.leaf(owner, value) if value is not None else archive.EMPTY[256]
        if owner in replacements:
            changed.add(position)
    levels = {}
    for row in proof['frontier']:
        depth = row['depth']
        position = int.from_bytes(hash_value(row['prefix']), 'big') >> (256 - depth)
        levels.setdefault(depth, {})[position] = hash_value(row['digest'])
    branches, changed_branches, changed_forks = 0, 0, 0
    for depth in range(256, 0, -1):
        for position, value in levels.get(depth, {}).items():
            require(position not in nodes, 'MULTIPROOF_OVERLAP')
            nodes[position] = value
        parents = {position // 2 for position in nodes}
        dirty = {position // 2 for position in changed}
        changed_forks += sum(2 * parent in nodes and 2 * parent + 1 in nodes for parent in dirty)
        branches += len(parents)
        changed_branches += len(dirty)
        nodes = {parent: archive.digest(archive.BRANCH_DOMAIN,
                    nodes.get(2 * parent, archive.EMPTY[depth]),
                    nodes.get(2 * parent + 1, archive.EMPTY[depth])) for parent in parents}
        changed = dirty
    return dict(root=nodes.get(0), branch_hashes=branches,
                changed_branch_hashes=changed_branches, changed_forks=changed_forks)


def verify_proof(proof, checkpoint, account_root, account_count=None):
    dimension(proof)
    archive.owner_bytes(checkpoint)
    archive.owner_bytes(account_root)
    require(hash_value(proof['checkpoint']) == checkpoint, 'MULTIPROOF_CHECKPOINT')
    if account_count is not None:
        archive.uint(account_count)
        require(len(proof['frontier']) <= account_count, 'MULTIPROOF_FRONTIER_COUNT')
    result = fold(proof)
    require(result['root'] is None or result['root'] == account_root, 'MULTIPROOF_ROOT')
    return proof_values(proof)


def checked_updates(proof, updates):
    values = proof_values(proof)
    require(type(updates) is list and len(updates) <= len(values), 'MULTIPROOF_UPDATE_BUDGET')
    replacements = {}
    previous = None
    for row in updates:
        require(type(row) is dict and set(row) == {'owner', 'before', 'after'}, 'MULTIPROOF_UPDATE_FIELDS')
        owner = hash_value(row['owner'])
        require(owner in values, 'MULTIPROOF_MISSING_WITNESS')
        require(previous is None or previous < owner, 'MULTIPROOF_UPDATE_ORDER')
        before = archive.account(row['before']) if row['before'] is not None else None
        after = archive.account(row['after'])
        require(before == values[owner], 'MULTIPROOF_UPDATE_BEFORE')
        require(before != after, 'MULTIPROOF_UPDATE_NOOP')
        require(before is None or before.nonce <= after.nonce, 'MULTIPROOF_NONCE_ROLLBACK')
        replacements[owner] = after
        previous = owner
    return replacements


def root_for_updates(proof, checkpoint, account_root, updates, account_count=None):
    verify_proof(proof, checkpoint, account_root, account_count)
    replacements = checked_updates(proof, updates)
    if not replacements:
        return account_root, dict(changed_accounts=0, changed_forks=0, branch_hashes=0)
    result = fold(proof, replacements)
    require(result['root'] is not None, 'MULTIPROOF_UPDATE_ROOT')
    return result['root'], dict(changed_accounts=len(updates), changed_forks=result['changed_forks'],
                               branch_hashes=result['changed_branch_hashes'])


def original_parent_updates(parent, child):
    before, after = archive.accounts_from_state(parent), archive.accounts_from_state(child)
    require(before.keys() <= after.keys(), 'MULTIPROOF_ACCOUNT_DELETION')
    return [dict(owner=list(owner), before=before[owner].as_json() if owner in before else None,
                 after=after[owner].as_json()) for owner in sorted(after)
            if before.get(owner) != after[owner]]


def proof_observation(proof):
    result = fold(proof)
    entries = len(proof['accounts']) + len(proof['frontier'])
    return dict(schema=PROOF_SCHEMA, accounts=len(proof['accounts']), frontier_nodes=len(proof['frontier']),
                encoded_bytes=dimension(proof), retained_tree_nodes=max(0, 2 * entries - 1),
                verification_branch_hashes=result['branch_hashes'])


def expected_archive_reads(accounts, requested):
    """Count selected database edges from an independently rebuilt complete tree.

    All records are constructed from full leaves first.  A child record must be
    read exactly when a query lies in its parent's side interval.  Queries that
    diverge inside a compressed child still need that child read to learn this.
    """
    if not accounts or not requested:
        return 0
    positions = sorted(int.from_bytes(archive.key_path(owner), 'big') for owner in requested)
    tree = archive.full_sparse_details(accounts)
    reads = 1
    for identity, raw in tree['records'].items():
        node = archive.decode_node(identity, raw)
        if node['depth'] == 256:
            continue
        depth = node['depth']
        prefix = int.from_bytes(node['path'], 'big') >> (256 - depth)
        for side in (0, 1):
            lower = (2 * prefix + side) << (255 - depth)
            upper = (2 * prefix + side + 1) << (255 - depth)
            reads += bisect_left(positions, lower) != bisect_left(positions, upper)
    return reads


def checked_native_query(query, context_json, branch_bytes, height, full_state, requested_owners):
    """Check a native-backend query against a separately authenticated full State.

    The caller supplies the independently replayed active branch, height, State
    and expected requested owners.  None is inferred from the query's claims.
    This transient archive checkpoint intentionally has no archive parent.
    """
    require(type(query) is dict and set(query) == {
        'checkpoint', 'proof', 'observation', 'encoded_bytes', 'proof_hex', 'requested_owners'},
        'MULTIPROOF_NATIVE_QUERY_FIELDS')
    requested_owners = tuple(requested_owners)
    equal(query['requested_owners'], [owner.hex() for owner in requested_owners],
          'MULTIPROOF_NATIVE_QUERY_REQUESTED')
    accounts = archive.accounts_from_state(full_state)
    source_root = archive.source_state_root(full_state)
    checkpoint, _ = archive.derive_checkpoint(context_json, branch_bytes, None, height,
                                              source_root, accounts)
    equal(query['checkpoint'], checkpoint, 'MULTIPROOF_NATIVE_QUERY_CHECKPOINT')
    proof, root = from_full_accounts(accounts, hash_value(checkpoint['id']), requested_owners)
    require(root == hash_value(checkpoint['account_root']), 'MULTIPROOF_NATIVE_QUERY_PARENT_ROOT')
    equal(query['proof'], proof, 'MULTIPROOF_NATIVE_QUERY_PROOF')
    raw = encode_proof(proof)
    require(hex_bytes(query['proof_hex']) == raw, 'MULTIPROOF_NATIVE_QUERY_BYTES')
    equal(decode_proof(raw), proof, 'MULTIPROOF_NATIVE_QUERY_DECODE')
    verify_proof(proof, hash_value(checkpoint['id']), root, len(accounts))
    require(type(query['encoded_bytes']) is int and query['encoded_bytes'] == len(raw),
            'MULTIPROOF_NATIVE_QUERY_LENGTH')
    metrics = proof_observation(proof)
    construction = dict(archive_point_reads=expected_archive_reads(accounts, requested_owners),
                        proof=metrics, expanded_witnesses_allocated=0)
    equal(query['observation'], construction, 'MULTIPROOF_NATIVE_QUERY_CONSTRUCTION')
    return dict(result='PASS', checkpoint=hash_value(checkpoint['id']).hex(),
        branch=branch_bytes.hex(), height=height, state_root=source_root.hex(),
        account_root=root.hex(), full_account_count=len(accounts),
        requested_owners=[owner.hex() for owner in requested_owners],
        present_accounts=sum(owner in accounts for owner in requested_owners),
        absent_accounts=sum(owner not in accounts for owner in requested_owners),
        canonical_aam1_sha256=sha256(raw).hexdigest(), encoded_bytes=len(raw),
        construction=construction, full_state_derived_checkpoint_checked=True,
        actual_native_wire_bytes_checked=True, independent_sparse_roots_checked=True)


def fixture_transactions(context, height):
    """Independently encode the forty funded owners and their forty reservations."""
    import account_execution_oracle as application
    if height == 1:
        return [application.signed_transaction(context, 0, owner - 99, 1,
                    application.development_public(owner) + application.u64(5_000))
                for owner in range(100, 140)]
    if height == 2:
        result = []
        for owner in range(100, 140):
            sender = application.development_public(owner)
            provider = application.development_public(2)
            budget, deadline = 1_000, 3 + (owner - 100) // 16
            identity = application.h('task-instance-v3', context.network, context.parameters,
                                     sender, application.u64(1), provider,
                                     application.u64(budget), application.u64(deadline))
            result.append(application.signed_transaction(context, owner, 1, 2,
                identity + provider + application.u64(budget) + application.u64(deadline)))
        return result
    require(height == 3, 'MULTIPROOF_FIXTURE_HEIGHT')
    return []


def check_observation_data(observed):
    """Rebuild the signed fixture before comparing every native proof and state.

    Complete native packets bind subsequent parents: the existing independent
    packet decoder recalculates ids and transaction/state/receipt commitments.
    W1 and fork choice remain out of scope.
    """
    import account_execution_oracle as application
    require(type(observed) is dict and observed.get('schema') == NATIVE_SCHEMA,
            'MULTIPROOF_NATIVE_SCHEMA')
    require(set(observed) == {'schema', 'context', 'genesis_state', 'genesis_checkpoint', 'blocks', 'scope'},
            'MULTIPROOF_NATIVE_FIELDS')
    application.strict_scope(observed['scope'], NATIVE_SCOPE, 'MULTIPROOF_NATIVE_SCOPE')
    context = application.derive_context(1)
    equal(observed['context'], context.as_json(), 'MULTIPROOF_NATIVE_CONTEXT')
    parent = application.derive_genesis(context)
    equal(observed['genesis_state'], parent, 'MULTIPROOF_NATIVE_GENESIS')
    parent_id = context.genesis
    parent_checkpoint, _ = archive.derive_checkpoint(context.as_json(), parent_id, None, 0,
        archive.source_state_root(parent), archive.accounts_from_state(parent))
    equal(observed['genesis_checkpoint'], parent_checkpoint, 'MULTIPROOF_NATIVE_GENESIS_CHECKPOINT')
    rows = observed['blocks']
    require(type(rows) is list and len(rows) == 3
            and [row.get('label') for row in rows] == ['funding', 'reservations', 'expiry'],
            'MULTIPROOF_NATIVE_BLOCKS')
    required = {'label', 'height', 'parent', 'miner', 'transactions_hex', 'parent_state',
                'parent_checkpoint', 'requested', 'proof', 'proof_hex', 'construction',
                'mandatory_state', 'mandatory_updates', 'mandatory_account_root',
                'successor_state', 'successor_updates', 'successor_account_root', 'admitted_id', 'packet_hex',
                'mandatory_update_observation', 'successor_update_observation'}
    optional = {'header_hex'}
    expected_owners = sorted(application.development_public(owner) for owner in [0, *range(100, 140)])
    block_reports = []
    packet_checks = 0
    transactions_checked = 0
    for height, row in enumerate(rows, 1):
        require(type(row) is dict and required <= set(row) <= required | optional,
                'MULTIPROOF_NATIVE_BLOCK_FIELDS')
        require(type(row['height']) is int and row['height'] == height
                and hash_value(row['parent']) == parent_id, 'MULTIPROOF_NATIVE_PARENT')
        equal(row['parent_state'], parent, 'MULTIPROOF_NATIVE_PARENT_STATE')
        equal(row['parent_checkpoint'], parent_checkpoint, 'MULTIPROOF_NATIVE_PARENT_CHECKPOINT')
        miner = application.development_public(0)
        require(hash_value(row['miner']) == miner, 'MULTIPROOF_NATIVE_MINER')
        transactions = fixture_transactions(context, height)
        equal(row['transactions_hex'], [raw.hex() for raw in transactions], 'MULTIPROOF_NATIVE_TRANSACTIONS')
        equal(row['requested'], [list(owner) for owner in expected_owners], 'MULTIPROOF_NATIVE_REQUESTED')
        require(len(expected_owners) <= application.execution_witness_budget(len(parent), len(transactions)),
                'MULTIPROOF_EXECUTION_BUDGET')
        parent_accounts = archive.accounts_from_state(parent)
        checkpoint_id = hash_value(parent_checkpoint['id'])
        proof, parent_root = from_full_accounts(parent_accounts, checkpoint_id, expected_owners)
        require(parent_root == hash_value(parent_checkpoint['account_root']), 'MULTIPROOF_PARENT_ROOT')
        equal(row['proof'], proof, 'MULTIPROOF_NATIVE_PROOF')
        encoded = encode_proof(proof)
        require(hex_bytes(row['proof_hex']) == encoded, 'MULTIPROOF_NATIVE_BYTES')
        equal(decode_proof(encoded), proof, 'MULTIPROOF_NATIVE_DECODE')
        verified = verify_proof(proof, checkpoint_id, parent_root, len(parent_accounts))
        metrics = proof_observation(proof)
        equal(row['construction'], dict(archive_point_reads=expected_archive_reads(parent_accounts, expected_owners),
              proof=metrics, expanded_witnesses_allocated=0), 'MULTIPROOF_NATIVE_CONSTRUCTION')
        mandatory_access = application.AccountAccess(parent, verified)
        # Run the pre-mandatory reserve scan as the real application relation does.
        application.capacity(parent, height - 1, context, mandatory_access)
        mandatory, mandatory_receipts = application.mandatory(parent, height, context, mandatory_access)
        output = application.transition(parent, transactions, height, miner, parent_id, context, verified)
        equal(output['used_owners'], row['requested'], 'MULTIPROOF_NATIVE_ACCOUNT_COVERAGE')
        phase_reports = {}
        for phase, state in [('mandatory', mandatory), ('successor', output['state'])]:
            updates = original_parent_updates(parent, state)
            equal(row[phase + '_state'], state, 'MULTIPROOF_NATIVE_' + phase.upper() + '_STATE')
            equal(row[phase + '_updates'], updates, 'MULTIPROOF_NATIVE_' + phase.upper() + '_UPDATES')
            update_root, update_metrics = root_for_updates(proof, checkpoint_id, parent_root, updates,
                                                           len(parent_accounts))
            full_root, _ = archive.full_sparse(archive.accounts_from_state(state))
            require(update_root == full_root == hash_value(row[phase + '_account_root']),
                    'MULTIPROOF_NATIVE_' + phase.upper() + '_ROOT')
            equal(row[phase + '_update_observation'], update_metrics,
                  'MULTIPROOF_NATIVE_' + phase.upper() + '_UPDATE_OBSERVATION')
            phase_reports[phase] = dict(account_root=full_root.hex(),
                state_root=archive.source_state_root(state).hex(), updates=len(updates),
                account_count=len(archive.accounts_from_state(state)), update_observation=update_metrics)
        identity = hash_value(row['admitted_id'])
        require(identity != parent_id and identity != bytes(32), 'MULTIPROOF_NATIVE_BLOCK_ID')
        packet = hex_bytes(row['packet_hex'])
        if 'header_hex' in row:
            require(hex_bytes(row['header_hex']) == packet[:318], 'MULTIPROOF_NATIVE_HEADER')
        require(application.verify_packet(packet, transactions, output, context,
                parent_id, height, miner) == identity, 'MULTIPROOF_NATIVE_PACKET')
        packet_checks += 1
        if height == 3:
            require(len(mandatory_receipts) == 16 and len(row['mandatory_updates']) == 16,
                    'MULTIPROOF_FIXTURE_EXPIRY')
            future = [value for key, value in mandatory.items()
                      if key.startswith('task:') and value['remaining'] > 0]
            require(len(future) == 24 and sum(value['remaining'] for value in future) == 24_000,
                    'MULTIPROOF_FIXTURE_FUTURE_OBLIGATIONS')
        expanded = sum(archive.MAX_WITNESS_BYTES if value is not None else archive.MIN_WITNESS_BYTES
                       for value in verified.values())
        block_reports.append(dict(label=row['label'], height=height, parent=parent_id.hex(),
            admitted_id=identity.hex(), transactions=len(transactions), present_accounts=sum(value is not None for value in verified.values()),
            absent_accounts=sum(value is None for value in verified.values()),
            requested_accounts=len(expected_owners), parent_account_root=parent_root.hex(),
            canonical_aam1_sha256=sha256(encoded).hexdigest(), encoded_bytes=len(encoded),
            expanded_aaw1_bytes=expanded, saved_bytes=expanded-len(encoded),
            proof_observation=metrics, archive_point_reads=row['construction']['archive_point_reads'],
            mandatory_receipts=len(mandatory_receipts), phases=phase_reports))
        transactions_checked += len(transactions)
        parent_checkpoint, _ = archive.derive_checkpoint(context.as_json(), identity, checkpoint_id, height,
            archive.source_state_root(output['state']), archive.accounts_from_state(output['state']))
        parent_id, parent = identity, output['state']
    require(transactions_checked == 80, 'MULTIPROOF_NATIVE_TRANSACTION_COUNT')
    return dict(schema=SCHEMA, native_schema=NATIVE_SCHEMA, result='PASS',
        genesis_checked=True, signed_application_transactions_checked=transactions_checked,
        complete_blocks_checked=3, mandatory_and_successor_roots_checked=6,
        packet_commitments_checked=packet_checks, native_work_admission_reexecuted=False,
        canonical_multiproofs_checked=3, queried_account_presence_values_checked=123,
        final_state_root=archive.source_state_root(parent).hex(),
        maximum_encoded_bytes=MAX_ENCODED_BYTES, block_observations=block_reports,
        scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE))


def check_observation(native_json):
    before = file_digest(native_json)
    observed = archive.load_json(native_json)
    canonical_before = archive.canonical(observed)
    report = check_observation_data(observed)
    report['oracle_negative_controls'] = negative_controls(observed)
    report['oracle_negative_controls_checked'] = len(report['oracle_negative_controls'])
    require(archive.canonical(observed) == canonical_before, 'MULTIPROOF_ORACLE_MUTATED_INPUT')
    require(file_digest(native_json) == before, 'MULTIPROOF_NATIVE_FILE_MUTATED')
    report['native_json_sha256'] = before
    return report


def negative_controls(observed):
    """Mutate actual native observations and require the independent checker to fail.

    These are oracle rejection controls, not claims that the mutations were sent
    to Rust.  Native invalid-input tests are separately executed by Cargo.
    """
    cases = []

    def add(label, mutate, code):
        changed = copy.deepcopy(observed)
        mutate(changed)
        cases.append((label, changed, code))

    add('extra-native-claim', lambda value: value.update(fully_validated=True), 'MULTIPROOF_NATIVE_FIELDS')
    add('production-scope-promoted', lambda value: value['scope'].__setitem__('production_activation', True),
        'MULTIPROOF_NATIVE_SCOPE')
    add('missing-packet', lambda value: value['blocks'][0].pop('packet_hex'), 'MULTIPROOF_NATIVE_BLOCK_FIELDS')
    add('height-coerced-from-bool', lambda value: value['blocks'][0].__setitem__('height', True),
        'MULTIPROOF_NATIVE_PARENT')
    add('wrong-checkpoint-count', lambda value: value['blocks'][0]['parent_checkpoint'].__setitem__('account_count', 5),
        'MULTIPROOF_NATIVE_PARENT_CHECKPOINT')
    add('omitted-absent-query', lambda value: value['blocks'][0]['requested'].pop(), 'MULTIPROOF_NATIVE_REQUESTED')
    add('reordered-proof-leaves', lambda value: value['blocks'][0]['proof']['accounts'].reverse(),
        'MULTIPROOF_NATIVE_PROOF')
    add('omitted-nonempty-boundary', lambda value: value['blocks'][0]['proof']['frontier'].pop(),
        'MULTIPROOF_NATIVE_PROOF')

    def invent(value):
        next(row for row in value['blocks'][0]['proof']['accounts'] if row['account'] is None)['account'] = dict(balance=0, nonce=0)

    add('absent-account-claimed-zero-member', invent, 'MULTIPROOF_NATIVE_PROOF')
    add('noncanonical-proof-trailer', lambda value: value['blocks'][0].__setitem__('proof_hex', value['blocks'][0]['proof_hex'] + '00'),
        'MULTIPROOF_NATIVE_BYTES')
    add('claimed-encoding-budget', lambda value: value['blocks'][0]['construction']['proof'].__setitem__('encoded_bytes', 44),
        'MULTIPROOF_NATIVE_CONSTRUCTION')
    add('expanded-witness-allocation-claim', lambda value: value['blocks'][0]['construction'].__setitem__('expanded_witnesses_allocated', 41),
        'MULTIPROOF_NATIVE_CONSTRUCTION')
    add('wrong-archive-read-count', lambda value: value['blocks'][0]['construction'].__setitem__('archive_point_reads', 1),
        'MULTIPROOF_NATIVE_CONSTRUCTION')
    add('omitted-phase-update-observation', lambda value: value['blocks'][0].pop('successor_update_observation'),
        'MULTIPROOF_NATIVE_BLOCK_FIELDS')
    add('false-update-branch-count', lambda value: value['blocks'][0]['successor_update_observation'].__setitem__('branch_hashes', 0),
        'MULTIPROOF_NATIVE_SUCCESSOR_UPDATE_OBSERVATION')

    def changed_transaction(value):
        raw = bytearray(hex_bytes(value['blocks'][0]['transactions_hex'][0]))
        raw[-1] ^= 1
        value['blocks'][0]['transactions_hex'][0] = raw.hex()

    add('changed-signed-transaction', changed_transaction, 'MULTIPROOF_NATIVE_TRANSACTIONS')

    def changed_packet(value):
        raw = bytearray(hex_bytes(value['blocks'][0]['packet_hex']))
        raw[214] ^= 1  # Existing PNH1 State-root field; body and observations remain unchanged.
        value['blocks'][0]['packet_hex'] = raw.hex()

    add('packet-state-commitment', changed_packet, 'PACKET_STATE_ROOT')

    def rolled_back_nonce(value):
        row = value['blocks'][1]
        key = next(key for key in sorted(row['successor_state'])
                   if key.startswith('account:') and row['successor_state'][key]['nonce'] == 1)
        row['successor_state'][key]['nonce'] = 0

    add('successor-nonce-rollback', rolled_back_nonce, 'MULTIPROOF_NATIVE_SUCCESSOR_STATE')
    add('missing-mandatory-update', lambda value: value['blocks'][2]['mandatory_updates'].pop(),
        'MULTIPROOF_NATIVE_MANDATORY_UPDATES')

    def future_obligation(value):
        state = value['blocks'][2]['mandatory_state']
        key = next(key for key in sorted(state) if key.startswith('task:') and state[key]['remaining'] > 0)
        del state[key]

    add('future-obligation-hidden', future_obligation, 'MULTIPROOF_NATIVE_MANDATORY_STATE')
    results = []
    for label, changed, expected in cases:
        try:
            check_observation_data(changed)
        except ValueError as error:
            require(str(error) == expected, 'MULTIPROOF_NEGATIVE_CONTROL_CODE:' + label + ':' + str(error))
            results.append(dict(label=label, input_sha256=sha256(archive.canonical(changed)).hexdigest(),
                                rejected_with=str(error), native_execution=False))
        else:
            raise ValueError('MULTIPROOF_NEGATIVE_CONTROL_ACCEPTED:' + label)
    return results


def file_digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native_json', nargs='?', type=Path)
    parser.add_argument('--native-json', dest='native_json_option', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if (args.native_json is None) == (args.native_json_option is None):
        parser.error('supply exactly one native JSON path, positionally or with --native-json')
    native = args.native_json or args.native_json_option
    try:
        if args.output is not None:
            require(args.output.resolve() != native.resolve(), 'MULTIPROOF_OUTPUT_OVERWRITES_INPUT')
            require(not args.output.exists(), 'MULTIPROOF_OUTPUT_EXISTS')
        report = check_observation(native)
    except Exception as error:
        report = dict(schema=SCHEMA, result='FAIL', error_type=type(error).__name__,
                      error=str(error), scope=dict(SCOPE))
        traceback.print_exc(file=sys.stderr)
    encoded = json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n'
    if args.output is not None and args.output.resolve() != native.resolve() and not args.output.exists():
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(encoded)
    print(encoded, end='')
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
