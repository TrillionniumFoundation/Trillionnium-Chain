"""Independent complete-State reader for monetary obligation range proofs.

The reference sorts every non-account key, hashes ranked leaves, and folds a
flat interval catalogue from children to parents. It selects all four monetary
namespaces and their immediate neighbours from that complete source ordering.
Untrusted rows and frontier digests are only compared with those results; they
never determine which obligations exist, the trusted index root, or its count.

This is a finite research relation with a full parent anchor. A complete range
does not establish data availability, a stateless node, native W1 verification,
fork choice, physical cost bounds, or production acceptance.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path

import account_archive_oracle as archive
import account_execution_oracle as application
import account_multiproof_oracle as multiproof
import state_witness_oracle as state_witness


SCHEMA = 'pon-monetary-obligation-range-oracle-observation-v1'
NATIVE_SCHEMA = 'pon-monetary-obligation-range-native-observation-v1'
PROOF_SCHEMA = 'pon-monetary-obligation-range-v1'
PREFIXES = ('quota:', 'release:', 'reward:', 'task:')
PROOF_FIELDS = ('schema', 'parent_checkpoint', 'parent_id', 'parent_height',
                'state_commitment', 'non_account_count', 'index_root', 'rows', 'frontier')
ANCHOR_FIELDS = ('parent_checkpoint', 'parent_id', 'parent_height', 'state_commitment')
MAX_ROWS = 65_536
MAX_KEY_BYTES = 160
MAX_VALUE_BYTES = 4096
MAX_INPUT_BYTES = 64 * 1024 * 1024
SCOPE = {
    'independent_complete_ordered_non_account_index': True,
    'all_four_monetary_ranges_and_immediate_boundaries': True,
    'future_and_zero_amount_obligations_included': True,
    'full_parent_reference_required': True,
    'native_consensus_admission_reexecuted': False,
    'work_relation_reverified': False,
    'fork_choice_reverified': False,
    'public_data_availability_accepted': False,
    'production_activation': False,
}
NATIVE_SCOPE = {
    'actual_signed_node_admission': True,
    'complete_state_reference_required': True,
    'monetary_ranges_complete': True,
    'parent_monetary_discovery_uses_verified_rows': True,
    'other_non_account_rules_use_full_state': True,
    'default_node_admission_uses_full_state': True,
    'public_availability_accepted': False,
    'production_activation': False,
}


def require(condition, code):
    if not condition:
        raise ValueError('OBLIGATION_RANGE_' + code)


def uint(value, maximum=archive.U64_MAX):
    require(type(value) is int and 0 <= value <= maximum, 'INTEGER')
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'FIELDS')
    return {name: value[name] for name in names}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def equal(left, right, code):
    # Strict JSON equality distinguishes absent, null, bool and integer values.
    require(json.dumps(left, sort_keys=True, ensure_ascii=False, allow_nan=False)
            == json.dumps(right, sort_keys=True, ensure_ascii=False, allow_nan=False), code)


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_INPUT_BYTES, 'INPUT_BUDGET')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def reject(_value):
        raise ValueError('OBLIGATION_RANGE_JSON_NUMBER')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def source_rows(non_accounts):
    # Full-State canonical roots already restrict Value strings/object keys to
    # ASCII and numbers to i64/u64. UTF-8 is supported for the top-level key;
    # this is not a general unbound serde_json::Value byte-equivalence claim.
    require(type(non_accounts) is dict and len(non_accounts) <= MAX_ROWS, 'SOURCE_BUDGET')
    require(all(type(key) is str and not key.startswith('account:') for key in non_accounts),
            'SOURCE_KEY')
    rows = []
    for rank, key in enumerate(sorted(non_accounts)):
        require(len(key.encode('utf-8')) <= MAX_KEY_BYTES, 'KEY_BUDGET')
        raw = archive.canonical(non_accounts[key])
        require(len(raw) <= MAX_VALUE_BYTES, 'VALUE_BUDGET')
        rows.append(dict(rank=rank, key=key, value=json.loads(raw)))
    return rows


def index_details(rows):
    """Build an interval catalogue, then hash it bottom-up without proof input."""
    count = len(rows)
    if count == 0:
        return dict(root=archive.digest(b'monetary-obligation-range-empty-v1'),
                    digests={}, parents={})
    # Catalogue intervals independently of their contents. This is not a walk
    # driven by supplied leaf ranks or a recursive frontier-consumption parser.
    parents = {(0, count): None}
    pending = [(0, count)]
    for first, size in pending:
        if size > 1:
            left_count = size // 2
            for child in ((first, left_count), (first + left_count, size - left_count)):
                parents[child] = (first, size)
                pending.append(child)
    digests = {}
    for first, size in sorted(parents, key=lambda item: (item[1], item[0])):
        if size == 1:
            row = rows[first]
            require(row['rank'] == first, 'SOURCE_RANK')
            value = archive.canonical(row['value'])
            digests[first, size] = archive.digest(b'monetary-obligation-range-leaf-v1',
                first.to_bytes(4, 'little'), row['key'].encode('utf-8'), value)
        else:
            left_count = size // 2
            digests[first, size] = archive.digest(b'monetary-obligation-range-node-v1',
                first.to_bytes(4, 'little'), size.to_bytes(4, 'little'),
                digests[first, left_count], digests[first + left_count, size - left_count])
    return dict(root=digests[0, count], digests=digests, parents=parents)


def required_ranks(rows):
    wanted, ranges = set(), []
    keys = [row['key'] for row in rows]
    for prefix in PREFIXES:
        # Count over the full ordering, without using proof ranks or boundaries.
        first = sum(key < prefix for key in keys)
        after = sum(key < prefix[:-1] + ';' for key in keys)
        matches = [rank for rank, key in enumerate(keys) if key.startswith(prefix)]
        require(matches == list(range(first, after)), 'REFERENCE_INTERVAL')
        wanted.update(matches)
        before = first - 1 if first > 0 else None
        following = after if after < len(rows) else None
        for rank in (before, following):
            if rank is not None:
                wanted.add(rank)
        ranges.append(dict(prefix=prefix, first=first, after=after,
            matched_rows=len(matches), predecessor_rank=before, successor_rank=following))
    return wanted, ranges


def reference_partition(non_accounts, anchor):
    """Pure proof relation; the caller must independently establish the anchor."""
    anchor = fields(anchor, ANCHOR_FIELDS)
    for name in ('parent_checkpoint', 'parent_id', 'state_commitment'):
        archive.hash_bytes(anchor[name])
    uint(anchor['parent_height'])
    rows = source_rows(non_accounts)
    details = index_details(rows)
    wanted, ranges = required_ranks(rows)
    coverage = [0]
    for rank in range(len(rows)):
        coverage.append(coverage[-1] + (rank in wanted))
    def covered(span):
        first, count = span
        return coverage[first + count] - coverage[first]
    # Maximal hidden intervals are empty of required leaves while their parent
    # is not. Selecting these over a flat catalogue yields the canonical frontier.
    hidden = sorted(span for span, parent in details['parents'].items()
                    if covered(span) == 0 and (parent is None or covered(parent) > 0))
    frontier = [dict(first=first, count=count, digest=list(details['digests'][first, count]))
                for first, count in hidden]
    proof = dict(schema=PROOF_SCHEMA, **anchor, non_account_count=len(rows),
                 index_root=list(details['root']), rows=[rows[rank] for rank in sorted(wanted)],
                 frontier=frontier)
    monetary = {row['key']: copy.deepcopy(row['value']) for row in rows
                if row['key'].startswith(PREFIXES)}
    observation = dict(schema=PROOF_SCHEMA, parent_checkpoint=anchor['parent_checkpoint'],
        state_commitment=anchor['state_commitment'], index_root=list(details['root']),
        complete_non_account_rows=len(rows), monetary_rows=len(monetary),
        revealed_rows=len(wanted), boundary_rows=len(wanted)-len(monetary),
        frontier_nodes=len(frontier), proof_json_bytes=len(proof_bytes(proof)),
        index_leaf_hashes=len(rows), index_branch_hashes=max(0, len(rows)-1),
        verification_leaf_hashes=len(wanted),
        verification_branch_hashes=sum(size > 1 and covered((first, size)) > 0
                                       for first, size in details['parents']),
        complete_future_monetary_ranges=True, full_parent_anchor_required=True,
        other_non_account_rules_use_full_state=True, consensus_admission=False)
    return dict(proof=proof, observation=observation, monetary=monetary,
                ranges=ranges, index=details)


def proof_bytes(proof):
    """Exact serde struct order; Value object keys retain canonical sorted order."""
    value = fields(proof, PROOF_FIELDS)
    value['rows'] = [dict(rank=row['rank'], key=row['key'],
                         value=json.loads(archive.canonical(row['value']))) for row in value['rows']]
    value['frontier'] = [dict(first=node['first'], count=node['count'], digest=node['digest'])
                         for node in value['frontier']]
    return json_bytes(value)


def proof_shape(proof):
    fields(proof, PROOF_FIELDS)
    require(proof['schema'] == PROOF_SCHEMA, 'SCHEMA')
    for name in ('parent_checkpoint', 'parent_id', 'state_commitment', 'index_root'):
        archive.hash_bytes(proof[name])
    uint(proof['parent_height'])
    count = uint(proof['non_account_count'], MAX_ROWS)
    rows, frontier = proof['rows'], proof['frontier']
    require(type(rows) is list and type(frontier) is list
            and len(rows) <= count and len(frontier) <= count, 'BUDGET')
    previous = None
    for row in rows:
        fields(row, ('rank', 'key', 'value'))
        rank = uint(row['rank'], MAX_ROWS-1)
        require(rank < count and type(row['key']) is str
                and len(row['key'].encode('utf-8')) <= MAX_KEY_BYTES, 'ROW_BOUNDS')
        require(len(archive.canonical(row['value'])) <= MAX_VALUE_BYTES, 'VALUE_BUDGET')
        require(previous is None or (previous['rank'] < rank and previous['key'] < row['key']),
                'ROW_ORDER')
        previous = row
    after = 0
    for node in frontier:
        fields(node, ('first', 'count', 'digest'))
        first, size = uint(node['first'], MAX_ROWS), uint(node['count'], MAX_ROWS)
        require(size > 0 and after <= first and first + size <= count, 'FRONTIER_BOUNDS')
        archive.hash_bytes(node['digest'])
        after = first + size


def check_partition(proof, non_accounts, anchor):
    proof_shape(proof)
    expected = reference_partition(non_accounts, anchor)
    for name in ('schema', *ANCHOR_FIELDS, 'non_account_count', 'index_root'):
        equal(proof[name], expected['proof'][name], 'ANCHOR:' + name)
    equal(proof['rows'], expected['proof']['rows'], 'COMPLETE_ROWS')
    equal(proof['frontier'], expected['proof']['frontier'], 'CANONICAL_FRONTIER')
    require(proof_bytes(proof) == proof_bytes(expected['proof']), 'ENCODING')
    return expected


def check_proof(proof, parent_state, context, checkpoint):
    """Bind to a full-State commitment and a separately derived checkpoint."""
    commitment = state_witness.derive_commitment(parent_state, context)
    require(archive.hash_bytes(checkpoint['source_state_root']) ==
            state_witness.state_root(parent_state), 'PARENT_STATE')
    anchor = dict(parent_checkpoint=checkpoint['id'], parent_id=checkpoint['branch'],
                  parent_height=checkpoint['height'], state_commitment=commitment['id'])
    return check_partition(proof, state_witness.non_accounts(parent_state), anchor)


def fixture_transactions(context, height):
    """Independently encode the fixed 37 signed transactions, including maturity."""
    if height == 1:
        return [application.signed_transaction(context, 0, owner-99, 1,
                    application.development_public(owner) + application.u64(5_000))
                for owner in range(100, 118)]
    if height == 2:
        result = []
        for owner in range(100, 118):
            sender = application.development_public(owner)
            provider = application.development_public(2)
            budget, deadline = 1_000, 3 + (owner-100)//16
            identity = application.h('task-instance-v3', context.network, context.parameters,
                sender, application.u64(1), provider, application.u64(budget), application.u64(deadline))
            result.append(application.signed_transaction(context, owner, 1, 2,
                identity + provider + application.u64(budget) + application.u64(deadline)))
        return result
    if height == 21:
        return [application.signed_transaction(context, 999, 1, 1,
                    application.development_public(0) + application.u64(1))]
    require(3 <= height < 21, 'FIXTURE_HEIGHT')
    return []


def fixture_label(height):
    return {1: 'funding', 2: 'reservations', 3: 'expiry', 21: 'maturity-spend'}.get(
        height, 'continuation-' + str(height))


def phase_transition(parent, successor, receipts, context, checkpoint, account_proof):
    """Compare a compact-proof update root with a complete independent rebuild."""
    commitment = state_witness.derive_commitment(successor, context)
    updates = multiproof.original_parent_updates(parent, successor)
    root, _metrics = multiproof.root_for_updates(account_proof,
        archive.hash_bytes(checkpoint['id']), archive.hash_bytes(checkpoint['account_root']),
        updates, checkpoint['account_count'])
    require(root == archive.hash_bytes(commitment['account_root']), 'ACCOUNT_UPDATE_ROOT')
    return dict(commitment=commitment, account_changes=state_witness.account_changes(parent, successor),
        non_account_changes=state_witness.ordered_deltas(state_witness.non_accounts(parent),
                                                        state_witness.non_accounts(successor)),
        receipts=[list(raw) for raw in receipts])


def state_observation(context, checkpoint, parent, height, miner, mandatory,
                      mandatory_receipts, output, account_proof):
    non_accounts = state_witness.non_accounts(parent)
    partition = [dict(key=key, value=value) for key, value in non_accounts.items()]
    return dict(schema=state_witness.EXECUTION_SCHEMA, parent_checkpoint=checkpoint['id'],
        parent_id=checkpoint['branch'], height=height, miner=list(miner),
        parent=state_witness.derive_commitment(parent, context),
        mandatory=phase_transition(parent, mandatory, mandatory_receipts, context, checkpoint, account_proof),
        successor=phase_transition(parent, output['state'],
            [application.hex_bytes(raw) for raw in output['receipts_hex']],
            context, checkpoint, account_proof),
        non_account_witness_count=len(non_accounts),
        non_account_witness_bytes=len(state_witness.non_account_row_bytes(partition)),
        complete_non_account_partition=True, account_roots_from_merged_proofs=True,
        full_state_reference_checked=True, complete_state_required=True,
        consensus_admission=False, archive_mutated=False)


def check_observation_data(observed):
    """Reexecute all signed application packets; no native output seeds State."""
    fields(observed, ('schema', 'context', 'genesis_state', 'genesis_checkpoint', 'blocks', 'scope'))
    require(observed['schema'] == NATIVE_SCHEMA, 'NATIVE_SCHEMA')
    application.strict_scope(observed['scope'], NATIVE_SCOPE, 'OBLIGATION_RANGE_NATIVE_SCOPE')
    context = application.derive_context(1)
    equal(observed['context'], context.as_json(), 'NATIVE_CONTEXT')
    parent, parent_id = application.derive_genesis(context), context.genesis
    equal(observed['genesis_state'], parent, 'NATIVE_GENESIS')
    checkpoint, _ = archive.derive_checkpoint(context.as_json(), parent_id, None, 0,
        state_witness.state_root(parent), archive.accounts_from_state(parent))
    equal(observed['genesis_checkpoint'], checkpoint, 'NATIVE_GENESIS_CHECKPOINT')
    rows = observed['blocks']
    require(type(rows) is list and len(rows) == 21, 'NATIVE_BLOCK_COUNT')
    block_fields = ('label', 'height', 'parent', 'miner', 'transactions_hex', 'parent_state',
                    'parent_checkpoint', 'requested', 'account_proof_hex', 'account_proof',
                    'range_proof', 'range_observation', 'state_observation', 'mandatory_state',
                    'successor_state', 'packet_hex', 'admitted_id')
    blocks, signed_count, expiry_count = [], 0, 0
    recipient = application.development_public(999)
    recipient_key = 'account:' + recipient.hex()
    for height, row in enumerate(rows, 1):
        fields(row, block_fields)
        require(type(row['height']) is int and row['height'] == height
                and row['label'] == fixture_label(height), 'NATIVE_BLOCK_ORDER')
        require(archive.hash_bytes(row['parent']) == parent_id, 'NATIVE_PARENT')
        equal(row['parent_state'], parent, 'NATIVE_PARENT_STATE')
        equal(row['parent_checkpoint'], checkpoint, 'NATIVE_PARENT_CHECKPOINT')
        miner = application.development_public(999 if height == 1 else 0)
        require(archive.hash_bytes(row['miner']) == miner, 'NATIVE_MINER')
        transactions = fixture_transactions(context, height)
        equal(row['transactions_hex'], [raw.hex() for raw in transactions], 'NATIVE_TRANSACTIONS')
        ranges = check_proof(row['range_proof'], parent, context, checkpoint)
        equal(row['range_observation'], ranges['observation'], 'NATIVE_RANGE_OBSERVATION')

        # Independently discover the exact semantic account accesses with a
        # complete reference execution, then authenticate every original value.
        discovery = application.transition(parent, transactions, height, miner, parent_id, context)
        owners = [archive.hash_bytes(owner) for owner in discovery['used_owners']]
        equal(row['requested'], discovery['used_owners'], 'NATIVE_REQUESTED')
        require(len(owners) <= application.execution_witness_budget(len(parent), len(transactions)),
                'NATIVE_ACCOUNT_BUDGET')
        account_values = archive.accounts_from_state(parent)
        expected_proof, root = multiproof.from_full_accounts(account_values,
            archive.hash_bytes(checkpoint['id']), owners)
        require(root == archive.hash_bytes(checkpoint['account_root']), 'NATIVE_ACCOUNT_ROOT')
        equal(row['account_proof'], expected_proof, 'NATIVE_ACCOUNT_PROOF')
        encoded = multiproof.encode_proof(expected_proof)
        require(application.hex_bytes(row['account_proof_hex']) == encoded, 'NATIVE_ACCOUNT_PROOF_BYTES')
        checked = multiproof.verify_proof(expected_proof, archive.hash_bytes(checkpoint['id']),
                                          root, len(account_values))
        output = application.transition(parent, transactions, height, miner, parent_id, context, checked)
        equal(output, discovery, 'NATIVE_M06_REFERENCE')
        access = application.AccountAccess(parent, checked)
        application.capacity(parent, height-1, context, access)
        mandatory, mandatory_receipts = application.mandatory(parent, height, context, access)
        equal(row['mandatory_state'], mandatory, 'NATIVE_MANDATORY_STATE')
        equal(row['successor_state'], output['state'], 'NATIVE_SUCCESSOR_STATE')
        expected_state = state_observation(context, checkpoint, parent, height, miner,
                                          mandatory, mandatory_receipts, output, expected_proof)
        equal(row['state_observation'], expected_state, 'NATIVE_STATE_OBSERVATION')
        packet = application.hex_bytes(row['packet_hex'])
        identity = application.verify_packet(packet, transactions, output, context, parent_id, height, miner)
        require(identity == archive.hash_bytes(row['admitted_id']), 'NATIVE_PACKET')

        if height in (3, 4):
            wanted_expiries = 16 if height == 3 else 2
            require(len(mandatory_receipts) == wanted_expiries, 'FIXTURE_EXPIRY')
            remaining = sum(value['remaining'] for key, value in mandatory.items() if key.startswith('task:'))
            require(remaining == (2_000 if height == 3 else 0), 'FIXTURE_FUTURE_TASKS')
        if height <= 20:
            require(recipient_key not in parent and recipient_key not in output['state'],
                    'FIXTURE_EARLY_REWARD_ACCOUNT')
        else:
            require(recipient_key not in parent and recipient in checked and checked[recipient] is None,
                    'FIXTURE_REWARD_ABSENCE_PROOF')
            require(mandatory[recipient_key]['balance'] > 0
                    and mandatory[recipient_key]['nonce'] == 0
                    and output['state'][recipient_key]['nonce'] == 1
                    and output['state'][recipient_key]['balance']
                    == mandatory[recipient_key]['balance'] - 1 - output['fees'],
                    'FIXTURE_MATURITY_SPEND')
        blocks.append(dict(label=row['label'], height=height, parent=parent_id.hex(),
            admitted_id=identity.hex(), transactions=len(transactions), requested_accounts=len(owners),
            account_proof_bytes=len(encoded), range_observation=ranges['observation'],
            complete_ranges=ranges['ranges'], mandatory_receipts=len(mandatory_receipts),
            mandatory_state_root=bytes(expected_state['mandatory']['commitment']['state_root']).hex(),
            successor_state_root=bytes(output['root']).hex(),
            parent_monetary_rows=len(ranges['monetary'])))
        signed_count += len(transactions)
        expiry_count += len(mandatory_receipts)
        checkpoint, _ = archive.derive_checkpoint(context.as_json(), identity,
            archive.hash_bytes(checkpoint['id']), height, archive.hash_bytes(output['root']),
            archive.accounts_from_state(output['state']))
        parent, parent_id = output['state'], identity
    require(signed_count == 37 and expiry_count == 18, 'FIXTURE_TOTALS')
    return dict(schema=SCHEMA, native_schema=NATIVE_SCHEMA, result='PASS',
        independent_genesis_checked=True, signed_application_transactions_checked=signed_count,
        complete_blocks_checked=21, packet_commitments_checked=21,
        canonical_range_proofs_checked=21, canonical_aam1_proofs_checked=21,
        mandatory_and_successor_state_roots_checked=42, expiries_replayed=expiry_count,
        absent_reward_recipient_matured_and_spent=True,
        final_state_root=state_witness.state_root(parent).hex(),
        block_observations=blocks, scope=dict(SCOPE), native_scope=dict(NATIVE_SCOPE))


def native_negative_controls(observed):
    """Three mutations of an already independently replayed native fixture.

    Each counterexample is consumed by the real complete reader. These are
    Python reexecutions, not additional native tests or native admission runs.
    """
    controls = []
    def reject(label, changed, code, **detail):
        try:
            check_observation_data(changed)
        except ValueError as error:
            require(str(error) == code, 'NEGATIVE_REJECTION:' + label + ':' + str(error))
            controls.append(dict(label=label, result='REJECTED', error=str(error),
                changed_observation_sha256=sha256(json_bytes(changed)).hexdigest(), **detail))
        else:
            raise ValueError('OBLIGATION_RANGE_NEGATIVE_ACCEPTED:' + label)

    changed = copy.deepcopy(observed)
    changed['blocks'][0]['range_observation']['proof_json_bytes'] += 1
    reject('reported-range-byte-count', changed, 'OBLIGATION_RANGE_NATIVE_RANGE_OBSERVATION')

    changed = copy.deepcopy(observed)
    final = changed['blocks'][20]
    owner = list(application.development_public(999))
    matches = [row for row in final['account_proof']['accounts'] if row['owner'] == owner]
    require(len(matches) == 1 and matches[0]['account'] is None, 'NEGATIVE_ABSENT_INPUT')
    matches[0]['account'] = dict(balance=0, nonce=0)
    reject('maturity-absence-changed-to-present-zero', changed, 'OBLIGATION_RANGE_NATIVE_ACCOUNT_PROOF')

    # A real future obligation is hidden behind a correct Merkle frontier. All
    # remaining leaves are authentic and the unchanged root still reconstructs;
    # only completeness, rather than membership alone, exposes the omission.
    changed = copy.deepcopy(observed)
    block = changed['blocks'][2]
    proof = block['range_proof']
    future = next(row for row in proof['rows'] if row['key'].startswith('task:')
                  and row['value']['deadline'] > block['height'] and row['value']['remaining'] > 0)
    source = source_rows(state_witness.non_accounts(block['parent_state']))
    details = index_details(source)
    require(details['root'] == archive.hash_bytes(proof['index_root']), 'NEGATIVE_ORIGINAL_ROOT')
    selected = {row['rank'] for row in proof['rows']} - {future['rank']}
    proof['rows'] = [row for row in proof['rows'] if row['rank'] in selected]
    proof['frontier'] = []
    def subset(first, count):
        if not any(rank in selected for rank in range(first, first + count)):
            proof['frontier'].append(dict(first=first, count=count,
                digest=list(details['digests'][first, count])))
        elif count > 1:
            left = count // 2
            subset(first, left)
            subset(first + left, count-left)
    subset(0, len(source))
    leaves = {row['rank']: row for row in proof['rows']}
    frontier = {(row['first'], row['count']): archive.hash_bytes(row['digest'])
                for row in proof['frontier']}
    def membership(first, count):
        if (first, count) in frontier:
            return frontier[first, count]
        if count == 1:
            row = leaves[first]
            return archive.digest(b'monetary-obligation-range-leaf-v1',
                first.to_bytes(4, 'little'), row['key'].encode('utf-8'), archive.canonical(row['value']))
        left = count // 2
        return archive.digest(b'monetary-obligation-range-node-v1',
            first.to_bytes(4, 'little'), count.to_bytes(4, 'little'),
            membership(first, left), membership(first+left, count-left))
    root = membership(0, len(source))
    require(root == details['root'], 'NEGATIVE_SUBSET_MEMBERSHIP')
    reject('authentic-subset-omits-future-task', changed, 'OBLIGATION_RANGE_COMPLETE_ROWS',
           omitted_key=future['key'], omitted_rank=future['rank'],
           original_index_root=root.hex(), authentic_subset_membership_recomputed=True)
    return controls


def check_observation(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= MAX_INPUT_BYTES, 'INPUT_BUDGET')
    raw = path.read_bytes()
    before = sha256(raw).hexdigest()
    observed = strict_json(raw)
    result = check_observation_data(observed)
    result['python_negative_controls'] = native_negative_controls(observed)
    require(sha256(path.read_bytes()).hexdigest() == before, 'INPUT_MUTATED')
    result['native_json_sha256'] = before
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native_json', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve() != args.native_json.resolve(), 'OUTPUT_COLLISION')
    try:
        report = check_observation(args.native_json)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        report = dict(schema=SCHEMA, result='FAIL', error_type=type(error).__name__,
                      error=str(error), scope=dict(SCOPE))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(result=report['result'], output=str(args.output)), sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
