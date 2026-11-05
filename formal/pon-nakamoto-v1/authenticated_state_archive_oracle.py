"""Independent read-only SQLite reconstruction for the research state archive.

Stored deltas are decoded with exact existence wrappers, then replayed from the
complete genesis snapshot. Every State root, account root, partition aggregate,
checkpoint identity and parent relation is independently recomputed. This does
not execute native recovery, establish public availability or change fork choice.
The finite fixture budget below is separate from the archive's installed limits.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import account_archive_oracle as archive
import account_execution_oracle as application
import state_witness_oracle as state_witness


SCHEMA = 'pon-authenticated-state-archive-v1'
CHECKPOINT_SCHEMA = 'pon-authenticated-state-checkpoint-v1'
ORACLE_SCHEMA = 'pon-authenticated-state-archive-oracle-observation-v1'
NATIVE_SCHEMA = 'pon-authenticated-state-archive-native-observation-v1'
MAX_CHECKPOINTS = 64
MAX_DELTA_ROWS = 131072
MAX_BYTES = 64 * 1024 * 1024
MAX_ROW_BYTES = 32 * 1024 * 1024
MAX_STATE_KEYS = 65536
CHECKPOINT_FIELDS = ('schema', 'id', 'branch', 'parent', 'height', 'commitment',
                     'delta_root', 'delta_count', 'snapshot_digest', 'execution')
COMMITMENT_FIELDS = ('schema', 'network', 'parameters', 'genesis', 'state_root',
                     'account_root', 'account_count', 'account_balance',
                     'non_account_root', 'non_account_count', 'escrow_balance',
                     'reward_balance', 'issued', 'id')
EXECUTION_FIELDS = ('archive_parent', 'native_parent', 'packet_digest',
                    'transactions_root', 'miner', 'receipts')
TABLES = ['authenticated_active', 'authenticated_checkpoints', 'authenticated_deltas',
          'authenticated_meta', 'authenticated_snapshots']


def require(condition, code):
    if not condition:
        raise ValueError(code)


def uint(value, maximum=archive.U64_MAX):
    require(type(value) is int and 0 <= value <= maximum, 'AUTH_ARCHIVE_INTEGER')
    return value


def blob(value, size=None):
    require(type(value) is bytes and (size is None or len(value) == size), 'AUTH_ARCHIVE_BLOB')
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'AUTH_ARCHIVE_FIELDS')
    return {name: value[name] for name in names}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_ROW_BYTES, 'AUTH_ARCHIVE_ROW_BUDGET')
    def object_pairs(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'AUTH_ARCHIVE_DUPLICATE_JSON_KEY')
            result[name] = value
        return result
    def reject(_value):
        raise ValueError('AUTH_ARCHIVE_JSON_NUMBER')
    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=reject)


def context_value(value):
    fields(value, ('network', 'parameters', 'genesis'))
    return SimpleNamespace(**{name: archive.hash_bytes(value[name]) for name in value})


def ordered_commitment(value):
    result = fields(value, COMMITMENT_FIELDS)
    require(archive.hash_bytes(value['id']) == state_witness.commitment_identity(value),
            'AUTH_ARCHIVE_COMMITMENT_ID')
    return result


def ordered_execution(value):
    if value is None:
        return None
    result = fields(value, EXECUTION_FIELDS)
    for name in EXECUTION_FIELDS[:-1]:
        archive.hash_bytes(value[name])
    require(type(value['receipts']) is list and len(value['receipts']) <= MAX_STATE_KEYS + 256,
            'AUTH_ARCHIVE_RECEIPTS')
    for receipt in value['receipts']:
        require(type(receipt) is list and len(receipt) <= 4096
                and all(type(word) is int and 0 <= word <= 255 for word in receipt),
                'AUTH_ARCHIVE_RECEIPTS')
    return result


def ordered_record(value):
    result = fields(value, CHECKPOINT_FIELDS)
    require(value['schema'] == CHECKPOINT_SCHEMA, 'AUTH_ARCHIVE_SCHEMA')
    for name in ('id', 'branch', 'delta_root'):
        archive.hash_bytes(value[name])
    for name in ('parent', 'snapshot_digest'):
        if value[name] is not None:
            archive.hash_bytes(value[name])
    uint(value['height'], (1 << 63) - 1)
    uint(value['delta_count'], 2 * MAX_STATE_KEYS)
    result['commitment'] = ordered_commitment(value['commitment'])
    result['execution'] = ordered_execution(value['execution'])
    initial = value['height'] == 0
    require(initial == (value['parent'] is None)
            == (value['snapshot_digest'] is not None) == (value['execution'] is None),
            'AUTH_ARCHIVE_INITIAL_SHAPE')
    require(not initial or value['delta_count'] == 0, 'AUTH_ARCHIVE_INITIAL_DELTAS')
    return result


def record_identity(value):
    record = ordered_record(value)
    return archive.digest(b'authenticated-state-checkpoint-v1',
                          json_bytes([record[name] for name in CHECKPOINT_FIELDS if name != 'id']))


def record_bytes(value):
    return json_bytes(ordered_record(value))


def stored_value(value):
    if value is None:
        return None
    fields(value, ('value',))
    # Canonical State values are independently restricted to the native integer
    # and ASCII JSON domain; a top-level record key may still contain UTF-8.
    archive.canonical(value['value'])
    return {'value': json.loads(archive.canonical(value['value']))}


def delta_bytes(value):
    fields(value, ('key', 'before', 'after'))
    require(type(value['key']) is str and len(value['key'].encode('utf-8')) <= 160,
            'AUTH_ARCHIVE_DELTA_KEY')
    result = dict(key=value['key'], before=stored_value(value['before']),
                  after=stored_value(value['after']))
    for name in ('before', 'after'):
        if result[name] is not None:
            require(len(archive.canonical(result[name]['value'])) <= 4096,
                    'AUTH_ARCHIVE_DELTA_VALUE')
    require(json_bytes(result['before']) != json_bytes(result['after']),
            'AUTH_ARCHIVE_UNCHANGED_DELTA')
    return json_bytes(result)


def snapshot_bytes(state):
    require(type(state) is dict and len(state) <= MAX_STATE_KEYS, 'AUTH_ARCHIVE_STATE_LIMIT')
    state_witness.state_root(state)
    return json_bytes({key: json.loads(archive.canonical(state[key])) for key in sorted(state)})


def apply_deltas(parent, deltas):
    """Require exact before values, including present null, without a get(None) alias."""
    state = copy.deepcopy(parent)
    previous = None
    for delta in deltas:
        delta_bytes(delta)
        key = delta['key']
        require(previous is None or previous < key, 'AUTH_ARCHIVE_DELTA_ORDER')
        previous = key
        before = None if key not in state else {'value': state[key]}
        require(json_bytes(stored_value(before)) == json_bytes(stored_value(delta['before'])),
                'AUTH_ARCHIVE_DELTA_BEFORE')
        if delta['after'] is None:
            require(not key.startswith('account:'), 'AUTH_ARCHIVE_ACCOUNT_DELETION')
            state.pop(key)
        else:
            if key.startswith('account:'):
                after = archive.account(delta['after']['value'])
                if before is not None:
                    require(after.nonce >= archive.account(before['value']).nonce,
                            'AUTH_ARCHIVE_NONCE_REWIND')
            state[key] = copy.deepcopy(delta['after']['value'])
    require(len(state) <= MAX_STATE_KEYS, 'AUTH_ARCHIVE_STATE_LIMIT')
    return state


def file_digest(path):
    digest = sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_sqlite(path, context_json, limits):
    """Read a closed sidecar through immutable SQLite; never modify or checkpoint it."""
    context = context_value(context_json)
    fields(limits, ('max_checkpoints', 'max_delta_rows', 'max_payload_bytes', 'max_history'))
    for value in limits.values():
        require(uint(value, (1 << 63) - 1) > 0, 'AUTH_ARCHIVE_LIMIT')
    path = Path(path).resolve()
    require(path.is_file(), 'AUTH_ARCHIVE_DATABASE_MISSING')
    require(path.stat().st_size <= 512 * 1024 * 1024, 'AUTH_ARCHIVE_DATABASE_BUDGET')
    wal = Path(str(path) + '-wal')
    require(not wal.exists() or wal.stat().st_size == 0, 'AUTH_ARCHIVE_DATABASE_WAL')
    before_hash = file_digest(path)
    db = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
    try:
        table_count = db.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        require(table_count == len(TABLES), 'AUTH_ARCHIVE_DATABASE_NAMESPACE')
        names = list(db.execute(
            "SELECT substr(name,1,128),length(CAST(name AS BLOB)) FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"))
        require(names == [(name, len(name)) for name in TABLES], 'AUTH_ARCHIVE_DATABASE_NAMESPACE')
        require(db.execute('SELECT count(*) FROM authenticated_meta').fetchone()[0] == 2,
                'AUTH_ARCHIVE_DATABASE_CONTEXT')
        meta = list(db.execute('SELECT substr(key,1,33),length(CAST(key AS BLOB)),typeof(key),'
                               'substr(value,1,97),length(value),typeof(value) '
                               'FROM authenticated_meta ORDER BY key'))
        require(meta == [('context', 7, 'text', context.network + context.parameters + context.genesis,
                          96, 'blob'),
                         ('schema', 6, 'text', SCHEMA.encode('ascii'), len(SCHEMA), 'blob')],
                'AUTH_ARCHIVE_DATABASE_CONTEXT')
        counts = [db.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
                  for name in ('authenticated_checkpoints', 'authenticated_deltas',
                               'authenticated_snapshots', 'authenticated_active')]
        payload = sum(db.execute(f'SELECT coalesce(sum(length(data)),0) FROM {name}').fetchone()[0]
                      for name in ('authenticated_checkpoints', 'authenticated_deltas',
                                   'authenticated_snapshots'))
        require(counts[0] <= min(MAX_CHECKPOINTS, limits['max_checkpoints'])
                and counts[1] <= min(MAX_DELTA_ROWS, limits['max_delta_rows'])
                and counts[2] <= 1 and counts[3] <= 1
                and payload <= min(MAX_BYTES, limits['max_payload_bytes']),
                'AUTH_ARCHIVE_DATABASE_BUDGET')
        records, states, delta_map, snapshots = {}, {}, {}, {}
        branches = set()
        for identity, branch, parent, height, raw in db.execute(
                'SELECT id,branch,parent,height,data FROM authenticated_checkpoints ORDER BY height,id'):
            blob(identity, 32)
            blob(branch, 32)
            if parent is not None:
                blob(parent, 32)
            record = strict_json(blob(raw))
            require(raw == record_bytes(record), 'AUTH_ARCHIVE_CANONICAL_RECORD')
            require(identity == record_identity(record) == archive.hash_bytes(record['id']),
                    'AUTH_ARCHIVE_RECORD_ID')
            require(branch == archive.hash_bytes(record['branch'])
                    and parent == (None if record['parent'] is None else archive.hash_bytes(record['parent']))
                    and uint(height, (1 << 63) - 1) == record['height'], 'AUTH_ARCHIVE_RECORD_COLUMNS')
            require(identity not in records and branch not in branches, 'AUTH_ARCHIVE_RECORD_DUPLICATE')
            require(record['height'] + 1 <= limits['max_history'], 'AUTH_ARCHIVE_HISTORY_BUDGET')
            records[identity] = record
            branches.add(branch)
        for checkpoint, ordinal, raw in db.execute(
                'SELECT checkpoint,ordinal,data FROM authenticated_deltas ORDER BY checkpoint,ordinal'):
            blob(checkpoint, 32)
            require(checkpoint in records, 'AUTH_ARCHIVE_ORPHAN_DELTA')
            values = delta_map.setdefault(checkpoint, [])
            require(uint(ordinal) == len(values), 'AUTH_ARCHIVE_DELTA_ORDINAL')
            value = strict_json(blob(raw))
            require(raw == delta_bytes(value), 'AUTH_ARCHIVE_CANONICAL_DELTA')
            values.append((raw, value))
        for checkpoint, raw in db.execute('SELECT checkpoint,data FROM authenticated_snapshots'):
            blob(checkpoint, 32)
            require(checkpoint in records and checkpoint not in snapshots, 'AUTH_ARCHIVE_ORPHAN_SNAPSHOT')
            state = strict_json(blob(raw))
            require(raw == snapshot_bytes(state), 'AUTH_ARCHIVE_CANONICAL_SNAPSHOT')
            snapshots[checkpoint] = (raw, state)
        derived_bytes = 0
        for identity, record in records.items():
            values = delta_map.get(identity, [])
            require(len(values) == record['delta_count'], 'AUTH_ARCHIVE_DELTA_COUNT')
            require(application.sequence_root('authenticated-state-deltas-v1', [raw for raw, _ in values])
                    == archive.hash_bytes(record['delta_root']), 'AUTH_ARCHIVE_DELTA_ROOT')
            if record['parent'] is None:
                require(archive.hash_bytes(record['branch']) == context.genesis
                        and identity in snapshots and not values, 'AUTH_ARCHIVE_GENESIS')
                raw, state = snapshots[identity]
                require(archive.digest(b'authenticated-state-snapshot-v1', raw)
                        == archive.hash_bytes(record['snapshot_digest']), 'AUTH_ARCHIVE_SNAPSHOT_DIGEST')
            else:
                parent = archive.hash_bytes(record['parent'])
                require(parent in states and records[parent]['height'] + 1 == record['height'],
                        'AUTH_ARCHIVE_PARENT')
                require(identity not in snapshots and archive.hash_bytes(record['execution']['native_parent'])
                        == archive.hash_bytes(records[parent]['branch']), 'AUTH_ARCHIVE_NATIVE_PARENT')
                state = apply_deltas(states[parent], [value for _, value in values])
            expected = state_witness.derive_commitment(state, context)
            require(archive.canonical(record['commitment']) == archive.canonical(expected),
                    'AUTH_ARCHIVE_COMPLETE_COMMITMENT')
            derived_bytes += len(snapshot_bytes(state))
            require(derived_bytes <= MAX_BYTES, 'AUTH_ARCHIVE_DERIVED_STATE_BUDGET')
            states[identity] = state
        active_rows = list(db.execute('SELECT singleton,checkpoint,generation FROM authenticated_active'))
        active = None
        if active_rows:
            singleton, identity, generation = active_rows[0]
            require(type(singleton) is int and singleton == 1 and blob(identity, 32) in records
                    and uint(generation, (1 << 63) - 1) > 0, 'AUTH_ARCHIVE_ACTIVE')
            active = dict(checkpoint=list(identity), generation=generation)
        observation = dict(checkpoint_rows=counts[0], delta_rows=counts[1],
                           snapshot_rows=counts[2], payload_bytes=payload)
    finally:
        db.close()
    require(before_hash == file_digest(path), 'AUTH_ARCHIVE_DATABASE_MUTATED')
    require(not wal.exists() or wal.stat().st_size == 0, 'AUTH_ARCHIVE_DATABASE_WAL')
    return dict(records=records, states=states, active=active, observation=observation,
                database_sha256=before_hash)


def check_operations(operations, checkpoint_ids):
    """Derive the complete fixture's local CAS generations, including inactive B.

    This checks reported operation records against the final database. Actual
    rollback and transaction scheduling are the native tests' separate evidence.
    """
    require(type(checkpoint_ids) is list and len(checkpoint_ids) == 4
            and len(set(checkpoint_ids)) == 4, 'AUTH_ARCHIVE_FIXTURE_CHECKPOINTS')
    for identity in checkpoint_ids:
        blob(identity, 32)
    genesis, a, a2, b = checkpoint_ids
    schedule = [('publish', genesis, True), ('publish', a, True),
                ('publish', a2, True), ('publish', b, False),
                ('activate', b, True), ('activate', genesis, True), ('activate', a2, True)]
    require(type(operations) is list and len(operations) == len(schedule),
            'AUTH_ARCHIVE_OPERATIONS')
    active, published = None, set()
    for row, (kind, identity, selected) in zip(operations, schedule):
        fields(row, ('kind', 'checkpoint', 'active_before', 'active_after'))
        require(row['kind'] == kind and archive.hash_bytes(row['checkpoint']) == identity,
                'AUTH_ARCHIVE_OPERATION_ORDER')
        require(archive.canonical(row['active_before']) == archive.canonical(active),
                'AUTH_ARCHIVE_CAS_BEFORE')
        if kind == 'publish':
            require(identity not in published, 'AUTH_ARCHIVE_DUPLICATE_PUBLICATION')
            published.add(identity)
        require(identity in published, 'AUTH_ARCHIVE_UNPUBLISHED_SELECTION')
        if selected:
            active = dict(checkpoint=list(identity),
                          generation=1 if active is None else uint(active['generation']) + 1)
        require(archive.canonical(row['active_after']) == archive.canonical(active),
                'AUTH_ARCHIVE_CAS_AFTER')
    require(published == set(checkpoint_ids), 'AUTH_ARCHIVE_MISSING_PUBLICATION')
    return active


def check_observation(native_path, database_path):
    native_path, database_path = Path(native_path).resolve(), Path(database_path).resolve()
    native_hash = file_digest(native_path)
    native = archive.load_json(native_path, max_bytes=MAX_BYTES)
    fields(native, ('schema', 'database', 'genesis_timestamp', 'context', 'limits',
                    'checkpoints', 'operations', 'final_active', 'final_observation',
                    'reopened', 'scope'))
    require(native['schema'] == NATIVE_SCHEMA and type(native['genesis_timestamp']) is int
            and native['genesis_timestamp'] == 1 and native['reopened'] is True,
            'AUTH_ARCHIVE_NATIVE_SCHEMA')
    require(native['database'] == database_path.name
            and database_path == native_path.with_suffix('.sqlite'), 'AUTH_ARCHIVE_DATABASE_PATH')
    context = application.derive_context(1)
    require(archive.canonical(native['context']) == archive.canonical(context.as_json()),
            'AUTH_ARCHIVE_NATIVE_CONTEXT')
    expected_limits = dict(max_checkpoints=2048, max_delta_rows=1000000,
                           max_payload_bytes=268435456, max_history=2048)
    require(archive.canonical(native['limits']) == archive.canonical(expected_limits),
            'AUTH_ARCHIVE_NATIVE_LIMITS')
    expected_scope = dict(native_active=list(context.genesis), account_archive_active=None,
        complete_native_execution=True, full_state_reference=True,
        node_backend_changed=False, production_qualification=False)
    require(archive.canonical(native['scope']) == archive.canonical(expected_scope),
            'AUTH_ARCHIVE_NATIVE_SCOPE')
    database = inspect_sqlite(database_path, native['context'], native['limits'])
    rows = native['checkpoints']
    require(type(rows) is list and len(rows) == 4, 'AUTH_ARCHIVE_FIXTURE_CHECKPOINTS')
    records, derived, account_checkpoints, summaries = [], {}, {}, []
    # These are the exact native fixture transactions, independently signed from
    # public development seeds, not transactions supplied as expected answers.
    transaction_plan = [(1, 1, 1000), (2, 2, 500), (1, 3, 700)]
    expected_parents = [None, 0, 1, 0]
    expected_heights = [0, 1, 2, 1]
    for index, row in enumerate(rows):
        fields(row, ('checkpoint', 'state', 'packet_hex', 'archive_parent_checkpoint'))
        fields(row['checkpoint'], ('record',))
        record = ordered_record(row['checkpoint']['record'])
        identity = archive.hash_bytes(record['id'])
        require(identity in database['records']
                and record_bytes(record) == record_bytes(database['records'][identity]),
                'AUTH_ARCHIVE_NATIVE_CHECKPOINT')
        require(record['height'] == expected_heights[index], 'AUTH_ARCHIVE_FIXTURE_HEIGHT')
        parent_index = expected_parents[index]
        if parent_index is None:
            require(record['parent'] is None and row['packet_hex'] is None,
                    'AUTH_ARCHIVE_FIXTURE_GENESIS')
            state = application.derive_genesis(context)
            source_branch, source_height, source_state, source_parent = context.genesis, 0, state, None
            branch = context.genesis
        else:
            parent = records[parent_index]
            parent_id = archive.hash_bytes(parent['id'])
            require(archive.hash_bytes(record['parent']) == parent_id, 'AUTH_ARCHIVE_FIXTURE_PARENT')
            source_branch = archive.hash_bytes(parent['branch'])
            source_height, source_state = parent['height'], derived[parent_id]
            nonce, recipient, amount = transaction_plan[index - 1]
            transactions = [application.signed_transaction(context, 0, nonce, 1,
                application.development_public(recipient) + application.u64(amount))]
            miner = application.development_public(7)
            output = application.transition(source_state, transactions, record['height'], miner,
                                            source_branch, context)
            raw_packet = application.hex_bytes(row['packet_hex'])
            branch = application.verify_packet(raw_packet, transactions, output, context,
                                               source_branch, record['height'], miner)
            execution = record['execution']
            require(archive.hash_bytes(execution['packet_digest']) == archive.digest(
                        b'authenticated-state-native-packet-v1', raw_packet)
                    and archive.hash_bytes(execution['transactions_root']) ==
                        application.sequence_root('transactions', transactions)
                    and archive.hash_bytes(execution['miner']) == miner,
                    'AUTH_ARCHIVE_NATIVE_EXECUTION')
            require(execution['receipts'] == [list(bytes.fromhex(raw)) for raw in output['receipts_hex']],
                    'AUTH_ARCHIVE_NATIVE_RECEIPTS')
            state = output['state']
            source_parent = account_checkpoints[parent_index]['parent']
        require(archive.hash_bytes(record['branch']) == branch, 'AUTH_ARCHIVE_NATIVE_BRANCH')
        require(snapshot_bytes(row['state']) == snapshot_bytes(state)
                == snapshot_bytes(database['states'][identity]), 'AUTH_ARCHIVE_NATIVE_STATE')
        require(archive.canonical(record['commitment']) == archive.canonical(
                    state_witness.derive_commitment(state, context)), 'AUTH_ARCHIVE_NATIVE_COMMITMENT')
        # Reconstruct the supplied AccountArchive source from the independent
        # parent State; no supplied account-root or balance total is an answer.
        expected_source, _ = archive.derive_checkpoint(context.as_json(), source_branch,
            None if source_parent is None else archive.hash_bytes(source_parent), source_height,
            state_witness.state_root(source_state), archive.accounts_from_state(source_state))
        require(archive.canonical(row['archive_parent_checkpoint']) == archive.canonical(expected_source),
                'AUTH_ARCHIVE_ACCOUNT_SOURCE')
        if record['execution'] is not None:
            require(record['execution']['archive_parent'] == expected_source['id'],
                    'AUTH_ARCHIVE_ACCOUNT_SOURCE_ID')
        current_account, _ = archive.derive_checkpoint(context.as_json(), branch,
            None if index == 0 else archive.hash_bytes(expected_source['id']), record['height'],
            state_witness.state_root(state), archive.accounts_from_state(state))
        account_checkpoints[index] = current_account
        records.append(record)
        derived[identity] = state
        summaries.append(dict(checkpoint=record['id'], branch=record['branch'],
            parent=record['parent'], height=record['height'], state_root=record['commitment']['state_root'],
            account_count=record['commitment']['account_count'], delta_count=record['delta_count']))
    identities = [archive.hash_bytes(record['id']) for record in records]
    require(set(identities) == set(database['records']), 'AUTH_ARCHIVE_UNREPORTED_CHECKPOINT')
    active = check_operations(native['operations'], identities)
    require(archive.canonical(active) == archive.canonical(native['final_active'])
            == archive.canonical(database['active']), 'AUTH_ARCHIVE_FINAL_ACTIVE')
    require(archive.canonical(native['final_observation']) == archive.canonical(database['observation']),
            'AUTH_ARCHIVE_FINAL_OBSERVATION')
    require(file_digest(native_path) == native_hash, 'AUTH_ARCHIVE_NATIVE_MUTATED')
    return dict(schema=ORACLE_SCHEMA, result='PASS', native_json_sha256=native_hash,
        database_sha256=database['database_sha256'], checkpoints=summaries,
        signed_transaction_count=3, checked_operation_count=7, final_active=active,
        observation=database['observation'], native_scope=expected_scope,
        scope=dict(independent_signed_application_replay=True, read_only_sqlite_opened=True,
            complete_deltas_roots_and_aggregates=True, original_native_states_compared=True,
            checkpoint_parent_and_cas_records_checked=True, native_recovery_reexecuted=False,
            work_relation_reverified=False, fork_choice_reverified=False,
            public_availability_accepted=False, production_qualification=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native_json', type=Path)
    parser.add_argument('database', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve() not in {args.native_json.resolve(), args.database.resolve()},
            'AUTH_ARCHIVE_OUTPUT_COLLISION')
    try:
        report = check_observation(args.native_json, args.database)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, sqlite3.Error) as error:
        report = dict(schema=ORACLE_SCHEMA, result='FAIL', error=str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(result=report['result'], output=str(args.output)), sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
