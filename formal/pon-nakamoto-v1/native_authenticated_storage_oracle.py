"""Independent, read-only reconstruction of the integrated native state store.

This finite oracle starts at the development genesis, replays the actual ordered
SQLite deltas, and independently reexecutes supported signed application packets.
Full State, account/non-account roots, conservation, record identities, retained
Patricia bytes and active/staged KV values are comparison outputs, never inputs
to the arithmetic. Migration additionally compares every old SQL cell by type
and value, including sqlite_sequence; only metadata.schema may change.

The CLI supports the revision-12 maintenance/public-evaluation-storage2 fixture
and application tags 1--5, 10, 11. It rejects other profiles instead of silently
skipping execution. This is not a W1 verifier, difficulty/fork-choice acceptance,
native crash replay, physical-WAL bound or public/production qualification.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import struct
from types import SimpleNamespace

import account_archive_oracle as archive
import account_execution_oracle as application
import account_multiproof_oracle as multiproof
import state_witness_oracle as state_witness


ROOT = Path(__file__).resolve().parents[2]
NATIVE_SCHEMA = 'pon-native-authenticated-storage-native-observation-v1'
SCHEMA = 'pon-native-authenticated-storage-oracle-observation-v1'
RECORD_SCHEMA = 'pon-native-authenticated-state-record-v1'
RECORD_FIELDS = ('schema', 'id', 'block', 'parent', 'parent_commitment', 'height',
                 'packet_digest', 'state', 'accounts', 'delta_count', 'delta_root')
STATE_FIELDS = ('schema', 'network', 'parameters', 'genesis', 'state_root',
                'account_root', 'account_count', 'account_balance', 'non_account_root',
                'non_account_count', 'escrow_balance', 'reward_balance', 'issued', 'id')
ROOT_FIELDS = ('node', 'digest', 'count', 'balance')
NEW_TABLES = {'archive_nodes', 'native_state_commitments'}
MAX_BLOCKS = 128
MAX_ROWS = 262144
MAX_BYTES = 64 * 1024 * 1024
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_STATE_KEYS = 65536
SQL_I64_MAX = (1 << 63) - 1


def require(condition, code):
    if not condition:
        raise ValueError('NATIVE_STORAGE_' + code)


def uint(value, maximum=archive.U64_MAX):
    require(type(value) is int and 0 <= value <= maximum, 'INTEGER')
    return value


def blob(value, size=None):
    require(type(value) is bytes and (size is None or len(value) == size), 'BLOB')
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), 'FIELDS')
    return {name: value[name] for name in names}


def equal(left, right, code):
    # JSON bool, integer, absent and present null are not interchangeable.
    require(json_bytes(left) == json_bytes(right), code)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def strict_json(raw, maximum=MAX_BYTES):
    require(type(raw) is bytes and len(raw) <= maximum, 'JSON_BUDGET')
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'DUPLICATE_JSON_KEY')
            result[name] = value
        return result
    def reject(_value):
        raise ValueError('NATIVE_STORAGE_JSON_NUMBER')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def state_bytes(value):
    require(type(value) is dict and len(value) <= MAX_STATE_KEYS, 'STATE_LIMIT')
    ordered = {}
    for key in sorted(value):
        require(type(key) is str and len(key.encode('utf-8')) <= 160, 'STATE_KEY')
        raw = archive.canonical(value[key])
        require(len(raw) <= 4096, 'STATE_VALUE')
        ordered[key] = json.loads(raw)
    return json_bytes(ordered)


def state_value(raw):
    value = strict_json(blob(raw))
    require(raw == state_bytes(value), 'CANONICAL_STATE')
    return value


def context_value(value):
    fields(value, ('network', 'parameters', 'genesis'))
    return SimpleNamespace(**{name: archive.hash_bytes(value[name]) for name in value})


def native_hash(value):
    """Native export envelopes use lowercase hex; stored serde records use u8 arrays."""
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            'NATIVE_HASH')
    return bytes.fromhex(value)


def ordered_record(value):
    record = fields(value, RECORD_FIELDS)
    require(record['schema'] == RECORD_SCHEMA, 'RECORD_SCHEMA')
    for name in ('id', 'block', 'delta_root'):
        archive.hash_bytes(record[name])
    for name in ('parent', 'parent_commitment', 'packet_digest'):
        if record[name] is not None:
            archive.hash_bytes(record[name])
    uint(record['height'], SQL_I64_MAX)
    uint(record['delta_count'], 2 * MAX_STATE_KEYS)
    record['state'] = fields(record['state'], STATE_FIELDS)
    require(archive.hash_bytes(record['state']['id']) ==
            state_witness.commitment_identity(record['state']), 'STATE_COMMITMENT_ID')
    record['accounts'] = fields(record['accounts'], ROOT_FIELDS)
    accounts = record['accounts']
    uint(accounts['count'], MAX_STATE_KEYS)
    uint(accounts['balance'])
    archive.hash_bytes(accounts['digest'])
    if accounts['node'] is not None:
        archive.hash_bytes(accounts['node'])
    require((accounts['node'] is None) == (accounts['count'] == 0), 'ACCOUNT_EMPTY')
    require(record['state']['account_root'] == accounts['digest']
            and record['state']['account_count'] == accounts['count']
            and record['state']['account_balance'] == accounts['balance'], 'ACCOUNT_BINDING')
    initial = record['height'] == 0
    require(initial == (record['parent'] is None) == (record['parent_commitment'] is None)
            == (record['packet_digest'] is None), 'RECORD_INITIAL_SHAPE')
    return record


def record_identity(value):
    record = ordered_record(value)
    return archive.digest(b'native-authenticated-state-record-v1',
        json_bytes([record[name] for name in RECORD_FIELDS if name != 'id']))


def record_bytes(value):
    return json_bytes(ordered_record(value))


def delta_bytes(row):
    key, before, after = row
    require(type(key) is str and len(key.encode('utf-8')) <= 160, 'DELTA_KEY')
    require(before != after, 'UNCHANGED_DELTA')
    for raw in (before, after):
        if raw is not None:
            value = strict_json(blob(raw), 4096)
            require(archive.canonical(value) == raw, 'CANONICAL_DELTA')
    return json_bytes([key, None if before is None else list(before),
                      None if after is None else list(after)])


def apply_deltas(parent, rows, detach=False):
    state = copy.deepcopy(parent)
    previous = None
    for row in rows:
        delta_bytes(row)
        key, before, after = row
        require(previous is None or previous < key, 'DELTA_ORDER')
        previous = key
        expected, replacement = (after, before) if detach else (before, after)
        actual = None if key not in state else archive.canonical(state[key])
        require(actual == expected, 'DELTA_BEFORE')
        if replacement is None:
            require(detach or not key.startswith('account:'), 'ACCOUNT_DELETION')
            del state[key]
        else:
            value = strict_json(replacement, 4096)
            if key.startswith('account:'):
                account = archive.account(value)
                if not detach and expected is not None:
                    require(account.nonce >= archive.account(strict_json(expected)).nonce,
                            'NONCE_REWIND')
            state[key] = value
    state_bytes(state)
    return state


def file_digest(path):
    digest = sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def rust_literal(path, name):
    """Read only the exact schema string, never native calculated roots/results."""
    text = path.read_text()
    matches = re.findall(r'\bconst\s+' + re.escape(name) +
                         r'\s*:\s*&str\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', text)
    require(len(matches) == 1, 'DDL_SOURCE')
    escapes = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"'}
    def decode(match):
        require(match[1] in escapes, 'DDL_ESCAPE')
        return escapes[match[1]]
    return re.sub(r'\\(.)', decode, matches[0])


def schema_contract():
    directory = ROOT / 'trillionnium/crates/trnm-pon-node/src'
    source = [(directory / 'store.rs', 'BASE_DDL'),
              (directory / 'ancestry_index.rs', 'DDL'),
              (directory / 'store/native_authenticated.rs', 'DDL')]
    hashes = {str(path.relative_to(ROOT)): file_digest(path) for path, _ in source}
    legacy = ''.join(rust_literal(path, name) for path, name in source[:2])
    native = legacy + rust_literal(*source[2])
    return dict(legacy=legacy, native=native,
        legacy_id=archive.digest(b'native-branch-schema-v2', legacy.encode('utf-8')),
        native_id=archive.digest(b'native-authenticated-branch-schema-v1', native.encode('utf-8')),
        source_sha256=hashes)


def catalog(db):
    return list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                           "WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type,name"))


def expected_catalog(ddl):
    with sqlite3.connect(':memory:') as db:
        db.executescript(ddl)
        return catalog(db)


def readonly(path):
    path = Path(path).resolve()
    require(path.is_file() and path.stat().st_size <= MAX_DATABASE_BYTES, 'DATABASE_BUDGET')
    wal = Path(str(path) + '-wal')
    require(not wal.exists() or wal.stat().st_size == 0, 'DATABASE_WAL')
    return sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)


def table_rows(db):
    """Bounded, typed rows in native column order; all internal sequence cells stay."""
    names = [row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    result, row_count, byte_count = {}, 0, 0
    for name in names:
        require(re.fullmatch('[a-z_]+', name) is not None, 'TABLE_NAME')
        count = db.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
        row_count += uint(count, MAX_ROWS)
        require(row_count <= MAX_ROWS, 'ROW_BUDGET')
        columns = len(db.execute(f'SELECT * FROM {name} LIMIT 0').description)
        require(0 < columns <= 32, 'COLUMN_BUDGET')
        sizes = '+'.join(f'coalesce(length(CAST("{row[1]}" AS BLOB)),0)'
                         for row in db.execute(f'PRAGMA table_info({name})'))
        byte_count += db.execute(f'SELECT coalesce(sum({sizes}),0) FROM {name}').fetchone()[0]
        require(byte_count <= MAX_BYTES, 'PAYLOAD_BUDGET')
        order = ','.join(str(index + 1) for index in range(columns))
        result[name] = list(db.execute(f'SELECT * FROM {name} ORDER BY {order}'))
    return result


def check_nodes(actual, expected):
    nodes = {identity: archive.decode_node(blob(identity, 32), blob(raw))
             for identity, raw in actual.items()}
    for identity, raw in expected.items():
        require(actual.get(identity) == raw, 'ACCOUNT_NODE_BYTES')
    # Validate every retained COW record, also intermediate records unreachable
    # from the final roots. Depth and prefix monotonicity forbid cycles.
    for node in nodes.values():
        if node['depth'] == 256:
            continue
        depth = node['depth']
        prefix = int.from_bytes(node['path'], 'big') >> (256 - depth)
        for side, name in enumerate(('left', 'right')):
            require(node[name] in nodes, 'ACCOUNT_DATA_UNAVAILABLE')
            child = nodes[node[name]]
            require(child['depth'] > depth, 'ACCOUNT_CHILD_DEPTH')
            position = int.from_bytes(child['path'], 'big')
            require(position >> (256 - depth) == prefix
                    and (position >> (255 - depth)) & 1 == side, 'ACCOUNT_CHILD_PREFIX')
            if side == 0:
                require(child['path'] == node['path'], 'ACCOUNT_REPRESENTATIVE')
            value = child['digest']
            position >>= 256 - child['depth']
            for current in range(child['depth'], depth + 1, -1):
                pair = ((archive.EMPTY[current], value) if position & 1
                        else (value, archive.EMPTY[current]))
                value = archive.digest(archive.BRANCH_DOMAIN, *pair)
                position //= 2
            require(value == node[name + '_hash'], 'ACCOUNT_CHILD_HASH')


def check_active(tables, states, blocks, deltas, genesis):
    rows = tables['active']
    require(len(rows) == 1, 'ACTIVE_COUNT')
    singleton, tip, generation, slot = rows[0]
    require(type(singleton) is int and singleton == 1 and blob(tip, 32) in states,
            'ACTIVE_ID')
    uint(generation, SQL_I64_MAX)
    uint(slot, SQL_I64_MAX)
    require(slot <= generation, 'ACTIVE_SLOT')
    kv = {}
    for state_slot, key, raw in tables['kv']:
        uint(state_slot, SQL_I64_MAX)
        require(type(key) is str and key not in kv.setdefault(state_slot, {}), 'KV_KEY')
        value = strict_json(blob(raw), 4096)
        require(archive.canonical(value) == raw, 'KV_VALUE')
        kv[state_slot][key] = value
    require(slot in kv and state_bytes(kv[slot]) == state_bytes(states[tip]), 'ACTIVE_STATE')
    # Reconstruct the reported branch event sequence, without claiming a fresh
    # network fork-choice execution or trusting only active.tip.
    events = {}
    for event_generation, ordinal, kind, block in tables['events']:
        require(1 <= uint(event_generation, SQL_I64_MAX) <= generation, 'EVENT_GENERATION')
        rows = events.setdefault(event_generation, [])
        require(uint(ordinal) == len(rows), 'EVENT_ORDINAL')
        rows.append((kind, blob(block, 32)))
    current = genesis
    require(generation == len(events)
            and all(value == index + 1 for index, value in enumerate(sorted(events))), 'EVENT_HISTORY')
    for rows in events.values():
        current = follow_steps(current, rows, blocks)
    require(current == tip, 'EVENT_ACTIVE')
    reorg = tables['reorg']
    require(len(reorg) <= 1, 'REORG_COUNT')
    pending = False
    expected_slots = {slot}
    if reorg:
        one, old, target, next_generation, cursor, done = reorg[0]
        require(type(one) is int and one == 1 and blob(old, 32) in states
                and blob(target, 32) in states and type(done) is int and done in (0, 1),
                'REORG_SHAPE')
        uint(next_generation, SQL_I64_MAX)
        steps = []
        for ordinal, kind, block in tables['steps']:
            require(uint(ordinal) == len(steps), 'REORG_ORDINAL')
            steps.append((kind, blob(block, 32)))
        require(follow_steps(old, steps, blocks) == target, 'REORG_TARGET')
        require(uint(cursor) <= len(steps), 'REORG_CURSOR')
        if done:
            require(cursor == len(steps) and 0 < next_generation <= generation
                    and events[next_generation] == steps, 'REORG_COMPLETE')
        else:
            pending = True
            require(old == tip and next_generation == generation + 1, 'REORG_GENERATION')
            staged = copy.deepcopy(states[old])
            for kind, block in steps[:cursor]:
                staged = apply_deltas(staged, deltas[block], detach=kind == 0)
            expected_slots.add(next_generation)
            require(next_generation in kv and state_bytes(kv[next_generation]) == state_bytes(staged),
                    'REORG_STAGED_STATE')
    else:
        require(not tables['steps'], 'ORPHAN_STEPS')
    require(set(kv) == expected_slots, 'KV_SLOTS')
    return dict(tip=list(tip), generation=generation, state_slot=slot), pending


def follow_steps(current, rows, blocks):
    attaching = False
    for kind, block in rows:
        require(type(kind) is int and kind in (0, 1) and block in blocks, 'STEP_BLOCK')
        if kind == 0:
            require(not attaching and current == block and blocks[block]['parent'] is not None,
                    'STEP_DETACH')
            current = blocks[block]['parent']
        else:
            attaching = True
            require(blocks[block]['parent'] == current, 'STEP_ATTACH')
            current = block
    return current


def inspect_sqlite(path, context_json, initial, *, authenticated=True, replay_context=None):
    """Low-level reader accepts explicit anchors; the CLI derives its own anchors."""
    context = context_value(context_json)
    initial_bytes = state_bytes(initial)
    contract = schema_contract()
    before = file_digest(path)
    db = readonly(path)
    try:
        require(catalog(db) == expected_catalog(contract['native' if authenticated else 'legacy']),
                'DATABASE_SCHEMA')
        tables = table_rows(db)
    finally:
        db.close()
    require(file_digest(path) == before, 'DATABASE_MUTATED')
    metadata = dict(tables['metadata'])
    require(set(metadata) in ({'schema', 'parameters', 'genesis'},
                              {'schema', 'parameters', 'genesis', 'operator_task_policy'}),
            'METADATA_KEYS')
    require(metadata['schema'] == contract['native_id' if authenticated else 'legacy_id']
            and metadata['parameters'] == context.parameters
            and metadata['genesis'] == context.genesis, 'METADATA_CONTEXT')
    require(0 < len(tables['blocks']) <= MAX_BLOCKS, 'BLOCK_BUDGET')
    blocks, deltas, snapshots, states, records, expected_nodes = {}, {}, {}, {}, {}, {}
    for identity, parent, height, work, packet, root in tables['blocks']:
        blob(identity, 32)
        require(identity not in blocks, 'DUPLICATE_BLOCK')
        if parent is not None:
            blob(parent, 32)
        uint(height, SQL_I64_MAX)
        work = int.from_bytes(blob(work, 64), 'big')
        blob(root, 32)
        if packet is not None:
            blob(packet)
        blocks[identity] = dict(parent=parent, height=height, work=work, packet=packet, root=root)
        deltas[identity] = []
    for identity, key, prior, after in tables['deltas']:
        require(blob(identity, 32) in blocks, 'ORPHAN_DELTA')
        row = (key, prior, after)
        delta_bytes(row)
        deltas[identity].append(row)
    for identity, raw in tables['snapshots']:
        require(blob(identity, 32) in blocks and identity not in snapshots, 'ORPHAN_SNAPSHOT')
        snapshots[identity] = state_value(raw)
    require(context.genesis in snapshots and state_bytes(snapshots[context.genesis]) == initial_bytes,
            'GENESIS_SNAPSHOT')
    if authenticated:
        for identity, raw in tables['native_state_commitments']:
            require(blob(identity, 32) in blocks and identity not in records, 'ORPHAN_COMMITMENT')
            record = strict_json(blob(raw), 16 * 1024)
            require(record_bytes(record) == raw, 'CANONICAL_RECORD')
            require(archive.hash_bytes(record['block']) == identity
                    and archive.hash_bytes(record['id']) == record_identity(record), 'RECORD_ID')
            records[identity] = record
        require(set(records) == set(blocks), 'MISSING_COMMITMENT')
    derived_bytes, signed_count = 0, 0
    observations = []
    for identity, block in sorted(blocks.items(), key=lambda item: (item[1]['height'], item[0])):
        parent, height, raw = block['parent'], block['height'], block['packet']
        rows = deltas[identity]
        if parent is None:
            require(identity == context.genesis and height == 0 and block['work'] == 0
                    and raw is None and rows == [], 'GENESIS_BLOCK')
            state, packet_digest = copy.deepcopy(initial), None
        else:
            require(parent in states and blocks[parent]['height'] + 1 == height, 'PARENT')
            state = apply_deltas(states[parent], rows)
            header, transactions, derived_id = application.decode_packet(raw)
            require(derived_id == identity and header['network'] == context.network
                    and header['parameters'] == context.parameters and header['parent'] == parent
                    and header['height'] == height and header['state'] == block['root']
                    and header['transactions'] == application.sequence_root('transactions', transactions),
                    'PACKET_BINDING')
            target = int.from_bytes(header['target'], 'big')
            require(target > 0 and blocks[parent]['work'] + (1 << 256) // (target + 1)
                    == block['work'] < (1 << 512), 'CHAINWORK_ARITHMETIC')
            packet_digest = list(archive.digest(b'native-authenticated-packet-v1', raw))
            if replay_context is not None:
                output = application.transition(states[parent], transactions, height,
                                                header['miner'], parent, replay_context)
                require(application.verify_packet(raw, transactions, output, replay_context,
                    parent, height, header['miner']) == identity, 'APPLICATION_PACKET')
                require(state_bytes(output['state']) == state_bytes(state), 'APPLICATION_STATE')
                signed_count += len(transactions)
        require(state_witness.state_root(state) == block['root'], 'STATE_ROOT')
        if identity in snapshots:
            require(state_bytes(snapshots[identity]) == state_bytes(state), 'SNAPSHOT_STATE')
        commitment = state_witness.derive_commitment(state, context)
        account_values = archive.accounts_from_state(state)
        details = archive.full_sparse_details(account_values)
        account_root = dict(node=None if details['root_node'] is None else list(details['root_node']),
            digest=list(details['root']), count=len(account_values),
            balance=sum(value.balance for value in account_values.values()))
        if authenticated:
            record = records[identity]
            equal(record['state'], {name: commitment[name] for name in STATE_FIELDS}, 'COMPLETE_COMMITMENT')
            equal(record['accounts'], account_root, 'ACCOUNT_ROOT')
            require(record['parent'] == (None if parent is None else list(parent))
                    and record['height'] == height and record['packet_digest'] == packet_digest
                    and record['parent_commitment'] == (None if parent is None else records[parent]['id']),
                    'RECORD_BINDING')
            require(record['delta_count'] == len(rows) and archive.hash_bytes(record['delta_root']) ==
                    application.sequence_root('native-authenticated-deltas-v1',
                                              [delta_bytes(row) for row in rows]), 'DELTA_ROOT')
            for node, data in details['records'].items():
                require(node not in expected_nodes or expected_nodes[node] == data, 'NODE_COLLISION')
                expected_nodes[node] = data
        derived_bytes += len(state_bytes(state))
        require(derived_bytes <= MAX_BYTES, 'DERIVED_STATE_BUDGET')
        states[identity] = state
        observations.append(dict(block=list(identity), height=height, state=commitment,
                                 account_node=account_root['node'], delta_count=len(rows)))
    require(len(states) == len(blocks), 'UNRECONSTRUCTED_BLOCK')
    active, pending = check_active(tables, states, blocks, deltas, context.genesis)
    if authenticated:
        actual_nodes = dict(tables['archive_nodes'])
        require(len(actual_nodes) == len(tables['archive_nodes']), 'DUPLICATE_ACCOUNT_NODE')
        check_nodes(actual_nodes, expected_nodes)
    require(file_digest(path) == before, 'DATABASE_MUTATED')
    wal = Path(str(Path(path).resolve()) + '-wal')
    require(not wal.exists() or wal.stat().st_size == 0, 'DATABASE_WAL')
    require(contract['source_sha256'] == schema_contract()['source_sha256'], 'DDL_SOURCE_MUTATED')
    return dict(database_sha256=before, tables=tables, states=states, records=records,
        active=active, pending_reorganization=pending, observations=observations,
        signed_transaction_count=signed_count, schema_contract=contract,
        counts=dict(blocks=len(blocks), deltas=len(tables['deltas']), snapshots=len(snapshots),
            state_commitments=len(records), account_nodes=len(tables.get('archive_nodes', [])),
            derived_state_bytes=derived_bytes, retained_tables=len(tables)))


def typed_cell(value):
    if value is None:
        return b'\0'
    if type(value) is int:
        require(-(1 << 63) <= value <= SQL_I64_MAX, 'SQL_INTEGER')
        return b'\1' + value.to_bytes(8, 'little', signed=True)
    if type(value) is float:
        return b'\2' + struct.pack('<d', value)
    if type(value) in (str, bytes):
        raw = value.encode('utf-8') if type(value) is str else value
        return (b'\3' if type(value) is str else b'\4') + len(raw).to_bytes(8, 'little') + raw
    raise ValueError('NATIVE_STORAGE_SQL_TYPE')


def typed_row(row):
    return len(row).to_bytes(8, 'little') + b''.join(typed_cell(value) for value in row)


def table_digest(name, rows):
    raw = name.encode('ascii')
    digest = sha256(b'native-authenticated-migration-table-v1\0'
                    + len(raw).to_bytes(8, 'little') + raw)
    for row in rows:
        digest.update(typed_row(row))
    digest.update(len(rows).to_bytes(8, 'little'))
    return digest.hexdigest()


def compare_migration(source, target):
    original, copied = source['tables'], target['tables']
    require(set(copied) == set(original) | NEW_TABLES and not set(original) & NEW_TABLES,
            'MIGRATION_TABLES')
    summaries = []
    for name, left in original.items():
        right = copied[name]
        require(len(left) == len(right), 'MIGRATION_ROW_COUNT:' + name)
        for old, new in zip(left, right):
            if name == 'metadata' and old[0] == 'schema':
                require(old == ('schema', source['schema_contract']['legacy_id'])
                        and new == ('schema', target['schema_contract']['native_id']),
                        'MIGRATION_SCHEMA')
                continue
            require(typed_row(old) == typed_row(new), 'MIGRATION_VALUE:' + name)
        summaries.append(dict(table=name, rows=len(left), sha256=table_digest(name, left)))
    require(source['active'] == target['active']
            and source['pending_reorganization'] == target['pending_reorganization'],
            'MIGRATION_ACTIVE')
    require(set(source['states']) == set(target['states']), 'MIGRATION_BLOCKS')
    for identity, state in source['states'].items():
        require(state_bytes(state) == state_bytes(target['states'][identity]), 'MIGRATION_STATE')
    return summaries


def check_observation(native_path, database_path, migration_source=None):
    native_path, database_path = Path(native_path).resolve(), Path(database_path).resolve()
    native_json_hash = file_digest(native_path)
    native = strict_json(native_path.read_bytes())
    required = {'schema', 'database', 'genesis_timestamp', 'context', 'initial', 'active', 'blocks'}
    optional = {'reopened', 'migrated', 'receipt', 'scope', 'operations', 'compact_query'}
    require(type(native) is dict and required <= set(native) <= required | optional,
            'NATIVE_FIELDS')
    require(native['schema'] == NATIVE_SCHEMA and native['database'] == database_path.name
            and database_path.parent == native_path.parent, 'NATIVE_SCHEMA')
    timestamp = uint(native['genesis_timestamp'], SQL_I64_MAX)
    require(timestamp > 0, 'GENESIS_TIMESTAMP')
    context = application.derive_context(timestamp)
    fields(native['context'], ('network', 'parameters', 'genesis'))
    require(all(native_hash(native['context'][name]) == getattr(context, name)
                for name in ('network', 'parameters', 'genesis')), 'NATIVE_CONTEXT')
    initial = application.derive_genesis(context)
    require(state_bytes(native['initial']) == state_bytes(initial), 'NATIVE_INITIAL')
    target = inspect_sqlite(database_path, context.as_json(), initial, replay_context=context)
    fields(native['active'], ('tip', 'generation', 'state_slot'))
    native_active = dict(tip=list(native_hash(native['active']['tip'])),
                        generation=uint(native['active']['generation'], SQL_I64_MAX),
                        state_slot=uint(native['active']['state_slot'], SQL_I64_MAX))
    require(archive.canonical(native_active) == archive.canonical(target['active']), 'NATIVE_ACTIVE')
    rows = native['blocks']
    require(type(rows) is list and len(rows) == len(target['states']), 'NATIVE_BLOCKS')
    seen = set()
    for row in rows:
        fields(row, ('id', 'state'))
        identity = native_hash(row['id'])
        require(identity in target['states'] and identity not in seen, 'NATIVE_BLOCK')
        seen.add(identity)
        require(state_bytes(row['state']) == state_bytes(target['states'][identity]), 'NATIVE_STATE')
    query_report = None
    if 'compact_query' in native:
        active_id = bytes(target['active']['tip'])
        query_report = multiproof.checked_native_query(native['compact_query'], context.as_json(),
            active_id, target['records'][active_id]['height'], target['states'][active_id],
            [application.development_public(number) for number in (0, 20, 999)])
    source, preserved = None, None
    if migration_source is not None:
        source = inspect_sqlite(migration_source, context.as_json(), initial,
                                authenticated=False, replay_context=context)
        preserved = compare_migration(source, target)
        if 'receipt' in native:
            receipt = native['receipt']
            require(type(receipt) is dict and receipt.get('profile') ==
                    'native-authenticated-local-migration-v1', 'MIGRATION_RECEIPT')
            comparisons = dict(source_schema=target['schema_contract']['legacy_id'].hex(),
                target_schema=target['schema_contract']['native_id'].hex(),
                genesis=context.genesis.hex(), parameters=context.parameters.hex(),
                retained_blocks=target['counts']['blocks'],
                replayed_blocks=target['counts']['blocks'] - 1,
                replayed_transactions=target['signed_transaction_count'],
                active_tip=bytes(target['active']['tip']).hex(),
                active_generation=target['active']['generation'],
                pending_reorganization=target['pending_reorganization'], preserved_tables=preserved,
                external_owner_operations_executed=0)
            require(set(receipt) == set(comparisons) | {'profile'}, 'MIGRATION_RECEIPT_FIELDS')
            for key, expected in comparisons.items():
                require(archive.canonical(receipt[key]) == archive.canonical(expected),
                        'MIGRATION_RECEIPT:' + key)
    else:
        require(not native.get('migrated', False) and 'receipt' not in native, 'MIGRATION_SOURCE_REQUIRED')
    require(file_digest(native_path) == native_json_hash, 'NATIVE_MUTATED')
    return dict(schema=SCHEMA, result='PASS', native_json_sha256=native_json_hash,
        database_sha256=target['database_sha256'],
        migration_source_sha256=None if source is None else source['database_sha256'],
        context=context.as_json(), counts=target['counts'], active=target['active'],
        pending_reorganization=target['pending_reorganization'],
        signed_transaction_count=target['signed_transaction_count'],
        blocks=target['observations'], preserved_tables=preserved,
        compact_query=query_report,
        schema_source_sha256=target['schema_contract']['source_sha256'],
        native_reported_scope=native.get('scope'),
        scope=dict(read_only_actual_sqlite=True, independent_genesis=True,
            supported_signed_application_replayed=True, complete_state_and_partition_roots=True,
            all_commitment_identities_and_account_nodes_checked=True,
            active_and_pending_reorg_kv_reconstructed=True,
            all_migration_preserved_cells_compared=source is not None,
            maintenance_revision_12_profile_only=True,
            supported_transaction_tags=list(application.SUPPORTED_TAGS),
            compact_query_reverified=query_report is not None,
            work_relation_reverified=False, target_retargeting_reverified=False,
            fork_choice_reexecuted=False, native_crash_recovery_reexecuted=False,
            public_availability_accepted=False, production_qualification=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native_json', type=Path)
    parser.add_argument('database', type=Path)
    parser.add_argument('--migration-source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = {args.native_json.resolve(), args.database.resolve()}
    if args.migration_source is not None:
        inputs.add(args.migration_source.resolve())
    require(args.output.resolve() not in inputs, 'OUTPUT_COLLISION')
    try:
        report = check_observation(args.native_json, args.database, args.migration_source)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, sqlite3.Error) as error:
        report = dict(schema=SCHEMA, result='FAIL', error_type=type(error).__name__, error=str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(result=report['result'], output=str(args.output)), sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
