#!/usr/bin/env python3
"""Read-only mathematical current-root check of an exported native GSC2 store.

No native execution, W1/signature replay, compilation identity, bounded witness,
physical durability, external operator or production qualification is supplied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
from urllib.parse import quote

from gsc2_independent_vectors import encode, h, sparse_root

SCHEMA = 'pon-native-growth-reference-readback-v2'
MAX_ACCOUNTS, MAX_WORKING = 1000000, 65536
MAX_KEYS = MAX_ACCOUNTS + MAX_WORKING
MAX_U64 = (1 << 64) - 1
COMMIT_HASH_FIELDS = ('network', 'parameters', 'account_root', 'working_root')
COMMIT_NUMBER_FIELDS = ('account_count', 'account_balance', 'maximum_permanent_accounts',
                       'working_count', 'maximum_working_keys', 'escrow_balance', 'reward_balance', 'issued')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, name):
    require(type(value) is int and 0 <= value <= MAX_U64, name + ': u64 required')
    return value


def digest(value, name):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            name + ': canonical 32-byte hex required')
    return bytes.fromhex(value)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def no_float(value):
    raise ValueError('floating or non-finite JSON number: ' + value)


def load(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_float=no_float, parse_constant=no_float)


def grammar(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(1 << 63) <= value <= MAX_U64, 'canonical integer range')
    elif type(value) is str:
        require(value.isascii(), 'canonical value string must be ASCII')
    elif type(value) is list:
        for item in value:
            grammar(item)
    elif type(value) is dict:
        for key, item in value.items():
            require(type(key) is str and key.isascii(), 'canonical object key must be ASCII')
            grammar(item)
    else:
        raise ValueError('unsupported canonical value')


def canonical(value):
    grammar(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def file_identities(database):
    result = {}
    for path in (database, Path(str(database) + '-wal')):
        require(not path.is_symlink(), 'regular database/WAL files required')
        if not path.exists():
            continue
        require(path.is_file(), 'regular database/WAL files required')
        size = path.stat().st_size
        # A mode=ro WAL reader may create an empty WAL alongside the database.
        # It contains no transaction bytes; keep pinning every nonempty WAL.
        if path != database and size == 0:
            continue
        result[path.name] = {'bytes': size, 'sha256': sha(path)}
    return result


def ddl_from_source(root):
    store = (root / 'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
    ancestry = (root / 'trillionnium/crates/trnm-pon-node/src/ancestry_index.rs').read_text()
    base = re.search(r'const BASE_DDL\s*:\s*&str\s*=\s*"(.*?)";', store, re.S)
    index = re.search(r'const DDL\s*:\s*&str\s*=\s*"(.*?)";', ancestry, re.S)
    require(base is not None and index is not None, 'literal native DDL inputs required')
    text = base.group(1) + index.group(1)
    require('\\' not in text and text.isascii(), 'unsupported escaped/non-ASCII DDL literal')
    return text


def schema_from_source(root):
    return h('native-growth-reference-branch-schema-v2', ddl_from_source(root).encode())


def expected_sqlite_schema(root):
    with sqlite3.connect(':memory:') as expected:
        expected.executescript(ddl_from_source(root))
        return {row[0]: row for row in expected.execute(
            'SELECT name,type,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL')}


def verify_actual_schema(connection, expected):
    # Bound Python copies. SQLite can already have materialized schema text while
    # opening the file; this does not claim a SQLite page or process-RSS bound.
    limits = tuple(max(len(row[i].encode()) for row in expected.values()) for i in range(4))
    columns = ','.join('typeof({0}),length(CAST({0} AS BLOB)),substr(CAST({0} AS BLOB),1,{1})'.format(
        field, limit + 1) for field, limit in zip(('name', 'type', 'tbl_name', 'sql'), limits))
    rows = connection.execute('SELECT ' + columns + ' FROM sqlite_master WHERE sql IS NOT NULL LIMIT ?',
                              (len(expected) + 1,)).fetchall()
    require(len(rows) == len(expected), 'actual SQLite schema object count mismatch')
    actual = {}
    for row in rows:
        fields = []
        for i, limit in enumerate(limits):
            kind, length, raw = row[3 * i:3 * i + 3]
            require(kind == 'text' and type(length) is int and length <= limit
                    and type(raw) is bytes and len(raw) == length, 'actual SQLite schema field bound/type')
            fields.append(raw.decode('utf-8'))
        require(fields[0] not in actual, 'duplicate actual SQLite schema name')
        actual[fields[0]] = tuple(fields)
    require(actual == expected, 'actual SQLite schema differs from source DDL')


def sequence_root(tag, values):
    leaves = [h(tag + '-leaf', struct.pack('<Q', i), value) for i, value in enumerate(values)]
    if not leaves:
        return h(tag + '-empty')
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [h(tag + '-node', leaves[i], leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def packet_header(raw):
    require(type(raw) is bytes and 320 + 49188 <= len(raw) <= 1048576, 'packet byte bound')
    header = raw[:318]
    require(header[:6] == b'PNH1\x01\x00', 'header codec')
    count = int.from_bytes(raw[318:320], 'little')
    require(count <= 256, 'packet transaction count')
    position, transactions = 320, []
    for _ in range(count):
        require(position + 2 <= len(raw), 'truncated transaction length')
        length = int.from_bytes(raw[position:position + 2], 'little')
        position += 2
        require(159 <= length <= 2048 and position + length <= len(raw), 'transaction byte bound')
        transactions.append(raw[position:position + length])
        position += length
    require(len(raw) - position == 49188 and raw[position:position + 4] == b'PNW1', 'proof framing')
    require(sequence_root('transactions', transactions) == header[182:214], 'transaction sequence root')
    return {'network': header[6:38], 'parameters': header[38:70], 'parent': header[70:102],
            'height': int.from_bytes(header[102:110], 'little'), 'state_root': header[214:246],
            'id': h('block', header, raw[-32:]), 'transactions': len(transactions)}


def readback(directory, source_root, minimum_accounts):
    receipt_path = directory / 'native.json'
    require(receipt_path.is_file() and not receipt_path.is_symlink() and receipt_path.stat().st_size <= 262144,
            'bounded regular native.json required')
    receipt_bytes = receipt_path.read_bytes()
    receipt = load(receipt_bytes)
    require(receipt['schema'] == SCHEMA and receipt['database'] == 'store/native.sqlite'
            and receipt['state_backend'] == 'growth-complete-state-reference-v2', 'native artifact schema/profile')
    for key in ('bounded_witness_qualified', 'production_activation'):
        require(receipt[key] is False, 'unsupported qualification: ' + key)
    for key in ('git_head_at_execution', 'git_tree_at_execution'):
        require(type(receipt[key]) is str and re.fullmatch('[0-9a-f]{40}', receipt[key]) is not None, key)
    require(type(receipt['git_reported_clean_at_execution']) is bool, 'Git cleanliness observation type')
    context = {key: digest(receipt['context'][key], key) for key in ('network', 'parameters', 'genesis')}
    schema = schema_from_source(source_root)
    expected_schema = expected_sqlite_schema(source_root)
    require(digest(receipt['storage_schema'], 'storage_schema') == schema, 'source-selected schema mismatch')
    database = directory / receipt['database']
    require(database.is_file() and not database.is_symlink(), 'regular exported database required')
    before_files = file_identities(database)
    connection = sqlite3.connect('file:' + quote(str(database.resolve()), safe='/') + '?mode=ro', uri=True)
    try:
        connection.execute('PRAGMA query_only=ON')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('BEGIN')
        verify_actual_schema(connection, expected_schema)
        require(connection.execute('SELECT COUNT(*) FROM active').fetchone()[0] == 1, 'one active row required')
        active = connection.execute('SELECT tip,generation,state_slot FROM active WHERE singleton=1').fetchone()
        require(active is not None, 'active singleton absent')
        tip, generation, slot = active
        require(type(tip) is bytes and len(tip) == 32, 'active tip width')
        uint(generation, 'generation'); uint(slot, 'slot')
        for key, expected in [('schema', schema), ('parameters', context['parameters']), ('genesis', context['genesis'])]:
            row = connection.execute('SELECT typeof(value),length(value),substr(value,1,33) FROM metadata WHERE key=?', (key,)).fetchone()
            require(row == ('blob', 32, expected), 'metadata context mismatch: ' + key)
        row = connection.execute('SELECT parent,height,typeof(chainwork),length(chainwork),typeof(packet),length(packet),substr(packet,1,1048577),typeof(state_root),length(state_root),substr(state_root,1,33) FROM blocks WHERE id=?', (tip,)).fetchone()
        require(row is not None, 'active block absent')
        parent, height, work_type, work_len, packet_type, packet_len, packet, root_type, root_len, recorded_root = row
        uint(height, 'height')
        require(work_type == 'blob' and work_len == 64 and root_type == 'blob' and root_len == 32, 'active record widths')
        require(type(parent) is bytes and len(parent) == 32 and height > 0, 'readback requires non-genesis tip')
        require(packet_type == 'blob' and packet_len == len(packet) <= 1048576, 'active packet type/length')
        parsed = packet_header(packet)
        require(parsed['id'] == tip and parsed['parent'] == parent and parsed['height'] == height
                and parsed['network'] == context['network'] and parsed['parameters'] == context['parameters']
                and parsed['state_root'] == recorded_root, 'actual header/record/context mismatch')
        count = connection.execute('SELECT COUNT(*) FROM kv WHERE slot=?', (slot,)).fetchone()[0]
        require(type(count) is int and count <= MAX_KEYS, 'total State count bound')
        account_leaves, working_leaves = [], []
        balances = escrow = rewards = 0
        issued = None
        nonce_digest = hashlib.sha256()
        kv_digest = hashlib.sha256()
        cursor = connection.execute('SELECT typeof(key),length(CAST(key AS BLOB)),substr(CAST(key AS BLOB),1,161),typeof(value),length(value),substr(value,1,4097) FROM kv WHERE slot=? ORDER BY key COLLATE BINARY', (slot,))
        for key_type, key_len, key_raw, value_type, value_len, raw in cursor:
            require(key_type == 'text' and key_len <= 160 and type(key_raw) is bytes and len(key_raw) == key_len,
                    'bounded UTF-8 state key')
            require(value_type == 'blob' and value_len <= 4096 and type(raw) is bytes and len(raw) == value_len,
                    'bounded State value bytes')
            key = key_raw.decode('utf-8')
            value = load(raw)
            require(canonical(value) == raw, 'noncanonical actual State bytes')
            kv_digest.update(struct.pack('<I', key_len) + key_raw + struct.pack('<I', value_len) + raw)
            if key.startswith('account:'):
                owner = digest(key[8:], 'account owner')
                require(type(value) is dict and set(value) == {'balance', 'nonce'}, 'account shape')
                amount, nonce = uint(value['balance'], 'balance'), uint(value['nonce'], 'nonce')
                balances = uint(balances + amount, 'balance sum')
                account_leaves.append((h('account-archive-key-v1', owner), h('account-archive-leaf-v1', owner, struct.pack('<Q', amount), struct.pack('<Q', nonce))))
                nonce_digest.update(owner + struct.pack('<Q', nonce))
            else:
                working_leaves.append((h('state-key', key_raw), h('state-leaf', key_raw, raw)))
                if key.startswith(('task:', 'quota:', 'release:')):
                    escrow = uint(escrow + uint(value['remaining'], 'escrow'), 'escrow sum')
                elif key.startswith('reward:'):
                    rewards = uint(rewards + uint(value['amount'], 'reward'), 'reward sum')
                if key == 'meta:issued':
                    issued = uint(value, 'issued')
        require(len(account_leaves) + len(working_leaves) == count, 'complete current KV count')
        require(minimum_accounts <= len(account_leaves) <= MAX_ACCOUNTS and len(working_leaves) <= MAX_WORKING,
                'account/working dimension limit')
        require(issued is not None and uint(balances + escrow + rewards, 'money total') == issued, 'monetary conservation')
        account_root = sparse_root(account_leaves, 'account-archive-empty-v1', 'account-archive-branch-v1')
        working_root = sparse_root(working_leaves, 'state-empty', 'state-node')
        computed = dict(network=context['network'].hex(), parameters=context['parameters'].hex(), account_root=account_root.hex(),
                        account_count=len(account_leaves), account_balance=balances, maximum_permanent_accounts=MAX_ACCOUNTS,
                        working_root=working_root.hex(), working_count=len(working_leaves), maximum_working_keys=MAX_WORKING,
                        escrow_balance=escrow, reward_balance=rewards, issued=issued)
        retained = receipt['commitment']
        require(type(retained) is dict and set(retained) == set(COMMIT_HASH_FIELDS + COMMIT_NUMBER_FIELDS), 'commitment exact fields')
        for key in COMMIT_HASH_FIELDS:
            require(retained[key] == list(bytes.fromhex(computed[key])) and all(type(v) is int for v in retained[key]),
                    'actual commitment hash field mismatch: ' + key)
        for key in COMMIT_NUMBER_FIELDS:
            require(uint(retained[key], key) == computed[key], 'actual commitment number mismatch: ' + key)
        encoded = encode(computed)
        calculated_root = h('native-permanent-account-state-v2', encoded)
        require(receipt['encoded_commitment'] == encoded.hex() and calculated_root == recorded_root,
                'GSC2 encoding or current root mismatch')
        for key in ('before_reopen', 'after_reopen'):
            uint(receipt[key]['generation'], key + '.generation')
            require(receipt[key] == {'tip': tip.hex(), 'generation': generation, 'state_root': calculated_root.hex()}, key + ' mismatch')
        observed = receipt['observation']
        for key, expected in {'schema':'pon-native-growth-reference-observation-v2', **{k:v.hex() for k,v in context.items()},
                              'tip':tip.hex(), 'generation':generation, 'height':height, 'state_root':calculated_root.hex(),
                              'permanent_accounts':len(account_leaves), 'working_keys':len(working_leaves),
                              'maximum_permanent_accounts':MAX_ACCOUNTS, 'maximum_working_keys':MAX_WORKING,
                              'complete_state_required':True, 'bounded_witness_qualified':False, 'production_activation':False}.items():
            require(observed[key] == expected and type(observed[key]) is type(expected), 'observation mismatch: ' + key)
        require(uint(observed['required_permanent_accounts'], 'required_accounts') >= len(account_leaves)
                and observed['required_permanent_accounts'] <= MAX_ACCOUNTS
                and uint(observed['required_working_keys'], 'required_working') >= len(working_leaves)
                and observed['required_working_keys'] <= MAX_WORKING, 'reported reserved dimension bounds')
        require(uint(receipt['initial_accounts'], 'initial_accounts') + uint(receipt['created_by_signed_transfers'], 'created_by_signed_transfers') == len(account_leaves), 'reported account-creation counts')
        require(type(receipt['sender_nonces']) is list and len(receipt['sender_nonces']) == 4, 'sender nonce observation shape')
        for nonce in receipt['sender_nonces']:
            uint(nonce, 'reported sender nonce')
        require(uint(receipt['blocks'], 'blocks') == height
                and uint(receipt['active_permanent_accounts'], 'active_accounts') == len(account_leaves), 'reported height/count')
        require(connection.execute('SELECT tip,generation,state_slot FROM active WHERE singleton=1').fetchone() == active,
                'active snapshot changed')
        connection.rollback()
    finally:
        connection.close()
    after_files = file_identities(database)
    require(before_files == after_files and receipt_path.read_bytes() == receipt_bytes, 'artifact changed during readback')
    return {'schema':'independent-native-gsc2-current-root-readback-v1', 'result':'PASS', 'database_files':before_files,
            'native_json_sha256':hashlib.sha256(receipt_bytes).hexdigest(), 'network':context['network'].hex(),
            'parameters':context['parameters'].hex(), 'genesis':context['genesis'].hex(), 'storage_schema':schema.hex(),
            'tip':tip.hex(), 'generation':generation, 'height':height, 'actual_accounts':len(account_leaves),
            'actual_working_keys':len(working_leaves), 'actual_state_keys':count, 'account_nonce_digest_sha256':nonce_digest.hexdigest(),
            'actual_canonical_kv_sha256':kv_digest.hexdigest(), 'commitment':computed, 'encoded_commitment':encoded.hex(),
            'state_root':calculated_root.hex(), 'historical_65536_key_profile_would_reject':count>65536,
            'git_head_at_execution_as_reported':receipt['git_head_at_execution'],
            'git_tree_at_execution_as_reported':receipt['git_tree_at_execution'],
            'git_reported_clean_at_execution':receipt['git_reported_clean_at_execution'],
            'scope':{'current_complete_state_root_verified':True,'uses_complete_state':True,'reader_executes_native_code':False,
                     'actual_sqlite_schema_matches_source_ddl':True,
                     'full_history_signatures_or_w1_replayed':False,'source_or_compiler_identity_attested':False,
                     'mandatory_liability_reserves_recomputed':False,'declared_sender_nonces_or_creation_history_replayed':False,
                     'boundary_fault_causality_replayed':False,'physical_power_loss_qualified':False,
                     'bounded_witness_qualified':False,'independent_operators_qualified':False,'production_activation':False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--minimum-accounts', type=int, required=True)
    args = parser.parse_args()
    require(0 <= args.minimum_accounts <= MAX_ACCOUNTS, 'minimum account bound')
    try:
        print(json.dumps(readback(args.artifact_dir, args.source_root, args.minimum_accounts), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError, sqlite3.Error) as error:
        print(json.dumps({'schema':'independent-native-gsc2-current-root-readback-v1','result':'FAIL','error':str(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
