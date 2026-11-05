"""Independent arithmetic oracle for the isolated account archive prototype.

The native prototype stores a compressed copy-on-write tree.  This reference
instead groups integer positions at each of all 256 sparse-tree levels.  It does
not import native code, reproduce its insertion/lift algorithm, or treat native
``expected`` fields as answers.  Missing data is distinct from a verified empty
leaf.  These calculations do not implement the M06 executor, authenticate a
consensus checkpoint, or certify native database recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import argparse
import copy
import json
from pathlib import Path
import sqlite3
import sys
import traceback


U64_MAX = (1 << 64) - 1
TREE_BITS = 256
MAX_VIEW_ACCOUNTS = 32
MIN_WITNESS_BYTES = 8261
MAX_WITNESS_BYTES = 8277
HASH_PREFIX = b'TRNM-PON1\0'
KEY_DOMAIN = b'account-archive-key-v1'
LEAF_DOMAIN = b'account-archive-leaf-v1'
EMPTY_DOMAIN = b'account-archive-empty-v1'
BRANCH_DOMAIN = b'account-archive-branch-v1'
RECORD_DOMAIN = b'account-archive-node-record-v1'
CHECKPOINT_DOMAIN = b'account-archive-checkpoint-v1'
SCHEMA = 'pon-account-archive-prototype-v1'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def uint(value):
    require(type(value) is int and 0 <= value <= U64_MAX, 'ARCHIVE_INTEGER')
    return value


def hash_bytes(value):
    """Decode a native serde [u8; 32], without bool/integer coercions."""
    require(type(value) is list and len(value) == 32
            and all(type(item) is int and 0 <= item <= 255 for item in value),
            'ARCHIVE_HASH_BYTES')
    return bytes(value)


def owner_bytes(value):
    require(type(value) is bytes and len(value) == 32, 'ARCHIVE_OWNER')
    return value


def digest(tag, *parts):
    require(type(tag) is bytes and len(tag) <= 65535, 'ARCHIVE_HASH_DOMAIN')
    require(all(type(part) is bytes and len(part) < 1 << 32 for part in parts),
            'ARCHIVE_HASH_PART')
    framed = (HASH_PREFIX + len(tag).to_bytes(2, 'little') + tag
              + b''.join(len(part).to_bytes(4, 'little') + part for part in parts))
    return sha256(framed).digest()


@dataclass(frozen=True)
class Account:
    balance: int
    nonce: int

    def __post_init__(self):
        uint(self.balance)
        uint(self.nonce)

    def as_json(self):
        return dict(balance=self.balance, nonce=self.nonce)


def account(value):
    require(type(value) is dict and set(value) == {'balance', 'nonce'},
            'ARCHIVE_ACCOUNT_FIELDS')
    return Account(value['balance'], value['nonce'])


def accounts_from_state(state):
    """Extract full account values; no missing/zero-nonce tombstone shortcut."""
    require(type(state) is dict, 'ARCHIVE_STATE')
    result = {}
    for key, value in state.items():
        require(type(key) is str, 'ARCHIVE_STATE_KEY')
        if not key.startswith('account:'):
            continue
        encoded = key[len('account:'):]
        require(len(encoded) == 64 and all(char in '0123456789abcdef' for char in encoded),
                'ARCHIVE_STATE_KEY')
        result[bytes.fromhex(encoded)] = account(value)
    return result


def key_path(owner):
    return digest(KEY_DOMAIN, owner_bytes(owner))


def leaf(owner, value):
    require(type(value) is Account, 'ARCHIVE_ACCOUNT')
    return digest(LEAF_DOMAIN, owner_bytes(owner), value.balance.to_bytes(8, 'little'),
                  value.nonce.to_bytes(8, 'little'))


def empty_hashes():
    empty = [bytes(32)] * (TREE_BITS + 1)
    empty[TREE_BITS] = digest(EMPTY_DOMAIN)
    for depth in range(TREE_BITS - 1, -1, -1):
        empty[depth] = digest(BRANCH_DOMAIN, empty[depth + 1], empty[depth + 1])
    return tuple(empty)


EMPTY = empty_hashes()


def full_sparse_details(accounts, queried_owners=()):
    """Build every nonempty level from leaves, without a compressed-tree path.

    Only the current level is retained: O(n + 256q) memory for n accounts and q
    requested proofs.  Construction intentionally hashes unary paths one level
    at a time instead of reusing the native prototype's compression algorithm.
    Siblings have the native depth order, from depth zero to depth 255.
    """
    require(type(accounts) is dict, 'ARCHIVE_ACCOUNTS')
    nodes = {}
    representatives = {}
    records = {}

    def record(raw):
        identity = digest(RECORD_DOMAIN, raw)
        require(identity not in records or records[identity] == raw, 'ARCHIVE_RECORD_COLLISION')
        records[identity] = raw
        return identity

    for owner, value in accounts.items():
        path = key_path(owner)
        position = int.from_bytes(path, 'big')
        require(position not in nodes, 'ARCHIVE_KEY_COLLISION')
        nodes[position] = leaf(owner, value)
        raw = (b'\0' + owner + value.balance.to_bytes(8, 'little')
               + value.nonce.to_bytes(8, 'little'))
        representatives[position] = (record(raw), path)
    queries = tuple(queried_owners)
    require(len(set(queries)) == len(queries), 'ARCHIVE_DUPLICATE_QUERY')
    positions = {owner: int.from_bytes(key_path(owner), 'big') for owner in queries}
    siblings = {owner: [None] * TREE_BITS for owner in queries}
    for depth in range(TREE_BITS, 0, -1):
        for owner, position in positions.items():
            siblings[owner][depth - 1] = nodes.get(position ^ 1, EMPTY[depth])
            positions[owner] = position // 2
        parents = {position // 2 for position in nodes}
        next_representatives = {}
        for parent in parents:
            left = representatives.get(2 * parent)
            right = representatives.get(2 * parent + 1)
            if left is None or right is None:
                next_representatives[parent] = right if left is None else left
            else:
                # Contract unary levels only after constructing their hashes.
                # No common-prefix search, native insertion or lift is used.
                raw = (b'\1' + (depth - 1).to_bytes(2, 'little') + left[1]
                       + left[0] + right[0] + nodes[2 * parent] + nodes[2 * parent + 1])
                next_representatives[parent] = (record(raw), left[1])
        nodes = {
            parent: digest(BRANCH_DOMAIN, nodes.get(2 * parent, EMPTY[depth]),
                           nodes.get(2 * parent + 1, EMPTY[depth]))
            for parent in parents
        }
        representatives = next_representatives
    root_node = representatives[0][0] if representatives else None
    return dict(root=nodes.get(0, EMPTY[0]),
                proofs={owner: tuple(path) for owner, path in siblings.items()},
                root_node=root_node, records=records)


def full_sparse(accounts, queried_owners=()):
    result = full_sparse_details(accounts, queried_owners)
    return result['root'], result['proofs']


def canonical(value):
    """The existing State's ASCII JSON bytes, separately implemented."""
    def visit(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            require(-(1 << 63) <= item <= U64_MAX, 'ARCHIVE_STATE_INTEGER')
        elif type(item) is str:
            require(item.isascii(), 'ARCHIVE_STATE_ASCII')
        elif type(item) is list:
            for child in item:
                visit(child)
        elif type(item) is dict:
            for name, child in item.items():
                require(type(name) is str and name.isascii(), 'ARCHIVE_STATE_ASCII')
                visit(child)
        else:
            raise ValueError('ARCHIVE_STATE_VALUE')
    visit(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('ascii')


def source_state_root(state):
    """Full source State root; not just the extracted account projection."""
    require(type(state) is dict and len(state) <= 65536, 'ARCHIVE_STATE_LIMIT')
    nodes = {}
    for name, value in state.items():
        require(type(name) is str and name.isascii(), 'ARCHIVE_STATE_ASCII')
        key, encoded = name.encode('ascii'), canonical(value)
        require(len(key) <= 160 and len(encoded) <= 4096, 'ARCHIVE_STATE_LIMIT')
        position = int.from_bytes(digest(b'state-key', key), 'big')
        require(position not in nodes, 'ARCHIVE_KEY_COLLISION')
        nodes[position] = digest(b'state-leaf', key, encoded)
    empty = digest(b'state-empty')
    for _ in range(TREE_BITS):
        parents = {position // 2 for position in nodes}
        nodes = {parent: digest(b'state-node', nodes.get(2 * parent, empty),
                                nodes.get(2 * parent + 1, empty)) for parent in parents}
        empty = digest(b'state-node', empty, empty)
    return nodes.get(0, empty)


def context_bytes(context):
    require(type(context) is dict and set(context) == {'network', 'parameters', 'genesis'},
            'ARCHIVE_CONTEXT')
    return b''.join(hash_bytes(context[name]) for name in ['network', 'parameters', 'genesis'])


def optional_hash(value):
    return b'\0' + bytes(32) if value is None else b'\1' + hash_bytes(value)


def checkpoint_unsigned(checkpoint):
    require(type(checkpoint) is dict and set(checkpoint) == {
        'id', 'context', 'branch', 'parent', 'height', 'source_state_root',
        'account_root', 'root_node', 'account_count'}, 'ARCHIVE_CHECKPOINT_FIELDS')
    return (context_bytes(checkpoint['context']) + hash_bytes(checkpoint['branch'])
            + optional_hash(checkpoint['parent']) + uint(checkpoint['height']).to_bytes(8, 'little')
            + optional_hash(checkpoint['source_state_root']) + hash_bytes(checkpoint['account_root'])
            + optional_hash(checkpoint['root_node'])
            + uint(checkpoint['account_count']).to_bytes(8, 'little'))


def checkpoint_record(checkpoint):
    unsigned = checkpoint_unsigned(checkpoint)
    require(len(unsigned) == 275, 'ARCHIVE_CHECKPOINT_LENGTH')
    identity = digest(CHECKPOINT_DOMAIN, unsigned)
    require(identity == hash_bytes(checkpoint['id']), 'ARCHIVE_CHECKPOINT_ID')
    count, reference = checkpoint['account_count'], checkpoint['root_node']
    require((reference is None) == (count == 0), 'ARCHIVE_CHECKPOINT_COUNT')
    require(reference is not None or hash_bytes(checkpoint['account_root']) == EMPTY[0],
            'ARCHIVE_CHECKPOINT_EMPTY')
    return b'AAC1' + identity + unsigned


def derive_checkpoint(context, branch, parent, height, source_root, accounts, queried_owners=()):
    """Derive commitments from input leaves and independently supplied context."""
    context_bytes(context)
    owner_bytes(branch)
    require(parent is None or type(parent) is bytes and len(parent) == 32, 'ARCHIVE_CHECKPOINT')
    require(source_root is None or type(source_root) is bytes and len(source_root) == 32,
            'ARCHIVE_SOURCE_ROOT')
    details = full_sparse_details(accounts, queried_owners)
    checkpoint = dict(
        id=[0] * 32, context=context, branch=list(branch),
        parent=None if parent is None else list(parent), height=uint(height),
        source_state_root=None if source_root is None else list(source_root),
        account_root=list(details['root']),
        root_node=None if details['root_node'] is None else list(details['root_node']),
        account_count=len(accounts))
    checkpoint['id'] = list(digest(CHECKPOINT_DOMAIN, checkpoint_unsigned(checkpoint)))
    return checkpoint, details


def decode_checkpoint(raw):
    require(type(raw) is bytes and len(raw) == 311 and raw[:4] == b'AAC1',
            'ARCHIVE_CHECKPOINT_LENGTH')
    cursor = 4

    def take(length):
        nonlocal cursor
        result = raw[cursor:cursor + length]
        require(len(result) == length, 'ARCHIVE_CHECKPOINT_LENGTH')
        cursor += length
        return result

    def optional():
        flag, value = take(1), take(32)
        require(flag == b'\1' or flag == b'\0' and value == bytes(32),
                'ARCHIVE_CHECKPOINT_OPTION')
        return list(value) if flag == b'\1' else None

    identity = list(take(32))
    context = {name: list(take(32)) for name in ['network', 'parameters', 'genesis']}
    checkpoint = dict(id=identity, context=context, branch=list(take(32)), parent=optional(),
                      height=int.from_bytes(take(8), 'little'), source_state_root=optional(),
                      account_root=list(take(32)), root_node=optional(),
                      account_count=int.from_bytes(take(8), 'little'))
    require(cursor == len(raw) and checkpoint_record(checkpoint) == raw, 'ARCHIVE_CHECKPOINT_RECORD')
    return checkpoint


def decode_node(identity, raw):
    owner_bytes(identity)
    require(type(raw) is bytes and len(raw) in [49, 163], 'ARCHIVE_NODE_LENGTH')
    require(digest(RECORD_DOMAIN, raw) == identity, 'ARCHIVE_NODE_ID')
    if raw[0] == 0:
        require(len(raw) == 49, 'ARCHIVE_NODE_LENGTH')
        owner = raw[1:33]
        value = Account(int.from_bytes(raw[33:41], 'little'), int.from_bytes(raw[41:49], 'little'))
        return dict(depth=256, path=key_path(owner), digest=leaf(owner, value),
                    owner=owner, account=value)
    require(raw[0] == 1 and len(raw) == 163, 'ARCHIVE_NODE_KIND')
    depth = int.from_bytes(raw[1:3], 'little')
    require(depth < TREE_BITS, 'ARCHIVE_NODE_DEPTH')
    left, right, left_hash, right_hash = (raw[offset:offset + 32] for offset in [35, 67, 99, 131])
    return dict(depth=depth, path=raw[3:35], left=left, right=right,
                left_hash=left_hash, right_hash=right_hash,
                digest=digest(BRANCH_DOMAIN, left_hash, right_hash))


def inspect_sqlite(path, context, expected_checkpoints, expected_records, expected_active):
    """Inspect a closed native database.  Recovery itself remains a native test.

    An uncheckpointed WAL is rejected instead of silently ignored by immutable
    SQLite reads.  No PRAGMA that can mutate the source database is issued.
    Every stored record is checked, including retained intermediate COW nodes.
    """
    path = Path(path).resolve()
    require(path.is_file(), 'ARCHIVE_DATABASE_MISSING')
    wal = Path(str(path) + '-wal')
    require(not wal.exists() or wal.stat().st_size == 0, 'ARCHIVE_DATABASE_WAL')
    before = sha256(path.read_bytes()).hexdigest()
    db = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
    try:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        require(names == ['archive_active', 'archive_checkpoints', 'archive_meta', 'archive_nodes'],
                'ARCHIVE_DATABASE_NAMESPACE')
        meta = dict(db.execute('SELECT key,value FROM archive_meta ORDER BY key'))
        require(meta == {'schema': SCHEMA.encode('ascii'), 'context': context_bytes(context)},
                'ARCHIVE_DATABASE_CONTEXT')
        actual_records = {}
        nodes = {}
        for identity, raw in db.execute('SELECT id,data FROM archive_nodes ORDER BY id'):
            owner_bytes(identity)
            require(identity not in actual_records, 'ARCHIVE_DUPLICATE_NODE')
            nodes[identity] = decode_node(identity, raw)
            actual_records[identity] = raw
        for identity, raw in expected_records.items():
            require(identity in actual_records, 'ARCHIVE_DATA_UNAVAILABLE')
            require(actual_records[identity] == raw, 'ARCHIVE_NODE_RECORD')
        for identity, node in nodes.items():
            if identity in expected_records:
                # These exact bytes were already derived by the independent
                # full-level construction, not taken from the native database.
                continue
            if node['depth'] == TREE_BITS:
                continue
            depth = node['depth']
            prefix = int.from_bytes(node['path'], 'big') >> (TREE_BITS - depth)
            for side, name in enumerate(['left', 'right']):
                require(node[name] in nodes, 'ARCHIVE_DATA_UNAVAILABLE')
                child = nodes[node[name]]
                require(child['depth'] > depth, 'ARCHIVE_NODE_CHILD_DEPTH')
                position = int.from_bytes(child['path'], 'big')
                require(position >> (TREE_BITS - depth) == prefix
                        and (position >> (TREE_BITS - depth - 1)) & 1 == side,
                        'ARCHIVE_NODE_CHILD_PREFIX')
                if side == 0:
                    require(child['path'] == node['path'], 'ARCHIVE_NODE_REPRESENTATIVE')
                value = child['digest']
                position >>= TREE_BITS - child['depth']
                # Expand levels by integer parent positions, as in the full-tree
                # reference, rather than calling native compressed-node helpers.
                for child_depth in range(child['depth'], depth + 1, -1):
                    value = (digest(BRANCH_DOMAIN, EMPTY[child_depth], value) if position & 1
                             else digest(BRANCH_DOMAIN, value, EMPTY[child_depth]))
                    position //= 2
                require(value == node[name + '_hash'], 'ARCHIVE_NODE_CHILD_HASH')
        checkpoints = {}
        for identity, branch, raw in db.execute('SELECT id,branch,data FROM archive_checkpoints ORDER BY id'):
            decoded = decode_checkpoint(raw)
            require(hash_bytes(decoded['id']) == identity and hash_bytes(decoded['branch']) == branch,
                    'ARCHIVE_DATABASE_CHECKPOINT_ID')
            require(decoded['context'] == context, 'ARCHIVE_DATABASE_CONTEXT')
            checkpoints[identity] = raw
        require(checkpoints == expected_checkpoints, 'ARCHIVE_DATABASE_CHECKPOINTS')
        rows = list(db.execute('SELECT singleton,checkpoint,generation FROM archive_active'))
        if expected_active is None:
            require(rows == [], 'ARCHIVE_DATABASE_ACTIVE')
        else:
            require(type(expected_active) is dict
                    and set(expected_active) == {'checkpoint', 'generation'}, 'ARCHIVE_DATABASE_ACTIVE')
            generation = uint(expected_active['generation'])
            checkpoint = hash_bytes(expected_active['checkpoint'])
            require(1 <= generation <= (1 << 63) - 1 and checkpoint in checkpoints,
                    'ARCHIVE_DATABASE_ACTIVE')
            require(rows == [(1, checkpoint, generation)], 'ARCHIVE_DATABASE_ACTIVE')
        counts = dict(node_rows=len(actual_records),
                      node_payload_bytes=sum(len(raw) for raw in actual_records.values()),
                      checkpoint_rows=len(checkpoints))
        page_count = db.execute('PRAGMA page_count').fetchone()[0]
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
    finally:
        db.close()
    require(before == sha256(path.read_bytes()).hexdigest(), 'ARCHIVE_DATABASE_MUTATED')
    require(not wal.exists() or wal.stat().st_size == 0, 'ARCHIVE_DATABASE_WAL')
    return dict(counts=counts, database_sha256=before, all_node_records_checked=True,
                page_count=page_count, page_size=page_size, file_bytes=path.stat().st_size,
                native_recovery_reexecuted=False)


def witness_json(checkpoint, owner, value, siblings):
    owner_bytes(checkpoint)
    owner_bytes(owner)
    require(value is None or type(value) is Account, 'ARCHIVE_ACCOUNT')
    require(len(siblings) == TREE_BITS and all(type(item) is bytes and len(item) == 32
                                              for item in siblings), 'ARCHIVE_WITNESS_LENGTH')
    return dict(checkpoint=list(checkpoint), owner=list(owner),
                account=None if value is None else value.as_json(),
                siblings=[list(item) for item in siblings])


def witness_fields(witness):
    if witness is None:
        raise ValueError('ARCHIVE_DATA_UNAVAILABLE')
    require(type(witness) is dict
            and set(witness) == {'checkpoint', 'owner', 'account', 'siblings'},
            'ARCHIVE_WITNESS_FIELDS')
    checkpoint, owner = hash_bytes(witness['checkpoint']), hash_bytes(witness['owner'])
    require(type(witness['siblings']) is list and len(witness['siblings']) == TREE_BITS,
            'ARCHIVE_WITNESS_LENGTH')
    siblings = tuple(hash_bytes(item) for item in witness['siblings'])
    value = None if witness['account'] is None else account(witness['account'])
    return checkpoint, owner, value, siblings


def encode_witness(witness):
    """Exact AAW1 bytes.  Encoding does not authenticate their checkpoint."""
    checkpoint, owner, value, siblings = witness_fields(witness)
    body = b'\0' if value is None else (b'\1' + value.balance.to_bytes(8, 'little')
                                       + value.nonce.to_bytes(8, 'little'))
    return b'AAW1' + checkpoint + owner + body + b''.join(siblings)


def decode_witness(raw):
    require(type(raw) is bytes and len(raw) in [MIN_WITNESS_BYTES, MAX_WITNESS_BYTES]
            and raw[:4] == b'AAW1', 'ARCHIVE_WITNESS_ENCODING')
    flag = raw[68]
    require(flag in [0, 1] and len(raw) == MIN_WITNESS_BYTES + 16 * flag,
            'ARCHIVE_WITNESS_ENCODING')
    value = (None if flag == 0 else Account(int.from_bytes(raw[69:77], 'little'),
                                           int.from_bytes(raw[77:85], 'little')))
    offset = 69 + 16 * flag
    return witness_json(raw[4:36], raw[36:68], value,
                        [raw[start:start + 32] for start in range(offset, len(raw), 32)])


def verify_witness(witness, expected_checkpoint, expected_root, expected_owner):
    """Return Account or proven nonmembership; absent bytes never mean empty."""
    checkpoint, owner, value, siblings = witness_fields(witness)
    owner_bytes(expected_checkpoint)
    owner_bytes(expected_root)
    owner_bytes(expected_owner)
    require(checkpoint == expected_checkpoint, 'ARCHIVE_CHECKPOINT')
    require(owner == expected_owner, 'ARCHIVE_OWNER')
    current = EMPTY[TREE_BITS] if value is None else leaf(owner, value)
    position = int.from_bytes(key_path(owner), 'big')
    for depth in range(TREE_BITS - 1, -1, -1):
        left, right = ((siblings[depth], current) if position & 1
                       else (current, siblings[depth]))
        current = digest(BRANCH_DOMAIN, left, right)
        position //= 2
    require(current == expected_root, 'ARCHIVE_ROOT')
    return value


def require_member(witness, checkpoint, root, owner):
    value = verify_witness(witness, checkpoint, root, owner)
    require(value is not None, 'ARCHIVE_ACCOUNT_ABSENT')
    return value


def load_json(path, max_bytes=64 * 1024 * 1024):
    """Strict evidence decoder; reject duplicate fields and non-JSON numbers."""
    with Path(path).open('rb') as handle:
        raw = handle.read(max_bytes + 1)
    require(len(raw) <= max_bytes, 'ARCHIVE_EVIDENCE_SIZE')

    def object_pairs(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, 'ARCHIVE_DUPLICATE_JSON_KEY')
            result[name] = value
        return result

    def reject_constant(_):
        raise ValueError('ARCHIVE_JSON_NUMBER')

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=reject_constant)


def accounts_from_rows(rows):
    require(type(rows) is list, 'ARCHIVE_ACCOUNT_ROWS')
    result = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'owner', 'account'}, 'ARCHIVE_ACCOUNT_ROWS')
        owner = hash_bytes(row['owner'])
        require(owner not in result, 'ARCHIVE_DUPLICATE_ACCOUNT')
        result[owner] = account(row['account'])
    return result


def point_reads(details, owner):
    """Expected compressed node reads, excluding checkpoint/SQLite page reads."""
    reference = details['root_node']
    target = int.from_bytes(key_path(owner), 'big')
    reads = 0
    while reference is not None:
        node = decode_node(reference, details['records'][reference])
        reads += 1
        depth = node['depth']
        if target >> (TREE_BITS - depth) != int.from_bytes(node['path'], 'big') >> (TREE_BITS - depth):
            break
        if depth == TREE_BITS:
            require(node['owner'] == owner, 'ARCHIVE_KEY_COLLISION')
            break
        side = target >> (TREE_BITS - depth - 1) & 1
        reference = node['right' if side else 'left']
    require(reads <= 257, 'ARCHIVE_NODE_READ_BOUND')
    return reads


def check_queries(queries, checkpoint, accounts, details):
    require(type(queries) is list and 0 < len(queries) <= MAX_VIEW_ACCOUNTS,
            'ARCHIVE_QUERY_BUDGET')
    owners = [hash_bytes(query['owner']) for query in queries]
    require(len(set(owners)) == len(owners), 'ARCHIVE_DUPLICATE_QUERY')
    checked = []
    for owner, query in zip(owners, queries):
        require(type(query) is dict and set(query) == {'owner', 'witness', 'node_reads', 'binary_hex'},
                'ARCHIVE_QUERY_FIELDS')
        expected = witness_json(hash_bytes(checkpoint['id']), owner, accounts.get(owner),
                                details['proofs'][owner])
        require(query['witness'] == expected, 'ARCHIVE_NATIVE_WITNESS')
        decoded = verify_witness(query['witness'], hash_bytes(checkpoint['id']),
                                 details['root'], owner)
        require(decoded == accounts.get(owner), 'ARCHIVE_NATIVE_ACCOUNT')
        encoded = encode_witness(expected)
        require(type(query['binary_hex']) is str and query['binary_hex'] == encoded.hex(),
                'ARCHIVE_NATIVE_WITNESS_BYTES')
        require(decode_witness(encoded) == expected, 'ARCHIVE_WITNESS_ROUND_TRIP')
        reads = uint(query['node_reads'])
        require(reads == point_reads(details, owner), 'ARCHIVE_NATIVE_NODE_READS')
        checked.append(dict(owner=owner.hex(), member=decoded is not None,
                            binary_bytes=len(encoded), node_reads=reads))
    return checked


def successful_observation(observation, schema):
    require(type(observation) is dict and observation.get('schema') == schema,
            'ARCHIVE_OBSERVATION_SCHEMA')
    require(observation.get('result') == 'PASS'
            and not set(observation).intersection({
                'error', 'errors', 'failure', 'exception', 'launch_error', 'timeout'}),
            'ARCHIVE_OBSERVATION_FAILURE')


def storage_counts(records, checkpoint_count):
    return dict(node_rows=len(records), node_payload_bytes=sum(map(len, records.values())),
                checkpoint_rows=checkpoint_count)


def equal_json(actual, expected, code):
    # Python considers True == 1.  Canonical JSON bytes keep their types apart.
    require(canonical(actual) == canonical(expected), code)


def row_snapshot(context, records, checkpoints, active):
    return dict(
        archive_nodes=[dict(id=identity.hex(), data=raw.hex())
                       for identity, raw in sorted(records.items())],
        archive_checkpoints=[dict(id=identity.hex(), branch=hash_bytes(
            decode_checkpoint(raw)['branch']).hex(), data=raw.hex())
            for identity, raw in sorted(checkpoints.items())],
        archive_active=[] if active is None else [dict(singleton=1,
            checkpoint=hash_bytes(active['checkpoint']).hex(), generation=active['generation'])],
        archive_meta=[dict(key='context', value=context_bytes(context).hex()),
                      dict(key='schema', value=SCHEMA.encode('ascii').hex())])


def merge_records(target, additions):
    for identity, raw in additions.items():
        require(identity not in target or target[identity] == raw, 'ARCHIVE_RECORD_COLLISION')
        target[identity] = raw


def hexadecimal(value):
    require(type(value) is str and len(value) % 2 == 0
            and all(char in '0123456789abcdef' for char in value), 'ARCHIVE_HEX')
    return bytes.fromhex(value)


def check_small_observation(observation, database):
    require(type(observation) is dict
            and observation.get('schema') == 'pon-account-archive-native-observation-v1',
            'ARCHIVE_OBSERVATION_SCHEMA')
    require(not set(observation).intersection({
        'error', 'errors', 'failure', 'exception', 'launch_error', 'timeout'}),
        'ARCHIVE_OBSERVATION_FAILURE')
    for name in ['archive_used_for_native_execution', 'protocol_capacity_changed',
                 'public_data_availability_accepted']:
        require(observation.get(name) is False, 'ARCHIVE_SCOPE')
    require(observation.get('reopened') is True, 'ARCHIVE_NATIVE_REOPEN')
    context = observation['context']
    context_bytes(context)
    labels = ['synthetic-empty', 'synthetic-single', 'synthetic-deep', 'synthetic-branch',
              'projection-genesis', 'projection-next']
    snapshots = observation['snapshots']
    require(type(snapshots) is list and [row['label'] for row in snapshots] == labels,
            'ARCHIVE_SNAPSHOT_SET')
    kinds = ['research-update', 'research-update', 'activate', 'cancel-research-update',
             'cancel-activate', 'stale-activate', 'old-branch-witness', 'nonce-rewind',
             'decode-witness', 'decode-witness', 'decode-witness', 'decode-witness',
             'verify-witness', 'missing-node', 'corrupt-node', 'project-successor', 'activate']
    operations = observation['operations']
    require(type(operations) is list and [row['kind'] for row in operations] == kinds,
            'ARCHIVE_OPERATION_SET')
    one, near, absent = (number.to_bytes(32, 'little') for number in [1, 3800, 99])
    prescribed = [{}, {one: Account(10, 7)},
                  {one: Account(10, 7), near: Account(3, 0)}, {one: Account(0, 8)}]
    query_owners = [[one, near], [one, near], [one, near, absent], [one, near]]
    projected_input = operations[15]['input']
    genesis_state, next_state = projected_input['before_state'], projected_input['after_state']
    equal_json(snapshots[4]['state'], genesis_state, 'ARCHIVE_SOURCE_STATE')
    equal_json(snapshots[5]['state'], next_state, 'ARCHIVE_SOURCE_STATE')
    projected_before, projected_after = accounts_from_state(genesis_state), accounts_from_state(next_state)
    require(0 < len(projected_before) < len(projected_after) <= 4096, 'ARCHIVE_SOURCE_ACCOUNTS')
    require(all(owner in projected_after and projected_after[owner].nonce >= value.nonce
                for owner, value in projected_before.items()), 'ARCHIVE_NONCE_REWIND')
    projection_queries = [hash_bytes(query['owner']) for query in snapshots[4]['queries']]
    require(len(projection_queries) == 2 and projection_queries[0] in projected_before
            and projection_queries[1] not in projected_before
            and projected_after.get(projection_queries[1]) == Account(500, 0),
            'ARCHIVE_SOURCE_TRANSFER')
    require(projected_after[projection_queries[0]].nonce == projected_before[projection_queries[0]].nonce + 1,
            'ARCHIVE_SOURCE_TRANSFER')
    prescribed.extend([projected_before, projected_after])
    query_owners.extend([projection_queries, projection_queries])
    branches = [bytes([number]) * 32 for number in [4, 5, 6, 7]]
    branches += [hash_bytes(context['genesis']), hash_bytes(projected_input['branch'])]
    heights = [0, 0, 1, 1, 0, 1]
    parents = [None, None, 1, 1, None, 4]
    expected_checkpoints, details, query_checks = [], [], []
    for index, snapshot in enumerate(snapshots):
        require(set(snapshot) == {'label', 'source_kind', 'state', 'accounts', 'checkpoint', 'queries'},
                'ARCHIVE_SNAPSHOT_FIELDS')
        kind = 'synthetic-account-space' if index < 4 else 'native-node-admitted-state'
        require(snapshot['source_kind'] == kind and (snapshot['state'] is None) == (index < 4),
                'ARCHIVE_SOURCE_KIND')
        require(accounts_from_rows(snapshot['accounts']) == prescribed[index], 'ARCHIVE_NATIVE_ACCOUNTS')
        require([hash_bytes(query['owner']) for query in snapshot['queries']] == query_owners[index],
                'ARCHIVE_QUERY_SET')
        parent = None if parents[index] is None else hash_bytes(expected_checkpoints[parents[index]]['id'])
        source = None if index < 4 else source_state_root(snapshot['state'])
        checkpoint, tree = derive_checkpoint(context, branches[index], parent, heights[index],
                                              source, prescribed[index], query_owners[index])
        equal_json(snapshot['checkpoint'], checkpoint, 'ARCHIVE_NATIVE_CHECKPOINT')
        query_checks.extend(check_queries(snapshot['queries'], checkpoint, prescribed[index], tree))
        expected_checkpoints.append(checkpoint)
        details.append(tree)
    ids = [checkpoint['id'] for checkpoint in expected_checkpoints]
    require(projected_input['parent'] == ids[4] and type(projected_input['height']) is int
            and projected_input['height'] == 1, 'ARCHIVE_SOURCE_PARENT')
    signed = projected_input['signed_transactions_hex']
    require(type(signed) is list and len(signed) == 1 and len(hexadecimal(signed[0])) > 64
            and len(hexadecimal(projected_input['native_packet_hex'])) > len(hexadecimal(signed[0])),
            'ARCHIVE_NATIVE_PACKET_BYTES')
    # This only checks retention of the signed packet.  Its signature, admission,
    # transaction semantics and consensus provenance remain the native evidence.
    live = witness_json(hash_bytes(ids[2]), one, prescribed[2][one], details[2]['proofs'][one])
    old = witness_json(hash_bytes(ids[1]), one, prescribed[1][one], details[1]['proofs'][one])
    encoded_live = encode_witness(live)
    bad_proof = copy.deepcopy(live)
    bad_proof['siblings'][12][0] ^= 1
    bad_bytes = encode_witness(bad_proof)
    bad_decodes = [bytes([encoded_live[0] ^ 1]) + encoded_live[1:],
                   encoded_live[:68] + b'\2' + encoded_live[69:],
                   encoded_live[:-1], encoded_live + b'\0']
    for raw in bad_decodes:
        try:
            decode_witness(raw)
        except ValueError:
            pass
        else:
            raise ValueError('ARCHIVE_NEGATIVE_DECODE')
    for bad, target in [(old, 2), (decode_witness(bad_bytes), 2)]:
        try:
            verify_witness(bad, hash_bytes(ids[target]), details[target]['root'], one)
        except ValueError:
            pass
        else:
            raise ValueError('ARCHIVE_NEGATIVE_WITNESS')
    leaf_raw = b'\0' + one + (10).to_bytes(8, 'little') + (7).to_bytes(8, 'little')
    leaf_id = digest(RECORD_DOMAIN, leaf_raw)
    replacement = leaf_raw[:40] + bytes([leaf_raw[40] ^ 1]) + leaf_raw[41:]
    require(leaf_id in details[2]['records'], 'ARCHIVE_REQUIRED_LEAF')
    deep_update = dict(owner=list(near), before=None, after=Account(3, 0).as_json())
    branch_update = dict(owner=list(one), before=Account(10, 7).as_json(), after=Account(0, 8).as_json())
    active_deep = dict(checkpoint=ids[2], generation=1)
    inputs = [
        dict(parent=ids[1], branch=list(branches[2]), updates=[deep_update]),
        dict(parent=ids[1], branch=list(branches[3]), updates=[branch_update]),
        dict(expected=None, checkpoint=ids[2]),
        dict(parent=ids[2], branch=[8] * 32, updates=[dict(owner=list(near),
            before=Account(3, 0).as_json(), after=Account(0, 1).as_json())], cancel_at_progress_call=3),
        dict(expected=active_deep, checkpoint=ids[3]),
        dict(expected=None, checkpoint=ids[3]),
        dict(expected_checkpoint=ids[2], requested=[list(one)], witnesses=[old]),
        dict(parent=ids[3], branch=[9] * 32, updates=[dict(owner=list(one),
            before=Account(0, 8).as_json(), after=Account(1, 0).as_json())]),
    ]
    inputs += [dict(case=case, binary_hex=raw.hex()) for case, raw in zip(
        ['wrong-magic', 'invalid-presence', 'truncated', 'trailing'], bad_decodes)]
    inputs += [dict(case='wrong-sibling', expected_checkpoint=ids[2], requested=[list(one)],
                    binary_hex=bad_bytes.hex())]
    inputs += [dict(checkpoint=ids[2], owner=list(one), row_id=leaf_id.hex(), original_hex=leaf_raw.hex(),
                    replacement_hex=raw) for raw in [None, replacement.hex()]]
    inputs += [dict(parent=ids[4], branch=list(branches[5]), height=1,
                    before_state=genesis_state, after_state=next_state,
                    signed_transactions_hex=signed, native_packet_hex=projected_input['native_packet_hex']),
               dict(expected=active_deep, checkpoint=ids[5])]
    outcomes = ['PASS', 'PASS', 'PASS', 'Cancelled', 'Cancelled', 'StaleActive',
                'InvalidWitness', 'InvalidTransition'] + ['InvalidWitness'] * 5
    outcomes += ['DataUnavailable', 'CorruptRecord', 'PASS', 'PASS']
    records, checkpoints, active = {}, {}, None

    def add_snapshot(index):
        merge_records(records, details[index]['records'])
        checkpoint = expected_checkpoints[index]
        checkpoints[hash_bytes(checkpoint['id'])] = checkpoint_record(checkpoint)

    add_snapshot(0)
    add_snapshot(1)
    row_checks = []
    for index, operation in enumerate(operations):
        require(set(operation) == {'kind', 'input', 'outcome', 'output', 'before_active', 'after_active',
                                   'before_storage', 'after_storage', 'before_rows', 'after_rows'},
                'ARCHIVE_OPERATION_FIELDS')
        if index == 15:
            # The native full initial projection is persisted outside operation().
            add_snapshot(4)
        equal_json(operation['input'], inputs[index], 'ARCHIVE_OPERATION_INPUT')
        require(operation['outcome'] == outcomes[index], 'ARCHIVE_NATIVE_OUTCOME')
        equal_json(operation['before_active'], active, 'ARCHIVE_NATIVE_ACTIVE')
        equal_json(operation['before_storage'], storage_counts(records, len(checkpoints)),
                   'ARCHIVE_NATIVE_STORAGE')
        before = row_snapshot(context, records, checkpoints, active)
        equal_json(operation['before_rows'], before, 'ARCHIVE_NATIVE_ROWS_BEFORE')
        expected_output = None
        if index in [0, 1]:
            add_snapshot(index + 2)
            expected_output = expected_checkpoints[index + 2]
        elif index in [2, 16]:
            active = dict(checkpoint=ids[2 if index == 2 else 5], generation=1 if index == 2 else 2)
            expected_output = active
        elif index == 15:
            partial = dict(projected_before)
            for owner in sorted(projected_after):
                if partial.get(owner) != projected_after[owner]:
                    partial[owner] = projected_after[owner]
                    # Each actual sequential COW update may retain an intermediate
                    # root.  Derive all its records afresh from the input leaves.
                    merge_records(records, full_sparse_details(partial)['records'])
            add_snapshot(5)
            expected_output = expected_checkpoints[5]
        equal_json(operation['output'], expected_output, 'ARCHIVE_NATIVE_OUTPUT')
        equal_json(operation['after_active'], active, 'ARCHIVE_NATIVE_ACTIVE')
        equal_json(operation['after_storage'], storage_counts(records, len(checkpoints)),
                   'ARCHIVE_NATIVE_STORAGE')
        after = row_snapshot(context, records, checkpoints, active)
        equal_json(operation['after_rows'], after, 'ARCHIVE_NATIVE_ROWS_AFTER')
        row_checks.append(dict(kind=operation['kind'], outcome=outcomes[index],
                               before_sha256=sha256(canonical(before)).hexdigest(),
                               after_sha256=sha256(canonical(after)).hexdigest(),
                               rows_unchanged=before == after))
    equal_json(observation['final_active'], active, 'ARCHIVE_NATIVE_ACTIVE')
    equal_json(observation['final_storage'], storage_counts(records, len(checkpoints)), 'ARCHIVE_NATIVE_STORAGE')
    equal_json(observation['final_rows'], row_snapshot(context, records, checkpoints, active),
               'ARCHIVE_NATIVE_FINAL_ROWS')
    stored = inspect_sqlite(database, context, checkpoints, records, active)
    equal_json(stored['counts'], observation['final_storage'], 'ARCHIVE_NATIVE_STORAGE')
    return dict(schema='pon-account-archive-oracle-observation-v1', result='PASS',
                native_schema=observation['schema'], snapshots_checked=len(snapshots),
                accounts_per_snapshot=[len(values) for values in prescribed],
                witness_checks=len(query_checks), witness_observations=query_checks,
                operation_observations_checked=len(row_checks), operation_observations=row_checks,
                database=stored,
                scope=dict(independent_root_and_proof_arithmetic=True,
                           native_recovery_reexecuted=False, source_transition_authorized=False,
                           production_activation=False, large_account_space_verified=False),
                native_scope=dict(archive_used_for_native_execution=False,
                           protocol_capacity_changed=False, public_data_availability_accepted=False,
                           production_accepted=False))


def check_large_observation(observation, database):
    """Full 65,537-account mathematical comparison; no ledger-growth claim."""
    successful_observation(observation, 'pon-account-archive-large-observation-v1')
    for name in ['actual_ledger_account_growth', 'protocol_capacity_changed',
                 'data_availability_accepted', 'production_accepted']:
        require(observation.get(name) is False, 'ARCHIVE_SCOPE')
    context = {name: [number] * 32 for number, name in enumerate(
        ['network', 'parameters', 'genesis'], 1)}
    equal_json(observation.get('context'), context, 'ARCHIVE_CONTEXT')
    accounts = accounts_from_rows(observation['accounts'])
    prescribed = {index.to_bytes(32, 'little'): Account(index, index % 19)
                  for index in range(65537)}
    require(accounts == prescribed, 'ARCHIVE_LARGE_INPUT')
    del prescribed
    owners = [(index * 2114).to_bytes(32, 'little') for index in range(31)]
    owners.append((100000).to_bytes(32, 'little'))
    require([hash_bytes(query['owner']) for query in observation['queries']] == owners,
            'ARCHIVE_LARGE_QUERIES')
    initial, first = derive_checkpoint(context, digest(b'archive-large-fixture'),
                                       None, 0, None, accounts, owners)
    equal_json(observation['initial'], initial, 'ARCHIVE_NATIVE_CHECKPOINT')
    first_checks = check_queries(observation['queries'], initial, accounts, first)
    changed_owner = (1).to_bytes(32, 'little')
    update = dict(owner=list(changed_owner), before=accounts[changed_owner].as_json(),
                  after=Account(0, 2).as_json())
    equal_json(observation['update'], update, 'ARCHIVE_LARGE_UPDATE')
    after = dict(accounts)
    after[changed_owner] = Account(0, 2)
    successor, second = derive_checkpoint(context, bytes([8]) * 32,
                                          hash_bytes(initial['id']), 1, None, after, [changed_owner])
    equal_json(observation['after_update'], successor, 'ARCHIVE_NATIVE_CHECKPOINT')
    require(hash_bytes(observation['next_query']['owner']) == changed_owner, 'ARCHIVE_LARGE_QUERY')
    second_checks = check_queries([observation['next_query']], successor, after, second)
    require(initial['account_count'] == successor['account_count'] == 65537,
            'ARCHIVE_LARGE_COUNT')
    equal_json(observation['initial_storage'], storage_counts(first['records'], 1),
               'ARCHIVE_NATIVE_STORAGE')
    records = dict(first['records'])
    records.update(second['records'])
    equal_json(observation['after_update_storage'], storage_counts(records, 2),
               'ARCHIVE_NATIVE_STORAGE')
    expected_active = dict(checkpoint=successor['id'], generation=1)
    equal_json(observation['reopened_active'], expected_active, 'ARCHIVE_NATIVE_ACTIVE')
    for name, expected in [('checked_view_accounts', 32), ('node_read_upper_bound', 257),
                           ('maximum_witness_bytes', MAX_WITNESS_BYTES),
                           ('maximum_observed_node_reads', max(row['node_reads'] for row in first_checks))]:
        require(type(observation.get(name)) is int and observation[name] == expected,
                'ARCHIVE_NATIVE_ACCOUNTING')
    checkpoints = {hash_bytes(value['id']): checkpoint_record(value) for value in [initial, successor]}
    stored = inspect_sqlite(database, context, checkpoints, records, expected_active)
    require(stored['counts'] == observation['after_update_storage'], 'ARCHIVE_NATIVE_STORAGE')
    for name, expected in [('sqlite_page_count', stored['page_count']),
                           ('sqlite_page_size', stored['page_size']),
                           ('sqlite_logical_file_bytes', stored['page_count'] * stored['page_size'])]:
        require(type(observation.get(name)) is int and observation[name] == expected,
                'ARCHIVE_NATIVE_SQLITE_SIZE')
    require(stored['file_bytes'] == stored['page_count'] * stored['page_size'],
            'ARCHIVE_NATIVE_SQLITE_SIZE')
    return dict(schema='pon-account-archive-oracle-observation-v1', result='PASS',
                native_schema=observation['schema'], snapshots_checked=2,
                accounts_per_snapshot=[65537, 65537], witness_checks=len(first_checks + second_checks),
                witness_observations=first_checks + second_checks,
                database=stored, initial_storage=observation['initial_storage'],
                after_update_storage=observation['after_update_storage'],
                scope=dict(independent_root_and_proof_arithmetic=True,
                           native_recovery_reexecuted=False, source_transition_authorized=False,
                           production_activation=False, large_account_space_verified=True),
                native_scope=dict(actual_ledger_account_growth=False,
                           protocol_capacity_changed=False, data_availability_accepted=False,
                           production_accepted=False))


def file_digest(path):
    value = sha256()
    with Path(path).open('rb') as handle:
        while block := handle.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def check_observation(native_json, database):
    before = file_digest(native_json)
    observed = load_json(native_json)
    require(type(observed) is dict, 'ARCHIVE_OBSERVATION_SCHEMA')
    schema = observed.get('schema')
    if schema == 'pon-account-archive-native-observation-v1':
        report = check_small_observation(observed, database)
    elif schema == 'pon-account-archive-large-observation-v1':
        report = check_large_observation(observed, database)
    else:
        raise ValueError('ARCHIVE_OBSERVATION_SCHEMA')
    require(file_digest(native_json) == before, 'ARCHIVE_NATIVE_JSON_MUTATED')
    report.update(native_json_sha256=before, database_sha256=report['database']['database_sha256'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-json', required=True, type=Path)
    parser.add_argument('--database', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check_observation(args.native_json, args.database)
    except Exception as error:
        result = dict(schema='pon-account-archive-oracle-observation-v1', result='FAIL',
                      error_type=type(error).__name__, error=str(error), native_recovery_reexecuted=False)
        traceback.print_exc(file=sys.stderr)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
