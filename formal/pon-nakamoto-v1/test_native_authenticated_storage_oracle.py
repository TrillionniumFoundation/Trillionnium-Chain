"""Independent synthetic corruption controls; native fixtures use the CLI.

Packets here have authentic storage framing, but deliberately do not claim W1 or
signed-application validity. The native CLI tests use independently derived
development genesis and real signed transactions, rather than these synthetic
states. Test mutations are confined to temporary SQLite copies.
"""
import copy
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import tempfile
import unittest

import account_archive_oracle as archive
import account_execution_oracle as application
import native_authenticated_storage_oracle as oracle
import state_witness_oracle as state_witness


class StorageFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = oracle.schema_contract()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'native.sqlite'
        self.context_json = dict(network=[1] * 32, parameters=[2] * 32, genesis=[3] * 32)
        self.context = oracle.context_value(self.context_json)
        self.owner = 'account:' + bytes([11] * 32).hex()
        self.other = 'account:' + bytes([12] * 32).hex()
        self.third = 'account:' + bytes([13] * 32).hex()
        self.initial = {self.owner: dict(balance=10, nonce=3), 'meta:issued': 10,
                        'retained:null': None, 'retained:bool': True, 'retained:汉': 7}
        a = copy.deepcopy(self.initial)
        a[self.owner] = dict(balance=5, nonce=4)
        a[self.other] = dict(balance=5, nonce=0)
        del a['retained:null']
        a['retained:new-null'] = None
        a['retained:bool'] = 1
        b = copy.deepcopy(self.initial)
        b[self.owner] = dict(balance=4, nonce=4)
        b[self.third] = dict(balance=4, nonce=0)
        b['reward:' + bytes([14] * 32).hex()] = dict(amount=2, maturity=20,
                                                    owner=bytes([13] * 32).hex())
        self.states = {self.context.genesis: self.initial}
        self.records = {}
        with sqlite3.connect(self.path) as db:
            db.executescript(self.contract['native'])
            db.executemany('INSERT INTO metadata VALUES(?,?)', [
                ('schema', self.contract['native_id']), ('parameters', self.context.parameters),
                ('genesis', self.context.genesis)])
            self.genesis = self.add_block(db, self.initial, None)
            self.a = self.add_block(db, a, self.genesis, target=bytes([127]) + bytes([255]) * 31)
            self.b = self.add_block(db, b, self.genesis, target=bytes([63]) + bytes([255]) * 31)
            db.execute('INSERT INTO snapshots VALUES(?,?)', (self.genesis, oracle.state_bytes(self.initial)))
            db.execute('INSERT INTO snapshots VALUES(?,?)', (self.a, oracle.state_bytes(a)))
            db.execute('INSERT INTO active VALUES(1,?,2,2)', (self.b,))
            db.executemany('INSERT INTO kv VALUES(2,?,?)',
                           [(key, archive.canonical(value)) for key, value in b.items()])
            db.executemany('INSERT INTO events VALUES(?,?,?,?)',
                           [(1, 0, 1, self.a), (2, 0, 0, self.a), (2, 1, 1, self.b)])
            db.execute('INSERT INTO reorg VALUES(1,?,?,2,2,1)', (self.a, self.b))
            db.executemany('INSERT INTO steps VALUES(?,?,?)', [(0, 0, self.a), (1, 1, self.b)])
            # Deleted maximum AUTOINCREMENT rows still leave durable frontiers.
            db.execute('INSERT INTO local_pool_groups VALUES(20,?,3,?)',
                       (bytes([21] * 32), 'test-retained-failure'))
            db.execute('DELETE FROM local_pool_groups WHERE ordinal=20')

    def packet(self, state, parent, height, target, transactions=(), receipts=(), miner=None, task=None):
        values = dict(network=self.context.network, parameters=self.context.parameters,
            parent=parent, height=height, timestamp=height + 1, target=target,
            miner=bytes([7] * 32) if miner is None else miner,
            transactions=application.sequence_root('transactions', transactions),
            state=state_witness.state_root(state), receipts=application.sequence_root('receipts', receipts),
            work_task=bytes([8] * 32) if task is None else task, nonce=0)
        order = ('network', 'parameters', 'parent', 'height', 'timestamp', 'target', 'miner',
                 'transactions', 'state', 'receipts', 'work_task', 'nonce')
        header = b'PNH1\1\0' + b''.join(value if type(value := values[name]) is bytes
                                        else value.to_bytes(8, 'little') for name in order)
        proof = b'PNW1' + bytes(49184)
        raw = (header + len(transactions).to_bytes(2, 'little')
               + b''.join(len(raw).to_bytes(2, 'little') + raw for raw in transactions) + proof)
        return application.decode_packet(raw)[2], raw

    def add_block(self, db, state, parent, target=None, **packet_options):
        if parent is None:
            identity, packet, height, chainwork = self.context.genesis, None, 0, 0
            rows = []
        else:
            height = self.records[parent]['height'] + 1
            identity, packet = self.packet(state, parent, height, target, **packet_options)
            prior_work = db.execute('SELECT chainwork FROM blocks WHERE id=?', (parent,)).fetchone()[0]
            chainwork = int.from_bytes(prior_work, 'big') + (1 << 256) // (int.from_bytes(target, 'big') + 1)
            rows = [(row['key'], None if row['before'] is None else archive.canonical(row['before']['value']),
                     None if row['after'] is None else archive.canonical(row['after']['value']))
                    for row in state_witness.ordered_deltas(self.states[parent], state)]
        db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?)', (identity, parent, height,
            chainwork.to_bytes(64, 'big'), packet, state_witness.state_root(state)))
        self.insert_ancestry(db, identity, parent, height)
        db.executemany('INSERT INTO deltas VALUES(?,?,?,?)', [(identity, *row) for row in rows])
        details = archive.full_sparse_details(archive.accounts_from_state(state))
        db.executemany('INSERT OR IGNORE INTO archive_nodes VALUES(?,?)', details['records'].items())
        record = dict(schema=oracle.RECORD_SCHEMA, id=[0] * 32, block=list(identity),
            parent=None if parent is None else list(parent),
            parent_commitment=None if parent is None else self.records[parent]['id'], height=height,
            packet_digest=None if packet is None else list(archive.digest(b'native-authenticated-packet-v1', packet)),
            state=state_witness.derive_commitment(state, self.context),
            accounts=dict(node=None if details['root_node'] is None else list(details['root_node']),
                digest=list(details['root']), count=len(archive.accounts_from_state(state)),
                balance=sum(value.balance for value in archive.accounts_from_state(state).values())),
            delta_count=len(rows), delta_root=list(application.sequence_root(
                'native-authenticated-deltas-v1', [oracle.delta_bytes(row) for row in rows])))
        record['id'] = list(oracle.record_identity(record))
        db.execute('INSERT INTO native_state_commitments VALUES(?,?)', (identity, oracle.record_bytes(record)))
        self.states[identity] = copy.deepcopy(state)
        self.records[identity] = record
        return identity

    def ancestry_seal(self, row, parent, height):
        identity, level, ancestor, ancestor_height, left, right, _seal = row
        return archive.digest(b'native-derived-ancestry-row-v1', self.context.network,
            self.context.parameters, self.context.genesis, identity, parent,
            height.to_bytes(8, 'little'), bytes([level]), ancestor,
            ancestor_height.to_bytes(8, 'little'), left, right)

    def insert_ancestry(self, db, identity, parent, height):
        # Synthetic fixtures use binary composition of existing SQL jumps.
        # The reader instead walks complete parent paths without consulting them.
        for level in range(height.bit_length()):
            if level == 0:
                ancestor, ancestor_height = parent, height - 1
                left = right = bytes(32)
            else:
                midpoint, left = db.execute(
                    'SELECT ancestor,seal FROM ancestry_jump WHERE block=? AND level=?',
                    (identity, level - 1)).fetchone()
                ancestor, ancestor_height, right = db.execute(
                    'SELECT ancestor,ancestor_height,seal FROM ancestry_jump WHERE block=? AND level=?',
                    (midpoint, level - 1)).fetchone()
            row = (identity, level, ancestor, ancestor_height, left, right, bytes(32))
            db.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)',
                       (*row[:-1], self.ancestry_seal(row, parent, height)))

    def inspect(self, path=None, authenticated=True):
        return oracle.inspect_sqlite(path or self.path, self.context_json, self.initial,
                                     authenticated=authenticated)

    def replace_record(self, identity, record):
        record['id'] = list(oracle.record_identity(record))
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE native_state_commitments SET data=? WHERE block=?',
                       (oracle.record_bytes(record), identity))


class NativeAuthenticatedStorageOracle(StorageFixture):
    def test_full_reconstruction_roots_nodes_snapshots_reorg_and_immutable_bytes(self):
        before = oracle.file_digest(self.path)
        result = self.inspect()
        self.assertEqual(result['states'], self.states)
        self.assertEqual(result['counts']['blocks'], 3)
        self.assertEqual(result['counts']['state_commitments'], 3)
        self.assertEqual(result['counts']['snapshots'], 2)
        self.assertEqual(result['ancestry'], dict(rows=2, blocks=3, max_level=0,
                          complete_parent_graph_reconstructed=True))
        self.assertEqual(result['active'], dict(tip=list(self.b), generation=2, state_slot=2))
        self.assertFalse(result['pending_reorganization'])
        self.assertEqual(result['signed_transaction_count'], 0)
        self.assertEqual(oracle.file_digest(self.path), before)

    def test_explicit_pending_reorg_reconstructs_staged_slot_and_preserves_active(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE active SET tip=?,generation=1,state_slot=0', (self.a,))
            db.execute('DELETE FROM events WHERE generation=2')
            db.execute('UPDATE reorg SET cursor=1,done=0')
            db.execute('DELETE FROM kv')
            db.executemany('INSERT INTO kv VALUES(0,?,?)',
                           [(key, archive.canonical(value)) for key, value in self.states[self.a].items()])
            db.executemany('INSERT INTO kv VALUES(2,?,?)',
                           [(key, archive.canonical(value)) for key, value in self.initial.items()])
        result = self.inspect()
        self.assertTrue(result['pending_reorganization'])
        self.assertEqual(result['active']['tip'], list(self.a))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE kv SET value='null' WHERE slot=2 AND key='meta:issued'")
        with self.assertRaises(ValueError):
            self.inspect()

    def test_null_boolean_absence_and_utf8_delta_values_remain_exact(self):
        rows = [('retained:bool', b'true', b'1'), ('retained:new-null', None, b'null'),
                ('retained:null', b'null', None), ('retained:汉', b'7', b'8')]
        after = oracle.apply_deltas(self.initial, rows)
        self.assertEqual(after['retained:bool'], 1)
        self.assertIsNone(after['retained:new-null'])
        self.assertNotIn('retained:null', after)
        self.assertEqual(after['retained:汉'], 8)
        self.assertEqual(oracle.state_bytes(oracle.apply_deltas(after, rows, detach=True)),
                         oracle.state_bytes(self.initial))
        for wrong in [('retained:null', None, b'1'), ('retained:bool', b'1', None)]:
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'DELTA_BEFORE$'):
                oracle.apply_deltas(self.initial, [wrong])

    def test_rehashed_false_aggregate_is_recomputed_from_full_state(self):
        record = copy.deepcopy(self.records[self.b])
        record['state']['reward_balance'] += 1
        record['state']['issued'] += 1
        record['state']['id'] = list(state_witness.commitment_identity(record['state']))
        self.replace_record(self.b, record)
        with self.assertRaisesRegex(ValueError, 'COMPLETE_COMMITMENT$'):
            self.inspect()

    def test_parent_commitment_and_packet_digest_are_bound(self):
        record = copy.deepcopy(self.records[self.b])
        record['parent_commitment'] = [97] * 32
        self.replace_record(self.b, record)
        with self.assertRaisesRegex(ValueError, 'RECORD_BINDING$'):
            self.inspect()
        record = copy.deepcopy(self.records[self.b])
        record['packet_digest'] = [98] * 32
        self.replace_record(self.b, record)
        with self.assertRaisesRegex(ValueError, 'RECORD_BINDING$'):
            self.inspect()

    def test_changed_delta_cannot_hide_behind_matching_account_leaf(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE deltas SET before=? WHERE block=? AND key=?',
                       (archive.canonical(dict(balance=10, nonce=2)), self.b, self.owner))
        with self.assertRaisesRegex(ValueError, 'DELTA_BEFORE$'):
            self.inspect()

    def test_changed_stored_delta_digest_is_detected(self):
        record = copy.deepcopy(self.records[self.b])
        record['delta_root'] = [99] * 32
        self.replace_record(self.b, record)
        with self.assertRaisesRegex(ValueError, 'DELTA_ROOT$'):
            self.inspect()

    def test_account_existence_and_nonce_monotonicity_are_checked(self):
        before = archive.canonical(self.initial[self.owner])
        for after, code in [(None, 'ACCOUNT_DELETION'),
                            (archive.canonical(dict(balance=10, nonce=2)), 'NONCE_REWIND')]:
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, code + '$'):
                oracle.apply_deltas(self.initial, [(self.owner, before, after)])

    def test_missing_required_node_and_damaged_unreachable_cow_child_are_detected(self):
        root = bytes(self.records[self.b]['accounts']['node'])
        with sqlite3.connect(self.path) as db:
            raw = db.execute('SELECT data FROM archive_nodes WHERE id=?', (root,)).fetchone()[0]
            db.execute('DELETE FROM archive_nodes WHERE id=?', (root,))
        with self.assertRaisesRegex(ValueError, 'ACCOUNT_NODE_BYTES$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO archive_nodes VALUES(?,?)', (root, raw))
            damaged = raw[:35] + bytes([101] * 32) + raw[67:]
            identity = archive.digest(archive.RECORD_DOMAIN, damaged)
            db.execute('INSERT INTO archive_nodes VALUES(?,?)', (identity, damaged))
        with self.assertRaisesRegex(ValueError, 'ACCOUNT_DATA_UNAVAILABLE$'):
            self.inspect()

    def test_missing_historical_commitment_and_orphan_deltas_are_refused(self):
        with sqlite3.connect(self.path) as db:
            raw = db.execute('SELECT data FROM native_state_commitments WHERE block=?', (self.a,)).fetchone()[0]
            db.execute('DELETE FROM native_state_commitments WHERE block=?', (self.a,))
        with self.assertRaisesRegex(ValueError, 'MISSING_COMMITMENT$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO native_state_commitments VALUES(?,?)', (self.a, raw))
            db.execute('INSERT INTO deltas VALUES(?,?,?,?)', (bytes([103] * 32), 'x', None, b'null'))
        with self.assertRaisesRegex(ValueError, 'ORPHAN_DELTA$'):
            self.inspect()

    def test_false_snapshot_and_active_kv_are_not_trusted(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE snapshots SET state=? WHERE block=?',
                       (oracle.state_bytes(self.initial), self.a))
        with self.assertRaisesRegex(ValueError, 'SNAPSHOT_STATE$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE snapshots SET state=? WHERE block=?',
                       (oracle.state_bytes(self.states[self.a]), self.a))
            db.execute('UPDATE kv SET value=? WHERE key=?',
                       (archive.canonical(dict(balance=4, nonce=3)), self.owner))
        with self.assertRaisesRegex(ValueError, 'ACTIVE_STATE$'):
            self.inspect()

    def test_chainwork_uses_full_unsigned_512_bit_value(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE blocks SET chainwork=? WHERE id=?', ((1 << 511).to_bytes(64, 'big'), self.b))
        with self.assertRaisesRegex(ValueError, 'CHAINWORK_ARITHMETIC$'):
            self.inspect()

    def test_all_retained_ancestry_rows_are_reconstructed_across_inactive_forks(self):
        with sqlite3.connect(self.path) as db:
            tip = self.a
            for height in range(2, 10):
                state = copy.deepcopy(self.states[tip])
                state['retained:branch-height'] = height
                tip = self.add_block(db, state, tip, target=bytes([127]) + bytes([255]) * 31)
            other = self.b
            for height in range(2, 6):
                state = copy.deepcopy(self.states[other])
                state['retained:branch-height'] = height
                other = self.add_block(db, state, other, target=bytes([63]) + bytes([255]) * 31)
        result = self.inspect()
        self.assertEqual(result['ancestry'], dict(rows=36, blocks=15, max_level=3,
                          complete_parent_graph_reconstructed=True))
        # Active remains the original b, while the damaged row is on a deep
        # inactive branch. Looking only at active-tip jumps would miss it.
        self.assertEqual(result['active']['tip'], list(self.b))
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE ancestry_jump SET seal=? WHERE block=? AND level=3',
                       (bytes(32), tip))
        with self.assertRaisesRegex(ValueError, 'ANCESTRY_CONTENT$'):
            self.inspect()

    def test_ancestry_missing_extra_genesis_and_unknown_rows_are_refused(self):
        with sqlite3.connect(self.path) as db:
            original = db.execute('SELECT * FROM ancestry_jump WHERE block=?', (self.a,)).fetchone()
            db.execute('DELETE FROM ancestry_jump WHERE block=?', (self.a,))
        with self.assertRaisesRegex(ValueError, 'ANCESTRY_ROW_SET$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)', original)
        for identity, level in ((self.genesis, 0), (self.a, 1), (bytes([117] * 32), 0)):
            with self.subTest(identity=identity.hex(), level=level):
                with sqlite3.connect(self.path) as db:
                    db.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)',
                        (identity, level, self.genesis, 0, bytes(32), bytes(32), bytes(32)))
                with self.assertRaisesRegex(ValueError, 'ANCESTRY_ROW_SET$'):
                    self.inspect()
                with sqlite3.connect(self.path) as db:
                    db.execute('DELETE FROM ancestry_jump WHERE block=? AND level=?', (identity, level))

    def test_resealed_wrong_ancestor_height_and_component_seals_are_recomputed(self):
        with sqlite3.connect(self.path) as db:
            state = copy.deepcopy(self.states[self.a])
            state['retained:height'] = 2
            middle = self.add_block(db, state, self.a, target=bytes([127]) + bytes([255]) * 31)
            state['retained:height'] = 3
            tip = self.add_block(db, state, middle, target=bytes([127]) + bytes([255]) * 31)
            original = db.execute('SELECT * FROM ancestry_jump WHERE block=? AND level=1',
                                  (tip,)).fetchone()
        self.inspect()
        changes = [dict(index=2, value=self.b), dict(index=3, value=0),
                   dict(index=4, value=bytes([118] * 32)), dict(index=5, value=bytes([119] * 32))]
        for changed in changes:
            with self.subTest(column=changed['index']):
                row = list(original)
                row[changed['index']] = changed['value']
                row[-1] = self.ancestry_seal(row, middle, 3)
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE ancestry_jump SET ancestor=?,ancestor_height=?,left_seal=?,right_seal=?,seal=? '
                               'WHERE block=? AND level=?', (*row[2:], row[0], row[1]))
                with self.assertRaisesRegex(ValueError, 'ANCESTRY_CONTENT$'):
                    self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE ancestry_jump SET ancestor=?,ancestor_height=?,left_seal=?,right_seal=?,seal=? '
                       'WHERE block=? AND level=?', (*original[2:], original[0], original[1]))
        self.inspect()

    def test_ancestry_rows_require_exact_types_and_unique_keys(self):
        with sqlite3.connect(self.path) as db:
            rows = db.execute('SELECT * FROM ancestry_jump ORDER BY block,level').fetchall()
            blocks = {identity: dict(parent=parent, height=height) for identity, parent, height in
                      db.execute('SELECT id,parent,height FROM blocks')}
        oracle.check_ancestry(rows, blocks, self.context)
        with self.assertRaisesRegex(ValueError, 'ANCESTRY_DUPLICATE$'):
            oracle.check_ancestry([*rows, rows[0]], blocks, self.context)
        for column, value in ((0, 'not a blob'), (1, False), (1, 63), (3, 0.0), (6, bytes(31))):
            changed = list(rows[0])
            changed[column] = value
            with self.subTest(column=column, value=value), self.assertRaises(ValueError):
                oracle.check_ancestry([tuple(changed), *rows[1:]], blocks, self.context)

    def test_event_generations_cannot_skip_or_rewind(self):
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM events WHERE generation=1')
        with self.assertRaisesRegex(ValueError, 'EVENT_HISTORY$'):
            self.inspect()

    def test_extra_active_and_kv_slots_are_detected(self):
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('INSERT INTO active VALUES(2,?,7,2)', (self.a,))
        with self.assertRaisesRegex(ValueError, 'ACTIVE_COUNT$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM active WHERE singleton=2')
            db.execute('INSERT INTO kv VALUES(7,?,?)', ('orphan', b'null'))
        with self.assertRaisesRegex(ValueError, 'KV_SLOTS$'):
            self.inspect()

    def test_duplicate_json_noncanonical_record_and_wrong_schema_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY$'):
            oracle.strict_json(b'{"a":1,"a":2}')
        record = copy.deepcopy(self.records[self.b])
        record['height'] = True
        with self.assertRaisesRegex(ValueError, 'INTEGER$'):
            oracle.record_identity(record)
        with sqlite3.connect(self.path) as db:
            raw = db.execute('SELECT data FROM native_state_commitments WHERE block=?', (self.b,)).fetchone()[0]
            db.execute('UPDATE native_state_commitments SET data=? WHERE block=?', (raw + b' ', self.b))
        with self.assertRaisesRegex(ValueError, 'CANONICAL_RECORD$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE native_state_commitments SET data=? WHERE block=?', (raw, self.b))
            db.execute('CREATE TABLE extra_payload(value BLOB)')
        with self.assertRaisesRegex(ValueError, 'DATABASE_SCHEMA$'):
            self.inspect()

    def test_uncheckpointed_wal_and_oversized_json_are_not_silently_ignored(self):
        Path(str(self.path) + '-wal').write_bytes(b'not included in immutable snapshot')
        with self.assertRaisesRegex(ValueError, 'DATABASE_WAL$'):
            self.inspect()
        with self.assertRaisesRegex(ValueError, 'JSON_BUDGET$'):
            oracle.strict_json(b'null', maximum=3)


class MigrationPreservationOracle(StorageFixture):
    def make_source(self):
        path = self.path.with_name('source.sqlite')
        shutil.copyfile(self.path, path)
        with sqlite3.connect(path) as db:
            db.execute('DROP TABLE archive_nodes')
            db.execute('DROP TABLE native_state_commitments')
            db.execute("UPDATE metadata SET value=? WHERE key='schema'", (self.contract['legacy_id'],))
        return path

    def test_only_schema_identity_changes_and_deleted_sequence_frontier_stays(self):
        source_path = self.make_source()
        source = self.inspect(source_path, authenticated=False)
        target = self.inspect()
        summaries = oracle.compare_migration(source, target)
        self.assertIn(dict(table='sqlite_sequence', rows=1,
            sha256=oracle.table_digest('sqlite_sequence', [('local_pool_groups', 20)])), summaries)
        self.assertEqual(len(summaries), len(source['tables']))
        self.assertEqual(source['states'], target['states'])

    def test_retained_values_cannot_change_type_or_contents(self):
        source_path = self.make_source()
        source = self.inspect(source_path, authenticated=False)
        original = self.inspect()
        for changed in [[], [('local_pool_groups', 19)], [('local_pool_groups', 20.0)],
                        [('local_pool_groups', b'20')]]:
            target = copy.deepcopy(original)
            target['tables']['sqlite_sequence'] = changed
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'MIGRATION_'):
                oracle.compare_migration(source, target)

    def test_every_retained_table_is_checked_including_empty_ones(self):
        source_path = self.make_source()
        source = self.inspect(source_path, authenticated=False)
        original = self.inspect()
        for table in ('peer_replay', 'peer_request_audit', 'peer_outbox', 'local_pool_removals'):
            target = copy.deepcopy(original)
            target['tables'][table] = [(b'injected',)]
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, 'MIGRATION_ROW_COUNT:'):
                oracle.compare_migration(source, target)
        target = copy.deepcopy(original)
        del target['tables']['peer_outbox']
        with self.assertRaisesRegex(ValueError, 'MIGRATION_TABLES$'):
            oracle.compare_migration(source, target)

    def test_identically_corrupt_migration_ancestry_is_not_qualified_by_cell_equality(self):
        source_path = self.make_source()
        for path in (source_path, self.path):
            with sqlite3.connect(path) as db:
                db.execute('UPDATE ancestry_jump SET seal=? WHERE block=? AND level=0',
                           (bytes(32), self.a))
        with sqlite3.connect(source_path) as source, sqlite3.connect(self.path) as target:
            self.assertEqual(source.execute('SELECT * FROM ancestry_jump ORDER BY block,level').fetchall(),
                             target.execute('SELECT * FROM ancestry_jump ORDER BY block,level').fetchall())
        for path, authenticated in ((source_path, False), (self.path, True)):
            with self.subTest(authenticated=authenticated), self.assertRaisesRegex(ValueError, 'ANCESTRY_CONTENT$'):
                self.inspect(path, authenticated=authenticated)

    def test_typed_hash_distinguishes_zero_sign_integer_float_blob_and_text(self):
        rows = [(None,), (0,), (0.0,), (-0.0,), ('0',), (b'0',), (1 << 62,)]
        self.assertEqual(len({oracle.typed_row(row) for row in rows}), len(rows))
        self.assertEqual(oracle.typed_cell(-0.0), b'\2' + struct.pack('<d', -0.0))
        self.assertNotEqual(oracle.table_digest('peer_replay', []),
                            oracle.table_digest('peer_outbox', []))


class SignedApplicationControls(StorageFixture):
    def signed_store(self, forge=False):
        self.path = self.path.with_name('signed.sqlite')
        self.context = application.derive_context(1)
        self.context_json = self.context.as_json()
        self.initial = application.derive_genesis(self.context)
        self.states, self.records = {self.context.genesis: self.initial}, {}
        transaction = application.signed_transaction(self.context, 0, 1, 1,
            application.development_public(1) + application.u64(1000))
        miner = application.development_public(7)
        output = application.transition(self.initial, [transaction], 1, miner,
                                        self.context.genesis, self.context)
        state = copy.deepcopy(output['state'])
        if forge:
            # Preserve conservation and recalculate every claimed root/ID. Only
            # independent execution of the signed amount exposes this mutation.
            state['account:' + application.development_public(0).hex()]['balance'] += 1
            state['account:' + application.development_public(1).hex()]['balance'] -= 1
        with sqlite3.connect(self.path) as db:
            db.executescript(self.contract['native'])
            db.executemany('INSERT INTO metadata VALUES(?,?)', [
                ('schema', self.contract['native_id']), ('parameters', self.context.parameters),
                ('genesis', self.context.genesis)])
            genesis = self.add_block(db, self.initial, None)
            tip = self.add_block(db, state, genesis, target=bytes([127]) + bytes([255]) * 31,
                transactions=[transaction], receipts=[bytes.fromhex(raw) for raw in output['receipts_hex']],
                miner=miner, task=bytes.fromhex(self.context.maintenance['matrix_task']))
            db.execute('INSERT INTO snapshots VALUES(?,?)', (genesis, oracle.state_bytes(self.initial)))
            db.execute('INSERT INTO active VALUES(1,?,1,0)', (tip,))
            db.executemany('INSERT INTO kv VALUES(0,?,?)',
                           [(key, archive.canonical(value)) for key, value in state.items()])
            db.execute('INSERT INTO events VALUES(1,0,1,?)', (tip,))
        native = dict(schema=oracle.NATIVE_SCHEMA, database=self.path.name, genesis_timestamp=1,
            context={name: getattr(self.context, name).hex() for name in ('network', 'parameters', 'genesis')},
            initial=self.initial, active=dict(tip=tip.hex(), generation=1, state_slot=0),
            blocks=[dict(id=identity.hex(), state=value) for identity, value in self.states.items()],
            scope=dict(synthetic_unit_fixture=True, native_work_execution=False))
        manifest = self.path.with_suffix('.json')
        manifest.write_text(json.dumps(native))
        return manifest

    def test_actual_hex_envelope_and_independent_signed_amount_replay(self):
        manifest = self.signed_store()
        result = oracle.check_observation(manifest, self.path)
        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(result['signed_transaction_count'], 1)
        self.assertEqual(result['counts']['blocks'], 2)
        self.assertFalse(result['scope']['work_relation_reverified'])

    def test_self_consistent_state_records_cannot_change_signed_transfer_amount(self):
        manifest = self.signed_store(forge=True)
        # Storage integrity alone is internally consistent; the CLI also checks
        # the independent application relation from the fixed development input.
        self.assertEqual(self.inspect()['counts']['blocks'], 2)
        with self.assertRaisesRegex(ValueError, 'PACKET_STATE_ROOT|APPLICATION_STATE'):
            oracle.check_observation(manifest, self.path)

    def test_native_compact_query_is_independently_checked_when_present(self):
        manifest = self.signed_store()
        value = json.loads(manifest.read_bytes())
        value['compact_query'] = {}
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'MULTIPROOF_NATIVE_QUERY_FIELDS'):
            oracle.check_observation(manifest, self.path)


if __name__ == '__main__':
    unittest.main()
