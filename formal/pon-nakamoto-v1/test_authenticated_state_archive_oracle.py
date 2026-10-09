"""Synthetic SQLite corruption controls; actual native observations use the CLI."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

import account_archive_oracle as archive
import account_execution_oracle as application
import authenticated_state_archive_oracle as oracle
import state_witness_oracle as state_witness


class AuthenticatedStateArchiveOracle(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'archive.sqlite'
        self.context_json = dict(network=[1] * 32, parameters=[2] * 32, genesis=[3] * 32)
        self.context = oracle.context_value(self.context_json)
        self.limits = dict(max_checkpoints=8, max_delta_rows=100, max_payload_bytes=1048576,
                           max_history=8)
        self.owner = 'account:' + bytes([11] * 32).hex()
        self.other = 'account:' + bytes([12] * 32).hex()
        self.parent = {self.owner: dict(balance=10, nonce=3), 'meta:issued': 10,
                       'retained:null': None, 'retained:bool': True}
        self.child = copy.deepcopy(self.parent)
        self.child[self.owner] = dict(balance=5, nonce=4)
        self.child[self.other] = dict(balance=5, nonce=0)
        del self.child['retained:null']
        self.child['retained:new-null'] = None
        self.child['retained:bool'] = 1
        self.genesis, _, snapshot = self.record(self.parent, self.context.genesis)
        self.successor, deltas, _ = self.record(self.child, bytes([4] * 32), self.genesis, self.parent)
        self.records = [self.genesis, self.successor]
        with sqlite3.connect(self.path) as db:
            db.executescript('''
                CREATE TABLE authenticated_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);
                CREATE TABLE authenticated_checkpoints(id BLOB PRIMARY KEY,branch BLOB UNIQUE NOT NULL,
                    parent BLOB,height INTEGER NOT NULL,data BLOB NOT NULL);
                CREATE TABLE authenticated_deltas(checkpoint BLOB NOT NULL,ordinal INTEGER NOT NULL,
                    data BLOB NOT NULL,PRIMARY KEY(checkpoint,ordinal));
                CREATE TABLE authenticated_snapshots(checkpoint BLOB PRIMARY KEY,data BLOB NOT NULL);
                CREATE TABLE authenticated_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    checkpoint BLOB NOT NULL,generation INTEGER NOT NULL);
            ''')
            db.executemany('INSERT INTO authenticated_meta VALUES(?,?)', [
                ('schema', oracle.SCHEMA.encode()),
                ('context', self.context.network + self.context.parameters + self.context.genesis)])
            for record in self.records:
                db.execute('INSERT INTO authenticated_checkpoints VALUES(?,?,?,?,?)',
                    (bytes(record['id']), bytes(record['branch']),
                     None if record['parent'] is None else bytes(record['parent']),
                     record['height'], oracle.record_bytes(record)))
            db.execute('INSERT INTO authenticated_snapshots VALUES(?,?)',
                       (bytes(self.genesis['id']), snapshot))
            db.executemany('INSERT INTO authenticated_deltas VALUES(?,?,?)',
                          [(bytes(self.successor['id']), index, raw) for index, raw in enumerate(deltas)])
            db.execute('INSERT INTO authenticated_active VALUES(1,?,2)', (bytes(self.successor['id']),))

    def record(self, state, branch, parent=None, prior=None):
        deltas = [] if parent is None else [oracle.delta_bytes(delta)
            for delta in state_witness.ordered_deltas(prior, state)]
        snapshot = oracle.snapshot_bytes(state) if parent is None else None
        record = dict(schema=oracle.CHECKPOINT_SCHEMA, id=[0] * 32, branch=list(branch),
            parent=None if parent is None else parent['id'],
            height=0 if parent is None else parent['height'] + 1,
            commitment=state_witness.derive_commitment(state, self.context),
            delta_root=list(application.sequence_root('authenticated-state-deltas-v1', deltas)),
            delta_count=len(deltas), snapshot_digest=None if snapshot is None else list(
                archive.digest(b'authenticated-state-snapshot-v1', snapshot)),
            execution=None if parent is None else dict(archive_parent=[8] * 32,
                native_parent=parent['branch'], packet_digest=[9] * 32,
                transactions_root=[10] * 32, miner=[11] * 32, receipts=[]))
        record['id'] = list(oracle.record_identity(record))
        return record, deltas, snapshot

    def inspect(self, **limits):
        return oracle.inspect_sqlite(self.path, self.context_json, self.limits | limits)

    def replace_successor(self, record):
        old = bytes(self.successor['id'])
        record['id'] = list(oracle.record_identity(record))
        new = bytes(record['id'])
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE authenticated_checkpoints SET id=?,parent=?,height=?,data=? WHERE id=?',
                (new, None if record['parent'] is None else bytes(record['parent']), record['height'],
                 oracle.record_bytes(record), old))
            db.execute('UPDATE authenticated_deltas SET checkpoint=? WHERE checkpoint=?', (new, old))
            db.execute('UPDATE authenticated_active SET checkpoint=? WHERE checkpoint=?', (new, old))

    def test_complete_reconstruction_roots_aggregates_and_read_only_bytes(self):
        before = oracle.file_digest(self.path)
        result = self.inspect()
        self.assertEqual(result['states'][bytes(self.genesis['id'])], self.parent)
        self.assertEqual(result['states'][bytes(self.successor['id'])], self.child)
        self.assertEqual(result['active'], dict(checkpoint=self.successor['id'], generation=2))
        self.assertEqual(result['observation']['checkpoint_rows'], 2)
        self.assertEqual(result['observation']['delta_rows'], 5)
        self.assertEqual(result['observation']['snapshot_rows'], 1)
        self.assertEqual(oracle.file_digest(self.path), before)

    def test_absent_present_null_boolean_and_number_are_distinct_values(self):
        changes = state_witness.ordered_deltas(self.parent, self.child)
        before = copy.deepcopy(self.parent)
        self.assertEqual(oracle.apply_deltas(self.parent, changes), self.child)
        self.assertEqual(self.parent, before)
        wrong = [dict(key='retained:null', before=None, after={'value': 4})]
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DELTA_BEFORE$'):
            oracle.apply_deltas(self.parent, wrong)
        wrong = [dict(key='retained:bool', before={'value': 1}, after=None)]
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DELTA_BEFORE$'):
            oracle.apply_deltas(self.parent, wrong)
        self.assertEqual(oracle.apply_deltas({'value': True}, [
            dict(key='value', before={'value': True}, after={'value': 1})]), {'value': 1})

    def test_account_nonce_and_existence_do_not_rewind(self):
        for after, error in [(None, 'ACCOUNT_DELETION'),
                             ({'value': dict(balance=10, nonce=2)}, 'NONCE_REWIND')]:
            with self.subTest(after=after), self.assertRaisesRegex(ValueError,
                    '^AUTH_ARCHIVE_' + error + '$'):
                oracle.apply_deltas(self.parent, [dict(key=self.owner,
                    before={'value': self.parent[self.owner]}, after=after)])

    def test_rehashed_false_aggregate_is_recomputed_from_actual_rows(self):
        forged = copy.deepcopy(self.successor)
        forged['commitment']['account_balance'] += 1
        forged['commitment']['issued'] += 1
        forged['commitment']['id'] = list(state_witness.commitment_identity(forged['commitment']))
        self.replace_successor(forged)
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_COMPLETE_COMMITMENT$'):
            self.inspect()

    def test_foreign_parent_cannot_be_hidden_by_fresh_record_identity(self):
        forged = copy.deepcopy(self.successor)
        forged['parent'] = [97] * 32
        self.replace_successor(forged)
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_PARENT$'):
            self.inspect()

    def test_missing_ordinal_and_orphan_rows_are_refused(self):
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE authenticated_deltas SET ordinal=99 WHERE ordinal=0')
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DELTA_ORDINAL$'):
            self.inspect()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE authenticated_deltas SET ordinal=0 WHERE ordinal=99')
            raw = db.execute('SELECT data FROM authenticated_deltas WHERE ordinal=0').fetchone()[0]
            db.execute('INSERT INTO authenticated_deltas VALUES(?,?,?)', (bytes([89]) * 32, 0, raw))
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_ORPHAN_DELTA$'):
            self.inspect()

    def test_changed_delta_cannot_reuse_the_original_sequence_commitment(self):
        with sqlite3.connect(self.path) as db:
            raw = db.execute('SELECT data FROM authenticated_deltas WHERE ordinal=0').fetchone()[0]
            changed = oracle.strict_json(raw)
            changed['after']['value']['nonce'] += 1
            db.execute('UPDATE authenticated_deltas SET data=? WHERE ordinal=0',
                       (oracle.delta_bytes(changed),))
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DELTA_ROOT$'):
            self.inspect()

    def test_extra_active_row_and_unreadable_successor_history_are_refused(self):
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_HISTORY_BUDGET$'):
            self.inspect(max_history=1)
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('INSERT INTO authenticated_active VALUES(2,?,7)', (bytes(self.genesis['id']),))
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DATABASE_BUDGET$'):
            self.inspect()

    def test_duplicate_fields_boolean_aliases_and_noncanonical_envelope_are_refused(self):
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DUPLICATE_JSON_KEY$'):
            oracle.strict_json(b'{"key":"a","key":"b"}')
        invalid = copy.deepcopy(self.successor)
        invalid['height'] = True
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_INTEGER$'):
            oracle.record_identity(invalid)
        with sqlite3.connect(self.path) as db:
            raw = db.execute('SELECT data FROM authenticated_checkpoints WHERE height=1').fetchone()[0]
            db.execute('UPDATE authenticated_checkpoints SET data=? WHERE height=1', (raw + b' ',))
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_CANONICAL_RECORD$'):
            self.inspect()

    def test_uncheckpointed_wal_is_not_silently_ignored(self):
        Path(str(self.path) + '-wal').write_bytes(b'unretained source changes')
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_DATABASE_WAL$'):
            self.inspect()

    def test_older_branch_selection_preserves_monotonic_cas_generation(self):
        identities = [bytes([number]) * 32 for number in range(1, 5)]
        g, a, a2, b = [list(identity) for identity in identities]
        states = [None, dict(checkpoint=g, generation=1), dict(checkpoint=a, generation=2),
                  dict(checkpoint=a2, generation=3), dict(checkpoint=a2, generation=3),
                  dict(checkpoint=b, generation=4), dict(checkpoint=g, generation=5),
                  dict(checkpoint=a2, generation=6)]
        operations = [dict(kind=kind, checkpoint=identity,
            active_before=copy.deepcopy(states[index]), active_after=copy.deepcopy(states[index + 1]))
            for index, (kind, identity) in enumerate([
                ('publish', g), ('publish', a), ('publish', a2), ('publish', b),
                ('activate', b), ('activate', g), ('activate', a2)])]
        self.assertEqual(oracle.check_operations(operations, identities), states[-1])
        damaged = copy.deepcopy(operations)
        damaged[5]['active_after']['generation'] = 1
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_CAS_AFTER$'):
            oracle.check_operations(damaged, identities)
        damaged = copy.deepcopy(operations)
        damaged[3]['active_before']['checkpoint'] = b
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_CAS_BEFORE$'):
            oracle.check_operations(damaged, identities)
        damaged = copy.deepcopy(operations)
        damaged[0]['active_after']['generation'] = True
        with self.assertRaisesRegex(ValueError, '^AUTH_ARCHIVE_CAS_AFTER$'):
            oracle.check_operations(damaged, identities)


if __name__ == '__main__':
    unittest.main()
