#!/usr/bin/env python3
"""Execute the native inventory SQL against real SQLite; NOT Rust/owner acceptance.

These are low-level cursor and query regressions. The Rust field decoder, JMT,
namespace checks and callbacks must additionally pass the native Rust tests.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / (
    'trillionnium/crates/trnm-native-execution-v0/src/durable.rs')
TEXT = SOURCE.read_text(encoding='utf-8')
CREATE = re.search(r'"(CREATE TABLE native_durable_execution_p_v0 \([^\"]+)"', TEXT)[1]
KEYS = re.search(r'"(SELECT block_id FROM native_durable_execution_p_v0 ORDER BY p_sequence ASC)"', TEXT)[1]
LOOKUP = re.search(r'"(SELECT target_height,store_id,p_sequence,[^\"]+WHERE block_id=\?)"', TEXT)[1]


def inventory(connection: sqlite3.Connection, consume=lambda p: p):
    """Same two-cursor SQL pattern; intentionally not a Rust implementation."""
    rows = []
    keys = connection.execute(KEYS)
    try:
        for (identity,) in keys:
            lookup = connection.execute(LOOKUP, (identity,))
            try:
                row = lookup.fetchone()
            finally:
                lookup.close()
            if row is None:
                raise ValueError('inventory key disappeared')
            rows.append(consume(row))
    finally:
        keys.close()
    return rows


class InventorySqlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-sql-diagnostic-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'inventory.db'
        self.reader = sqlite3.connect(self.path, isolation_level=None, timeout=0)
        self.addCleanup(self.reader.close)
        self.reader.execute(CREATE)
        self.ids = []
        for sequence in [9, 3, 7, 2**63 + 1, 2**64 - 1]:
            identity = hashlib.sha256(str(sequence).encode()).digest()
            self.ids.append(identity)
            value = {
                'block_id': identity, 'target_height': (1).to_bytes(8, 'big'),
                'store_id': b's' * 32, 'p_sequence': sequence.to_bytes(8, 'big'),
                'status': (1).to_bytes(8, 'big'), 'parent_height': bytes(8),
                'parent_block_id': b'b' * 32, 'parent_state_root': b'r' * 32,
                'parent_commit_id': b'c' * 32, 'artifact': b'a' + identity,
                'artifact_digest': b'd' * 32, 'target_snapshot': b'x' * (64 * 1024),
                'target_snapshot_digest': b'z' * 32,
                'target_replay_command_ids': b'[]', 'target_replay_signer_nonces': b'[]',
                'target_lifecycle_json': b'{}', 'p_digest': b'p' * 32,
                'commit_sequence': None, 'commit_id': None,
            }
            columns = ','.join(value)
            placeholders = ','.join('?' for _ in value)
            self.reader.execute(f'INSERT INTO native_durable_execution_p_v0 ({columns}) VALUES ({placeholders})',
                                tuple(value.values()))

    def test_unsigned_blob_order_and_every_payload_preserved(self):
        observed = inventory(self.reader)
        self.assertEqual([int.from_bytes(row[2], 'big') for row in observed],
                         [3, 7, 9, 2**63+1, 2**64-1])
        self.assertTrue(all(row[11] == b'x' * (64*1024) for row in observed))
        self.assertEqual(len({row[8] for row in observed}), 5)

    def test_cursor_prevents_mixed_row_snapshots(self):
        self.reader.execute('PRAGMA journal_mode=WAL')
        writer = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(writer.close)
        expected = inventory(self.reader)
        later = expected[1][8]
        count = 0
        def consume(row):
            nonlocal count
            count += 1
            if count == 1:
                writer.execute('UPDATE native_durable_execution_p_v0 SET artifact=? WHERE block_id=?',
                               (b'new', later))
            return row
        self.assertEqual(inventory(self.reader, consume), expected)
        self.assertEqual(self.reader.execute(LOOKUP, (later,)).fetchone()[9], b'new')

    def test_old_materialized_keys_pattern_exposes_mixed_snapshot(self):
        self.reader.execute('PRAGMA journal_mode=WAL')
        writer = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(writer.close)
        expected = inventory(self.reader)
        keys = self.reader.execute(KEYS).fetchall()
        observed = []
        for index, (identity,) in enumerate(keys):
            observed.append(self.reader.execute(LOOKUP, (identity,)).fetchone())
            if index == 0:
                writer.execute('UPDATE native_durable_execution_p_v0 SET artifact=? WHERE block_id=?',
                               (b'new', keys[1][0]))
        self.assertNotEqual(observed, expected)
        self.assertEqual(observed[1][9], b'new')

    def test_callback_failure_releases_cursor(self):
        count = 0
        def consume(row):
            nonlocal count
            count += 1
            if count == 2:
                raise ValueError('injected-consumer-failure')
            return row
        with self.assertRaisesRegex(ValueError, 'injected-consumer-failure'):
            inventory(self.reader, consume)
        self.assertEqual(count, 2)
        writer = sqlite3.connect(self.path, isolation_level=None, timeout=0)
        self.addCleanup(writer.close)
        writer.execute('BEGIN EXCLUSIVE')
        writer.execute('ROLLBACK')
        self.assertEqual(len(inventory(self.reader)), 5)

    def test_cached_statement_does_not_cache_query_result(self):
        identity = self.ids[0]
        before = self.reader.execute(LOOKUP, (identity,)).fetchone()
        self.reader.execute('UPDATE native_durable_execution_p_v0 SET artifact=? WHERE block_id=?',
                            (b'changed', identity))
        after = self.reader.execute(LOOKUP, (identity,)).fetchone()
        self.assertNotEqual(before[9], after[9])
        self.assertEqual(after[9], b'changed')

    def test_empty_inventory_and_read_only_connection(self):
        self.reader.execute('DELETE FROM native_durable_execution_p_v0')
        readonly = sqlite3.connect(f'file:{self.path}?mode=ro', uri=True)
        self.addCleanup(readonly.close)
        self.assertEqual(inventory(readonly), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
