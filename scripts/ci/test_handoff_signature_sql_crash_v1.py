#!/usr/bin/env python3
"""Exercise schema1's exact signed-event SQL at process-kill transaction cuts.

Uses production DDL and four production DML literals; Rust control flow, hash
computation, signature verification, external CAS, HSM and physical power loss
are NOT executed. Shape-only fixture rows deliberately cannot pass a Rust
canonical-history audit. Passing this test is local SQLite evidence only.
"""
from __future__ import annotations

from pathlib import Path
import re
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / 'trillionnium/crates/trnm-consensus-signer-journal/src'
FINGERPRINT = b'F' * 32
CHAIN_PREPARED = b'P' * 32
CHAIN_SIGNED = b'S' * 32


def be(value: int) -> bytes:
    return value.to_bytes(8, 'big')


def schema() -> str:
    source = (OWNER / 'handoff_schema_v1.rs').read_text(encoding='utf-8')
    match = re.search(r'JOURNAL_SCHEMA_SQL_V1: &str = "([^"]+)";', source)
    if match is None:
        raise ValueError('production schema literal changed; explicit review required')
    return match[1]


def dml(function: str, verb: str) -> str:
    source = (OWNER / 'handoff_sqlite_v1.rs').read_text(encoding='utf-8')
    match = re.search(r'(?ms)^fn ' + re.escape(function) + r'\(.*?(?=^fn |\Z)', source)
    if match is None:
        raise ValueError(f'missing production SQL function: {function}')
    sql = re.findall(r'"(' + re.escape(verb) + r' [^"]+)"', match[0])
    if len(sql) != 1:
        raise ValueError(f'expected one reviewed SQL literal in {function}')
    return sql[0]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=2, isolation_level=None)
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA journal_mode=DELETE')
    conn.execute('PRAGMA synchronous=FULL')
    return conn


def seed(path: Path) -> None:
    conn = connect(path)
    try:
        conn.executescript(schema())
        conn.execute('BEGIN IMMEDIATE')
        # These are shape-only values, not production hashes or authority.
        conn.execute('''INSERT INTO signer_intents_v1 (
            fingerprint, intent_class, signing_root, canonical_intent, intent_checksum,
            genesis_hash, old_epoch_be, new_epoch_be, handoff_role, validator_id,
            descriptor_digest, descriptor_cev0, admission_digest
        ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)''',
                     (FINGERPRINT, b'R'*32, b'shape-only', b'I'*32, b'G'*32,
                      be(0), be(1), b'fixture', b'D'*32, b'shape-only', b'A'*32))
        conn.execute(dml('insert_event_v1', 'INSERT'),
                     (be(1), 0, FINGERPRINT, None, be(0), b'Z'*32, b'E'*32, CHAIN_PREPARED))
        conn.execute('INSERT INTO signer_head_v1 VALUES (1, ?, ?, ?)',
                     (be(1), CHAIN_PREPARED, b'H'*32))
        conn.execute('INSERT INTO signer_accounting_v1 VALUES (1, 1, 1, 10, NULL, NULL, NULL)')
        conn.execute('COMMIT')
    finally:
        conn.close()


def signed_statements() -> list[tuple[str, tuple]]:
    return [
        (dml('insert_event_v1', 'INSERT'),
         (be(2), 1, FINGERPRINT, b'X'*64, be(1), CHAIN_PREPARED, b'E'*32, CHAIN_SIGNED)),
        (dml('update_accounting_signed_v1', 'UPDATE'), (2,)),
        (dml('insert_terminal_fence_v1', 'INSERT'),
         (b'G'*32, be(0), be(1), b'fixture', b'D'*32, FINGERPRINT, be(2), b'C'*32)),
        (dml('update_head_v1', 'UPDATE'), (be(2), CHAIN_SIGNED, b'H'*32, be(1), CHAIN_PREPARED)),
    ]


def stop_for_kill() -> None:
    print('AT_CUT', flush=True)
    signal.pause()
    raise RuntimeError('child unexpectedly resumed')


def child(path: str, cut: int) -> None:
    conn = connect(path)
    conn.execute('BEGIN IMMEDIATE')
    for index, (sql, params) in enumerate(signed_statements(), 1):
        if conn.execute(sql, params).rowcount != 1:
            raise RuntimeError('expected exactly one changed row')
        if cut == index:
            stop_for_kill()
    conn.execute('COMMIT')
    if cut == 5:
        stop_for_kill()
    raise ValueError('unsupported crash cut')


def summary(path: Path) -> tuple[int, int, int, int]:
    conn = connect(path)
    try:
        if conn.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise RuntimeError('SQLite integrity check failed')
        if conn.execute('PRAGMA foreign_key_check').fetchall():
            raise RuntimeError('SQLite foreign key check failed')
        return (
            conn.execute('SELECT count(*) FROM signer_events_v1').fetchone()[0],
            conn.execute('SELECT count(*) FROM terminal_old_epoch_fence_v1').fetchone()[0],
            conn.execute('SELECT event_count FROM signer_accounting_v1').fetchone()[0],
            int.from_bytes(conn.execute('SELECT active_sequence_be FROM signer_head_v1').fetchone()[0], 'big'),
        )
    finally:
        conn.close()


@unittest.skipUnless(sys.platform == 'linux', 'requires real Linux SIGKILL')
class SignedHandoffSqlCrashTests(unittest.TestCase):
    def test_five_sigkill_cuts_preserve_the_whole_local_signature_transaction(self) -> None:
        for cut in range(1, 6):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'fixture.sqlite3'
                seed(path)
                proc = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), '--child', str(path), str(cut)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    assert proc.stdout is not None
                    with selectors.DefaultSelector() as selector:
                        selector.register(proc.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=10), 'child did not reach the cut')
                        self.assertEqual(proc.stdout.readline().strip(), 'AT_CUT')
                    proc.kill()
                    proc.communicate(timeout=10)
                    self.assertEqual(proc.returncode, -signal.SIGKILL)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.communicate(timeout=10)
                expected = (1, 0, 1, 1) if cut < 5 else (2, 1, 2, 2)
                self.assertEqual(summary(path), expected)
                print(f'local_sql_sigkill_cut={cut} expected={expected} observed={summary(path)}', flush=True)

    def test_duplicate_signed_event_cannot_create_a_second_local_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sqlite3'
            seed(path)
            conn = connect(path)
            try:
                conn.execute('BEGIN IMMEDIATE')
                for sql, params in signed_statements():
                    self.assertEqual(conn.execute(sql, params).rowcount, 1)
                conn.execute('COMMIT')
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(*signed_statements()[0])
            finally:
                conn.close()
            self.assertEqual(summary(path), (2, 1, 2, 2))

    def test_local_schema_alone_is_not_complete_signature_recovery_authority(self) -> None:
        # Negative control: omitting fence/accounting/head can commit at the SQL
        # level. The Rust full-history audit is necessary; DDL is not a proof.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sqlite3'
            seed(path)
            conn = connect(path)
            try:
                conn.execute(*signed_statements()[0])
            finally:
                conn.close()
            self.assertEqual(summary(path), (2, 0, 1, 1))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        child(sys.argv[2], int(sys.argv[3]))
    else:
        unittest.main(verbosity=2)
