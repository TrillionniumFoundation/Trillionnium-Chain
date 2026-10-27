"""W2-C research only: exact paid-ticket replay owner across local SQLite connections.

The original trusted process supplies a stable absolute database path, a
nonrollback monotonic millisecond clock, receiver identity, and process epoch.
This is NOT a public network, a consensus state machine or a security audit.
If a service clones secrets/epoch but creates an independent database, replay
is STILL possible. A durable local DB is not cross-host distributed consensus.
"""
from __future__ import annotations
from pathlib import Path
import sqlite3
import threading
from w2c_receiver_admission import bytes32, exact_u64

SCHEMA = 'w2c-durable-paid-spend-local-research-v1'


class SQLiteSpentOwner:
    """A single durable local store shared by receiver clones; no valid-work authority."""

    def __init__(self, path: str | Path, receiver: bytes, epoch: bytes,
                 required_bits: int, capacity: int = 64):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.epoch = bytes32(epoch, 'EPOCH')
        if type(required_bits) is not int or not 8 <= required_bits <= 24:
            raise ValueError('REQUIRED_BITS')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        self.required_bits = required_bits
        self.capacity = capacity
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.is_symlink() or not self.path.parent.is_dir():
            raise ValueError('SPEND_OWNER_PATH')
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=2.0, isolation_level=None,
                                  check_same_thread=False)
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA busy_timeout=2000')
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('CREATE TABLE IF NOT EXISTS identity '
                            '(id INTEGER PRIMARY KEY CHECK (id = 1), '
                            'schema TEXT NOT NULL, receiver BLOB NOT NULL, '
                            'epoch BLOB NOT NULL, bits INTEGER NOT NULL, '
                            'capacity INTEGER NOT NULL, last_ms INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS spent '
                            '(key BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL)')
            prior = self.db.execute(
                'SELECT schema,receiver,epoch,bits,capacity FROM identity WHERE id=1'
            ).fetchone()
            bound = (SCHEMA, self.receiver, self.epoch, self.required_bits, self.capacity)
            if prior is None:
                self.db.execute(
                    'INSERT INTO identity(id,schema,receiver,epoch,bits,capacity,last_ms) '
                    'VALUES(1,?,?,?,?,?,0)', bound
                )
            elif tuple(prior) != bound:
                raise ValueError('SPEND_OWNER_CONTEXT')
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            self.db.close()
            raise

    def close(self):
        with self.lock:
            self.db.close()

    def pending_paid(self):
        with self.lock:
            return self.db.execute('SELECT count(*) FROM spent').fetchone()[0]

    def spend(self, key: bytes, expires_ms: int, now_ms: int) -> str:
        """Atomic spend-before-work. Failures never create VerifiedWork or refund."""
        bytes32(key, 'SPEND_KEY')
        exact_u64(expires_ms, 'EXPIRY')
        exact_u64(now_ms, 'CLOCK')
        # SQLite stores signed i64; no cast/truncation to turn large clocks into
        # negative or wraparound eligibility. Missing oversized observations fail.
        if expires_ms >= 1 << 63 or now_ms >= 1 << 63:
            return 'SPEND_OWNER_RANGE'
        with self.lock:
            try:
                self.db.execute('BEGIN IMMEDIATE')
                row = self.db.execute(
                    'SELECT last_ms FROM identity WHERE id=1'
                ).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError('missing identity')
                if now_ms < row[0]:
                    self.db.execute('ROLLBACK')
                    return 'SPEND_CLOCK_REGRESSION'
                self.db.execute('UPDATE identity SET last_ms=? WHERE id=1', (now_ms,))
                self.db.execute('DELETE FROM spent WHERE expires_ms<=?', (now_ms,))
                if expires_ms <= now_ms:
                    self.db.execute('COMMIT')
                    return 'SPEND_EXPIRED'
                already = self.db.execute(
                    'SELECT 1 FROM spent WHERE key=?', (key,)
                ).fetchone()
                if already is not None:
                    self.db.execute('COMMIT')
                    return 'REPLAY'
                total = self.db.execute('SELECT count(*) FROM spent').fetchone()[0]
                if total >= self.capacity:
                    self.db.execute('COMMIT')
                    return 'PAID_CAPACITY_BUSY'
                self.db.execute('INSERT INTO spent(key,expires_ms) VALUES(?,?)',
                                (key, expires_ms))
                self.db.execute('COMMIT')
                return 'READY_RESOURCE_ONLY'
            except (sqlite3.Error, ValueError):
                if self.db.in_transaction:
                    try:
                        self.db.execute('ROLLBACK')
                    except sqlite3.Error:
                        pass
                return 'SPEND_UNAVAILABLE'
