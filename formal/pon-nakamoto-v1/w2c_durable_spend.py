"""W2-C experiment: durable, one-use receiver admission, never W1/Chainwork.

Only an administrator-controlled, common SQLite file coordinates local processes.
Independent copies or rollback of that file are explicitly NOT prevented.
"""
from __future__ import annotations
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import stat
import threading
from contract_wire import H
from w2c_receiver_admission import Grant, bytes32, exact_u64, qualifies, ticket

SCHEMA = 'w2c-durable-spend-research-v1'
MAX_SQL_INT = (1 << 63) - 1


class DurableSpendGate:
    def __init__(self, path, receiver, secret, epoch, *, minimum_bits=8,
                 capacity=64, lifetime_ms=2000):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        self.epoch = bytes32(epoch, 'EPOCH')
        if type(minimum_bits) is not int or not 8 <= minimum_bits <= 24:
            raise ValueError('PRICE_BITS')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        self.capacity, self.lifetime_ms = capacity, lifetime_ms
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError('ABSOLUTE_PATH_REQUIRED')
        # Parent trust is an explicit deployer precondition. Do not open a
        # preexisting symlink, hardlink or nonregular database as a W1 budget.
        if self.path.is_symlink():
            raise ValueError('UNTRUSTED_DATABASE')
        if self.path.exists():
            mode = self.path.stat()
            if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1 or mode.st_mode & 0o077:
                raise ValueError('UNTRUSTED_DATABASE')
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=2.0,
                                  isolation_level=None, check_same_thread=False)
        try:
            self.db.execute('PRAGMA busy_timeout=2000')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('CREATE TABLE IF NOT EXISTS owner ('
                            'id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL, '
                            'minimum_bits INTEGER NOT NULL, capacity INTEGER NOT NULL, '
                            'lifetime_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS paid ('
                            'key BLOB PRIMARY KEY, expiry_ms INTEGER NOT NULL) WITHOUT ROWID')
            os.chmod(self.path, 0o600)
            self.scope = H('w2c-durable-scope-v1', self.receiver, self.epoch,
                           hashlib.sha256(self.secret).digest())
            with self._transaction() as cur:
                row = cur.execute('SELECT scope,minimum_bits,capacity,lifetime_ms FROM owner WHERE id=1').fetchone()
                if row is None:
                    cur.execute('INSERT INTO owner (id,scope,minimum_bits,capacity,lifetime_ms,last_ms) '
                                'VALUES (1,?,?,?,?,0)', (self.scope, minimum_bits, capacity, lifetime_ms))
                else:
                    if row[0] != self.scope:
                        raise ValueError('HOST_SCOPE_MISMATCH')
                    if capacity != row[2] or lifetime_ms != row[3]:
                        raise ValueError('HOST_POLICY_MISMATCH')
                    if minimum_bits < row[1]:
                        raise ValueError('PRICE_ROLLBACK')
                    if minimum_bits > row[1]:
                        cur.execute('UPDATE owner SET minimum_bits=? WHERE id=1',
                                    (minimum_bits,))
        except BaseException:
            self.db.close()
            raise

    class _Tx:
        def __init__(self, outer):
            self.outer = outer
        def __enter__(self):
            self.outer.lock.acquire()
            try:
                self.outer.db.execute('BEGIN IMMEDIATE')
                return self.outer.db
            except BaseException:
                self.outer.lock.release()
                raise
        def __exit__(self, typ, value, traceback):
            try:
                self.outer.db.execute('COMMIT' if typ is None else 'ROLLBACK')
            finally:
                self.outer.lock.release()

    def _transaction(self):
        return self._Tx(self)

    def _clock(self, cur, now_ms):
        exact_u64(now_ms, 'CLOCK')
        if now_ms > MAX_SQL_INT:
            raise ValueError('CLOCK_RANGE')
        row = cur.execute('SELECT minimum_bits,last_ms FROM owner WHERE id=1').fetchone()
        if row is None:
            raise ValueError('HOST_SCOPE_MISMATCH')
        bits, last = row
        if now_ms < last:
            raise ValueError('CLOCK_REGRESSION')
        cur.execute('UPDATE owner SET last_ms=? WHERE id=1', (now_ms,))
        cur.execute('DELETE FROM paid WHERE expiry_ms<=?', (now_ms,))
        return bits

    def raise_minimum_bits(self, bits):
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('PRICE_BITS')
        with self._transaction() as cur:
            prior = cur.execute('SELECT minimum_bits FROM owner WHERE id=1').fetchone()
            if prior is None:
                raise ValueError('HOST_SCOPE_MISMATCH')
            if bits < prior[0]:
                raise ValueError('PRICE_ROLLBACK')
            cur.execute('UPDATE owner SET minimum_bits=? WHERE id=1', (bits,))

    def consume(self, grant, proposal, caller, nonce, now_ms):
        """READY_RESOURCE_ONLY means one local CPU gate; never verified work."""
        if not isinstance(grant, Grant):
            return 'GRANT_ENCODING'
        try:
            unsigned = grant.unsigned()
            mac = bytes32(grant.mac, 'MAC')
            proposal = bytes32(proposal, 'PROPOSAL')
            caller = bytes32(caller, 'CALLER')
            exact_u64(nonce, 'NONCE')
        except ValueError:
            return 'GRANT_ENCODING'
        expected = H('w2c-stateless-caller-proposal-v1', caller, proposal)
        if (grant.receiver != self.receiver or grant.epoch != self.epoch
                or grant.proposal != expected):
            return 'CONTEXT'
        if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
            return 'LIFETIME_POLICY'
        if not hmac.compare_digest(
                hmac.new(self.secret, unsigned, hashlib.sha256).digest(), mac):
            return 'GRANT_MAC'
        if not qualifies(ticket(grant, nonce), grant.bits):
            return 'TARGET'
        key = H('w2c-stateless-paid-grant-v1', unsigned, mac)
        with self._transaction() as cur:
            price = self._clock(cur, now_ms)
            if grant.bits < price:
                return 'PRICE_POLICY'
            if not grant.issued_ms <= now_ms < grant.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            if cur.execute('SELECT 1 FROM paid WHERE key=?', (key,)).fetchone():
                return 'REPLAY'
            if cur.execute('SELECT count(*) FROM paid').fetchone()[0] >= self.capacity:
                return 'PAID_CAPACITY_BUSY'
            cur.execute('INSERT INTO paid(key,expiry_ms) VALUES (?,?)',
                        (key, grant.expires_ms))
            return 'READY_RESOURCE_ONLY'

    def pending_paid(self):
        with self.lock:
            return self.db.execute('SELECT count(*) FROM paid').fetchone()[0]

    def close(self):
        with self.lock:
            self.db.close()
