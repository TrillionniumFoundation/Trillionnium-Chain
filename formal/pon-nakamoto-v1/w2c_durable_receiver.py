"""Research-only single-durable-owner W2-C paid ticket fence.

No W1 work authority, chainwork, listener, or production activation. The durable
SQLite file and its key/epoch custody MUST belong to one trusted host owner;
copying both the database and key defeats this local proof-of-spend model.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import hmac
from pathlib import Path
import secrets
import sqlite3
import struct
import threading
from contract_wire import H
from w2c_receiver_admission import Grant, bytes32, exact_u64, ticket, qualifies, MAX_U64

SCHEMA = 'w2c-durable-paid-owner-research-v1'


class DurableReceiverAdmission:
    """Explicit rotate-on-start or controlled join of one durable shared owner.

    A *restart* must use mode='rotate'. mode='join' is only for workers that
    share the very same original SQLite WAL database and root process owner.
    No user-supplied proof, nonce or caller may choose or reset the epoch.
    """

    def __init__(self, database: str, receiver: bytes, secret: bytes,
                 *, mode: str = 'rotate', lifetime_ms: int = 2000,
                 capacity: int = 64, entropy=None):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        if mode not in ('rotate', 'join'):
            raise ValueError('MODE')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        self.lifetime_ms, self.capacity = lifetime_ms, capacity
        self.entropy = entropy if entropy is not None else secrets.token_bytes
        self._lock = threading.RLock()
        # This file is never an untrusted CLI-selected production DB. Trusted
        # directory/file ownership, symlink and rollback prevention remain an
        # explicit deployment requirement, not silently assumed by SQLite.
        path = Path(database)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('TRUSTED_ABSOLUTE_DATABASE_REQUIRED')
        self._db = sqlite3.connect(str(path), timeout=2.0,
                                   isolation_level=None, check_same_thread=False)
        try:
            self._db.execute('PRAGMA journal_mode=WAL')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA busy_timeout=2000')
            self._db.execute('CREATE TABLE IF NOT EXISTS owner ('
                             'id INTEGER PRIMARY KEY CHECK(id=1),'
                             'receiver BLOB NOT NULL, secret_tag BLOB NOT NULL,'
                             'epoch BLOB NOT NULL, generation INTEGER NOT NULL,'
                             'last_ms INTEGER NOT NULL)')
            self._db.execute('CREATE TABLE IF NOT EXISTS spent ('
                             'paid_id BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL)')
            self._owner_tag = H('w2c-durable-owner-key-v1', self.receiver, self.secret)
            with self._lock:
                self._db.execute('BEGIN IMMEDIATE')
                try:
                    prior = self._db.execute('SELECT receiver, secret_tag, epoch, generation '
                                             'FROM owner WHERE id=1').fetchone()
                    if prior is None:
                        if mode != 'rotate':
                            raise ValueError('OWNER_NOT_INITIALIZED')
                        epoch = bytes32(self.entropy(32), 'ENTROPY')
                        self._db.execute('INSERT INTO owner VALUES (1,?,?,?,?,0)',
                                         (self.receiver, self._owner_tag, epoch, 1))
                    else:
                        if prior[0] != self.receiver or not hmac.compare_digest(prior[1], self._owner_tag):
                            raise ValueError('OWNER_IDENTITY_MISMATCH')
                        if mode == 'rotate':
                            epoch = bytes32(self.entropy(32), 'ENTROPY')
                            if epoch == prior[2] or prior[3] >= 2**63 - 1:
                                raise ValueError('EPOCH_REUSE_OR_OVERFLOW')
                            self._db.execute('UPDATE owner SET epoch=?, generation=?, last_ms=0 '
                                             'WHERE id=1', (epoch, prior[3]+1))
                            self._db.execute('DELETE FROM spent')
                        else:
                            epoch = prior[2]
                    self._db.execute('COMMIT')
                except BaseException:
                    self._db.execute('ROLLBACK')
                    raise
            self.epoch = bytes(epoch)
            self._last_local_ms = 0
        except BaseException:
            self._db.close()
            raise

    def close(self):
        with self._lock:
            self._db.close()

    def _current_owner(self):
        row = self._db.execute('SELECT epoch, last_ms FROM owner WHERE id=1').fetchone()
        if row is None or row[0] != self.epoch:
            raise ValueError('STALE_EPOCH')
        return row

    def offer(self, proposal: bytes, caller: bytes, bits: int, now_ms: int) -> Grant:
        bytes32(proposal, 'PROPOSAL')
        bytes32(caller, 'CALLER')
        if type(bits) is not int or not 8 <= bits <= 24:
            raise ValueError('BITS')
        exact_u64(now_ms, 'CLOCK')
        if now_ms > min(MAX_U64, 2**63-1) - self.lifetime_ms:
            raise ValueError('CLOCK_OVERFLOW')
        with self._lock:
            # Stateless issuance: no paid row and no DB update for each offer.
            # Stale worker processes cannot mint tickets for an old epoch.
            try:
                persisted = self._current_owner()
            except sqlite3.Error as error:
                raise ValueError('DURABLE_UNAVAILABLE') from error
            if now_ms < self._last_local_ms or now_ms < persisted[1]:
                raise ValueError('CLOCK_REGRESSION')
            self._last_local_ms = now_ms
            token = bytes32(self.entropy(32), 'ENTROPY')
            caller_proposal = H('w2c-stateless-caller-proposal-v1', caller, proposal)
            unsigned = Grant(self.receiver, self.epoch, caller_proposal,
                             token, bits, now_ms, now_ms + self.lifetime_ms, b'')
            mac = hmac.new(self.secret, unsigned.unsigned(), hashlib.sha256).digest()
            return replace(unsigned, mac=mac)

    def consume(self, grant: Grant, proposal: bytes, caller: bytes,
                nonce: int, now_ms: int) -> str:
        if not isinstance(grant, Grant):
            return 'GRANT_ENCODING'
        try:
            payload = grant.unsigned()
            mac = bytes32(grant.mac, 'MAC')
            bytes32(proposal, 'PROPOSAL')
            bytes32(caller, 'CALLER')
            exact_u64(nonce, 'NONCE')
            exact_u64(now_ms, 'CLOCK')
        except ValueError:
            return 'GRANT_ENCODING'
        caller_proposal = H('w2c-stateless-caller-proposal-v1', caller, proposal)
        if (grant.receiver != self.receiver or grant.epoch != self.epoch
                or grant.proposal != caller_proposal):
            return 'CONTEXT'
        if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
            return 'LIFETIME_POLICY'
        if not hmac.compare_digest(hmac.new(self.secret, payload, hashlib.sha256).digest(), mac):
            return 'GRANT_MAC'
        if not grant.issued_ms <= now_ms < grant.expires_ms:
            return 'EXPIRED_OR_FUTURE'
        if not qualifies(ticket(grant, nonce), grant.bits):
            return 'TARGET'
        key = H('w2c-durable-paid-ticket-v1', payload, mac)
        with self._lock:
            try:
                self._db.execute('BEGIN IMMEDIATE')
                try:
                    row = self._current_owner()
                    if now_ms < row[1] or now_ms < self._last_local_ms:
                        answer = 'CLOCK_REGRESSION'
                    else:
                        self._db.execute('UPDATE owner SET last_ms=? WHERE id=1', (now_ms,))
                        self._db.execute('DELETE FROM spent WHERE expires_ms<=?', (now_ms,))
                        if self._db.execute('SELECT 1 FROM spent WHERE paid_id=?', (key,)).fetchone():
                            answer = 'REPLAY'
                        elif self._db.execute('SELECT COUNT(*) FROM spent').fetchone()[0] >= self.capacity:
                            answer = 'PAID_CAPACITY_BUSY'
                        else:
                            self._db.execute('INSERT INTO spent VALUES (?,?)',
                                             (key, grant.expires_ms))
                            answer = 'READY_RESOURCE_ONLY'
                    # Do not return READY until durable SQLite commit succeeded.
                    self._db.execute('COMMIT')
                    self._last_local_ms = max(self._last_local_ms, now_ms)
                    return answer
                except BaseException:
                    self._db.execute('ROLLBACK')
                    raise
            except ValueError as error:
                return str(error)
            except sqlite3.Error:
                return 'DURABLE_UNAVAILABLE'

    def paid_count(self):
        with self._lock:
            try:
                self._current_owner()
                return self._db.execute('SELECT COUNT(*) FROM spent').fetchone()[0]
            except sqlite3.Error as error:
                raise ValueError('DURABLE_UNAVAILABLE') from error
