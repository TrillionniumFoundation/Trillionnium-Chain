"""Research-only durable single-receiver W2-C admission owner.

A fresh process epoch is committed under one SQLite writer transaction before
issuance; its paid ticket is committed before returning RESOURCE_ONLY. The
surviving database fences an older instance even if the secret was copied.
This is not Chainwork, a V3 Cookie, cross-host anti-clone, or FinalUse.
"""
from __future__ import annotations
import os
import sqlite3
import threading
from pathlib import Path
from contract_wire import H
from w2c_receiver_admission import bytes32, Grant
from w2c_stateless_receiver import StatelessReceiverAdmission

SCHEMA = 'w2c-durable-single-owner-research-v1'


class DurableReceiverOwner:
    def __init__(self, path: str, receiver: bytes, secret: bytes,
                 *, lifetime_ms: int = 2000, capacity: int = 64,
                 entropy=None, epoch_entropy=None):
        self.path = Path(path)
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        self.lock = threading.RLock()
        self.creator_pid = os.getpid()
        if not self.path.is_absolute():
            raise ValueError('ABSOLUTE_DB_PATH')
        if self.path.is_symlink():
            raise ValueError('SYMLINK_DB')
        # SQLite owns its journal and lock; this research wrapper assumes the
        # directory and local filesystem are already trusted by the operator.
        # This is NOT a safe arbitrary filesystem-path or remote-storage API.
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            descriptor = None
        if descriptor is not None:
            os.close(descriptor)
        stat = self.path.stat(follow_symlinks=False)
        if not self.path.is_file() or stat.st_nlink != 1 or stat.st_mode & 0o077:
            raise ValueError('DB_OWNER_MODE')
        self.db = sqlite3.connect(str(self.path), isolation_level=None, timeout=5,
                                  check_same_thread=False)
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA busy_timeout=5000')
            self.db.execute('CREATE TABLE IF NOT EXISTS authority (singleton INTEGER PRIMARY KEY CHECK (singleton=1), schema TEXT NOT NULL, receiver BLOB NOT NULL, seq INTEGER NOT NULL, epoch BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS paid (epoch BLOB NOT NULL, digest BLOB NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(epoch,digest)) WITHOUT ROWID')
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT schema, receiver, seq FROM authority WHERE singleton=1').fetchone()
            if row is None:
                seq = 0
            else:
                old_schema, old_receiver, seq = row
                if old_schema != SCHEMA or old_receiver != self.receiver:
                    raise ValueError('AUTHORITY_CONTEXT')
            if type(seq) is not int or not 0 <= seq < (1 << 63) - 1:
                raise ValueError('EPOCH_SEQUENCE_OVERFLOW')
            seq += 1
            fresh = bytes32((epoch_entropy or os.urandom)(32), 'EPOCH_ENTROPY')
            epoch = H('w2c-durable-owner-epoch-v1', self.receiver,
                      seq.to_bytes(8, 'little'), fresh)
            self.db.execute('INSERT INTO authority(singleton,schema,receiver,seq,epoch) VALUES (1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET seq=excluded.seq,epoch=excluded.epoch',
                            (SCHEMA, self.receiver, seq, epoch))
            # Previous grants have a different epoch. Old paid entries do not
            # grant authority; discard their bounded short-lived lookup state.
            self.db.execute('DELETE FROM paid')
            self.db.execute('COMMIT')
            self.epoch = epoch
            self.issuer = StatelessReceiverAdmission(
                self.receiver, self.secret, epoch,
                lifetime_ms=lifetime_ms, capacity=capacity, entropy=entropy)
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            self.db.close()
            raise

    def _ensure_process(self):
        if os.getpid() != self.creator_pid:
            raise ValueError('FORKED_OWNER')

    def _current(self):
        row = self.db.execute('SELECT epoch FROM authority WHERE singleton=1').fetchone()
        return row is not None and row[0] == self.epoch

    def is_current_epoch(self):
        self._ensure_process()
        with self.lock:
            return self._current()

    def offer(self, proposal: bytes, caller: bytes, bits: int, now_ms: int):
        self._ensure_process()
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if not self._current():
                    self.db.execute('ROLLBACK')
                    return 'STALE_EPOCH'
                grant = self.issuer.offer(proposal, caller, bits, now_ms)
                self.db.execute('COMMIT')
                return grant
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise

    def consume(self, grant, proposal: bytes, caller: bytes, nonce: int, now_ms: int):
        """READY_RESOURCE_ONLY is neither W1 validity nor final commit authority."""
        self._ensure_process()
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if not self._current():
                    self.db.execute('ROLLBACK')
                    return 'STALE_EPOCH'
                self.db.execute('DELETE FROM paid WHERE expires <= ?', (now_ms,))
                # Precise duplicate semantics are preserved even if the bounded
                # paid table is already at capacity. This never authorizes W1.
                if isinstance(grant, Grant):
                    try:
                        prior_key = H('w2c-durable-paid-grant-v1',
                                      grant.unsigned(), grant.mac)
                    except ValueError:
                        prior_key = None
                    if prior_key is not None and self.db.execute(
                            'SELECT 1 FROM paid WHERE epoch=? AND digest=?',
                            (self.epoch, prior_key)).fetchone():
                        self.db.execute('COMMIT')
                        return 'REPLAY'
                count = self.db.execute('SELECT COUNT(*) FROM paid WHERE epoch=?',
                                        (self.epoch,)).fetchone()[0]
                if count >= self.issuer.capacity:
                    self.db.execute('COMMIT')
                    return 'PAID_CAPACITY_BUSY'
                verdict = self.issuer.consume(grant, proposal, caller, nonce, now_ms)
                if verdict != 'READY_RESOURCE_ONLY':
                    self.db.execute('COMMIT')
                    return verdict
                # Do not return READY until the SQLite spend survives COMMIT.
                key = H('w2c-durable-paid-grant-v1', grant.unsigned(), grant.mac)
                try:
                    self.db.execute('INSERT INTO paid(epoch,digest,expires) VALUES (?,?,?)',
                                    (self.epoch, key, grant.expires_ms))
                except sqlite3.IntegrityError:
                    self.db.execute('ROLLBACK')
                    return 'REPLAY'
                self.db.execute('COMMIT')
                return 'READY_RESOURCE_ONLY'
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise

    def close(self):
        self._ensure_process()
        with self.lock:
            self.db.close()
