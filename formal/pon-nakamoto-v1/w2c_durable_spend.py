"""W2-C research ONLY: durable paid-only spend fence for a cloned receiver epoch.

Receives an already authenticated caller identity and a server-MACed grant.
SQLite COMMIT (synchronous FULL) precedes READY_RESOURCE_ONLY. No valid ticket
constructs VerifiedWork; no native Node, chainwork, V3 wire or protocol change.

This is a *single local durable-store failure domain*. Forked/cloned database
snapshots on independent hosts remain unsafe. The trusted caller is responsible
for operating-system clock, unique epoch and storage/credential custody.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import stat
import threading
from pathlib import Path

from contract_wire import H
from w2c_receiver_admission import (
    Grant, MAX_U64, bytes32, exact_u64, qualifies, ticket,
)
from w2c_stateless_receiver import StatelessReceiverAdmission

SQLITE_MAX_MS = (1 << 63) - 1
SCHEMA_VERSION = 1


def _private_database_path(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('ABSOLUTE_DATABASE_PATH')
    parent = path.parent
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('PRIVATE_DATABASE_DIRECTORY')
    if path.name in ('', '.', '..'):
        raise ValueError('DATABASE_NAME')
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError('PRIVATE_DATABASE_FILE')
    finally:
        os.close(fd)
    return path


class DurableStatelessReceiver(StatelessReceiverAdmission):
    """Same receiver/epoch and DB file share exactly one paid-spend owner.

    SQLite 'BEGIN IMMEDIATE' serializes separate processes. A committed spend
    is not rolled back when subsequent W1 validation fails or the caller dies.
    Database/clock faults fail closed; no in-memory replay fallback exists.
    """

    def __init__(self, receiver, secret, epoch, database, boot_context,
                 *, lifetime_ms=2000, capacity=64, entropy=None):
        super().__init__(receiver, secret, epoch, lifetime_ms=lifetime_ms,
                         capacity=capacity, entropy=entropy)
        self.boot_context = bytes32(boot_context, 'BOOT_CONTEXT')
        self.binding = H('w2c-durable-store-binding-v1',
                         self.receiver, self.epoch,
                         H('w2c-durable-secret-id-v1', self.secret),
                         self.boot_context)
        self.path = _private_database_path(database)
        self._sql_lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), isolation_level=None,
                                  timeout=2.0, check_same_thread=False)
        try:
            mode = self.db.execute('PRAGMA journal_mode=WAL').fetchone()
            if mode != ('wal',):
                raise ValueError('DURABLE_JOURNAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA busy_timeout=2000')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                version = self.db.execute('PRAGMA user_version').fetchone()[0]
                if version not in (0, SCHEMA_VERSION):
                    raise ValueError('DURABLE_SCHEMA')
                self.db.execute(
                    'CREATE TABLE IF NOT EXISTS authority ('
                    'id INTEGER PRIMARY KEY CHECK (id=1), '
                    'binding BLOB NOT NULL, last_ms INTEGER NOT NULL)'
                )
                self.db.execute(
                    'CREATE TABLE IF NOT EXISTS spent ('
                    'k BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL)'
                )
                row = self.db.execute(
                    'SELECT binding,last_ms FROM authority WHERE id=1'
                ).fetchone()
                if row is None:
                    if version == SCHEMA_VERSION:
                        raise ValueError('DURABLE_AUTHORITY_MISSING')
                    self.db.execute('INSERT INTO authority VALUES (1,?,0)', (self.binding,))
                elif row[0] != self.binding:
                    raise ValueError('DURABLE_AUTHORITY_MISMATCH')
                self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        except BaseException:
            self.db.close()
            raise

    def close(self):
        with self._sql_lock:
            self.db.close()

    def _valid_paid_ticket(self, grant, proposal, caller, nonce, now_ms):
        try:
            exact_u64(now_ms, 'CLOCK')
            if now_ms > SQLITE_MAX_MS:
                return 'CLOCK_UNREPRESENTABLE'
            if not isinstance(grant, Grant):
                return 'GRANT_ENCODING'
            unsigned = grant.unsigned()
            mac = bytes32(grant.mac, 'MAC')
            bytes32(proposal, 'PROPOSAL')
            bytes32(caller, 'CALLER')
            exact_u64(nonce, 'NONCE')
        except (TypeError, ValueError):
            return 'GRANT_ENCODING'
        if (grant.receiver != self.receiver or grant.epoch != self.epoch
                or grant.proposal != H('w2c-stateless-caller-proposal-v1',
                                       caller, proposal)):
            return 'CONTEXT'
        if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
            return 'LIFETIME_POLICY'
        if not hmac.compare_digest(
                hmac.new(self.secret, unsigned, hashlib.sha256).digest(), mac):
            return 'GRANT_MAC'
        if not grant.issued_ms <= now_ms < grant.expires_ms:
            return 'EXPIRED_OR_FUTURE'
        if not qualifies(ticket(grant, nonce), grant.bits):
            return 'TARGET'
        return 'PAID_MATH_OK'

    def consume(self, grant, proposal, caller, nonce, now_ms):
        """One original durable spend before any W1 computation may start."""
        checked = self._valid_paid_ticket(grant, proposal, caller, nonce, now_ms)
        if checked != 'PAID_MATH_OK':
            return checked
        key = H('w2c-stateless-paid-grant-v1', grant.unsigned(), grant.mac)
        with self._sql_lock:
            try:
                self.db.execute('BEGIN IMMEDIATE')
                row = self.db.execute(
                    'SELECT binding,last_ms FROM authority WHERE id=1'
                ).fetchone()
                if row is None or row[0] != self.binding:
                    raise ValueError('DURABLE_AUTHORITY_MISMATCH')
                if now_ms < row[1]:
                    raise ValueError('DURABLE_CLOCK_REGRESSION')
                # Reject a previously paid exact grant before considering
                # capacity. Expiration is protected by the signed grant.
                found = self.db.execute(
                    'SELECT 1 FROM spent WHERE k=?', (key,)
                ).fetchone()
                if found is not None:
                    self.db.rollback()
                    return 'REPLAY'
                self.db.execute('DELETE FROM spent WHERE expires_ms<=?', (now_ms,))
                count = self.db.execute('SELECT COUNT(*) FROM spent').fetchone()[0]
                if count >= self.capacity:
                    self.db.rollback()
                    return 'PAID_CAPACITY_BUSY'
                self.db.execute(
                    'INSERT INTO spent (k,expires_ms) VALUES (?,?)',
                    (key, grant.expires_ms),
                )
                self.db.execute('UPDATE authority SET last_ms=? WHERE id=1', (now_ms,))
                # A caller may not invoke W1 until this commit succeeds.
                self.db.commit()
                return 'READY_RESOURCE_ONLY'
            except sqlite3.Error as error:
                self.db.rollback()
                raise ValueError('DURABLE_RESOURCE_UNAVAILABLE') from error
            except BaseException:
                self.db.rollback()
                raise

    def pending_paid(self):
        with self._sql_lock:
            return self.db.execute('SELECT COUNT(*) FROM spent').fetchone()[0]
