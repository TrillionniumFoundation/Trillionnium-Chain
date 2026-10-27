"""Research-only same-operator durable W2-C spend fence.

A MAC-valid/target-valid stateless ticket is NOT Chainwork or VerifiedWork.
This prototype closes ONLY replay across receivers that share one honest,
durable SQLite file. Separate copied databases/host secrets remain unsafe.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import threading

MAX_I64 = (1 << 63) - 1


class DurableSpentFence:
    """One SQLite write owner: atomic paid-token consume across processes."""

    def __init__(self, path: str | Path, capacity: int = 64):
        self.path = Path(path)
        if (not self.path.is_absolute() or self.path.name in ('', '.', '..')
                or type(capacity) is not int or not 1 <= capacity <= 1024):
            raise ValueError('DURABLE_FENCE_CONFIG')
        parent = self.path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
            raise ValueError('DURABLE_FENCE_UNTRUSTED_PARENT')
        self.capacity = capacity
        # The parent directory is trusted by the local operator. No symlink,
        # hardlink or untrusted filesystem path may be selected by a peer.
        flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0)
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise ValueError('DURABLE_FENCE_FILE_OWNER')
        finally:
            os.close(fd)
        self.connection = sqlite3.connect(str(self.path), timeout=5,
                                          isolation_level=None,
                                          check_same_thread=False)
        self.lock = threading.RLock()
        try:
            self.connection.execute('PRAGMA trusted_schema=OFF')
            self.connection.execute('PRAGMA journal_mode=WAL')
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute(
                'CREATE TABLE IF NOT EXISTS spent ('
                ' identity BLOB PRIMARY KEY NOT NULL,'
                ' expires_ms INTEGER NOT NULL CHECK(expires_ms >= 0))'
            )
            self.connection.execute(
                'CREATE TABLE IF NOT EXISTS frontier ('
                ' id INTEGER PRIMARY KEY CHECK(id=1),'
                ' last_ms INTEGER NOT NULL CHECK(last_ms >= 0))'
            )
            self.connection.execute(
                'INSERT OR IGNORE INTO frontier(id,last_ms) VALUES(1,0)'
            )
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        with self.lock:
            self.connection.close()

    def spend(self, identity: bytes, expires_ms: int, now_ms: int) -> str:
        """'READY_RESOURCE_ONLY' is not a proof-validity or ledger result."""
        if type(identity) is not bytes or len(identity) != 32:
            raise ValueError('PAID_IDENTITY')
        if (type(expires_ms) is not int or type(now_ms) is not int
                or not 0 <= now_ms <= MAX_I64
                or not 0 <= expires_ms <= MAX_I64):
            raise ValueError('DURABLE_CLOCK_RANGE')
        if now_ms >= expires_ms:
            return 'EXPIRED'
        if expires_ms - now_ms > 2000:
            raise ValueError('DURABLE_LIFETIME')
        with self.lock:
            try:
                self.connection.execute('BEGIN IMMEDIATE')
                prior = self.connection.execute(
                    'SELECT last_ms FROM frontier WHERE id=1'
                ).fetchone()
                if prior is None or now_ms < prior[0]:
                    raise ValueError('DURABLE_CLOCK_REGRESSION')
                self.connection.execute(
                    'DELETE FROM spent WHERE expires_ms <= ?', (now_ms,)
                )
                seen = self.connection.execute(
                    'SELECT 1 FROM spent WHERE identity=?', (identity,)
                ).fetchone()
                if seen is not None:
                    result = 'REPLAY'
                elif self.connection.execute(
                    'SELECT COUNT(*) FROM spent'
                ).fetchone()[0] >= self.capacity:
                    result = 'PAID_CAPACITY_BUSY'
                else:
                    self.connection.execute(
                        'INSERT INTO spent(identity,expires_ms) VALUES(?,?)',
                        (identity, expires_ms)
                    )
                    result = 'READY_RESOURCE_ONLY'
                self.connection.execute(
                    'UPDATE frontier SET last_ms=? WHERE id=1', (now_ms,)
                )
                self.connection.execute('COMMIT')
                return result
            except ValueError:
                self.connection.execute('ROLLBACK')
                raise
            except sqlite3.Error:
                try:
                    self.connection.execute('ROLLBACK')
                except sqlite3.Error:
                    pass
                return 'DURABLE_LEDGER_UNAVAILABLE'


class DurableStatelessReceiver:
    """Safe conservative wrapper around existing research-only stateless W2-C.

    The in-memory checker FIRST verifies MAC, bound caller/body/receiver and
    original Hashcash target. Only its READY result can attempt an atomic
    durable spend; a failed persistent insert never reaches full W1.
    """
    def __init__(self, receiver, secret, epoch, ledger_path,
                 *, lifetime_ms=2000, capacity=64, entropy=None):
        from w2c_stateless_receiver import StatelessReceiverAdmission
        self.original = StatelessReceiverAdmission(
            receiver, secret, epoch, lifetime_ms=lifetime_ms,
            capacity=capacity, entropy=entropy)
        self.fence = DurableSpentFence(ledger_path, capacity)

    def offer(self, proposal: bytes, caller: bytes, bits: int, now_ms: int):
        return self.original.offer(proposal, caller, bits, now_ms)

    def consume(self, grant, proposal: bytes, caller: bytes,
                nonce: int, now_ms: int):
        from contract_wire import H
        first = self.original.consume(grant, proposal, caller, nonce, now_ms)
        if first != 'READY_RESOURCE_ONLY':
            return first
        # Original research domain and canonical signed grant identity.
        key = H('w2c-stateless-paid-grant-v1', grant.unsigned(), grant.mac)
        return self.fence.spend(key, grant.expires_ms, now_ms)

    def close(self):
        self.fence.close()
