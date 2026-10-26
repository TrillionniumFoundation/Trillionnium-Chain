"""Research-only durable one-use Hashcash spend owner, NO work/ledger authority.

Called only after an independent verifier has authenticated the complete
receiver-bound grant, exact policy bits, caller/proposal and successful ticket.
Shares one local private SQLite file across independent processes. It cannot
protect other physical hosts or independently copied database files.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import struct

SCHEMA = b"trnm-w2c-durable-spent-research-v1"
MAX_U64 = (1 << 64) - 1
SQLITE_SIGNED_MAX = (1 << 63) - 1


class OwnerUnavailable(RuntimeError):
    """Fail closed: an unavailable/unsafe durable owner cannot authorize W1."""


def _u64(n: int, name: str) -> int:
    if type(n) is not int or not 0 <= n <= MAX_U64:
        raise ValueError(name)
    return n


def _hash32(value: bytes, name: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(name)
    return value


class DurablePaidSpendOwner:
    def __init__(self, path: str | Path, receiver: bytes, epoch: bytes, capacity: int = 64):
        self.receiver = _hash32(receiver, "RECEIVER")
        self.epoch = _hash32(epoch, "EPOCH")
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("CAPACITY")
        self.capacity = capacity
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.name in ("", ".", ".."):
            raise OwnerUnavailable("PATH")
        self._owner_dir()
        self._check_file(create=True)
        self._initialize()

    def _owner_dir(self):
        parent = self.path.parent
        try:
            st = parent.lstat()
        except OSError as error:
            raise OwnerUnavailable("PARENT") from error
        # A private directory is needed for SQLite WAL and SHM sidecars.
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
                or st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise OwnerUnavailable("PARENT")

    def _check_file(self, create=False):
        self._owner_dir()
        flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        if create:
            flags |= os.O_CREAT
        try:
            fd = os.open(self.path, flags, 0o600)
            st = os.fstat(fd)
            os.close(fd)
        except OSError as error:
            raise OwnerUnavailable("OPEN") from error
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise OwnerUnavailable("FILE_MODE")
        return (st.st_dev, st.st_ino)

    def _connect(self):
        before = self._check_file()
        try:
            db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
            db.execute("PRAGMA busy_timeout=3000")
            db.execute("PRAGMA synchronous=FULL")
            mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != 'wal' or before != self._check_file():
                raise OwnerUnavailable("JOURNAL_REPLACED")
            return db
        except (sqlite3.Error, OSError, OwnerUnavailable) as error:
            if "db" in locals():
                db.close()
            raise OwnerUnavailable("SQLITE_OPEN") from error

    @staticmethod
    def _expected(receiver, epoch, capacity):
        return {
            'schema': SCHEMA,
            'receiver': receiver,
            'epoch': epoch,
            'capacity': struct.pack('<I', capacity),
        }

    def _initialize(self):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID")
            db.execute("CREATE TABLE IF NOT EXISTS spent (key BLOB PRIMARY KEY, expiry INTEGER NOT NULL) WITHOUT ROWID")
            for name, value in self._expected(self.receiver, self.epoch, self.capacity).items():
                prior = db.execute("SELECT value FROM meta WHERE name=?", (name,)).fetchone()
                if prior is None:
                    db.execute("INSERT INTO meta(name,value) VALUES (?,?)", (name, value))
                elif prior[0] != value:
                    raise OwnerUnavailable("OWNER_CONTEXT")
            if db.execute("SELECT value FROM meta WHERE name='last_time'").fetchone() is None:
                db.execute("INSERT INTO meta(name,value) VALUES('last_time',?)", (struct.pack('<Q', 0),))
            db.execute("COMMIT")
        except (sqlite3.Error, OwnerUnavailable) as error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise OwnerUnavailable("INIT") from error
        finally:
            db.close()

    def spend(self, key: bytes, expires_ms: int, now_ms: int) -> str:
        """Atomic paid-only claim: READY happens *after* FULL durable commit."""
        _hash32(key, 'SPEND_KEY')
        _u64(expires_ms, 'EXPIRY')
        _u64(now_ms, 'CLOCK')
        if expires_ms > SQLITE_SIGNED_MAX:
            raise ValueError('EXPIRY_RANGE')
        if now_ms >= expires_ms:
            return 'EXPIRED'
        if expires_ms - now_ms > 2000:
            return 'LIFETIME_POLICY'
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT value FROM meta WHERE name='last_time'").fetchone()
            if old is None or len(old[0]) != 8:
                raise OwnerUnavailable("CLOCK_MISSING")
            old_ms = struct.unpack('<Q', old[0])[0]
            if now_ms < old_ms:
                raise OwnerUnavailable('CLOCK_REGRESSION')
            db.execute("DELETE FROM spent WHERE expiry<=?", (now_ms,))
            existing = db.execute("SELECT expiry FROM spent WHERE key=?", (key,)).fetchone()
            if existing is not None:
                result = 'REPLAY'
            elif db.execute("SELECT COUNT(*) FROM spent").fetchone()[0] >= self.capacity:
                result = 'PAID_CAPACITY_BUSY'
            else:
                db.execute("INSERT INTO spent(key,expiry) VALUES(?,?)", (key, expires_ms))
                result = 'READY_RESOURCE_ONLY'
            db.execute("UPDATE meta SET value=? WHERE name='last_time'", (struct.pack('<Q', now_ms),))
            db.execute("COMMIT")
            return result
        except (sqlite3.Error, OwnerUnavailable) as error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise OwnerUnavailable("SPEND") from error
        finally:
            db.close()

    def pending_paid(self):
        db = self._connect()
        try:
            row = db.execute("SELECT COUNT(*) FROM spent").fetchone()
            if row is None:
                raise OwnerUnavailable('COUNT')
            return row[0]
        except sqlite3.Error as error:
            raise OwnerUnavailable('COUNT') from error
        finally:
            db.close()
