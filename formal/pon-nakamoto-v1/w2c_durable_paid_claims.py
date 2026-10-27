"""Research-only durable one-use spend owner for W2-C stateless admissions.

A shared SQLite WAL and BEGIN IMMEDIATE serialize paid admissions across processes
that share one administrator-controlled local store. This does NOT prove safety
when operators copy credentials but do not share a durable store. Never grants
W1 VerifiedWork, chainwork or deployment authority; no live V3 integration.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote

from contract_wire import H
from w2c_stateless_receiver import StatelessReceiverAdmission

READY = 'READY_RESOURCE_ONLY'
DB_VERSION = 1


def _checked_path(path: str) -> Path:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError('SPEND_OWNER_ABSOLUTE_PATH')
    p = Path(path)
    if p.name in ('', '.', '..') or not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError('SPEND_OWNER_DIRECTORY')
    directory = p.parent.stat()
    # This is a SAME-UID local-file demonstration only. A hostile privileged
    # operator can duplicate either the database or service keys.
    if (directory.st_uid != os.geteuid() or directory.st_mode & 0o077):
        raise ValueError('SPEND_OWNER_DIRECTORY')
    return p


def _existing_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError('SPEND_OWNER_FILE') from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ValueError('SPEND_OWNER_FILE')


def _connect(path: Path) -> sqlite3.Connection:
    _existing_file(path)
    # mode=rw prevents accidental fresh empty databases on an alternate path.
    url = 'file:' + quote(str(path), safe='/') + '?mode=rw'
    db = sqlite3.connect(url, uri=True, isolation_level=None, timeout=0.25)
    try:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA busy_timeout=250')
        if db.execute('PRAGMA user_version').fetchone()[0] != DB_VERSION:
            raise ValueError('SPEND_OWNER_SCHEMA')
        return db
    except BaseException:
        db.close()
        raise


def provision(path: str) -> None:
    """Create a single owner-owned file once. Never repair an unknown DB."""
    p = _checked_path(path)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(p, flags, 0o600)
    os.close(fd)
    try:
        # Keep the initial SQLite transaction and schema durable before any
        # MAC-authenticated paid claim is eligible to consume this store.
        db = sqlite3.connect(str(p), isolation_level=None)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE paid (key BLOB PRIMARY KEY NOT NULL, expiry INTEGER NOT NULL) WITHOUT ROWID')
            db.execute('CREATE TABLE clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), watermark INTEGER NOT NULL)')
            db.execute('INSERT INTO clock(singleton, watermark) VALUES(1, 0)')
            db.execute('PRAGMA user_version=1')  # PRAGMA may not change inside txn on old sqlite.
            db.commit()
        finally:
            db.close()
    except BaseException:
        # Do not silently recreate or forgive a failed/unknown paid owner.
        raise
    _existing_file(p)


class DurableStatelessReceiver(StatelessReceiverAdmission):
    """Research service: no W1 caller may bypass this paid-spend gate."""

    def __init__(self, receiver: bytes, secret: bytes, epoch: bytes,
                 *, db_path: str, lifetime_ms: int = 2000, capacity: int = 64,
                 entropy=None):
        super().__init__(receiver, secret, epoch, lifetime_ms=lifetime_ms,
                         capacity=capacity, entropy=entropy)
        self.db_path = _checked_path(db_path)
        db = _connect(self.db_path)
        try:
            # Deny corrupt or accidentally mismatched schemas and fail closed.
            names = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if names != {'paid', 'clock'}:
                raise ValueError('SPEND_OWNER_SCHEMA')
            if db.execute('SELECT COUNT(*) FROM clock').fetchone()[0] != 1:
                raise ValueError('SPEND_OWNER_SCHEMA')
        finally:
            db.close()

    def consume(self, grant, proposal: bytes, caller: bytes, nonce: int,
                now_ms: int) -> str:
        # Source authenticity, caller/body MAC, expiry and hash target are all
        # checked by the unchanged stateless candidate before durable claim.
        # Its finite local map is NOT global authority and grants NO W1 call.
        with self.lock:
            local = super().consume(grant, proposal, caller, nonce, now_ms)
            if local != READY:
                return local
            key = H('w2c-stateless-paid-grant-v1', grant.unsigned(), grant.mac)
            try:
                db = _connect(self.db_path)
                try:
                    db.execute('BEGIN IMMEDIATE')
                    row = db.execute('SELECT watermark FROM clock WHERE singleton=1').fetchone()
                    if row is None or now_ms < row[0]:
                        db.rollback()
                        return 'SPEND_OWNER_CLOCK_REGRESSION'
                    # Only expired tokens can be forgotten; exact live paid
                    # claim IDs cannot be evicted when capacity is reached.
                    db.execute('DELETE FROM paid WHERE expiry<=?', (now_ms,))
                    if db.execute('SELECT 1 FROM paid WHERE key=?', (key,)).fetchone():
                        db.rollback()
                        return 'REPLAY'
                    if db.execute('SELECT COUNT(*) FROM paid').fetchone()[0] >= self.capacity:
                        db.rollback()
                        return 'PAID_CAPACITY_BUSY'
                    db.execute('INSERT INTO paid(key,expiry) VALUES(?,?)',
                               (key, grant.expires_ms))
                    db.execute('UPDATE clock SET watermark=? WHERE singleton=1',
                               (now_ms,))
                    db.commit()  # before any caller can begin expensive W1
                    return READY
                finally:
                    db.close()
            except (sqlite3.Error, OSError, ValueError):
                # Unknown commits/faults are never silently retried as a free
                # W1 admission. Only original operator recovery may examine DB.
                return 'SPEND_OWNER_UNAVAILABLE'
