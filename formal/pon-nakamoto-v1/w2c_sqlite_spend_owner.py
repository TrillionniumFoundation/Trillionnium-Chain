"""W2-C research only: local SQLite durable, atomically consumed paid grants.

NOT an admission server, consensus rule, cryptocurrency receipt or GPU-cost
proof. A single trusted local filesystem owner is assumed; replicated SQLite
files, shared secrets on disconnected hosts or stolen credentials are NOT safe.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
import stat
from pathlib import Path

MAX_CLOCK = (1 << 63) - 1  # SQLite signed INTEGER; no unsigned wrap/aliases.


def _hash32(value, label):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(label)
    return value


def _time(value, label):
    if type(value) is not int or not 0 <= value <= MAX_CLOCK:
        raise ValueError(label)
    return value


class SqlitePaidSpendOwner:
    """Atomic paid-only claims under one original, privately owned SQLite file.

    Context binds receiver, epoch and intended contract at creation. Two
    workers can share the file; changing context or reusing a cloned copy
    is rejected or outside the security claim. Each claim opens its own
    connection, never holding locks across W1 computation.
    """

    def __init__(self, path, context, capacity=64):
        self.path = Path(path)
        _hash32(context, 'OWNER_CONTEXT')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if not self.path.is_absolute() or self.path.name in ('', '.', '..'):
            raise ValueError('OWNER_PATH')
        parent = self.path.parent
        parent_stat = parent.lstat()
        if (not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != os.geteuid()
                or parent_stat.st_mode & 0o077):
            raise ValueError('OWNER_DIRECTORY')
        self.context = context
        self.capacity = capacity
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError:
            self._check_file()
        else:
            os.close(descriptor)
        with closing(self._connect()) as con, con:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('BEGIN IMMEDIATE')
            con.execute('CREATE TABLE IF NOT EXISTS owner ('
                        'single INTEGER PRIMARY KEY CHECK(single=1), '
                        'context BLOB NOT NULL, capacity INTEGER NOT NULL, highest_ms INTEGER NOT NULL)')
            con.execute('CREATE TABLE IF NOT EXISTS spent ('
                        'key BLOB PRIMARY KEY CHECK(length(key)=32), '
                        'expires_ms INTEGER NOT NULL) WITHOUT ROWID')
            row = con.execute('SELECT context, capacity FROM owner WHERE single=1').fetchone()
            if row is None:
                con.execute('INSERT INTO owner VALUES(1, ?, ?, -1)', (context, capacity))
            elif row[0] != context or row[1] != capacity:
                raise ValueError('OWNER_CONTEXT_MISMATCH')
            con.commit()
        self._check_file()

    def _check_file(self):
        try:
            st = self.path.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise ValueError('OWNER_FILE')

    def _connect(self):
        self._check_file()
        # The owner path is a research-only local trust assumption; opening it
        # again is not a hardened no-TOCTOU file-descriptor binding.
        con = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        con.execute('PRAGMA busy_timeout=5000')
        con.execute('PRAGMA synchronous=FULL')
        return con

    def claim(self, key, expires_ms, now_ms):
        _hash32(key, 'PAID_KEY')
        _time(expires_ms, 'EXPIRES_MS')
        _time(now_ms, 'CLOCK')
        if expires_ms <= now_ms:
            return 'EXPIRED_OR_FUTURE'
        try:
            with closing(self._connect()) as con, con:
                con.execute('BEGIN IMMEDIATE')
                row = con.execute('SELECT context, capacity, highest_ms FROM owner WHERE single=1').fetchone()
                if row is None or row[0] != self.context or row[1] != self.capacity:
                    raise ValueError('OWNER_CONTEXT_MISMATCH')
                if now_ms < row[2]:
                    return 'CLOCK_REGRESSION'
                con.execute('UPDATE owner SET highest_ms=? WHERE single=1', (now_ms,))
                con.execute('DELETE FROM spent WHERE expires_ms<=?', (now_ms,))
                if con.execute('SELECT 1 FROM spent WHERE key=?', (key,)).fetchone():
                    con.commit()
                    return 'REPLAY'
                count = con.execute('SELECT count(*) FROM spent').fetchone()[0]
                if count >= self.capacity:
                    con.commit()
                    return 'PAID_CAPACITY_BUSY'
                con.execute('INSERT INTO spent VALUES(?, ?)', (key, expires_ms))
                con.commit()  # Durable *before* W1 is permitted to start.
                return 'READY_RESOURCE_ONLY'
        except (sqlite3.Error, OSError) as exc:
            raise ValueError('PAID_OWNER_UNAVAILABLE') from exc

    def pending_paid(self):
        try:
            with closing(self._connect()) as con, con:
                row = con.execute('SELECT context, capacity FROM owner WHERE single=1').fetchone()
                if row is None or row[0] != self.context or row[1] != self.capacity:
                    raise ValueError('OWNER_CONTEXT_MISMATCH')
                return con.execute('SELECT count(*) FROM spent').fetchone()[0]
        except (sqlite3.Error, OSError) as exc:
            raise ValueError('PAID_OWNER_UNAVAILABLE') from exc
