"""Research-only durable paid-ticket owner for existing W2-C stateless offers.

No consensus, VerifiedWork, public V3 transport or user-controlled storage URI.
A fixed trusted local SQLite database serializes paid grants across processes.
It cannot prevent copies of the database + same HMAC key/epoch elsewhere.
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
from w2c_receiver_admission import Grant, MAX_U64, bytes32, exact_u64, qualifies, ticket
from w2c_stateless_receiver import StatelessReceiverAdmission

SCHEMA = 'w2c-research-durable-paid-spend-v1'
DB_NAME = 'paid-spend.sqlite'
MAX_DB_BYTES = 2 * 1024 * 1024
SQL_MAX_TIME = (1 << 63) - 1


class DurableReceiverAdmission(StatelessReceiverAdmission):
    """Never call W1 based on a response other than READY_RESOURCE_ONLY.

    The caller must separately authenticate the signed peer and protect an
    absolute, owner-private directory. Each serving process reopens the SAME
    physical DB; missing or independently copied DBs are not safe restarts.
    """

    def __init__(self, receiver: bytes, secret: bytes, epoch: bytes,
                 directory: str | Path, *, create: bool = False,
                 lifetime_ms: int = 2000, capacity: int = 64, entropy=None):
        super().__init__(receiver, secret, epoch, lifetime_ms=lifetime_ms,
                         capacity=capacity, entropy=entropy)
        self._db_lock = threading.RLock()
        self._directory = Path(directory)
        if (not self._directory.is_absolute()
                or os.path.realpath(self._directory) != str(self._directory)):
            raise ValueError('OWNER_DIRECTORY')
        parent = os.lstat(self._directory)
        if (not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise ValueError('OWNER_DIRECTORY')
        self._path = self._directory / DB_NAME
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        self._fd = os.open(self._path, flags, 0o600)
        self._db = None
        try:
            self._check_file()
            self._db = sqlite3.connect(
                self._path.as_uri() + '?mode=rw', uri=True,
                isolation_level=None, timeout=0.25, check_same_thread=False,
            )
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=EXTRA')
            self._db.execute('PRAGMA busy_timeout=250')
            self._fingerprint = hmac.new(
                self.secret, b'TRNM-W2C-PAID-OWNER-V1\0' + self.receiver + self.epoch,
                hashlib.sha256,
            ).digest()
            if create:
                self._db.execute('BEGIN IMMEDIATE')
                try:
                    self._db.execute(
                        'CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), '
                        'schema TEXT NOT NULL, fingerprint BLOB NOT NULL, '
                        'watermark INTEGER NOT NULL)'
                    )
                    self._db.execute(
                        'CREATE TABLE spent (identity BLOB PRIMARY KEY, expiry INTEGER NOT NULL)'
                    )
                    self._db.execute(
                        'INSERT INTO config(id,schema,fingerprint,watermark) VALUES(1,?,?,0)',
                        (SCHEMA, self._fingerprint),
                    )
                    self._db.execute('COMMIT')
                except BaseException:
                    self._db.execute('ROLLBACK')
                    raise
            self._check_file()
            if self._db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('OWNER_CORRUPT')
            config = self._db.execute(
                'SELECT schema,fingerprint,watermark FROM config WHERE id=1'
            ).fetchone()
            if (config is None or config[0] != SCHEMA
                    or not isinstance(config[1], bytes)
                    or not hmac.compare_digest(config[1], self._fingerprint)):
                raise ValueError('OWNER_CONTEXT')
            if (type(config[2]) is not int or config[2] < 0
                    or config[2] > SQL_MAX_TIME):
                raise ValueError('OWNER_WATERMARK')
            self.last_now_ms = config[2]
        except BaseException:
            if self._db is not None:
                self._db.close()
                self._db = None
            os.close(self._fd)
            self._fd = -1
            raise

    def _check_file(self):
        if self._fd < 0:
            raise ValueError('OWNER_CLOSED')
        held = os.fstat(self._fd)
        current = os.lstat(self._path)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                or held.st_uid != os.geteuid() or held.st_mode & 0o077
                or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
                or current.st_size > MAX_DB_BYTES):
            raise ValueError('OWNER_REPLACED')

    def close(self):
        with self._db_lock:
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1

    def pending_paid(self):
        with self._db_lock:
            self._check_file()
            return self._db.execute('SELECT COUNT(*) FROM spent').fetchone()[0]

    def consume(self, grant: Grant, proposal: bytes, caller: bytes,
                nonce: int, now_ms: int) -> str:
        """Only a DURABLY COMMITTED spend can permit separate W1 work.

        A local write/lock/corruption failure is UNAVAILABLE, not Invalid W1.
        A crashed process after commit may have spent a ticket without W1;
        safe at-most-once admission, NOT exactly-once execution.
        """
        with self._db_lock, self.lock:
            exact_u64(now_ms, 'CLOCK')
            if now_ms > SQL_MAX_TIME:
                return 'CLOCK_RANGE'
            if now_ms < self.last_now_ms:
                return 'CLOCK_REGRESSION'
            if not isinstance(grant, Grant):
                return 'GRANT_ENCODING'
            try:
                payload = grant.unsigned()
                mac = bytes32(grant.mac, 'MAC')
                bytes32(proposal, 'PROPOSAL')
                bytes32(caller, 'CALLER')
                exact_u64(nonce, 'NONCE')
            except ValueError:
                return 'GRANT_ENCODING'
            expected_proposal = H('w2c-stateless-caller-proposal-v1', caller, proposal)
            if (grant.receiver != self.receiver or grant.epoch != self.epoch
                    or grant.proposal != expected_proposal):
                return 'CONTEXT'
            if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
                return 'LIFETIME_POLICY'
            if not hmac.compare_digest(
                    hmac.new(self.secret, payload, hashlib.sha256).digest(), mac):
                return 'GRANT_MAC'
            if not grant.issued_ms <= now_ms < grant.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            # SQLite stores signed 64-bit integer timestamps. Reject a valid
            # u64 grant outside that persistence domain, never overflow INSERT.
            if grant.expires_ms > SQL_MAX_TIME:
                return 'CLOCK_RANGE'
            if not qualifies(ticket(grant, nonce), grant.bits):
                return 'TARGET'
            key = H('w2c-stateless-paid-grant-v1', payload, mac)
            try:
                self._check_file()
                self._db.execute('BEGIN IMMEDIATE')
                row = self._db.execute(
                    'SELECT schema,fingerprint,watermark FROM config WHERE id=1'
                ).fetchone()
                if (row is None or row[0] != SCHEMA or row[1] != self._fingerprint):
                    raise ValueError('OWNER_CONTEXT')
                if now_ms < row[2]:
                    self._db.execute('ROLLBACK')
                    return 'CLOCK_REGRESSION'
                self._db.execute('DELETE FROM spent WHERE expiry <= ?', (now_ms,))
                if self._db.execute(
                        'SELECT 1 FROM spent WHERE identity=?', (key,)
                ).fetchone() is not None:
                    self._db.execute('ROLLBACK')
                    return 'REPLAY'
                if self._db.execute('SELECT COUNT(*) FROM spent').fetchone()[0] >= self.capacity:
                    self._db.execute('ROLLBACK')
                    return 'PAID_CAPACITY_BUSY'
                self._db.execute(
                    'INSERT INTO spent(identity,expiry) VALUES(?,?)',
                    (key, grant.expires_ms),
                )
                self._db.execute('UPDATE config SET watermark=? WHERE id=1', (now_ms,))
                self._db.execute('COMMIT')
                self._check_file()
                self.last_now_ms = now_ms
                return 'READY_RESOURCE_ONLY'
            except (sqlite3.Error, OSError, ValueError):
                try:
                    self._db.execute('ROLLBACK')
                except (sqlite3.Error, AttributeError):
                    pass
                return 'DURABLE_UNAVAILABLE'
