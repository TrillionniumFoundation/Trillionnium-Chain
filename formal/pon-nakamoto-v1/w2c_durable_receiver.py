"""W2-C research only: restart-fenced, durable paid ticket consumption.

A receiver-local SQLite transaction commits exactly one paid grant BEFORE
any W1 replay. An exclusive private-directory lock prevents same-host twin
receivers; each startup commits an independently fresh epoch before issuing
grants. Cloned hosts/secrets, forged clock, GPU cost and public service remain
unqualified. NO VerifiedWork/Chainwork, V3 Cookie or W1 rule is changed.
"""
from __future__ import annotations
from dataclasses import replace
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import struct
import threading
from contract_wire import H
from w2c_receiver_admission import Grant, MAX_U64, bytes32, exact_u64, qualifies, ticket

MAX_GENERATION = (1 << 63) - 1


def _file(path: Path):
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        os.close(fd)
        raise ValueError('PRIVATE_REGULAR_FILE_REQUIRED')
    return fd


class DurableReceiverAdmission:
    """Isolated same-host durable research owner; actual transport is external."""

    def __init__(self, directory: str | Path, receiver: bytes, secret: bytes,
                 *, capacity: int = 64, lifetime_ms: int = 2000,
                 entropy=None):
        self.receiver = bytes32(receiver, 'RECEIVER')
        self.secret = bytes32(secret, 'SECRET')
        if self.secret == bytes(32):
            raise ValueError('SECRET_ZERO')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError('LIFETIME')
        self.capacity, self.lifetime_ms = capacity, lifetime_ms
        self.entropy = secrets.token_bytes if entropy is None else entropy
        self.lock = threading.RLock()
        self.closed = True
        self.conn = None
        self.guard_fd = None
        directory = Path(directory)
        info = directory.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or directory.is_symlink()):
            raise ValueError('PRIVATE_DIRECTORY_REQUIRED')
        fd = _file(directory / '.w2c-receiver.lock')
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError('EXCLUSIVE_RECEIVER_OWNER') from error
            # The SQLite path must be a preopened, ordinary owned 0600 file.
            dbfd = _file(directory / 'w2c-paid.sqlite')
            os.close(dbfd)
            conn = sqlite3.connect(directory / 'w2c-paid.sqlite',
                                   timeout=1.0, isolation_level=None,
                                   check_same_thread=False)
            try:
                journal = conn.execute('PRAGMA journal_mode=DELETE').fetchone()[0]
                conn.execute('PRAGMA synchronous=FULL')
                if journal.lower() != 'delete' or conn.execute(
                        'PRAGMA synchronous').fetchone()[0] != 2:
                    raise ValueError('DURABLE_SQLITE_POLICY')
                conn.execute('CREATE TABLE IF NOT EXISTS metadata ('
                             'one INTEGER PRIMARY KEY CHECK(one=1), '
                             'owner BLOB NOT NULL, generation INTEGER NOT NULL,'
                             'epoch BLOB NOT NULL)')
                conn.execute('CREATE TABLE IF NOT EXISTS paid ('
                             'key BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL)')
                # Every startup MUST advance and persist the epoch before
                # issuing even one resource grant. No same-epoch restart.
                conn.execute('BEGIN IMMEDIATE')
                try:
                    fingerprint = H('w2c-durable-owner-v1', self.receiver, self.secret)
                    prior = conn.execute('SELECT owner,generation FROM metadata WHERE one=1').fetchone()
                    if prior is not None and prior[0] != fingerprint:
                        raise ValueError('OWNER_CREDENTIAL_CHANGED')
                    generation = 1 if prior is None else prior[1] + 1
                    if generation > MAX_GENERATION:
                        raise ValueError('GENERATION_OVERFLOW')
                    random = bytes32(self.entropy(32), 'ENTROPY')
                    self.epoch = H('w2c-durable-process-epoch-v1', self.receiver,
                                   struct.pack('<Q', generation), random)
                    if prior is None:
                        conn.execute('INSERT INTO metadata VALUES(1,?,?,?)',
                                     (fingerprint,generation,self.epoch))
                    else:
                        conn.execute('UPDATE metadata SET generation=?, epoch=? WHERE one=1',
                                     (generation,self.epoch))
                    # Old epoch tickets cannot be admitted after restart.
                    # The historical aggregate counter is NOT inferred from
                    # the current bounded paid table.
                    conn.execute('DELETE FROM paid')
                    conn.execute('COMMIT')
                except BaseException:
                    conn.execute('ROLLBACK')
                    raise
                # Persist the private DB/directory entry before publishing any
                # signed grant from this newly committed service epoch.
                parent_fd = os.open(directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except BaseException:
                conn.close()
                raise
            self.guard_fd, self.conn = fd, conn
            self.closed = False
            self.last_now_ms = 0
        except BaseException:
            os.close(fd)
            raise

    def _available(self):
        if self.closed:
            raise ValueError('RECEIVER_CLOSED')

    def _clock(self, value):
        exact_u64(value, 'CLOCK')
        if value < self.last_now_ms:
            raise ValueError('CLOCK_REGRESSION')
        self.last_now_ms = value

    def offer(self, proposal: bytes, caller: bytes, bits: int, now_ms: int) -> Grant:
        """Offer is stateless; caller MUST have been independently authenticated."""
        with self.lock:
            self._available()
            self._clock(now_ms)
            bytes32(proposal, 'PROPOSAL')
            bytes32(caller, 'CALLER')
            if type(bits) is not int or not 8 <= bits <= 24:
                raise ValueError('BITS')
            if now_ms > MAX_U64 - self.lifetime_ms:
                raise ValueError('CLOCK_OVERFLOW')
            token = bytes32(self.entropy(32), 'ENTROPY')
            statement = H('w2c-stateless-caller-proposal-v1',caller,proposal)
            bare = Grant(self.receiver, self.epoch,statement,token,bits,
                         now_ms,now_ms+self.lifetime_ms,b'')
            mac = hmac.new(self.secret,bare.unsigned(),hashlib.sha256).digest()
            return replace(bare,mac=mac)

    def consume(self, grant: Grant, proposal: bytes, caller: bytes,
                nonce: int, now_ms: int) -> str:
        """Returns resource permission ONLY after SQLite durable commit."""
        with self.lock:
            self._available()
            self._clock(now_ms)
            if not isinstance(grant,Grant):
                return 'GRANT_ENCODING'
            try:
                unsigned=grant.unsigned()
                mac=bytes32(grant.mac,'MAC')
                bytes32(proposal,'PROPOSAL')
                bytes32(caller,'CALLER')
                exact_u64(nonce,'NONCE')
            except ValueError:
                return 'GRANT_ENCODING'
            statement=H('w2c-stateless-caller-proposal-v1',caller,proposal)
            if (grant.receiver!=self.receiver or grant.epoch!=self.epoch
                    or grant.proposal!=statement):
                return 'CONTEXT'
            if grant.expires_ms-grant.issued_ms!=self.lifetime_ms:
                return 'LIFETIME_POLICY'
            if not hmac.compare_digest(
                    hmac.new(self.secret,unsigned,hashlib.sha256).digest(),mac):
                return 'GRANT_MAC'
            if not grant.issued_ms<=now_ms<grant.expires_ms:
                return 'EXPIRED_OR_FUTURE'
            if not qualifies(ticket(grant,nonce),grant.bits):
                return 'TARGET'
            key=H('w2c-stateless-paid-grant-v1',unsigned,mac)
            # An SQLite rollback or I/O failure does NOT return READY; the
            # caller cannot enter W1 before transaction success.
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                self.conn.execute('DELETE FROM paid WHERE expires_ms<=?',(now_ms,))
                if self.conn.execute('SELECT 1 FROM paid WHERE key=?',(key,)).fetchone():
                    outcome='REPLAY'
                elif self.conn.execute('SELECT COUNT(*) FROM paid').fetchone()[0]>=self.capacity:
                    outcome='PAID_CAPACITY_BUSY'
                else:
                    self.conn.execute('INSERT INTO paid(key,expires_ms) VALUES(?,?)',
                                      (key,grant.expires_ms))
                    outcome='READY_RESOURCE_ONLY'
                self.conn.execute('COMMIT')
            except BaseException:
                self.conn.execute('ROLLBACK')
                raise
            return outcome

    def paid_count(self):
        with self.lock:
            self._available()
            return self.conn.execute('SELECT COUNT(*) FROM paid').fetchone()[0]

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed=True
            try:
                self.conn.close()
            finally:
                fcntl.flock(self.guard_fd,fcntl.LOCK_UN)
                os.close(self.guard_fd)

    def __enter__(self):
        self._available()
        return self

    def __exit__(self,*_):
        self.close()
