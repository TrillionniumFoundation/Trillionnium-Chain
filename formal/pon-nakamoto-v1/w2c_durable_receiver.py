"""Research-only durable, receiver-scoped W2-C ticket ownership.

No Chainwork, VerifiedWork, V3 network integration, independent cryptographic
acceptance or secure cross-host fork prevention. Caller must be authenticated
by an upstream transport. State directory is trusted to its OS owner.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
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
import time
from contract_wire import H

PROFILE = b'w2c-receiver-durable-spend-research-v1\0'
MAX_U64 = (1 << 64) - 1


def hash32(x, label):
    if type(x) is not bytes or len(x) != 32:
        raise ValueError(label)
    return x


def integer(x, label):
    if type(x) is not int or x < 0 or x > MAX_U64:
        raise ValueError(label)
    return x


def challenge_ticket(wire: bytes, nonce: int):
    return H('w2c-durable-local-security-v1', wire, struct.pack('<Q', integer(nonce, 'NONCE')))


def qualified(ticket: bytes, bits: int):
    hash32(ticket, 'TICKET')
    if type(bits) is not int or not 8 <= bits <= 24:
        raise ValueError('BITS')
    return (int.from_bytes(ticket[:4], 'big') >> (32-bits)) == 0


@dataclass(frozen=True)
class Grant:
    receiver: bytes
    epoch: bytes
    claim: bytes
    token: bytes
    issued_ms: int
    expires_ms: int
    bits: int
    mac: bytes

    def unsigned(self):
        for k in ('receiver','epoch','claim','token'):
            hash32(getattr(self,k), k.upper())
        integer(self.issued_ms,'ISSUED')
        integer(self.expires_ms,'EXPIRES')
        if self.expires_ms < self.issued_ms:
            raise ValueError('TIME_ORDER')
        if type(self.bits) is not int or not 8 <= self.bits <= 24:
            raise ValueError('BITS')
        return (PROFILE + self.receiver + self.epoch + self.claim + self.token
                + struct.pack('<QQB',self.issued_ms,self.expires_ms,self.bits))

    def ticket(self, nonce: int):
        return challenge_ticket(self.unsigned()+hash32(self.mac,'MAC'), nonce)


def solve(grant: Grant, cap=1 << 17):
    if type(cap) is not int or not 1 <= cap <= 1 << 20:
        raise ValueError('CAP')
    start=time.process_time_ns()
    for nonce in range(cap):
        if qualified(grant.ticket(nonce),grant.bits):
            return nonce, {'tries':nonce+1,'cpu_ns':time.process_time_ns()-start,'hit':True}
    return None, {'tries':cap,'cpu_ns':time.process_time_ns()-start,'hit':False}


class DurableReceiver:
    """One OS-host owner; SQLite commit must succeed before W1 may begin.

    A fresh secret epoch is forced and committed on every genuine opening.
    The lock file prevents a second same-host process from minting another
    independent spend view. Cross-host clones require external fencing.
    """
    def __init__(self, path, receiver, secret, *, capacity=64,
                 ttl_ms=2000, clock=None, entropy=None, before_commit=None):
        self.receiver=hash32(receiver,'RECEIVER')
        self.secret=hash32(secret,'SECRET')
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('CAPACITY')
        if type(ttl_ms) is not int or not 100 <= ttl_ms <= 2000:
            raise ValueError('TTL')
        self.capacity=capacity
        self.ttl_ms=ttl_ms
        self.clock=clock if clock is not None else lambda:time.monotonic_ns()//1_000_000
        self.entropy=entropy if entropy is not None else secrets.token_bytes
        self.before_commit=before_commit
        self.failed=False
        self.last_ms=0
        self.mu=threading.RLock()
        self.lock_fd=None
        self.db=None
        self.epoch=None
        path=Path(path).absolute()
        parent=path.parent
        pstat=os.lstat(parent)
        if not stat.S_ISDIR(pstat.st_mode) or pstat.st_uid!=os.geteuid() or pstat.st_mode & 0o077:
            raise ValueError('UNTRUSTED_DIRECTORY')
        self.path=path
        try:
            self.lock_fd=self._owned_file(path.with_name(path.name+'.lock'))
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('OWNER_BUSY') from exc
            db_fd=self._owned_file(path)
            os.close(db_fd)
            self.db=sqlite3.connect(path, timeout=1, isolation_level=None,
                                    check_same_thread=False)
            self.db.execute('PRAGMA busy_timeout=1000')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK (id=1), epoch BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS paid (key BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL) WITHOUT ROWID')
            self.db.execute('BEGIN IMMEDIATE')
            self.epoch=hash32(self.entropy(32),'EPOCH_ENTROPY')
            self.db.execute('INSERT INTO meta(id,epoch) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch', (self.epoch,))
            if self.before_commit is not None:
                self.before_commit('epoch')
            self.db.commit()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _owned_file(path):
        flags=os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW
        fd=os.open(path,flags,0o600)
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1
                or st.st_uid!=os.geteuid() or st.st_mode & 0o077):
            os.close(fd)
            raise ValueError('UNTRUSTED_FILE')
        return fd

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db=None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd=None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _now(self):
        if self.failed or self.db is None:
            raise ValueError('OWNER_UNAVAILABLE')
        n=integer(self.clock(),'CLOCK')
        if n < self.last_ms:
            self.failed=True
            raise ValueError('CLOCK_REGRESSION')
        self.last_ms=n
        return n

    def offer(self, proposal, caller, bits):
        with self.mu:
            n=self._now()
            hash32(proposal,'PROPOSAL');hash32(caller,'CALLER')
            if type(bits) is not int or not 8 <= bits <= 24:
                raise ValueError('BITS')
            if n > MAX_U64 - self.ttl_ms:
                raise ValueError('CLOCK_OVERFLOW')
            token=hash32(self.entropy(32),'TOKEN_ENTROPY')
            claim=H('w2c-durable-proposal-caller-v1',proposal,caller)
            untrusted=Grant(self.receiver,self.epoch,claim,token,n,n+self.ttl_ms,bits,b'')
            mac=hmac.new(self.secret,untrusted.unsigned(),hashlib.sha256).digest()
            return replace(untrusted,mac=mac)  # no server-side pending row

    def consume(self, grant, proposal, caller, nonce):
        """READY_RESOURCE_ONLY is a durable spend, NEVER validated W1/Chainwork."""
        with self.mu:
            now=self._now()
            if not isinstance(grant,Grant):
                return 'GRANT_ENCODING'
            try:
                unsigned=grant.unsigned()
                mac=hash32(grant.mac,'MAC')
                claim=H('w2c-durable-proposal-caller-v1',hash32(proposal,'PROPOSAL'),hash32(caller,'CALLER'))
                expected=grant.ticket(nonce)
            except ValueError:
                return 'GRANT_ENCODING'
            if grant.receiver!=self.receiver or grant.epoch!=self.epoch or grant.claim!=claim:
                return 'CONTEXT'
            if grant.expires_ms-grant.issued_ms!=self.ttl_ms:
                return 'POLICY'
            if not hmac.compare_digest(hmac.new(self.secret,unsigned,hashlib.sha256).digest(),mac):
                return 'MAC'
            if not grant.issued_ms <= now < grant.expires_ms:
                return 'EXPIRED'
            if not qualified(expected,grant.bits):
                return 'TARGET'
            key=H('w2c-durable-paid-grant-v1',unsigned,mac)
            try:
                self.db.execute('BEGIN IMMEDIATE')
                # Exactly one current shared DB epoch. Any external epoch
                # change fences an old owner even if its memory was cloned.
                original=self.db.execute('SELECT epoch FROM meta WHERE id=1').fetchone()
                if original is None or original[0]!=self.epoch:
                    self.db.rollback()
                    self.failed=True
                    return 'EPOCH_CHANGED'
                self.db.execute('DELETE FROM paid WHERE expires_ms<=?', (now,))
                if self.db.execute('SELECT 1 FROM paid WHERE key=?',(key,)).fetchone():
                    self.db.rollback()
                    return 'REPLAY'
                count=self.db.execute('SELECT count(*) FROM paid').fetchone()[0]
                if count>=self.capacity:
                    self.db.rollback()
                    return 'PAID_CAPACITY_BUSY'
                self.db.execute('INSERT INTO paid(key,expires_ms) VALUES(?,?)',(key,grant.expires_ms))
                if self.before_commit is not None:
                    self.before_commit('spend')
                self.db.commit()
            except BaseException:
                try:self.db.rollback()
                except BaseException:pass
                self.failed=True
                raise RuntimeError('DURABLE_SPEND_UNKNOWN')
            return 'READY_RESOURCE_ONLY'

    def paid_rows(self):
        with self.mu:
            self._now()
            return self.db.execute('SELECT count(*) FROM paid').fetchone()[0]
