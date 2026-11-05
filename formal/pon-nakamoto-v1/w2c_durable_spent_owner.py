"""Research-only durable W2-C paid-ticket settlement, not Chain authority.

An explicit existing SQLite owner serializes spent W2-C MACed grants across
independent processes. No W1 proof, consensus work, client identity or CPU credit
is minted by this module. Filesystem cloning is outside its guarantee.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import struct
import threading
from urllib.parse import quote

from contract_wire import H
from w2c_receiver_admission import Grant, bytes32, exact_u64, qualifies, ticket

PROFILE = b"trnm-w2c-durable-spent-research-v1\0"
SCHEMA = "w2c-durable-spent-research-v1"


def require_private_file(path: Path) -> tuple[int, int]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("ABSOLUTE_PATH_REQUIRED")
    st = path.lstat()
    if not os.path.isfile(path) or not __import__("stat").S_ISREG(st.st_mode):
        raise ValueError("REGULAR_FILE_REQUIRED")
    if st.st_nlink != 1 or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("PRIVATE_OWNER_REQUIRED")
    return (st.st_dev, st.st_ino)


class DurableSpentOwner:
    """One shared local DB/boot/epoch; never a permissionless anti-Sybil proof."""

    def __init__(self, path: Path, *, receiver: bytes, secret: bytes,
                 epoch: bytes, boot: bytes, lifetime_ms: int = 2000,
                 capacity: int = 64, create: bool = False):
        self.receiver = bytes32(receiver, "RECEIVER")
        self.secret = bytes32(secret, "SECRET")
        self.epoch = bytes32(epoch, "EPOCH")
        self.boot = bytes32(boot, "BOOT")
        if type(lifetime_ms) is not int or not 100 <= lifetime_ms <= 2000:
            raise ValueError("LIFETIME")
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("CAPACITY")
        self.lifetime_ms = lifetime_ms
        self.capacity = capacity
        self.path = path
        self.mutex = threading.Lock()
        if create:
            if not isinstance(path, Path) or not path.is_absolute() or path.exists() or path.is_symlink():
                raise ValueError("CREATE_NEW_ONLY")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self.identity = require_private_file(path)
        uri = "file:" + quote(str(path), safe="/") + "?mode=rw"
        self.db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=1.0)
        self.db.execute("PRAGMA busy_timeout=1000")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.context = H("w2c-durable-owner-context", PROFILE, self.receiver,
                         self.epoch, self.boot,
                         struct.pack("<HI", self.lifetime_ms, self.capacity))
        if create:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, context BLOB NOT NULL, last_ms INTEGER NOT NULL)")
                self.db.execute("CREATE TABLE spent (receipt BLOB PRIMARY KEY, expires_ms INTEGER NOT NULL)")
                self.db.execute("INSERT INTO meta(id,schema,context,last_ms) VALUES (1,?,?,0)", (SCHEMA, self.context))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        self._check_owner()

    def _check_owner(self):
        if require_private_file(self.path) != self.identity:
            raise ValueError("OWNER_STORE_REPLACED")
        row = self.db.execute("SELECT schema,context,last_ms FROM meta WHERE id=1").fetchone()
        if (not row or row[0] != SCHEMA or row[1] != self.context
                or type(row[2]) is not int or row[2] < 0):
            raise ValueError("OWNER_EPOCH_OR_SCHEMA")

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _validate_paid(self, grant: Grant, proposal: bytes, caller: bytes,
                       nonce: int, now_ms: int) -> tuple[str, bytes | None]:
        exact_u64(now_ms, "CLOCK")
        if not isinstance(grant, Grant):
            return "GRANT_ENCODING", None
        try:
            payload = grant.unsigned()
            mac = bytes32(grant.mac, "MAC")
            bytes32(proposal, "PROPOSAL")
            bytes32(caller, "CALLER")
            exact_u64(nonce, "NONCE")
        except ValueError:
            return "GRANT_ENCODING", None
        if (grant.receiver != self.receiver or grant.epoch != self.epoch
                or grant.proposal != H("w2c-stateless-caller-proposal-v1", caller, proposal)):
            return "CONTEXT", None
        if grant.expires_ms - grant.issued_ms != self.lifetime_ms:
            return "LIFETIME_POLICY", None
        if not hmac.compare_digest(hmac.new(self.secret, payload, hashlib.sha256).digest(), mac):
            return "GRANT_MAC", None
        if not grant.issued_ms <= now_ms < grant.expires_ms:
            return "EXPIRED_OR_FUTURE", None
        if not qualifies(ticket(grant, nonce), grant.bits):
            return "TARGET", None
        return "PAID_CHECKED", H("w2c-stateless-paid-grant-v1", payload, mac)

    def consume(self, grant: Grant, proposal: bytes, caller: bytes, nonce: int,
                now_ms: int) -> str:
        """Commit one receipt before costly W1. Never a VerifiedWork or payment."""
        status, receipt = self._validate_paid(grant, proposal, caller, nonce, now_ms)
        if status != "PAID_CHECKED":
            return status
        if now_ms > (1 << 63) - 1:
            return "CLOCK_RANGE"
        # SQLite BEGIN IMMEDIATE enforces atomicity even between processes.
        # A local lock also prevents thread-level use of one sqlite handle.
        with self.mutex:
            if require_private_file(self.path) != self.identity:
                raise ValueError("OWNER_STORE_REPLACED")
            try:
                self.db.execute("BEGIN IMMEDIATE")
                context, prior = self.db.execute(
                    "SELECT context,last_ms FROM meta WHERE id=1").fetchone()
                if context != self.context:
                    result = "OWNER_EPOCH_OR_SCHEMA"
                elif now_ms < prior:
                    result = "CLOCK_REGRESSION"
                else:
                    self.db.execute("DELETE FROM spent WHERE expires_ms<=?", (now_ms,))
                    existing = self.db.execute(
                        "SELECT 1 FROM spent WHERE receipt=?", (receipt,)).fetchone()
                    if existing:
                        result = "REPLAY"
                    elif self.db.execute("SELECT count(*) FROM spent").fetchone()[0] >= self.capacity:
                        result = "PAID_CAPACITY_BUSY"
                    else:
                        self.db.execute("INSERT INTO spent(receipt,expires_ms) VALUES (?,?)",
                                        (receipt, grant.expires_ms))
                        result = "READY_RESOURCE_ONLY"
                    self.db.execute("UPDATE meta SET last_ms=? WHERE id=1", (now_ms,))
                self.db.execute("COMMIT")
                return result
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def count_spent(self):
        return self.db.execute("SELECT count(*) FROM spent").fetchone()[0]
