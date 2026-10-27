"""Research-only dual-possession Ed25519 -> ML-DSA migration + local replay journal.

Not a ledger transaction, authority grant, checkpoint or Hepta final-use capability.
Every production Chain migration MUST validate current chain ownership / finalized
policy and respect reorg, global storage and independent revocation authorities.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
import stat
from pathlib import Path
import sqlite3
from cryptography.exceptions import InvalidSignature

from pq_envelope import Reject, make_unsigned, public_key_id, sign_reference, verify_reference
from strict_signature import verify as verify_ed25519_strict

DOMAIN = b"TRNM/PoN/Ed25519-to-MLDSA65/v1\x00"
RECEIPT_DOMAIN = b"TRNM/PoN/PQMigrationReceipt/v1\x00"
MESSAGE_BYTES = len(DOMAIN) + 4 * 32 + 3 * 8


def exact(v: bytes, label: str) -> bytes:
    if type(v) is not bytes or len(v) != 32:
        raise Reject(label)
    return v


def u64(v: int) -> bytes:
    if type(v) is not int or not 0 < v < 1 << 64:
        raise Reject("migration identity/time")
    return v.to_bytes(8, "big")


@dataclass(frozen=True)
class MigrationStatement:
    network: bytes
    old_ed25519_pub: bytes
    new_pq_key_id: bytes
    authorized_head: bytes
    owner_generation: int
    operation_sequence: int
    expires_at: int

    def encode(self) -> bytes:
        return (DOMAIN + exact(self.network, "network")
                + exact(self.old_ed25519_pub, "old signer")
                + exact(self.new_pq_key_id, "new PQ signer")
                + exact(self.authorized_head, "owner head")
                + u64(self.owner_generation) + u64(self.operation_sequence)
                + u64(self.expires_at))


@dataclass(frozen=True)
class SignedMigration:
    statement: MigrationStatement
    old_signature: bytes  # exactly 64 bytes
    new_pq_frame: bytes


def make_signed_migration(statement: MigrationStatement, *, old_signer, new_pq_private: Path) -> SignedMigration:
    """Offline fixture signer only. Old signer must be an explicit Ed25519 private-key owner."""
    old_sig = old_signer.sign(statement.encode())
    if type(old_sig) is not bytes or len(old_sig) != 64:
        raise Reject("old signature length")
    unsigned = make_unsigned(purpose=1, network=statement.network,
                              context=statement.authorized_head,
                              signer_key_id=statement.new_pq_key_id,
                              owner_generation=statement.owner_generation,
                              operation_sequence=statement.operation_sequence,
                              expires_at=statement.expires_at, payload=statement.encode())
    return SignedMigration(statement, old_sig, sign_reference(unsigned, private_key_path=new_pq_private))


def verify_migration(proof: SignedMigration, *, new_public_pem: bytes,
                     expected_network: bytes, expected_old_pub: bytes,
                     expected_authority_head: bytes,
                     expected_generation: int, expected_sequence: int,
                     now: int) -> bytes:
    """Only validates signatures and declared bindings; DOES NOT consult ledger owner."""
    if not isinstance(proof, SignedMigration):
        raise Reject("migration proof type")
    m = proof.statement
    blob = m.encode()
    if (m.network != exact(expected_network, "network") or
            m.old_ed25519_pub != exact(expected_old_pub, "old key") or
            m.authorized_head != exact(expected_authority_head, "authority head") or
            m.owner_generation != expected_generation or
            m.operation_sequence != expected_sequence or
            type(expected_generation) is not int or type(expected_sequence) is not int or
            type(now) is not int or not 0 <= now < (1 << 64) or now > m.expires_at or
            m.new_pq_key_id != public_key_id(new_public_pem)):
        raise Reject("migration context/current identity")
    if type(proof.old_signature) is not bytes or len(proof.old_signature) != 64:
        raise Reject("old signature length")
    try:
        verify_ed25519_strict(m.old_ed25519_pub, proof.old_signature, blob)
    except (ValueError, InvalidSignature) as exc:
        raise Reject("old signature invalid") from exc
    verify_reference(proof.new_pq_frame, payload=blob, public_pem=new_public_pem,
                     expected_network=m.network, expected_context=m.authorized_head,
                     expected_purpose=1, expected_generation=m.owner_generation,
                     expected_sequence=m.operation_sequence, now=now)
    return hashlib.sha384(RECEIPT_DOMAIN + blob).digest()


class OfflineMigrationJournal:
    """Offline one-use migration fact journal; never a Chain authority issuer.

    The caller must own trustworthy parent directories and provide independent
    current chain/source and revocation anchors. A local SQLite DB cannot
    prevent full-store rollback or malicious same-UID ancestor replacement.
    """
    DDL = """CREATE TABLE pq_migration (
          network BLOB NOT NULL,
          old_pub BLOB NOT NULL,
          new_key_id BLOB NOT NULL,
          statement BLOB NOT NULL,
          receipt BLOB NOT NULL,
          PRIMARY KEY (network,old_pub),
          UNIQUE (network,new_key_id)
        ) WITHOUT ROWID"""
    SCHEMA_QUERY = "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    TEMP_QUERY = "SELECT name FROM sqlite_temp_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
    EXPECTED_SCHEMA = [("table", "pq_migration", DDL)]

    @staticmethod
    def _leaf_inode(path: Path, *, allow_missing: bool = False):
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise Reject("PQ migration journal disappeared") from None
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise Reject("PQ migration journal must be a single-link regular file")
        if value.st_mode & 0o077:
            raise Reject("PQ migration journal requires owner-only permissions")
        return (value.st_dev, value.st_ino)

    def _audit_owned_schema(self):
        """Execute under BEGIN IMMEDIATE to pin actual table and temp namespace."""
        if self.db.execute(self.SCHEMA_QUERY).fetchall() != self.EXPECTED_SCHEMA:
            raise Reject("PQ migration foreign or altered SQLite schema")
        if self.db.execute(self.TEMP_QUERY).fetchone() is not None:
            raise Reject("PQ migration temporary SQLite schema forbidden")
        if self.db.execute("PRAGMA journal_mode").fetchone() != ("wal",):
            raise Reject("PQ migration WAL missing")
        if self.db.execute("PRAGMA synchronous").fetchone() != (2,):
            raise Reject("PQ migration FULL durability missing")
        if self._leaf_inode(self.path) != self._inode:
            raise Reject("PQ migration journal inode replaced")

    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.name or self.path.name in {".", ".."}:
            raise Reject("PQ migration journal path")
        existed = self._leaf_inode(self.path, allow_missing=True)
        created = existed is None
        if created:
            if not hasattr(os, "O_NOFOLLOW"):
                raise Reject("PQ migration journal requires O_NOFOLLOW")
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600)
            except FileExistsError as exc:
                raise Reject("concurrent/foreign PQ journal creation") from exc
            else:
                os.close(fd)
        self._inode = self._leaf_inode(self.path)
        self.db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            self.db.execute("PRAGMA busy_timeout=10000")
            existing_schema = self.db.execute(self.SCHEMA_QUERY).fetchall()
            if (created and existing_schema) or (not created and existing_schema != self.EXPECTED_SCHEMA):
                raise Reject("foreign or empty PQ migration namespace; no in-place import")
            if self.db.execute(self.TEMP_QUERY).fetchone() is not None:
                raise Reject("PQ migration temporary SQLite schema forbidden")
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                raise Reject("PQ migration WAL unavailable")
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA synchronous").fetchone() != (2,):
                raise Reject("PQ migration FULL unavailable")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if created:
                    self.db.execute(self.DDL)
                self._audit_owned_schema()
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _confirm_postcommit(self, m: MigrationStatement, data: bytes, receipt: bytes):
        """Missing/renamed/corrupted record after COMMIT is indeterminate, not ACK."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._audit_owned_schema()
            readback = self.db.execute(
                "SELECT new_key_id, statement, receipt FROM pq_migration WHERE network=? AND old_pub=?",
                (m.network, m.old_ed25519_pub)).fetchone()
            if readback != (m.new_pq_key_id, data, receipt):
                raise Reject("PQ migration committed readback mismatch")
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        if self._leaf_inode(self.path) != self._inode:
            raise Reject("PQ migration path moved before acknowledgement")

    def consume(self, proof: SignedMigration, *, new_public_pem: bytes,
                expected_network: bytes, expected_old_pub: bytes,
                expected_authority_head: bytes, expected_generation: int,
                expected_sequence: int, now: int) -> tuple[str, bytes]:
        args = dict(new_public_pem=new_public_pem, expected_network=expected_network,
                    expected_old_pub=expected_old_pub,
                    expected_authority_head=expected_authority_head,
                    expected_generation=expected_generation,
                    expected_sequence=expected_sequence, now=now)
        # This is actual dual-signature verification, not a cached success flag.
        receipt = verify_migration(proof, **args)
        m = proof.statement
        data = m.encode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._audit_owned_schema()
            found = self.db.execute(
                "SELECT new_key_id, statement, receipt FROM pq_migration WHERE network=? AND old_pub=?",
                (m.network, m.old_ed25519_pub)).fetchone()
            if found is not None:
                if found != (m.new_pq_key_id, data, receipt):
                    raise Reject("conflicting or stale old-key migration")
                result = "ALREADY_RECORDED"
            else:
                try:
                    self.db.execute(
                        "INSERT INTO pq_migration(network,old_pub,new_key_id,statement,receipt) VALUES(?,?,?,?,?)",
                        (m.network, m.old_ed25519_pub, m.new_pq_key_id, data, receipt))
                except sqlite3.IntegrityError as exc:
                    raise Reject("PQ key reused by another old account") from exc
                result = "FIRST_RECORD"
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        self._confirm_postcommit(m, data, receipt)
        return result, receipt
