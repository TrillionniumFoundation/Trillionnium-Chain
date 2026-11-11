"""Research-only dual-possession Ed25519 -> ML-DSA migration + local replay journal.

Not a ledger transaction, authority grant, checkpoint or Hepta final-use capability.
Every production Chain migration MUST validate current chain ownership / finalized
policy and respect reorg, global storage and independent revocation authorities.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
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
    """Local single-writer proof-consumption journal; never consensus-replicated authority."""
    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=10000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""
        CREATE TABLE IF NOT EXISTS pq_migration (
          network BLOB NOT NULL,
          old_pub BLOB NOT NULL,
          new_key_id BLOB NOT NULL,
          statement BLOB NOT NULL,
          receipt BLOB NOT NULL,
          PRIMARY KEY (network,old_pub),
          UNIQUE (network,new_key_id)
        ) WITHOUT ROWID
        """)

    def close(self):
        self.db.close()

    def consume(self, proof: SignedMigration, *, new_public_pem: bytes,
                expected_network: bytes, expected_old_pub: bytes,
                expected_authority_head: bytes, expected_generation: int,
                expected_sequence: int, now: int) -> tuple[str, bytes]:
        args = dict(new_public_pem=new_public_pem, expected_network=expected_network,
                    expected_old_pub=expected_old_pub,
                    expected_authority_head=expected_authority_head,
                    expected_generation=expected_generation,
                    expected_sequence=expected_sequence, now=now)
        receipt = verify_migration(proof, **args)
        m = proof.statement
        data = m.encode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            found = self.db.execute(
                "SELECT new_key_id, statement, receipt FROM pq_migration WHERE network=? AND old_pub=?",
                (m.network, m.old_ed25519_pub)).fetchone()
            if found is not None:
                if found != (m.new_pq_key_id, data, receipt):
                    raise Reject("conflicting or stale old-key migration")
                self.db.execute("COMMIT")
                return "ALREADY_RECORDED", receipt
            try:
                self.db.execute(
                    "INSERT INTO pq_migration(network,old_pub,new_key_id,statement,receipt) VALUES(?,?,?,?,?)",
                    (m.network, m.old_ed25519_pub, m.new_pq_key_id, data, receipt))
            except sqlite3.IntegrityError as exc:
                raise Reject("PQ key reused by another old account") from exc
            self.db.execute("COMMIT")
            return "FIRST_RECORD", receipt
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
