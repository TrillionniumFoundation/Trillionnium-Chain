#!/usr/bin/env python3
"""External monotonic rollback *reference oracle*, not a production security gate.

The trusted witness and its HMAC key are OUTSIDE the node/database rollback
and attacker control domain.  HMAC-SHA-512 is an isolated deterministic test
mechanism, NOT a deployed ML-DSA witness, a hardware root, or PQ-128 proof.
An application must refuse effects until the fresh external check succeeds.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

DOMAIN = b'TRNM/PQ/external-rollback-witness/reference-v1\0'
MAGIC = b'PQR1'
DIGEST_BYTES = 32
CHALLENGE_BYTES = 32
TAG_BYTES = 64
FRAME_BYTES = 4 + 32 + 8 + 32 + 32 + 32 + TAG_BYTES
MAX_SEQUENCE = (1 << 64) - 1


class Refuse(ValueError):
    """No recovery, effect or use authorization may follow this result."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Refuse(reason)


def digest(value: bytes, label: str) -> None:
    require(type(value) is bytes and len(value) == DIGEST_BYTES and value != bytes(32), label)


def challenge_check(value: bytes) -> None:
    digest(value, 'untrusted/stale challenge')


def secret_check(value: bytes) -> None:
    # The test key is never serialized with the checkpoint or database.
    require(type(value) is bytes and len(value) == 64, 'witness key contract')


@dataclass(frozen=True)
class Checkpoint:
    network: bytes
    sequence: int  # External observation order; NOT chain height or account nonce.
    state_root: bytes
    journal_root: bytes

    def validate(self) -> None:
        digest(self.network, 'network context')
        digest(self.state_root, 'state root')
        digest(self.journal_root, 'journal root')
        require(type(self.sequence) is int and 1 <= self.sequence <= MAX_SEQUENCE,
                'external sequence')


def body(checkpoint: Checkpoint, challenge: bytes) -> bytes:
    checkpoint.validate()
    challenge_check(challenge)
    return (MAGIC + checkpoint.network + checkpoint.sequence.to_bytes(8, 'big')
            + checkpoint.state_root + checkpoint.journal_root + challenge)


class ExternalMonotonicWitness:
    """A distinct trusted state domain, simulated by an isolated Python object.

    This is not persisted by the node and cannot be reconstructed from its DB.
    Remote authentication, witness durability and access control are not modeled.
    """
    def __init__(self, network: bytes, secret: bytes):
        digest(network, 'witness network')
        secret_check(secret)
        self.__network = network
        self.__key = secret
        self.__head: Checkpoint | None = None

    def publish(self, checkpoint: Checkpoint) -> None:
        checkpoint.validate()
        require(checkpoint.network == self.__network, 'witness network mismatch')
        if self.__head is None:
            require(checkpoint.sequence == 1, 'witness first sequence')
        elif checkpoint == self.__head:
            return  # exact retry only; no replacement of old state at same serial
        else:
            require(self.__head.sequence < MAX_SEQUENCE and
                    checkpoint.sequence == self.__head.sequence + 1,
                    'witness monotonic/fork conflict')
        self.__head = checkpoint

    def respond_to_fresh_challenge(self, challenge: bytes) -> bytes:
        challenge_check(challenge)
        require(self.__head is not None, 'missing external witness head')
        prefix = body(self.__head, challenge)
        return prefix + hmac.new(self.__key, DOMAIN + prefix, hashlib.sha512).digest()


def authorize_restore(local: Checkpoint, *, challenge: bytes,
                      fresh_witness_reply: bytes | None,
                      pinned_external_verification_key: bytes) -> None:
    """Refuse unless a fresh trusted external head exactly matches the local DB.

    This function MUST run at an independent trust boundary, with a fresh
    challenge generated outside the restored DB. Its success is ONLY a rollback
    consistency observation; it cannot authorize consensus, spend or FinalUse.
    """
    local.validate()
    challenge_check(challenge)
    secret_check(pinned_external_verification_key)
    require(type(fresh_witness_reply) is bytes and
            len(fresh_witness_reply) == FRAME_BYTES, 'witness unavailable/frame size')
    prefix = fresh_witness_reply[:-TAG_BYTES]
    tag = fresh_witness_reply[-TAG_BYTES:]
    expected = hmac.new(pinned_external_verification_key, DOMAIN + prefix,
                        hashlib.sha512).digest()
    require(hmac.compare_digest(tag, expected), 'witness authentication')
    require(prefix[:4] == MAGIC, 'witness version')
    remote = Checkpoint(prefix[4:36], int.from_bytes(prefix[36:44], 'big'),
                        prefix[44:76], prefix[76:108])
    remote.validate()
    require(prefix[108:140] == challenge, 'witness challenge replay')
    require(remote == local, 'restored DB is not the latest externally witnessed state')
