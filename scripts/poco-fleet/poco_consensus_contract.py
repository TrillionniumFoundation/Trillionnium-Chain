#!/usr/bin/env python3
"""Independent byte-exact helpers for frozen PoCO consensus identities."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable


CEV0_HASH_PREFIX = b"trnm.cev0.hash.v0"
PARAMETERS_DOMAIN = b"trnm.poco-bft.parameters.v0"
CANONICAL_LAB_GENESIS_DOMAIN = (
    b"trnm.native-application.canonical-lab-genesis-hash.v0"
)


def cev0_hash(domain: bytes, body: bytes) -> bytes:
    return hashlib.sha256(
        len(CEV0_HASH_PREFIX).to_bytes(4, "big")
        + CEV0_HASH_PREFIX
        + len(domain).to_bytes(4, "big")
        + domain
        + len(body).to_bytes(4, "big")
        + body
    ).digest()


def reference_parameters_bytes() -> bytes:
    """Encode ``ConsensusParametersV0::reference_shadow_v0`` exactly."""
    fields: tuple[tuple[str, int], ...] = (
        ("H", 0), ("I", 0), ("B", 0), ("H", 128), ("H", 128),
        ("I", 4_194_304), ("I", 8_388_608), ("I", 4), ("I", 100),
        ("I", 2), ("I", 3), ("I", 1), ("B", 3),
        ("Q", 1_152_921_504_606_846_975), ("Q", 60_000), ("B", 0),
        ("B", 1), ("Q", 1_000), ("I", 3), ("I", 2), ("Q", 30_000),
        ("Q", 10_000), ("B", 2), ("Q", 100), ("B", 1), ("B", 1),
        ("Q", 2), ("I", 1), ("Q", 1_000_000), ("Q", 2), ("Q", 20),
        ("Q", 50_000),
    )
    encoded = bytearray()
    for width, value in fields:
        encoded.extend(struct.pack(f">{width}", value))
    for value in (
        1_000_000,
        10_000_000,
        50_000_000,
        500_000_000,
        1_000_000,
        1_000_000_000,
    ):
        encoded.extend(value.to_bytes(16, "big"))
    tail: tuple[tuple[str, int], ...] = (
        ("Q", 1), ("Q", 1_000_000), ("Q", 250_000), ("Q", 250_000),
        ("Q", 1_000_000), ("B", 0), ("Q", 10), ("Q", 10), ("Q", 20),
        ("B", 0), ("Q", 28), ("Q", 30), ("Q", 2), ("Q", 21),
        ("B", 1), ("B", 1),
    )
    for width, value in tail:
        encoded.extend(struct.pack(f">{width}", value))
    if len(encoded) != 341:
        raise ValueError("reference-parameter encoding length differs from CEV0")
    return bytes(encoded)


def reference_parameters_hash() -> bytes:
    return cev0_hash(PARAMETERS_DOMAIN, reference_parameters_bytes())


def finality_hash_domain(domain: bytes, parts: Iterable[bytes]) -> bytes:
    """Mirror ``trnm_finality_types::crypto::hash_domain`` exactly."""
    digest = hashlib.sha256()
    digest.update(b"trnm.domain.hash.v1")
    digest.update(len(domain).to_bytes(8, "big"))
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def canonical_lab_genesis_hash(
    chain_id: str,
    validators: Iterable[tuple[bytes, bytes, int]],
) -> bytes:
    """Mirror ``derive_canonical_lab_genesis_hash_v0`` public preimage."""
    chain = chain_id.encode("utf-8")
    records = list(validators)
    if len(records) > 0xFFFF_FFFF:
        raise ValueError("canonical lab validator count exceeds u32")
    inventory = bytearray()
    for validator_id, public_key, voting_power in records:
        if len(validator_id) > 0xFFFF:
            raise ValueError("canonical lab validator ID exceeds u16")
        if len(public_key) != 32:
            raise ValueError("canonical lab public key must be 32 bytes")
        if voting_power <= 0 or voting_power > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError("canonical lab voting power is out of range")
        inventory.extend(len(validator_id).to_bytes(2, "big"))
        inventory.extend(validator_id)
        inventory.extend(public_key)
        inventory.extend(voting_power.to_bytes(8, "big"))
    return finality_hash_domain(
        CANONICAL_LAB_GENESIS_DOMAIN,
        (
            chain,
            (0).to_bytes(4, "big"),
            (0).to_bytes(8, "big"),
            reference_parameters_hash(),
            len(records).to_bytes(4, "big"),
            bytes(inventory),
        ),
    )
