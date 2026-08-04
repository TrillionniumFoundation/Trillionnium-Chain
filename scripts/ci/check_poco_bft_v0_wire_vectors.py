#!/usr/bin/env python3
"""Independently reconstruct the foundational PoCO-BFT v0 wire vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Iterable


HASH_PREFIX = b"trnm.cev0.hash.v0"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/wire-foundation-v0.json"
)
CONSENSUS_STRING = re.compile(rb"[a-z0-9][a-z0-9._:-]{0,127}\Z")

DOMAINS = (
    "trnm.poco-bft.block.v0",
    "trnm.poco-bft.proposal.v0",
    "trnm.poco-bft.vote.v0",
    "trnm.poco-bft.timeout.v0",
    "trnm.poco-bft.qc.v0",
    "trnm.poco-bft.tc.v0",
    "trnm.poco-bft.handoff-descriptor.v0",
    "trnm.poco-bft.handoff-vote.v0",
    "trnm.poco-bft.handoff-certificate.v0",
    "trnm.poco-bft.validator-set.v0",
    "trnm.poco-bft.validator-key-pop.v0",
    "trnm.poco-bft.parameters.v0",
    "trnm.poco-bft.epoch-commitment.v0",
    "trnm.poco-bft.upgrade-plan.v0",
    "trnm.poco-bft.finality-proof.v0",
    "trnm.poco-bft.double-sign-evidence.v0",
    "trnm.poco.consumption-certificate.v0",
    "trnm.poco.consumption-certificate-id.v0",
)


class VectorError(ValueError):
    pass


def uint(value: int, bits: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"u{bits} value is not an integer")
    if value < 0 or value >= 1 << bits:
        raise VectorError(f"value {value} is outside u{bits}")
    return value.to_bytes(bits // 8, "big")


def boolean(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise VectorError("boolean value is not bool")
    return b"\x01" if value else b"\x00"


def fixed(value: bytes, length: int, label: str) -> bytes:
    if len(value) != length:
        raise VectorError(f"{label} must contain exactly {length} bytes")
    return value


def cev0_bytes(value: bytes) -> bytes:
    return uint(len(value), 32) + value


def consensus_string(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise VectorError("ConsensusString must be ASCII") from error
    if not CONSENSUS_STRING.fullmatch(encoded):
        raise VectorError("ConsensusString violates the frozen grammar")
    return uint(len(encoded), 16) + encoded


def optional(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value


def cev0_list(values: Iterable[bytes]) -> bytes:
    items = tuple(values)
    return uint(len(items), 32) + b"".join(items)


def frame(value: bytes) -> bytes:
    return uint(len(value), 32) + value


def digest(domain: str, encoded: bytes) -> bytes:
    if domain not in DOMAINS:
        raise VectorError(f"unfrozen domain: {domain}")
    domain_bytes = domain.encode("ascii")
    return hashlib.sha256(
        frame(HASH_PREFIX) + frame(domain_bytes) + frame(encoded)
    ).digest()


def common_context(
    *,
    genesis_hash: bytes,
    chain_id: str,
    protocol_version: int,
    epoch: int,
    validator_set_hash: bytes,
    view: int,
    message_kind: int,
) -> bytes:
    return b"".join(
        (
            uint(0, 16),
            fixed(genesis_hash, 32, "genesis_hash"),
            consensus_string(chain_id),
            uint(protocol_version, 32),
            uint(epoch, 64),
            fixed(validator_set_hash, 32, "validator_set_hash"),
            uint(view, 64),
            uint(message_kind, 8),
        )
    )


def pattern(start: int) -> bytes:
    if not 0 <= start <= 224:
        raise VectorError("32-byte pattern start is out of range")
    return bytes(range(start, start + 32))


def build_vectors() -> dict[str, object]:
    chain_id = "trnm-test-0"
    genesis_hash = pattern(0)
    validator_set_hash = pattern(32)
    parameters_hash = pattern(64)
    parent_block_id = pattern(96)
    payload_root = pattern(128)
    state_root = pattern(160)
    receipts_root = pattern(192)
    evidence_root = bytes(reversed(range(32)))

    primitives = {
        "u8_255": uint(255, 8).hex(),
        "u16_0x0102": uint(0x0102, 16).hex(),
        "u32_0x01020304": uint(0x01020304, 32).hex(),
        "u64_0x0102030405060708": uint(0x0102030405060708, 64).hex(),
        "u128_boundary": uint((1 << 128) - 1, 128).hex(),
        "bool_false": boolean(False).hex(),
        "bool_true": boolean(True).hex(),
        "bytes_empty": cev0_bytes(b"").hex(),
        "bytes_000102": cev0_bytes(b"\x00\x01\x02").hex(),
        "consensus_string_trnm_test_0": consensus_string(chain_id).hex(),
        "optional_absent": optional(None).hex(),
        "optional_hash32_present": optional(pattern(0)).hex(),
        "list_u16_0_258": cev0_list((uint(0, 16), uint(258, 16))).hex(),
    }

    empty_domain_digests = {
        domain: digest(domain, b"").hex() for domain in DOMAINS
    }

    vote_context = common_context(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=7,
        validator_set_hash=validator_set_hash,
        view=42,
        message_kind=1,
    )

    block_header = b"".join(
        (
            uint(0, 16),
            genesis_hash,
            consensus_string(chain_id),
            uint(0, 32),
            uint(7, 64),
            uint(42, 64),
            uint(99, 64),
            uint(0, 8),
            parent_block_id,
            cev0_bytes(b"validator-a"),
            validator_set_hash,
            parameters_hash,
            payload_root,
            state_root,
            receipts_root,
            evidence_root,
            uint(1_700_000_000_000, 64),
            optional(None),
        )
    )
    block_id = digest("trnm.poco-bft.block.v0", block_header)

    qc_preimage = b"sample-qc-preimage-v0"
    justify_qc_digest = digest("trnm.poco-bft.qc.v0", qc_preimage)

    proposal_context = common_context(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=7,
        validator_set_hash=validator_set_hash,
        view=42,
        message_kind=0,
    )
    proposal_sign = b"".join(
        (
            proposal_context,
            uint(99, 64),
            block_id,
            justify_qc_digest,
            optional(None),
            optional(None),
        )
    )

    vote_sign = vote_context + uint(99, 64) + block_id

    timeout_context = common_context(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=7,
        validator_set_hash=validator_set_hash,
        view=42,
        message_kind=2,
    )
    high_qc_summary = b"".join(
        (
            justify_qc_digest,
            uint(7, 64),
            uint(41, 64),
            uint(98, 64),
            parent_block_id,
        )
    )
    timeout_sign = timeout_context + high_qc_summary

    validators = (
        cev0_bytes(b"validator-a") + bytes([0x11]) * 32 + uint(3, 64),
        cev0_bytes(b"validator-b") + bytes([0x22]) * 32 + uint(2, 64),
    )
    validator_set = b"".join(
        (
            uint(0, 16),
            genesis_hash,
            consensus_string(chain_id),
            uint(0, 32),
            uint(7, 64),
            parameters_hash,
            cev0_list(validators),
        )
    )

    sample = {
        "inputs": {
            "schema_version": 0,
            "genesis_hash_hex": genesis_hash.hex(),
            "chain_id": chain_id,
            "protocol_version": 0,
            "epoch": 7,
            "validator_set_hash_hex": validator_set_hash.hex(),
            "consensus_parameters_hash_hex": parameters_hash.hex(),
            "view": 42,
            "height": 99,
            "parent_block_id_hex": parent_block_id.hex(),
            "proposer_id_hex": b"validator-a".hex(),
            "timestamp_ms": 1_700_000_000_000,
        },
        "common_vote_context": {
            "cev0_hex": vote_context.hex(),
            "length": len(vote_context),
        },
        "block_header_v0": {
            "cev0_hex": block_header.hex(),
            "length": len(block_header),
            "block_id_hex": block_id.hex(),
        },
        "proposal_sign_v0": {
            "cev0_hex": proposal_sign.hex(),
            "length": len(proposal_sign),
            "signing_root_hex": digest(
                "trnm.poco-bft.proposal.v0", proposal_sign
            ).hex(),
        },
        "vote_sign_v0": {
            "cev0_hex": vote_sign.hex(),
            "length": len(vote_sign),
            "signing_root_hex": digest("trnm.poco-bft.vote.v0", vote_sign).hex(),
        },
        "timeout_sign_v0": {
            "cev0_hex": timeout_sign.hex(),
            "length": len(timeout_sign),
            "signing_root_hex": digest(
                "trnm.poco-bft.timeout.v0", timeout_sign
            ).hex(),
        },
        "validator_set_v0": {
            "cev0_hex": validator_set.hex(),
            "length": len(validator_set),
            "validator_set_hash_hex": digest(
                "trnm.poco-bft.validator-set.v0", validator_set
            ).hex(),
        },
        "sample_qc_preimage": {
            "cev0_hex": qc_preimage.hex(),
            "qc_digest_hex": justify_qc_digest.hex(),
            "note": "domain-separation fixture only; not a logical QC vector",
        },
    }

    return {
        "schema": "trnm_poco_bft_wire_foundation_vectors_v0",
        "protocol_version": 0,
        "canonical_codec": "CEV0",
        "hash_algorithm": "sha256",
        "hash_prefix_ascii": HASH_PREFIX.decode("ascii"),
        "primitives": primitives,
        "empty_payload_domain_digests": empty_domain_digests,
        "sample": sample,
        "scope": (
            "Foundational encoding and signing-root vectors only; this file "
            "does not claim complete QC/TC/epoch/light-client conformance."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--print-expected",
        action="store_true",
        help="print the independently reconstructed JSON",
    )
    args = parser.parse_args()

    expected = build_vectors()
    if args.print_expected:
        print(json.dumps(expected, indent=2, sort_keys=True))
        return 0

    try:
        with args.vector.open("r", encoding="utf-8") as source:
            committed = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        print(f"wire vector could not be loaded: {error}", file=sys.stderr)
        return 1

    if committed != expected:
        print(
            "committed wire vector differs from independent reconstruction; "
            "run with --print-expected and review the protocol change",
            file=sys.stderr,
        )
        return 1

    sample = expected["sample"]
    assert isinstance(sample, dict)
    print(
        "[ok] PoCO-BFT v0 foundational wire vectors: "
        f"block={sample['block_header_v0']['block_id_hex']} "
        f"vote={sample['vote_sign_v0']['signing_root_hex']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
