#!/usr/bin/env python3
"""Check the PoCO-BFT v0 handoff certificate-kernel crypto vectors.

The committed corpus contains only public verification material.  Deterministic
fixture key derivation stays in this checker.  Ed25519 is imported only for the
small strict RFC 8032 primitives and self-test already used by the independent
QC/TC gate; every handoff, block, QC, descriptor, certificate, authorization,
domain, and relational check below is reconstructed locally.

This gate intentionally does not authenticate checkpoint/seal ancestry, a
NextEpochCommitment preimage, parameter preimages, proof of possession, or a
complete epoch transition.  It closes only the weighted certificate kernel and
the exact derived EpochAnchorQC binding described by the vector.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Callable, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = (
    REPO_ROOT
    / "docs/protocol/poco-bft-v0/vectors/handoff-certificate-kernel-v0.json"
)

# Import only the audited strict RFC 8032 implementation.  Protocol encoders,
# domains, object builders, and relation checks are deliberately not imported.
from check_poco_bft_v0_qc_tc_vectors import (  # noqa: E402
    ed25519_public_key,
    ed25519_self_test,
    ed25519_sign,
    ed25519_verify,
)


HASH_PREFIX = b"trnm.cev0.hash.v0"
DOMAIN_BLOCK = b"trnm.poco-bft.block.v0"
DOMAIN_VOTE = b"trnm.poco-bft.vote.v0"
DOMAIN_QC = b"trnm.poco-bft.qc.v0"
DOMAIN_VALIDATOR_SET = b"trnm.poco-bft.validator-set.v0"
DOMAIN_HANDOFF_DESCRIPTOR = b"trnm.poco-bft.handoff-descriptor.v0"
DOMAIN_HANDOFF_VOTE = b"trnm.poco-bft.handoff-vote.v0"
DOMAIN_HANDOFF_CERTIFICATE = b"trnm.poco-bft.handoff-certificate.v0"

SCHEMA_VERSION = 0
MESSAGE_KIND_VOTE = 1
MESSAGE_KIND_OLD_HANDOFF = 3
MESSAGE_KIND_NEW_HANDOFF = 4
BLOCK_KIND_EPOCH_SEAL_2 = 3


class VectorError(ValueError):
    """The committed corpus or a reconstructed protocol relation is invalid."""


def uint(value: object, bits: int, label: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"{label} is not a u{bits} integer")
    if value < 0 or value >= 1 << bits:
        raise VectorError(f"{label} is outside u{bits}")
    return value.to_bytes(bits // 8, "big")


def fixed_hex(value: object, length: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise VectorError(f"{label} is not hexadecimal text")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{label} is not hexadecimal") from error
    if value != value.lower() or decoded.hex() != value:
        raise VectorError(f"{label} is not canonical lowercase hexadecimal")
    if len(decoded) != length:
        raise VectorError(f"{label} must contain exactly {length} bytes")
    return decoded


def variable_hex(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise VectorError(f"{label} is not hexadecimal text")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{label} is not hexadecimal") from error
    if value != value.lower() or decoded.hex() != value:
        raise VectorError(f"{label} is not canonical lowercase hexadecimal")
    return decoded


def identifier(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise VectorError(f"{label} is not text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise VectorError(f"{label} must be ASCII") from error
    if not encoded or len(encoded) > 128:
        raise VectorError(f"{label} must contain 1..128 bytes")
    return encoded


def consensus_string(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise VectorError(f"{label} is not text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise VectorError(f"{label} must be ASCII") from error
    allowed = b"abcdefghijklmnopqrstuvwxyz0123456789._:-"
    if not encoded or len(encoded) > 128 or encoded[0] not in allowed[:36]:
        raise VectorError(f"{label} violates the frozen ConsensusString grammar")
    if any(byte not in allowed for byte in encoded[1:]):
        raise VectorError(f"{label} violates the frozen ConsensusString grammar")
    return uint(len(encoded), 16, f"{label} length") + encoded


def cev0_bytes(value: bytes) -> bytes:
    return uint(len(value), 32, "Bytes length") + value


def cev0_list(values: Iterable[bytes]) -> bytes:
    items = tuple(values)
    return uint(len(items), 32, "List count") + b"".join(items)


def optional_hash(value: object, label: str) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + fixed_hex(value, 32, label)


def frame(value: bytes) -> bytes:
    return uint(len(value), 32, "hash frame length") + value


def cev0_digest(domain: bytes, encoded: bytes) -> bytes:
    return hashlib.sha256(
        frame(HASH_PREFIX) + frame(domain) + frame(encoded)
    ).digest()


def fixture_seed(label: str) -> bytes:
    # This is the only private fixture material and is never emitted to JSON.
    return hashlib.sha256(
        b"trnm.poco-bft.handoff-kernel.private-fixture.v0:" + label.encode("ascii")
    ).digest()


def fixture_hash(label: str) -> str:
    return hashlib.sha256(
        b"trnm.poco-bft.handoff-kernel.public-fixture.v0:" + label.encode("ascii")
    ).hexdigest()


def validator_set_cev0(value: dict[str, object]) -> bytes:
    entries = []
    for index, validator in enumerate(value["validators"]):
        entries.append(
            cev0_bytes(identifier(validator["id_ascii"], f"validators[{index}].id"))
            + fixed_hex(
                validator["public_key_hex"],
                32,
                f"validators[{index}].public_key",
            )
            + uint(validator["power"], 64, f"validators[{index}].power")
        )
    return b"".join(
        (
            uint(value["schema_version"], 16, "validator-set schema_version"),
            fixed_hex(value["genesis_hash_hex"], 32, "validator-set genesis_hash"),
            consensus_string(value["chain_id"], "validator-set chain_id"),
            uint(value["protocol_version"], 32, "validator-set protocol_version"),
            uint(value["epoch"], 64, "validator-set epoch"),
            fixed_hex(
                value["consensus_parameters_hash_hex"],
                32,
                "validator-set consensus_parameters_hash",
            ),
            cev0_list(entries),
        )
    )


def block_header_cev0(value: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(value["schema_version"], 16, "block schema_version"),
            fixed_hex(value["genesis_hash_hex"], 32, "block genesis_hash"),
            consensus_string(value["chain_id"], "block chain_id"),
            uint(value["protocol_version"], 32, "block protocol_version"),
            uint(value["epoch"], 64, "block epoch"),
            uint(value["view"], 64, "block view"),
            uint(value["height"], 64, "block height"),
            uint(value["block_kind"], 8, "block kind"),
            fixed_hex(value["parent_block_id_hex"], 32, "block parent_id"),
            cev0_bytes(identifier(value["proposer_id_ascii"], "block proposer_id")),
            fixed_hex(
                value["validator_set_id_hex"], 32, "block validator_set_id"
            ),
            fixed_hex(
                value["consensus_parameters_hash_hex"],
                32,
                "block consensus_parameters_hash",
            ),
            fixed_hex(value["payload_digest_hex"], 32, "block payload_digest"),
            fixed_hex(value["state_root_hex"], 32, "block state_root"),
            fixed_hex(value["receipts_root_hex"], 32, "block receipts_root"),
            fixed_hex(value["evidence_root_hex"], 32, "block evidence_root"),
            uint(value["timestamp_ms"], 64, "block timestamp_ms"),
            optional_hash(
                value["next_epoch_commitment_hash_hex"],
                "block next_epoch_commitment_hash",
            ),
        )
    )


def block_id(value: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_BLOCK, block_header_cev0(value))


def common_context(
    *,
    genesis_hash_hex: object,
    chain_id: object,
    protocol_version: object,
    epoch: object,
    validator_set_id_hex: object,
    view: object,
    message_kind: int,
) -> bytes:
    return b"".join(
        (
            uint(SCHEMA_VERSION, 16, "context schema_version"),
            fixed_hex(genesis_hash_hex, 32, "context genesis_hash"),
            consensus_string(chain_id, "context chain_id"),
            uint(protocol_version, 32, "context protocol_version"),
            uint(epoch, 64, "context epoch"),
            fixed_hex(validator_set_id_hex, 32, "context validator_set_id"),
            uint(view, 64, "context view"),
            uint(message_kind, 8, "context message_kind"),
        )
    )


def qc_vote_preimage(value: dict[str, object]) -> bytes:
    return b"".join(
        (
            common_context(
                genesis_hash_hex=value["genesis_hash_hex"],
                chain_id=value["chain_id"],
                protocol_version=value["protocol_version"],
                epoch=value["epoch"],
                validator_set_id_hex=value["validator_set_id_hex"],
                view=value["view"],
                message_kind=MESSAGE_KIND_VOTE,
            ),
            uint(value["height"], 64, "QC height"),
            fixed_hex(value["block_id_hex"], 32, "QC block_id"),
        )
    )


def qc_signing_root(value: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_VOTE, qc_vote_preimage(value))


def signature_share_cev0(value: dict[str, object], label: str) -> bytes:
    return cev0_bytes(identifier(value["signer_id_ascii"], f"{label} signer_id")) + fixed_hex(
        value["signature_hex"], 64, f"{label} signature"
    )


def qc_cev0(value: dict[str, object]) -> bytes:
    votes = [
        signature_share_cev0(vote, f"QC votes[{index}]")
        for index, vote in enumerate(value["votes"])
    ]
    return b"".join(
        (
            uint(value["schema_version"], 16, "QC schema_version"),
            fixed_hex(value["genesis_hash_hex"], 32, "QC genesis_hash"),
            consensus_string(value["chain_id"], "QC chain_id"),
            uint(value["protocol_version"], 32, "QC protocol_version"),
            uint(value["epoch"], 64, "QC epoch"),
            fixed_hex(value["validator_set_id_hex"], 32, "QC validator_set_id"),
            uint(value["view"], 64, "QC view"),
            uint(value["height"], 64, "QC height"),
            fixed_hex(value["block_id_hex"], 32, "QC block_id"),
            cev0_list(votes),
        )
    )


def descriptor_cev0(value: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(value["schema_version"], 16, "descriptor schema_version"),
            fixed_hex(value["genesis_hash_hex"], 32, "descriptor genesis_hash"),
            consensus_string(value["chain_id"], "descriptor chain_id"),
            uint(value["old_epoch"], 64, "descriptor old_epoch"),
            uint(value["new_epoch"], 64, "descriptor new_epoch"),
            uint(
                value["old_protocol_version"], 32, "descriptor old_protocol_version"
            ),
            uint(
                value["new_protocol_version"], 32, "descriptor new_protocol_version"
            ),
            fixed_hex(
                value["old_validator_set_hash_hex"],
                32,
                "descriptor old_validator_set_hash",
            ),
            fixed_hex(
                value["new_validator_set_hash_hex"],
                32,
                "descriptor new_validator_set_hash",
            ),
            fixed_hex(
                value["old_consensus_parameters_hash_hex"],
                32,
                "descriptor old_consensus_parameters_hash",
            ),
            fixed_hex(
                value["new_consensus_parameters_hash_hex"],
                32,
                "descriptor new_consensus_parameters_hash",
            ),
            uint(value["checkpoint_height"], 64, "descriptor checkpoint_height"),
            fixed_hex(
                value["checkpoint_block_id_hex"], 32, "descriptor checkpoint_block_id"
            ),
            fixed_hex(
                value["checkpoint_state_root_hex"],
                32,
                "descriptor checkpoint_state_root",
            ),
            fixed_hex(
                value["next_epoch_commitment_digest_hex"],
                32,
                "descriptor next_epoch_commitment_digest",
            ),
            uint(
                value["terminal_old_height"], 64, "descriptor terminal_old_height"
            ),
            fixed_hex(
                value["terminal_old_block_id_hex"],
                32,
                "descriptor terminal_old_block_id",
            ),
            fixed_hex(
                value["terminal_old_qc_digest_hex"],
                32,
                "descriptor terminal_old_qc_digest",
            ),
            uint(value["terminal_old_view"], 64, "descriptor terminal_old_view"),
            uint(value["activation_height"], 64, "descriptor activation_height"),
            uint(value["initial_new_view"], 64, "descriptor initial_new_view"),
        )
    )


def descriptor_digest(value: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_HANDOFF_DESCRIPTOR, descriptor_cev0(value))


def handoff_vote_preimage(value: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(value["schema_version"], 16, "handoff vote schema_version"),
            fixed_hex(value["genesis_hash_hex"], 32, "handoff vote genesis_hash"),
            consensus_string(value["chain_id"], "handoff vote chain_id"),
            uint(
                value["signing_protocol_version"],
                32,
                "handoff vote signing_protocol_version",
            ),
            uint(value["signing_epoch"], 64, "handoff vote signing_epoch"),
            fixed_hex(
                value["signing_validator_set_hash_hex"],
                32,
                "handoff vote signing_validator_set_hash",
            ),
            uint(value["signing_view"], 64, "handoff vote signing_view"),
            uint(value["message_kind"], 8, "handoff vote message_kind"),
            fixed_hex(
                value["handoff_descriptor_digest_hex"],
                32,
                "handoff vote descriptor digest",
            ),
        )
    )


def handoff_vote_root(value: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_HANDOFF_VOTE, handoff_vote_preimage(value))


def handoff_certificate_cev0(value: dict[str, object]) -> bytes:
    old_shares = [
        signature_share_cev0(share, f"old_signatures[{index}]")
        for index, share in enumerate(value["old_signatures"])
    ]
    new_shares = [
        signature_share_cev0(share, f"new_signatures[{index}]")
        for index, share in enumerate(value["new_signatures"])
    ]
    return b"".join(
        (
            uint(value["schema_version"], 16, "certificate schema_version"),
            descriptor_cev0(value["descriptor"]),
            cev0_list(old_shares),
            cev0_list(new_shares),
        )
    )


def epoch_anchor_authorization_cev0(value: dict[str, object]) -> bytes:
    return b"".join(
        (
            block_header_cev0(value["terminal_old_header"]),
            qc_cev0(value["terminal_old_qc"]),
            handoff_certificate_cev0(value["handoff_certificate"]),
        )
    )


def finalize_validator_set(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    encoded = validator_set_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["validator_set_id_hex"] = cev0_digest(
        DOMAIN_VALIDATOR_SET, encoded
    ).hex()
    result["total_power"] = sum(int(item["power"]) for item in result["validators"])
    result["quorum_power"] = 2 * int(result["total_power"]) // 3 + 1
    return result


def finalize_header(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    encoded = block_header_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["block_id_hex"] = cev0_digest(DOMAIN_BLOCK, encoded).hex()
    return result


def finalize_qc(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    if result.get("votes"):
        preimage = qc_vote_preimage(result)
        result["signing_preimage_cev0_hex"] = preimage.hex()
        result["signing_root_hex"] = cev0_digest(DOMAIN_VOTE, preimage).hex()
    encoded = qc_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["digest_hex"] = cev0_digest(DOMAIN_QC, encoded).hex()
    return result


def finalize_descriptor(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    encoded = descriptor_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["digest_hex"] = cev0_digest(DOMAIN_HANDOFF_DESCRIPTOR, encoded).hex()
    return result


def finalize_vote_root(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    encoded = handoff_vote_preimage(result)
    result["cev0_hex"] = encoded.hex()
    result["signing_root_hex"] = cev0_digest(DOMAIN_HANDOFF_VOTE, encoded).hex()
    return result


def finalize_certificate(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result["descriptor"] = finalize_descriptor(result["descriptor"])
    encoded = handoff_certificate_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["digest_hex"] = cev0_digest(DOMAIN_HANDOFF_CERTIFICATE, encoded).hex()
    return result


def finalize_authorization(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result["terminal_old_header"] = finalize_header(result["terminal_old_header"])
    result["terminal_old_qc"] = finalize_qc(result["terminal_old_qc"])
    result["handoff_certificate"] = finalize_certificate(
        result["handoff_certificate"]
    )
    encoded = epoch_anchor_authorization_cev0(result)
    result["cev0_hex"] = encoded.hex()
    result["digest_domain"] = None
    result["digest_hex"] = None
    return result


def make_validator_set(
    *,
    role: str,
    genesis_hash_hex: str,
    chain_id: str,
    protocol_version: int,
    epoch: int,
    parameters_hash_hex: str,
) -> dict[str, object]:
    validators = []
    for suffix, power in (("a", 4), ("b", 3), ("c", 2), ("d", 1)):
        signer_id = f"{role}-{suffix}"
        validators.append(
            {
                "id_ascii": signer_id,
                "public_key_hex": ed25519_public_key(fixture_seed(signer_id)).hex(),
                "power": power,
            }
        )
    return finalize_validator_set(
        {
            "schema_version": SCHEMA_VERSION,
            "genesis_hash_hex": genesis_hash_hex,
            "chain_id": chain_id,
            "protocol_version": protocol_version,
            "epoch": epoch,
            "consensus_parameters_hash_hex": parameters_hash_hex,
            "validators": validators,
            "threshold_formula": "floor(2 * W / 3) + 1",
        }
    )


def make_qc(
    *,
    validator_set: dict[str, object],
    view: int,
    height: int,
    certified_block_id_hex: str,
    signer_ids: list[str],
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "genesis_hash_hex": validator_set["genesis_hash_hex"],
        "chain_id": validator_set["chain_id"],
        "protocol_version": validator_set["protocol_version"],
        "epoch": validator_set["epoch"],
        "validator_set_id_hex": validator_set["validator_set_id_hex"],
        "view": view,
        "height": height,
        "block_id_hex": certified_block_id_hex,
        "votes": [],
    }
    root = qc_signing_root(value)
    value["votes"] = [
        {
            "signer_id_ascii": signer_id,
            "signing_root_hex": root.hex(),
            "signature_hex": ed25519_sign(fixture_seed(signer_id), root).hex(),
        }
        for signer_id in signer_ids
    ]
    powers = {
        str(item["id_ascii"]): int(item["power"])
        for item in validator_set["validators"]
    }
    value["signed_power"] = sum(powers[signer] for signer in signer_ids)
    value["signing_preimage_cev0_hex"] = qc_vote_preimage(value).hex()
    value["signing_root_hex"] = root.hex()
    return finalize_qc(value)


def resign_qc(
    value: dict[str, object], signer_ids: list[str]
) -> dict[str, object]:
    """Re-sign mutated QC coordinates while retaining its declared context."""
    result = copy.deepcopy(value)
    root = qc_signing_root(result)
    result["votes"] = [
        {
            "signer_id_ascii": signer,
            "signing_root_hex": root.hex(),
            "signature_hex": ed25519_sign(fixture_seed(signer), root).hex(),
        }
        for signer in signer_ids
    ]
    result["signed_power"] = 7
    return finalize_qc(result)


def make_handoff_vote(
    descriptor: dict[str, object], role: str
) -> dict[str, object]:
    if role == "old":
        value = {
            "schema_version": SCHEMA_VERSION,
            "role": "old",
            "genesis_hash_hex": descriptor["genesis_hash_hex"],
            "chain_id": descriptor["chain_id"],
            "signing_protocol_version": descriptor["old_protocol_version"],
            "signing_epoch": descriptor["old_epoch"],
            "signing_validator_set_hash_hex": descriptor[
                "old_validator_set_hash_hex"
            ],
            "signing_view": descriptor["terminal_old_view"],
            "message_kind": MESSAGE_KIND_OLD_HANDOFF,
            "handoff_descriptor_digest_hex": descriptor["digest_hex"],
        }
    elif role == "new":
        value = {
            "schema_version": SCHEMA_VERSION,
            "role": "new",
            "genesis_hash_hex": descriptor["genesis_hash_hex"],
            "chain_id": descriptor["chain_id"],
            "signing_protocol_version": descriptor["new_protocol_version"],
            "signing_epoch": descriptor["new_epoch"],
            "signing_validator_set_hash_hex": descriptor[
                "new_validator_set_hash_hex"
            ],
            "signing_view": descriptor["initial_new_view"],
            "message_kind": MESSAGE_KIND_NEW_HANDOFF,
            "handoff_descriptor_digest_hex": descriptor["digest_hex"],
        }
    else:  # pragma: no cover - fixture construction invariant
        raise VectorError(f"unknown handoff role {role!r}")
    return finalize_vote_root(value)


def make_shares(signers: list[str], root: bytes) -> list[dict[str, object]]:
    return [
        {
            "signer_id_ascii": signer,
            "signing_root_hex": root.hex(),
            "signature_hex": ed25519_sign(fixture_seed(signer), root).hex(),
        }
        for signer in signers
    ]


def resign_certificate(value: dict[str, object]) -> dict[str, object]:
    """Re-sign a mutated descriptor so relational negatives stay single-fault."""
    result = copy.deepcopy(value)
    result["descriptor"] = finalize_descriptor(result["descriptor"])
    old_root = handoff_vote_root(make_handoff_vote(result["descriptor"], "old"))
    new_root = handoff_vote_root(make_handoff_vote(result["descriptor"], "new"))
    result["old_signatures"] = make_shares(["old-a", "old-b"], old_root)
    result["new_signatures"] = make_shares(["new-a", "new-b"], new_root)
    result["old_signed_power"] = 7
    result["new_signed_power"] = 7
    return finalize_certificate(result)


def derive_epoch_anchor_qc(
    authorization: dict[str, object]
) -> dict[str, object]:
    descriptor = authorization["handoff_certificate"]["descriptor"]
    return finalize_qc(
        {
            "schema_version": SCHEMA_VERSION,
            "genesis_hash_hex": descriptor["genesis_hash_hex"],
            "chain_id": descriptor["chain_id"],
            "protocol_version": descriptor["new_protocol_version"],
            "epoch": descriptor["new_epoch"],
            "validator_set_id_hex": descriptor["new_validator_set_hash_hex"],
            "view": 0,
            "height": descriptor["terminal_old_height"],
            "block_id_hex": descriptor["terminal_old_block_id_hex"],
            "votes": [],
            "signed_power": 0,
            "authorization": "derived_only_after_full_authorization_verifies",
            "ordinary_qc_admission": "unauthorized_synthetic_qc",
        }
    )


def mutate(
    value: dict[str, object], operation: Callable[[dict[str, object]], None]
) -> dict[str, object]:
    result = copy.deepcopy(value)
    operation(result)
    return result


def bitflip_signature(signature_hex: str) -> str:
    value = bytearray.fromhex(signature_hex)
    value[0] ^= 1
    return bytes(value).hex()


def validator_maps(
    validator_set: dict[str, object],
) -> tuple[dict[str, dict[str, object]], int, int]:
    validators = {
        str(item["id_ascii"]): item for item in validator_set["validators"]
    }
    total = sum(int(item["power"]) for item in validators.values())
    return validators, total, 2 * total // 3 + 1


def check_raw(
    value: dict[str, object],
    encoder: Callable[[dict[str, object]], bytes],
    domain: bytes | None,
    label: str,
) -> bytes:
    encoded = encoder(value)
    if fixed_hex(value["cev0_hex"], len(encoded), f"{label} cev0") != encoded:
        raise VectorError(f"{label} CEV0 is not byte-identical")
    if domain is None:
        if value.get("digest_domain") is not None or value.get("digest_hex") is not None:
            raise VectorError(f"{label} incorrectly claims an independent digest")
    else:
        expected = cev0_digest(domain, encoded)
        if fixed_hex(value["digest_hex"], 32, f"{label} digest") != expected:
            raise VectorError(f"{label} digest mismatch")
    return encoded


def check_header_raw(value: dict[str, object], label: str) -> None:
    encoded = block_header_cev0(value)
    if fixed_hex(value["cev0_hex"], len(encoded), f"{label} cev0") != encoded:
        raise VectorError(f"{label} CEV0 mismatch")
    if fixed_hex(value["block_id_hex"], 32, f"{label} block_id") != cev0_digest(
        DOMAIN_BLOCK, encoded
    ):
        raise VectorError(f"{label} BlockId mismatch")


def check_qc_raw(value: dict[str, object], label: str) -> None:
    check_raw(value, qc_cev0, DOMAIN_QC, label)
    if value.get("votes"):
        expected_preimage = qc_vote_preimage(value)
        expected_root = cev0_digest(DOMAIN_VOTE, expected_preimage)
        if "signing_preimage_cev0_hex" in value and fixed_hex(
            value["signing_preimage_cev0_hex"],
            len(expected_preimage),
            f"{label} signing preimage",
        ) != expected_preimage:
            raise VectorError(f"{label} signing preimage mismatch")
        if "signing_root_hex" in value and fixed_hex(
            value["signing_root_hex"], 32, f"{label} signing root"
        ) != expected_root:
            raise VectorError(f"{label} signing root mismatch")


def check_descriptor_raw(value: dict[str, object], label: str) -> None:
    check_raw(value, descriptor_cev0, DOMAIN_HANDOFF_DESCRIPTOR, label)


def check_certificate_raw(value: dict[str, object], label: str) -> None:
    check_descriptor_raw(value["descriptor"], f"{label}.descriptor")
    check_raw(value, handoff_certificate_cev0, DOMAIN_HANDOFF_CERTIFICATE, label)


def check_authorization_raw(value: dict[str, object], label: str) -> None:
    check_header_raw(value["terminal_old_header"], f"{label}.terminal_header")
    check_qc_raw(value["terminal_old_qc"], f"{label}.terminal_qc")
    check_certificate_raw(value["handoff_certificate"], f"{label}.certificate")
    check_raw(value, epoch_anchor_authorization_cev0, None, label)


def validate_validator_set(value: dict[str, object], label: str) -> str:
    encoded = validator_set_cev0(value)
    if fixed_hex(value["cev0_hex"], len(encoded), f"{label} CEV0") != encoded:
        raise VectorError(f"{label} CEV0 mismatch")
    expected_id = cev0_digest(DOMAIN_VALIDATOR_SET, encoded)
    if fixed_hex(value["validator_set_id_hex"], 32, f"{label} ID") != expected_id:
        raise VectorError(f"{label} digest mismatch")
    previous: bytes | None = None
    keys: set[bytes] = set()
    total = 0
    for index, validator in enumerate(value["validators"]):
        signer = identifier(validator["id_ascii"], f"{label}[{index}].id")
        if previous is not None and previous >= signer:
            raise VectorError(f"{label} validator IDs are not strictly ordered")
        previous = signer
        key = fixed_hex(
            validator["public_key_hex"], 32, f"{label}[{index}].public_key"
        )
        if key in keys:
            raise VectorError(f"{label} repeats a consensus public key")
        keys.add(key)
        power = int(validator["power"])
        if power <= 0:
            raise VectorError(f"{label} has zero voting power")
        total += power
    quorum = 2 * total // 3 + 1
    if total != 10 or quorum != 7:
        raise VectorError(f"{label} no longer witnesses W=10, quorum=7")
    if value["total_power"] != total or value["quorum_power"] != quorum:
        raise VectorError(f"{label} committed threshold metadata mismatch")
    return "valid"


def validate_header_shape(value: dict[str, object]) -> str:
    check_header_raw(value, "terminal header")
    if value["schema_version"] != SCHEMA_VERSION:
        return "invalid_schema_version"
    if fixed_hex(value["genesis_hash_hex"], 32, "header genesis_hash") == bytes(32):
        return "zero_genesis_hash"
    if int(value["view"]) == 0 or int(value["height"]) == 0:
        return "invalid_network_block"
    if int(value["block_kind"]) not in range(5):
        return "invalid_network_block"
    if fixed_hex(value["validator_set_id_hex"], 32, "header set") == bytes(32):
        return "invalid_network_block"
    commitment = value["next_epoch_commitment_hash_hex"]
    kind = int(value["block_kind"])
    if kind in (0, 4) and commitment is not None:
        return "invalid_network_block"
    if kind in (1, 2, 3) and commitment is None:
        return "invalid_network_block"
    return "valid"


def validate_qc_shape(
    value: dict[str, object], validator_set: dict[str, object]
) -> str:
    check_qc_raw(value, "QC")
    if value["schema_version"] != SCHEMA_VERSION:
        return "invalid_schema_version"
    scope = (
        value["genesis_hash_hex"],
        value["chain_id"],
        value["protocol_version"],
        value["epoch"],
        value["validator_set_id_hex"],
    )
    expected_scope = (
        validator_set["genesis_hash_hex"],
        validator_set["chain_id"],
        validator_set["protocol_version"],
        validator_set["epoch"],
        validator_set["validator_set_id_hex"],
    )
    if scope != expected_scope:
        return "validator_set_mismatch"
    if not value["votes"]:
        return "unauthorized_synthetic_qc"
    validators, _, quorum = validator_maps(validator_set)
    previous: bytes | None = None
    signed_power = 0
    for vote in value["votes"]:
        signer = str(vote["signer_id_ascii"])
        signer_bytes = identifier(signer, "QC signer")
        if previous == signer_bytes:
            return "duplicate_signer"
        if previous is not None and previous > signer_bytes:
            return "noncanonical_signer_order"
        previous = signer_bytes
        validator = validators.get(signer)
        if validator is None:
            return "unknown_signer"
        fixed_hex(vote["signature_hex"], 64, "QC signature")
        signed_power += int(validator["power"])
    if "signed_power" in value and int(value["signed_power"]) != signed_power:
        raise VectorError("QC signed_power metadata mismatch")
    if signed_power < quorum:
        return "insufficient_quorum"
    return "valid"


def verify_qc_signatures(
    value: dict[str, object], validator_set: dict[str, object]
) -> str:
    validators, _, _ = validator_maps(validator_set)
    root = qc_signing_root(value)
    for vote in value["votes"]:
        signer = str(vote["signer_id_ascii"])
        validator = validators[signer]
        if fixed_hex(
            vote["signing_root_hex"], 32, "QC declared signing root"
        ) != root:
            return "invalid_signature"
        if not ed25519_verify(
            fixed_hex(validator["public_key_hex"], 32, "QC public key"),
            root,
            fixed_hex(vote["signature_hex"], 64, "QC signature"),
        ):
            return "invalid_signature"
    return "valid"


def validate_ordinary_qc(
    value: dict[str, object], validator_set: dict[str, object]
) -> str:
    result = validate_qc_shape(value, validator_set)
    if result != "valid":
        return result
    return verify_qc_signatures(value, validator_set)


def validate_descriptor(
    value: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> str:
    check_descriptor_raw(value, "handoff descriptor")
    if value["schema_version"] != SCHEMA_VERSION:
        return "invalid_schema_version"
    if fixed_hex(value["genesis_hash_hex"], 32, "descriptor genesis") == bytes(32):
        return "zero_genesis_hash"
    nonzero_fields = (
        "old_validator_set_hash_hex",
        "new_validator_set_hash_hex",
        "old_consensus_parameters_hash_hex",
        "new_consensus_parameters_hash_hex",
        "checkpoint_block_id_hex",
        "checkpoint_state_root_hex",
        "next_epoch_commitment_digest_hex",
        "terminal_old_block_id_hex",
        "terminal_old_qc_digest_hex",
    )
    for field in nonzero_fields:
        if fixed_hex(value[field], 32, f"descriptor {field}") == bytes(32):
            return "zero_descriptor_commitment"
    if int(value["new_epoch"]) != int(value["old_epoch"]) + 1:
        return "descriptor_epoch_mismatch"
    if int(value["activation_height"]) != int(value["terminal_old_height"]) + 1:
        return "descriptor_activation_height_mismatch"
    if int(value["initial_new_view"]) != 1:
        return "descriptor_initial_view_mismatch"
    if int(value["checkpoint_height"]) > int(value["terminal_old_height"]):
        return "descriptor_checkpoint_height_mismatch"
    shared = (value["genesis_hash_hex"], value["chain_id"])
    if shared != (old_set["genesis_hash_hex"], old_set["chain_id"]):
        return "descriptor_old_context_mismatch"
    if shared != (new_set["genesis_hash_hex"], new_set["chain_id"]):
        return "descriptor_new_context_mismatch"
    if value["old_epoch"] != old_set["epoch"]:
        return "descriptor_old_epoch_mismatch"
    if value["new_epoch"] != new_set["epoch"]:
        return "descriptor_new_epoch_mismatch"
    if value["old_protocol_version"] != old_set["protocol_version"]:
        return "descriptor_old_version_mismatch"
    if value["new_protocol_version"] != new_set["protocol_version"]:
        return "descriptor_new_version_mismatch"
    if value["old_validator_set_hash_hex"] != old_set["validator_set_id_hex"]:
        return "descriptor_old_set_mismatch"
    if value["new_validator_set_hash_hex"] != new_set["validator_set_id_hex"]:
        return "descriptor_new_set_mismatch"
    if (
        value["old_consensus_parameters_hash_hex"]
        != old_set["consensus_parameters_hash_hex"]
    ):
        return "descriptor_old_parameters_mismatch"
    if (
        value["new_consensus_parameters_hash_hex"]
        != new_set["consensus_parameters_hash_hex"]
    ):
        return "descriptor_new_parameters_mismatch"
    return "valid"


def expected_handoff_vote(
    descriptor: dict[str, object], role: str
) -> dict[str, object]:
    return make_handoff_vote(descriptor, role)


def validate_handoff_vote_artifact(
    value: dict[str, object], descriptor: dict[str, object], role: str
) -> str:
    encoded = handoff_vote_preimage(value)
    if fixed_hex(
        value["cev0_hex"], len(encoded), f"{role} handoff vote CEV0"
    ) != encoded:
        raise VectorError(f"{role} handoff vote CEV0 mismatch")
    root = cev0_digest(DOMAIN_HANDOFF_VOTE, encoded)
    if fixed_hex(
        value["signing_root_hex"], 32, f"{role} handoff vote root"
    ) != root:
        raise VectorError(f"{role} handoff vote root mismatch")
    expected = expected_handoff_vote(descriptor, role)
    if encoded != handoff_vote_preimage(expected):
        return "handoff_role_scope_mismatch"
    return "valid"


def validate_role_share_shape(
    shares: list[dict[str, object]],
    validator_set: dict[str, object],
    role: str,
) -> str:
    validators, _, quorum = validator_maps(validator_set)
    previous: bytes | None = None
    signed_power = 0
    for share in shares:
        signer = str(share["signer_id_ascii"])
        signer_bytes = identifier(signer, f"{role} signer")
        if previous == signer_bytes:
            return f"{role}_duplicate_signer"
        if previous is not None and previous > signer_bytes:
            return f"{role}_noncanonical_signer_order"
        previous = signer_bytes
        validator = validators.get(signer)
        if validator is None:
            return f"{role}_unknown_signer"
        fixed_hex(share["signature_hex"], 64, f"{role} signature")
        signed_power += int(validator["power"])
    if signed_power < quorum:
        return f"{role}_insufficient_quorum"
    return "valid"


def validate_certificate_shape(
    value: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> str:
    check_certificate_raw(value, "handoff certificate")
    if value["schema_version"] != SCHEMA_VERSION:
        return "invalid_schema_version"
    result = validate_descriptor(value["descriptor"], old_set, new_set)
    if result != "valid":
        return result
    result = validate_role_share_shape(value["old_signatures"], old_set, "old")
    if result != "valid":
        return result
    return validate_role_share_shape(value["new_signatures"], new_set, "new")


def verify_certificate_signatures(
    value: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> str:
    descriptor = value["descriptor"]
    for shares, validator_set, role in (
        (value["old_signatures"], old_set, "old"),
        (value["new_signatures"], new_set, "new"),
    ):
        root = handoff_vote_root(expected_handoff_vote(descriptor, role))
        validators, _, _ = validator_maps(validator_set)
        for share in shares:
            signer = str(share["signer_id_ascii"])
            if fixed_hex(
                share["signing_root_hex"],
                32,
                f"{role} declared signing root",
            ) != root:
                return "invalid_signature"
            if not ed25519_verify(
                fixed_hex(
                    validators[signer]["public_key_hex"],
                    32,
                    f"{role} public key",
                ),
                root,
                fixed_hex(share["signature_hex"], 64, f"{role} signature"),
            ):
                return "invalid_signature"
    return "valid"


def validate_handoff_certificate(
    value: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> str:
    result = validate_certificate_shape(value, old_set, new_set)
    if result != "valid":
        return result
    return verify_certificate_signatures(value, old_set, new_set)


def validate_authorization_relations(value: dict[str, object]) -> str:
    header = value["terminal_old_header"]
    qc = value["terminal_old_qc"]
    descriptor = value["handoff_certificate"]["descriptor"]
    if int(header["block_kind"]) != BLOCK_KIND_EPOCH_SEAL_2:
        return "terminal_not_epoch_seal_2"
    if (
        header["genesis_hash_hex"],
        header["chain_id"],
        header["protocol_version"],
        header["epoch"],
    ) != (
        descriptor["genesis_hash_hex"],
        descriptor["chain_id"],
        descriptor["old_protocol_version"],
        descriptor["old_epoch"],
    ):
        return "terminal_header_context_mismatch"
    if header["validator_set_id_hex"] != descriptor["old_validator_set_hash_hex"]:
        return "terminal_header_set_mismatch"
    if (
        header["consensus_parameters_hash_hex"]
        != descriptor["old_consensus_parameters_hash_hex"]
    ):
        return "terminal_header_parameters_mismatch"
    if header["view"] != descriptor["terminal_old_view"]:
        return "terminal_header_view_mismatch"
    if header["height"] != descriptor["terminal_old_height"]:
        return "terminal_header_height_mismatch"
    if header["block_id_hex"] != descriptor["terminal_old_block_id_hex"]:
        return "terminal_header_id_mismatch"
    if header["state_root_hex"] != descriptor["checkpoint_state_root_hex"]:
        return "terminal_header_state_root_mismatch"
    if (
        header["next_epoch_commitment_hash_hex"]
        != descriptor["next_epoch_commitment_digest_hex"]
    ):
        return "terminal_header_commitment_mismatch"
    if (
        qc["genesis_hash_hex"],
        qc["chain_id"],
        qc["protocol_version"],
        qc["epoch"],
    ) != (
        header["genesis_hash_hex"],
        header["chain_id"],
        header["protocol_version"],
        header["epoch"],
    ):
        return "terminal_qc_context_mismatch"
    if qc["validator_set_id_hex"] != header["validator_set_id_hex"]:
        return "terminal_qc_set_mismatch"
    if qc["view"] != header["view"]:
        return "terminal_qc_view_mismatch"
    if qc["height"] != header["height"]:
        return "terminal_qc_height_mismatch"
    if qc["block_id_hex"] != header["block_id_hex"]:
        return "terminal_qc_block_mismatch"
    if qc["digest_hex"] != descriptor["terminal_old_qc_digest_hex"]:
        return "terminal_qc_digest_mismatch"
    return "valid"


def validate_epoch_anchor_authorization(
    value: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> str:
    check_authorization_raw(value, "epoch anchor authorization")
    certificate = value["handoff_certificate"]
    result = validate_certificate_shape(certificate, old_set, new_set)
    if result != "valid":
        return result
    result = validate_qc_shape(value["terminal_old_qc"], old_set)
    if result != "valid":
        return result
    result = validate_header_shape(value["terminal_old_header"])
    if result != "valid":
        return result
    result = validate_authorization_relations(value)
    if result != "valid":
        return result
    result = verify_qc_signatures(value["terminal_old_qc"], old_set)
    if result != "valid":
        return result
    return verify_certificate_signatures(certificate, old_set, new_set)


def ensure_alternate_signature_binding(
    case: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> None:
    alternate = case.get("alternate_signature_binding")
    if alternate is None:
        return
    signer = str(alternate["signer_id_ascii"])
    validators = {**validator_maps(old_set)[0], **validator_maps(new_set)[0]}
    validator = validators.get(signer)
    if validator is None:
        raise VectorError(f"{case['id']} alternate signer is unknown")
    domains = {
        DOMAIN_HANDOFF_VOTE.decode("ascii"): DOMAIN_HANDOFF_VOTE,
        DOMAIN_QC.decode("ascii"): DOMAIN_QC,
    }
    domain = domains.get(str(alternate["domain_ascii"]))
    if domain is None:
        raise VectorError(f"{case['id']} alternate signature domain is unknown")
    preimage = variable_hex(
        alternate["signing_preimage_cev0_hex"], "alternate signing preimage"
    )
    root = fixed_hex(alternate["signing_root_hex"], 32, "alternate signing root")
    if cev0_digest(domain, preimage) != root:
        raise VectorError(f"{case['id']} alternate signing-root derivation mismatch")
    if not ed25519_verify(
        fixed_hex(validator["public_key_hex"], 32, "alternate public key"),
        root,
        fixed_hex(alternate["signature_hex"], 64, "alternate signature"),
    ):
        raise VectorError(f"{case['id']} alternate signature is not actually valid")


def validate_negative_case(
    case: dict[str, object],
    old_set: dict[str, object],
    new_set: dict[str, object],
) -> None:
    target = case["target"]
    artifact = case["artifact"]
    if target in ("terminal_qc", "ordinary_qc"):
        validator_set = old_set if case["validator_role"] == "old" else new_set
        result = validate_ordinary_qc(artifact, validator_set)
    elif target == "handoff_certificate":
        result = validate_handoff_certificate(artifact, old_set, new_set)
    elif target == "epoch_anchor_authorization":
        result = validate_epoch_anchor_authorization(artifact, old_set, new_set)
    elif target == "derived_anchor_binding":
        authorization = artifact["authorization"]
        claimed = artifact["claimed_epoch_anchor_qc"]
        result = validate_epoch_anchor_authorization(authorization, old_set, new_set)
        check_qc_raw(claimed, f"{case['id']} claimed anchor")
        if result == "valid" and qc_cev0(claimed) != qc_cev0(
            derive_epoch_anchor_qc(authorization)
        ):
            result = "derived_anchor_mismatch"
    else:
        raise VectorError(f"{case['id']} has unknown target {target!r}")
    ensure_alternate_signature_binding(case, old_set, new_set)
    if result != case["expected_result"]:
        raise VectorError(
            f"{case['id']} returned {result!r}, expected {case['expected_result']!r}"
        )


def case(
    identifier_text: str,
    target: str,
    expected_result: str,
    artifact: dict[str, object],
    *,
    validator_role: str | None = None,
    mutation: str,
    alternate_signature_binding: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "id": identifier_text,
        "target": target,
        "mutation": mutation,
        "expected_result": expected_result,
        "artifact": artifact,
    }
    if validator_role is not None:
        result["validator_role"] = validator_role
    if alternate_signature_binding is not None:
        result["alternate_signature_binding"] = alternate_signature_binding
    return result


def build_vectors() -> dict[str, object]:
    ed25519_self_test()
    genesis = fixture_hash("genesis")
    chain_id = "trnm-handoff-kernel-v0"
    old_parameters = fixture_hash("old-consensus-parameters")
    new_parameters = fixture_hash("new-consensus-parameters")
    old_set = make_validator_set(
        role="old",
        genesis_hash_hex=genesis,
        chain_id=chain_id,
        protocol_version=0,
        epoch=7,
        parameters_hash_hex=old_parameters,
    )
    new_set = make_validator_set(
        role="new",
        genesis_hash_hex=genesis,
        chain_id=chain_id,
        protocol_version=0,
        epoch=8,
        parameters_hash_hex=new_parameters,
    )

    checkpoint_state_root = fixture_hash("checkpoint-state-root")
    next_epoch_commitment = fixture_hash("next-epoch-commitment-digest")
    terminal_header = finalize_header(
        {
            "schema_version": SCHEMA_VERSION,
            "genesis_hash_hex": genesis,
            "chain_id": chain_id,
            "protocol_version": 0,
            "epoch": 7,
            "view": 12,
            "height": 100,
            "block_kind": BLOCK_KIND_EPOCH_SEAL_2,
            "parent_block_id_hex": fixture_hash("terminal-parent-seal-1"),
            "proposer_id_ascii": "old-d",
            "validator_set_id_hex": old_set["validator_set_id_hex"],
            "consensus_parameters_hash_hex": old_parameters,
            "payload_digest_hex": fixture_hash("empty-payload-root"),
            "state_root_hex": checkpoint_state_root,
            "receipts_root_hex": fixture_hash("empty-receipts-root"),
            "evidence_root_hex": fixture_hash("empty-evidence-root"),
            "timestamp_ms": 1_800_000_000_000,
            "next_epoch_commitment_hash_hex": next_epoch_commitment,
        }
    )
    terminal_qc = make_qc(
        validator_set=old_set,
        view=12,
        height=100,
        certified_block_id_hex=terminal_header["block_id_hex"],
        signer_ids=["old-a", "old-b"],
    )
    terminal_qc_one_below = make_qc(
        validator_set=old_set,
        view=12,
        height=100,
        certified_block_id_hex=terminal_header["block_id_hex"],
        signer_ids=["old-b", "old-c", "old-d"],
    )
    descriptor = finalize_descriptor(
        {
            "schema_version": SCHEMA_VERSION,
            "genesis_hash_hex": genesis,
            "chain_id": chain_id,
            "old_epoch": 7,
            "new_epoch": 8,
            "old_protocol_version": 0,
            "new_protocol_version": 0,
            "old_validator_set_hash_hex": old_set["validator_set_id_hex"],
            "new_validator_set_hash_hex": new_set["validator_set_id_hex"],
            "old_consensus_parameters_hash_hex": old_parameters,
            "new_consensus_parameters_hash_hex": new_parameters,
            "checkpoint_height": 98,
            "checkpoint_block_id_hex": fixture_hash("checkpoint-block"),
            "checkpoint_state_root_hex": checkpoint_state_root,
            "next_epoch_commitment_digest_hex": next_epoch_commitment,
            "terminal_old_height": 100,
            "terminal_old_block_id_hex": terminal_header["block_id_hex"],
            "terminal_old_qc_digest_hex": terminal_qc["digest_hex"],
            "terminal_old_view": 12,
            "activation_height": 101,
            "initial_new_view": 1,
        }
    )
    old_vote = make_handoff_vote(descriptor, "old")
    new_vote = make_handoff_vote(descriptor, "new")
    old_root = fixed_hex(old_vote["signing_root_hex"], 32, "old role root")
    new_root = fixed_hex(new_vote["signing_root_hex"], 32, "new role root")
    certificate = finalize_certificate(
        {
            "schema_version": SCHEMA_VERSION,
            "descriptor": descriptor,
            "old_signatures": make_shares(["old-a", "old-b"], old_root),
            "new_signatures": make_shares(["new-a", "new-b"], new_root),
            "old_signed_power": 7,
            "new_signed_power": 7,
        }
    )
    authorization = finalize_authorization(
        {
            "terminal_old_header": terminal_header,
            "terminal_old_qc": terminal_qc,
            "handoff_certificate": certificate,
        }
    )
    anchor = derive_epoch_anchor_qc(authorization)

    negative_cases: list[dict[str, object]] = []
    negative_cases.append(
        case(
            "terminal_qc_one_below_6",
            "terminal_qc",
            "insufficient_quorum",
            terminal_qc_one_below,
            validator_role="old",
            mutation="replace exact-7 terminal voters with old-b/c/d power 6",
        )
    )

    old_below = mutate(
        certificate,
        lambda value: value.__setitem__(
            "old_signatures", make_shares(["old-b", "old-c", "old-d"], old_root)
        ),
    )
    old_below["old_signed_power"] = 6
    negative_cases.append(
        case(
            "old_role_one_below_6",
            "handoff_certificate",
            "old_insufficient_quorum",
            finalize_certificate(old_below),
            mutation="replace exact-7 old role with old-b/c/d power 6",
        )
    )
    new_below = mutate(
        certificate,
        lambda value: value.__setitem__(
            "new_signatures", make_shares(["new-b", "new-c", "new-d"], new_root)
        ),
    )
    new_below["new_signed_power"] = 6
    negative_cases.append(
        case(
            "new_role_one_below_6",
            "handoff_certificate",
            "new_insufficient_quorum",
            finalize_certificate(new_below),
            mutation="replace exact-7 new role with new-b/c/d power 6",
        )
    )

    for role in ("old", "new"):
        field = f"{role}_signatures"
        duplicate = mutate(
            certificate,
            lambda value, field=field: value[field].__setitem__(
                1, copy.deepcopy(value[field][0])
            ),
        )
        negative_cases.append(
            case(
                f"{role}_role_duplicate_signer",
                "handoff_certificate",
                f"{role}_duplicate_signer",
                finalize_certificate(duplicate),
                mutation=f"duplicate {role}-a in the {role} signature list",
            )
        )
        noncanonical = mutate(
            certificate,
            lambda value, field=field: value[field].reverse(),
        )
        negative_cases.append(
            case(
                f"{role}_role_noncanonical_signer_order",
                "handoff_certificate",
                f"{role}_noncanonical_signer_order",
                finalize_certificate(noncanonical),
                mutation=f"reverse the {role} signature list",
            )
        )
        unknown = mutate(
            certificate,
            lambda value, field=field, role=role: value[field][1].__setitem__(
                "signer_id_ascii", f"{role}-z"
            ),
        )
        negative_cases.append(
            case(
                f"{role}_role_unknown_signer",
                "handoff_certificate",
                f"{role}_unknown_signer",
                finalize_certificate(unknown),
                mutation=f"replace {role}-b with unknown {role}-z",
            )
        )

    def alternate_signature_case(
        *,
        case_id: str,
        role: str,
        preimage: bytes,
        domain: bytes,
        mutation_text: str,
    ) -> None:
        root = cev0_digest(domain, preimage)
        signer = f"{role}-a"
        signature = ed25519_sign(fixture_seed(signer), root).hex()
        changed = mutate(
            certificate,
            lambda value: (
                value[f"{role}_signatures"][0].__setitem__(
                    "signing_root_hex", root.hex()
                ),
                value[f"{role}_signatures"][0].__setitem__(
                    "signature_hex", signature
                ),
            ),
        )
        negative_cases.append(
            case(
                case_id,
                "handoff_certificate",
                "invalid_signature",
                finalize_certificate(changed),
                mutation=mutation_text,
                alternate_signature_binding={
                    "signer_id_ascii": signer,
                    "domain_ascii": domain.decode("ascii"),
                    "signing_preimage_cev0_hex": preimage.hex(),
                    "signing_root_hex": root.hex(),
                    "signature_hex": signature,
                },
            )
        )

    alternate_signature_case(
        case_id="old_role_signed_as_new_role",
        role="old",
        preimage=handoff_vote_preimage(new_vote),
        domain=DOMAIN_HANDOFF_VOTE,
        mutation_text="old-a signs the new-role root",
    )
    alternate_signature_case(
        case_id="new_role_signed_as_old_role",
        role="new",
        preimage=handoff_vote_preimage(old_vote),
        domain=DOMAIN_HANDOFF_VOTE,
        mutation_text="new-a signs the old-role root",
    )
    alternate_signature_case(
        case_id="old_role_wrong_domain",
        role="old",
        preimage=handoff_vote_preimage(old_vote),
        domain=DOMAIN_QC,
        mutation_text="old-a signs the same preimage under the QC domain",
    )
    wrong_context_vote = copy.deepcopy(new_vote)
    wrong_context_vote["signing_epoch"] = int(new_vote["signing_epoch"]) + 1
    alternate_signature_case(
        case_id="new_role_wrong_context",
        role="new",
        preimage=handoff_vote_preimage(wrong_context_vote),
        domain=DOMAIN_HANDOFF_VOTE,
        mutation_text="new-a signs a handoff context for the wrong epoch",
    )
    mutated_signature = mutate(
        certificate,
        lambda value: value["new_signatures"][1].__setitem__(
            "signature_hex",
            bitflip_signature(str(value["new_signatures"][1]["signature_hex"])),
        ),
    )
    negative_cases.append(
        case(
            "new_role_mutated_signature",
            "handoff_certificate",
            "invalid_signature",
            finalize_certificate(mutated_signature),
            mutation="flip one bit in new-b's signature",
        )
    )

    descriptor_mutations: list[
        tuple[str, str, str, object]
    ] = [
        (
            "descriptor_old_set_mismatch",
            "old_validator_set_hash_hex",
            "descriptor_old_set_mismatch",
            fixture_hash("wrong-old-set"),
        ),
        (
            "descriptor_new_set_mismatch",
            "new_validator_set_hash_hex",
            "descriptor_new_set_mismatch",
            fixture_hash("wrong-new-set"),
        ),
        (
            "descriptor_old_parameters_mismatch",
            "old_consensus_parameters_hash_hex",
            "descriptor_old_parameters_mismatch",
            fixture_hash("wrong-old-parameters"),
        ),
        (
            "descriptor_new_parameters_mismatch",
            "new_consensus_parameters_hash_hex",
            "descriptor_new_parameters_mismatch",
            fixture_hash("wrong-new-parameters"),
        ),
        (
            "descriptor_old_version_mismatch",
            "old_protocol_version",
            "descriptor_old_version_mismatch",
            1,
        ),
        (
            "descriptor_new_version_mismatch",
            "new_protocol_version",
            "descriptor_new_version_mismatch",
            1,
        ),
        (
            "descriptor_epoch_relation_mismatch",
            "new_epoch",
            "descriptor_epoch_mismatch",
            9,
        ),
        (
            "descriptor_activation_height_mismatch",
            "activation_height",
            "descriptor_activation_height_mismatch",
            102,
        ),
        (
            "descriptor_initial_view_mismatch",
            "initial_new_view",
            "descriptor_initial_view_mismatch",
            2,
        ),
    ]
    for case_id, field, expected, replacement in descriptor_mutations:
        changed = mutate(
            certificate,
            lambda value, field=field, replacement=replacement: value[
                "descriptor"
            ].__setitem__(field, replacement),
        )
        negative_cases.append(
            case(
                case_id,
                "handoff_certificate",
                expected,
                resign_certificate(changed),
                mutation=f"replace descriptor.{field}",
            )
        )

    header_kind = mutate(
        authorization,
        lambda value: value["terminal_old_header"].__setitem__("block_kind", 2),
    )
    negative_cases.append(
        case(
            "terminal_header_wrong_kind",
            "epoch_anchor_authorization",
            "terminal_not_epoch_seal_2",
            finalize_authorization(header_kind),
            mutation="change terminal EpochSeal2 kind to EpochSeal1",
        )
    )
    header_id = mutate(
        authorization,
        lambda value: value["terminal_old_header"].__setitem__(
            "parent_block_id_hex", fixture_hash("wrong-terminal-parent")
        ),
    )
    negative_cases.append(
        case(
            "terminal_header_id_mismatch",
            "epoch_anchor_authorization",
            "terminal_header_id_mismatch",
            finalize_authorization(header_id),
            mutation="change a header field so its derived BlockId no longer matches descriptor",
        )
    )
    terminal_qc_digest_case = mutate(
        authorization,
        lambda value: value["handoff_certificate"]["descriptor"].__setitem__(
            "terminal_old_qc_digest_hex", fixture_hash("wrong-terminal-qc-digest")
        ),
    )
    terminal_qc_digest_case["handoff_certificate"] = resign_certificate(
        terminal_qc_digest_case["handoff_certificate"]
    )
    negative_cases.append(
        case(
            "terminal_descriptor_qc_digest_mismatch",
            "epoch_anchor_authorization",
            "terminal_qc_digest_mismatch",
            finalize_authorization(terminal_qc_digest_case),
            mutation="replace descriptor terminal_old_qc_digest",
        )
    )
    header_height = mutate(
        authorization,
        lambda value: value["terminal_old_header"].__setitem__("height", 99),
    )
    negative_cases.append(
        case(
            "terminal_header_height_mismatch",
            "epoch_anchor_authorization",
            "terminal_header_height_mismatch",
            finalize_authorization(header_height),
            mutation="change terminal header height",
        )
    )
    header_view = mutate(
        authorization,
        lambda value: value["terminal_old_header"].__setitem__("view", 13),
    )
    negative_cases.append(
        case(
            "terminal_header_view_mismatch",
            "epoch_anchor_authorization",
            "terminal_header_view_mismatch",
            finalize_authorization(header_view),
            mutation="change terminal header view",
        )
    )
    qc_block = copy.deepcopy(authorization)
    qc_block["terminal_old_qc"] = make_qc(
        validator_set=old_set,
        view=12,
        height=100,
        certified_block_id_hex=fixture_hash("wrong-certified-terminal-block"),
        signer_ids=["old-a", "old-b"],
    )
    negative_cases.append(
        case(
            "terminal_qc_block_mismatch",
            "epoch_anchor_authorization",
            "terminal_qc_block_mismatch",
            finalize_authorization(qc_block),
            mutation="change terminal QC certified block",
        )
    )
    qc_view = copy.deepcopy(authorization)
    qc_view["terminal_old_qc"] = make_qc(
        validator_set=old_set,
        view=13,
        height=100,
        certified_block_id_hex=terminal_header["block_id_hex"],
        signer_ids=["old-a", "old-b"],
    )
    negative_cases.append(
        case(
            "terminal_qc_view_mismatch",
            "epoch_anchor_authorization",
            "terminal_qc_view_mismatch",
            finalize_authorization(qc_view),
            mutation="replace the terminal QC view with a strictly valid view-13 QC",
        )
    )
    qc_height = copy.deepcopy(authorization)
    qc_height["terminal_old_qc"] = make_qc(
        validator_set=old_set,
        view=12,
        height=99,
        certified_block_id_hex=terminal_header["block_id_hex"],
        signer_ids=["old-a", "old-b"],
    )
    negative_cases.append(
        case(
            "terminal_qc_height_mismatch",
            "epoch_anchor_authorization",
            "terminal_qc_height_mismatch",
            finalize_authorization(qc_height),
            mutation="replace the terminal QC height with a strictly valid height-99 QC",
        )
    )
    qc_set = copy.deepcopy(authorization)
    wrong_set_qc = copy.deepcopy(qc_set["terminal_old_qc"])
    wrong_set_qc["validator_set_id_hex"] = fixture_hash("wrong-terminal-qc-set")
    qc_set["terminal_old_qc"] = resign_qc(
        wrong_set_qc, ["old-a", "old-b"]
    )
    negative_cases.append(
        case(
            "terminal_qc_set_mismatch",
            "epoch_anchor_authorization",
            "validator_set_mismatch",
            finalize_authorization(qc_set),
            mutation="bind and re-sign the terminal QC under an uncommitted set digest",
        )
    )
    header_set = mutate(
        authorization,
        lambda value: value["terminal_old_header"].__setitem__(
            "validator_set_id_hex", fixture_hash("wrong-terminal-header-set")
        ),
    )
    negative_cases.append(
        case(
            "terminal_header_set_mismatch",
            "epoch_anchor_authorization",
            "terminal_header_set_mismatch",
            finalize_authorization(header_set),
            mutation="change terminal header validator-set binding",
        )
    )

    negative_cases.append(
        case(
            "bare_derived_anchor_as_ordinary_qc",
            "ordinary_qc",
            "unauthorized_synthetic_qc",
            anchor,
            validator_role="new",
            mutation="submit the exact derived empty anchor to ordinary-QC admission",
        )
    )
    odd_anchor = mutate(
        anchor,
        lambda value: (
            value.__setitem__("view", 4),
            value.__setitem__("height", 103),
            value.__setitem__("block_id_hex", fixture_hash("odd-empty-qc-block")),
        ),
    )
    negative_cases.append(
        case(
            "odd_empty_qc_as_ordinary_qc",
            "ordinary_qc",
            "unauthorized_synthetic_qc",
            finalize_qc(odd_anchor),
            validator_role="new",
            mutation="submit an arbitrary empty-signature QC to ordinary admission",
        )
    )
    wrong_anchor = mutate(
        anchor,
        lambda value: value.__setitem__(
            "block_id_hex", fixture_hash("wrong-derived-anchor-block")
        ),
    )
    negative_cases.append(
        case(
            "derived_epoch_anchor_binding_mismatch",
            "derived_anchor_binding",
            "derived_anchor_mismatch",
            {
                "authorization": authorization,
                "claimed_epoch_anchor_qc": finalize_qc(wrong_anchor),
            },
            mutation="claim a derived anchor for a different terminal block",
        )
    )

    return {
        "schema": "trnm_poco_bft_handoff_certificate_kernel_vectors_v0",
        "schema_version": SCHEMA_VERSION,
        "scope": (
            "B2-B weighted handoff certificate kernel, terminal ordinary-QC binding, "
            "strict Ed25519, and exact derived EpochAnchorQC binding only"
        ),
        "key_material_policy": (
            "Deterministic private fixture material exists only in the checker; "
            "this JSON contains public verification material only"
        ),
        "cryptography": {
            "algorithm": "RFC8032 Ed25519",
            "message_boundary": "exact raw 32-byte SigningRoot",
            "verification_profile": (
                "strict canonical encodings, S < L, uncofactored equation, "
                "and small-order rejection"
            ),
        },
        "domains": {
            "hash_prefix_ascii": HASH_PREFIX.decode("ascii"),
            "block_ascii": DOMAIN_BLOCK.decode("ascii"),
            "vote_ascii": DOMAIN_VOTE.decode("ascii"),
            "qc_ascii": DOMAIN_QC.decode("ascii"),
            "validator_set_ascii": DOMAIN_VALIDATOR_SET.decode("ascii"),
            "handoff_descriptor_ascii": DOMAIN_HANDOFF_DESCRIPTOR.decode("ascii"),
            "handoff_vote_ascii": DOMAIN_HANDOFF_VOTE.decode("ascii"),
            "handoff_certificate_ascii": DOMAIN_HANDOFF_CERTIFICATE.decode("ascii"),
        },
        "validator_sets": {"old": old_set, "new": new_set},
        "terminal_old_header": terminal_header,
        "terminal_old_qcs": {
            "exact_7": {**terminal_qc, "expected_result": "valid"},
            "one_below_6": {
                **terminal_qc_one_below,
                "expected_result": "insufficient_quorum",
            },
        },
        "handoff_descriptor": descriptor,
        "handoff_vote_roots": {"old": old_vote, "new": new_vote},
        "handoff_certificate_exact_7": certificate,
        "epoch_anchor_authorization": authorization,
        "derived_epoch_anchor_qc": anchor,
        "negative_cases": negative_cases,
        "coverage": [
            "old/new sets each have four distinct keys and powers 4/3/2/1",
            "W=10, quorum=7, exact-7 acceptance and one-below-6 rejection for all three roles",
            "strict old/new signer ordering, uniqueness, membership, weighted quorum, and Ed25519",
            "role, domain, context, and signature separation",
            "descriptor set, parameter, version, epoch, activation-height, and initial-view relations",
            "terminal EpochSeal2 header, BlockId, QC digest, height, view, block, and set bindings",
            "bare and arbitrary empty QCs rejected by ordinary-QC admission",
            "strictly verified certificate kernel fixes one exact empty EpochAnchorQC field/byte binding",
        ],
        "honest_boundary": [
            "Checkpoint ancestry and both seal links are not carried or authenticated here.",
            "This B2-B cryptographic corpus treats the NextEpochCommitmentV0 digest, validator-set/parameter preimages, and protocol-upgrade authorization as opaque commitments; B2-C separately closes exact inert commitment decoding, while authenticated preimage/state provenance and transition authorization remain open.",
            "Proof of possession, persist-before-sign, slashing, complete epoch authorization, and first-new-block proposal admission remain open.",
            "The derived EpochAnchorQC has no peer-controlled bare authorization and is never an ordinary certifying QC.",
        ],
    }


def assert_no_private_material(value: object, path: str = "$") -> None:
    forbidden_keys = {"seed", "private_key", "secret_key", "secret_scalar"}
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in forbidden_keys:
                raise VectorError(f"private fixture material leaked at {path}.{key}")
            assert_no_private_material(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_no_private_material(item, f"{path}[{index}]")


def validate_vector_data(data: dict[str, object]) -> None:
    ed25519_self_test()
    if data.get("schema") != "trnm_poco_bft_handoff_certificate_kernel_vectors_v0":
        raise VectorError("unexpected vector schema")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise VectorError("unexpected vector schema version")
    assert_no_private_material(data)
    expected_domains = {
        "hash_prefix_ascii": HASH_PREFIX.decode("ascii"),
        "block_ascii": DOMAIN_BLOCK.decode("ascii"),
        "vote_ascii": DOMAIN_VOTE.decode("ascii"),
        "qc_ascii": DOMAIN_QC.decode("ascii"),
        "validator_set_ascii": DOMAIN_VALIDATOR_SET.decode("ascii"),
        "handoff_descriptor_ascii": DOMAIN_HANDOFF_DESCRIPTOR.decode("ascii"),
        "handoff_vote_ascii": DOMAIN_HANDOFF_VOTE.decode("ascii"),
        "handoff_certificate_ascii": DOMAIN_HANDOFF_CERTIFICATE.decode("ascii"),
    }
    if data.get("domains") != expected_domains:
        raise VectorError("frozen domain table drift")

    old_set = data["validator_sets"]["old"]
    new_set = data["validator_sets"]["new"]
    validate_validator_set(old_set, "old validator set")
    validate_validator_set(new_set, "new validator set")
    old_validators, _, _ = validator_maps(old_set)
    new_validators, _, _ = validator_maps(new_set)
    if set(old_validators).intersection(new_validators):
        raise VectorError("old/new validator identities are not distinct")
    all_keys = {
        str(item["public_key_hex"])
        for validator_set in (old_set, new_set)
        for item in validator_set["validators"]
    }
    if len(all_keys) != 8:
        raise VectorError("old/new fixture does not contain eight distinct keys")

    header = data["terminal_old_header"]
    if validate_header_shape(header) != "valid":
        raise VectorError("positive terminal header is invalid")
    qcs = data["terminal_old_qcs"]
    exact_qc = qcs["exact_7"]
    below_qc = qcs["one_below_6"]
    if validate_ordinary_qc(exact_qc, old_set) != "valid":
        raise VectorError("positive terminal QC is invalid")
    if validate_ordinary_qc(below_qc, old_set) != "insufficient_quorum":
        raise VectorError("terminal one-below QC did not fail at quorum")
    if verify_qc_signatures(below_qc, old_set) != "valid":
        raise VectorError("terminal one-below control signatures are not strictly valid")
    if exact_qc["signed_power"] != 7 or below_qc["signed_power"] != 6:
        raise VectorError("terminal QC threshold metadata drift")

    descriptor = data["handoff_descriptor"]
    if validate_descriptor(descriptor, old_set, new_set) != "valid":
        raise VectorError("positive handoff descriptor is invalid")
    for role in ("old", "new"):
        if (
            validate_handoff_vote_artifact(
                data["handoff_vote_roots"][role], descriptor, role
            )
            != "valid"
        ):
            raise VectorError(f"positive {role} handoff vote root is invalid")

    certificate = data["handoff_certificate_exact_7"]
    if validate_handoff_certificate(certificate, old_set, new_set) != "valid":
        raise VectorError("positive handoff certificate is invalid")
    if certificate["old_signed_power"] != 7 or certificate["new_signed_power"] != 7:
        raise VectorError("handoff certificate threshold metadata drift")
    authorization = data["epoch_anchor_authorization"]
    if validate_epoch_anchor_authorization(authorization, old_set, new_set) != "valid":
        raise VectorError("positive epoch-anchor authorization is invalid")
    anchor = data["derived_epoch_anchor_qc"]
    check_qc_raw(anchor, "derived epoch anchor")
    if qc_cev0(anchor) != qc_cev0(derive_epoch_anchor_qc(authorization)):
        raise VectorError("derived EpochAnchorQC binding mismatch")
    if validate_ordinary_qc(anchor, new_set) != "unauthorized_synthetic_qc":
        raise VectorError("derived anchor was accidentally admitted as an ordinary QC")

    cases = data["negative_cases"]
    cases_by_id = {str(entry["id"]): entry for entry in cases}
    for case_id in ("old_role_one_below_6", "new_role_one_below_6"):
        if (
            verify_certificate_signatures(
                cases_by_id[case_id]["artifact"], old_set, new_set
            )
            != "valid"
        ):
            raise VectorError(f"{case_id} control signatures are not strictly valid")
    seen: set[str] = set()
    for entry in cases:
        case_id = str(entry["id"])
        if case_id in seen:
            raise VectorError(f"duplicate negative case ID {case_id!r}")
        seen.add(case_id)
        if "rust_error_contains" in entry:
            raise VectorError(f"{case_id} uses forbidden fuzzy rust_error_contains")
        validate_negative_case(entry, old_set, new_set)
    required_case_ids = {
        "terminal_qc_one_below_6",
        "old_role_one_below_6",
        "new_role_one_below_6",
        "old_role_duplicate_signer",
        "old_role_noncanonical_signer_order",
        "old_role_unknown_signer",
        "new_role_duplicate_signer",
        "new_role_noncanonical_signer_order",
        "new_role_unknown_signer",
        "old_role_signed_as_new_role",
        "new_role_signed_as_old_role",
        "old_role_wrong_domain",
        "new_role_wrong_context",
        "new_role_mutated_signature",
        "descriptor_old_set_mismatch",
        "descriptor_new_set_mismatch",
        "descriptor_old_parameters_mismatch",
        "descriptor_new_parameters_mismatch",
        "descriptor_old_version_mismatch",
        "descriptor_new_version_mismatch",
        "descriptor_epoch_relation_mismatch",
        "descriptor_activation_height_mismatch",
        "descriptor_initial_view_mismatch",
        "terminal_header_wrong_kind",
        "terminal_header_id_mismatch",
        "terminal_descriptor_qc_digest_mismatch",
        "terminal_header_height_mismatch",
        "terminal_header_view_mismatch",
        "terminal_qc_block_mismatch",
        "terminal_qc_view_mismatch",
        "terminal_qc_height_mismatch",
        "terminal_qc_set_mismatch",
        "terminal_header_set_mismatch",
        "bare_derived_anchor_as_ordinary_qc",
        "odd_empty_qc_as_ordinary_qc",
        "derived_epoch_anchor_binding_mismatch",
    }
    if seen != required_case_ids:
        raise VectorError(
            f"negative corpus drift: missing={sorted(required_case_ids - seen)}, "
            f"extra={sorted(seen - required_case_ids)}"
        )


def canonical_json(data: dict[str, object]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the deterministic committed JSON fixture",
    )
    arguments = parser.parse_args()
    generated = build_vectors()
    validate_vector_data(generated)
    expected_text = canonical_json(generated)
    if arguments.write:
        arguments.vector.write_text(expected_text, encoding="utf-8")
        print(f"wrote {arguments.vector}")
        return 0
    try:
        actual_text = arguments.vector.read_text(encoding="utf-8")
        actual = json.loads(actual_text)
    except (OSError, json.JSONDecodeError) as error:
        raise VectorError(f"cannot read {arguments.vector}: {error}") from error
    validate_vector_data(actual)
    if actual_text != expected_text or actual != generated:
        raise VectorError(
            "committed handoff vector drift; run this checker with --write"
        )
    print(
        "PoCO-BFT v0 handoff vectors OK: 11 public artifacts, "
        f"{len(actual['negative_cases'])} stable negative cases, W=10/quorum=7"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VectorError as error:
        print(f"handoff vector check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
