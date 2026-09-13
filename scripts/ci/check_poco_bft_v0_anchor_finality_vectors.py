#!/usr/bin/env python3
"""Reconstruct PoCO-BFT v0 anchor, handoff, and finality golden vectors.

This independent standard-library checker covers canonical encoding, frozen
domain digests, and the exact logical relationships needed by a three-header
finality proof.  Composite signatures are opaque 64-byte fixtures: this gate
does not implement Ed25519 or claim that those signatures verify.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Iterable


HASH_PREFIX = b"trnm.cev0.hash.v0"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/anchor-finality-v0.json"
)
ED25519_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/ed25519-v0.json"
)
CONSENSUS_STRING = re.compile(rb"[a-z0-9][a-z0-9._:-]{0,127}\Z")

BLOCK_DOMAIN = "trnm.poco-bft.block.v0"
PROPOSAL_DOMAIN = "trnm.poco-bft.proposal.v0"
QC_DOMAIN = "trnm.poco-bft.qc.v0"
TC_DOMAIN = "trnm.poco-bft.tc.v0"
HANDOFF_DESCRIPTOR_DOMAIN = "trnm.poco-bft.handoff-descriptor.v0"
HANDOFF_CERTIFICATE_DOMAIN = "trnm.poco-bft.handoff-certificate.v0"
FINALITY_PROOF_DOMAIN = "trnm.poco-bft.finality-proof.v0"

DOMAINS = {
    BLOCK_DOMAIN,
    PROPOSAL_DOMAIN,
    QC_DOMAIN,
    TC_DOMAIN,
    HANDOFF_DESCRIPTOR_DOMAIN,
    HANDOFF_CERTIFICATE_DOMAIN,
    FINALITY_PROOF_DOMAIN,
}

# Copied from vectors/ed25519-v0.json.  It is valid only for that file's
# foundation vote root.  Reuse here exercises Signature64 width and nested
# CEV0 layout; none of the composite signatures below is claimed valid.
FIXED_SIGNATURE64 = bytes.fromhex(
    "324a7b305ab428de6f7bdde956b7c9f6f5cf0a92bdd21b0b2b5b0b166fa614114"
    "03ed1a3b5d4f2dc234ac78b11a5ca5f8d8fae548c22b5386818f328e503bd0d"
)


class VectorError(ValueError):
    """The fixture or committed vector is malformed."""


class LogicalValidationError(ValueError):
    """A structural or digest relationship in the logical proof is invalid."""


def uint(value: int, bits: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"u{bits} value is not an integer")
    if value < 0 or value >= 1 << bits:
        raise VectorError(f"value {value} is outside u{bits}")
    return value.to_bytes(bits // 8, "big")


def fixed(value: object, length: int, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise LogicalValidationError(
            f"{label} must contain exactly {length} bytes"
        )
    return value


def cev0_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise VectorError("CEV0 Bytes value is not bytes")
    return uint(len(value), 32) + value


def consensus_string(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as error:
        raise VectorError("ConsensusString must be ASCII text") from error
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
    return hashlib.sha256(
        frame(HASH_PREFIX) + frame(domain.encode("ascii")) + frame(encoded)
    ).digest()


def fixture_hash(label: str) -> bytes:
    return hashlib.sha256(
        b"trnm.poco-bft.anchor-finality.fixture.v0:" + label.encode("ascii")
    ).digest()


def encode_signature_share(share: dict[str, object]) -> bytes:
    return cev0_bytes(share["validator_id"]) + fixed(
        share["signature"], 64, "signature share"
    )


def encode_block_header(header: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(header["schema_version"], 16),
            fixed(header["genesis_hash"], 32, "header genesis_hash"),
            consensus_string(header["chain_id"]),
            uint(header["protocol_version"], 32),
            uint(header["epoch"], 64),
            uint(header["view"], 64),
            uint(header["height"], 64),
            uint(header["block_kind"], 8),
            fixed(header["parent_block_id"], 32, "header parent_block_id"),
            cev0_bytes(header["proposer_id"]),
            fixed(
                header["active_validator_set_hash"],
                32,
                "header active_validator_set_hash",
            ),
            fixed(
                header["consensus_parameters_hash"],
                32,
                "header consensus_parameters_hash",
            ),
            fixed(header["payload_root"], 32, "header payload_root"),
            fixed(header["state_root"], 32, "header state_root"),
            fixed(header["receipts_root"], 32, "header receipts_root"),
            fixed(header["evidence_root"], 32, "header evidence_root"),
            uint(header["timestamp_ms"], 64),
            optional(
                None
                if header["next_epoch_commitment_hash"] is None
                else fixed(
                    header["next_epoch_commitment_hash"],
                    32,
                    "header next_epoch_commitment_hash",
                )
            ),
        )
    )


def block_id(header: dict[str, object]) -> bytes:
    return digest(BLOCK_DOMAIN, encode_block_header(header))


def encode_qc(qc: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(qc["schema_version"], 16),
            fixed(qc["genesis_hash"], 32, "QC genesis_hash"),
            consensus_string(qc["chain_id"]),
            uint(qc["protocol_version"], 32),
            uint(qc["epoch"], 64),
            fixed(qc["validator_set_hash"], 32, "QC validator_set_hash"),
            uint(qc["view"], 64),
            uint(qc["height"], 64),
            fixed(qc["block_id"], 32, "QC block_id"),
            cev0_list(encode_signature_share(item) for item in qc["signatures"]),
        )
    )


def qc_digest(qc: dict[str, object]) -> bytes:
    return digest(QC_DOMAIN, encode_qc(qc))


def high_qc_summary(qc: dict[str, object]) -> dict[str, object]:
    return {
        "qc_digest": qc_digest(qc),
        "qc_epoch": qc["epoch"],
        "qc_view": qc["view"],
        "qc_height": qc["height"],
        "qc_block_id": qc["block_id"],
    }


def encode_high_qc_summary(summary: dict[str, object]) -> bytes:
    return b"".join(
        (
            fixed(summary["qc_digest"], 32, "high-QC digest"),
            uint(summary["qc_epoch"], 64),
            uint(summary["qc_view"], 64),
            uint(summary["qc_height"], 64),
            fixed(summary["qc_block_id"], 32, "high-QC block_id"),
        )
    )


def encode_timeout_entry(entry: dict[str, object]) -> bytes:
    return b"".join(
        (
            cev0_bytes(entry["signer_id"]),
            encode_high_qc_summary(entry["high_qc"]),
            fixed(entry["signature"], 64, "timeout signature"),
        )
    )


def encode_tc(tc: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(tc["schema_version"], 16),
            fixed(tc["genesis_hash"], 32, "TC genesis_hash"),
            consensus_string(tc["chain_id"]),
            uint(tc["protocol_version"], 32),
            uint(tc["epoch"], 64),
            fixed(tc["validator_set_hash"], 32, "TC validator_set_hash"),
            uint(tc["timed_out_view"], 64),
            cev0_list(encode_timeout_entry(item) for item in tc["entries"]),
            cev0_list(encode_qc(item) for item in tc["referenced_qcs"]),
            fixed(
                tc["selected_high_qc_digest"],
                32,
                "TC selected_high_qc_digest",
            ),
        )
    )


def tc_digest(tc: dict[str, object]) -> bytes:
    return digest(TC_DOMAIN, encode_tc(tc))


def encode_handoff_descriptor(descriptor: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(descriptor["schema_version"], 16),
            fixed(descriptor["genesis_hash"], 32, "descriptor genesis_hash"),
            consensus_string(descriptor["chain_id"]),
            uint(descriptor["old_epoch"], 64),
            uint(descriptor["new_epoch"], 64),
            uint(descriptor["old_protocol_version"], 32),
            uint(descriptor["new_protocol_version"], 32),
            fixed(
                descriptor["old_validator_set_hash"],
                32,
                "descriptor old_validator_set_hash",
            ),
            fixed(
                descriptor["new_validator_set_hash"],
                32,
                "descriptor new_validator_set_hash",
            ),
            fixed(
                descriptor["old_consensus_parameters_hash"],
                32,
                "descriptor old_consensus_parameters_hash",
            ),
            fixed(
                descriptor["new_consensus_parameters_hash"],
                32,
                "descriptor new_consensus_parameters_hash",
            ),
            uint(descriptor["checkpoint_height"], 64),
            fixed(
                descriptor["checkpoint_block_id"],
                32,
                "descriptor checkpoint_block_id",
            ),
            fixed(
                descriptor["checkpoint_state_root"],
                32,
                "descriptor checkpoint_state_root",
            ),
            fixed(
                descriptor["next_epoch_commitment_digest"],
                32,
                "descriptor next_epoch_commitment_digest",
            ),
            uint(descriptor["terminal_old_height"], 64),
            fixed(
                descriptor["terminal_old_block_id"],
                32,
                "descriptor terminal_old_block_id",
            ),
            fixed(
                descriptor["terminal_old_qc_digest"],
                32,
                "descriptor terminal_old_qc_digest",
            ),
            uint(descriptor["terminal_old_view"], 64),
            uint(descriptor["activation_height"], 64),
            uint(descriptor["initial_new_view"], 64),
        )
    )


def handoff_descriptor_digest(descriptor: dict[str, object]) -> bytes:
    return digest(HANDOFF_DESCRIPTOR_DOMAIN, encode_handoff_descriptor(descriptor))


def encode_handoff_certificate(certificate: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(certificate["schema_version"], 16),
            encode_handoff_descriptor(certificate["descriptor"]),
            cev0_list(
                encode_signature_share(item)
                for item in certificate["old_signatures"]
            ),
            cev0_list(
                encode_signature_share(item)
                for item in certificate["new_signatures"]
            ),
        )
    )


def handoff_certificate_digest(certificate: dict[str, object]) -> bytes:
    return digest(
        HANDOFF_CERTIFICATE_DOMAIN, encode_handoff_certificate(certificate)
    )


def encode_epoch_anchor_authorization(authorization: dict[str, object]) -> bytes:
    return b"".join(
        (
            encode_block_header(authorization["terminal_old_header"]),
            encode_qc(authorization["terminal_old_qc"]),
            encode_handoff_certificate(authorization["handoff_certificate"]),
        )
    )


def encode_common_context(context: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(context["schema_version"], 16),
            fixed(context["genesis_hash"], 32, "context genesis_hash"),
            consensus_string(context["chain_id"]),
            uint(context["protocol_version"], 32),
            uint(context["epoch"], 64),
            fixed(
                context["validator_set_hash"],
                32,
                "context validator_set_hash",
            ),
            uint(context["view"], 64),
            uint(context["message_kind"], 8),
        )
    )


def encode_proposal_sign(proposal: dict[str, object]) -> bytes:
    return b"".join(
        (
            encode_common_context(proposal["context"]),
            uint(proposal["height"], 64),
            fixed(proposal["block_id"], 32, "proposal block_id"),
            fixed(
                proposal["justify_qc_digest"],
                32,
                "proposal justify_qc_digest",
            ),
            optional(
                None
                if proposal["timeout_certificate_digest"] is None
                else fixed(
                    proposal["timeout_certificate_digest"],
                    32,
                    "proposal timeout_certificate_digest",
                )
            ),
            optional(
                None
                if proposal["handoff_certificate_digest"] is None
                else fixed(
                    proposal["handoff_certificate_digest"],
                    32,
                    "proposal handoff_certificate_digest",
                )
            ),
        )
    )


def proposal_signing_root(proposal: dict[str, object]) -> bytes:
    return digest(PROPOSAL_DOMAIN, encode_proposal_sign(proposal))


def proposal_for_certified_header(certified: dict[str, object]) -> dict[str, object]:
    header = certified["header"]
    timeout_certificate = certified["timeout_certificate"]
    authorization = certified["epoch_anchor_authorization"]
    return {
        "context": {
            "schema_version": 0,
            "genesis_hash": header["genesis_hash"],
            "chain_id": header["chain_id"],
            "protocol_version": header["protocol_version"],
            "epoch": header["epoch"],
            "validator_set_hash": header["active_validator_set_hash"],
            "view": header["view"],
            "message_kind": 0,
        },
        "height": header["height"],
        "block_id": block_id(header),
        "justify_qc_digest": qc_digest(certified["justify_qc"]),
        "timeout_certificate_digest": (
            None if timeout_certificate is None else tc_digest(timeout_certificate)
        ),
        "handoff_certificate_digest": (
            None
            if authorization is None
            else handoff_certificate_digest(authorization["handoff_certificate"])
        ),
    }


def encode_certified_header(certified: dict[str, object]) -> bytes:
    return b"".join(
        (
            encode_block_header(certified["header"]),
            encode_qc(certified["justify_qc"]),
            optional(
                None
                if certified["timeout_certificate"] is None
                else encode_tc(certified["timeout_certificate"])
            ),
            optional(
                None
                if certified["epoch_anchor_authorization"] is None
                else encode_epoch_anchor_authorization(
                    certified["epoch_anchor_authorization"]
                )
            ),
            fixed(
                certified["proposer_signature"],
                64,
                "proposer_signature",
            ),
            encode_qc(certified["certifying_qc"]),
        )
    )


def encode_finality_proof(proof: dict[str, object]) -> bytes:
    return b"".join(
        (
            uint(proof["schema_version"], 16),
            fixed(proof["genesis_hash"], 32, "proof genesis_hash"),
            consensus_string(proof["chain_id"]),
            uint(proof["protocol_version"], 32),
            uint(proof["epoch"], 64),
            fixed(
                proof["validator_set_hash"], 32, "proof validator_set_hash"
            ),
            fixed(
                proof["consensus_parameters_hash"],
                32,
                "proof consensus_parameters_hash",
            ),
            encode_certified_header(proof["finalized_block"]),
            encode_certified_header(proof["child"]),
            encode_certified_header(proof["grandchild"]),
        )
    )


def finality_proof_digest(proof: dict[str, object]) -> bytes:
    return digest(FINALITY_PROOF_DOMAIN, encode_finality_proof(proof))


def shares(validator_ids: Iterable[bytes]) -> list[dict[str, object]]:
    return [
        {"validator_id": validator_id, "signature": FIXED_SIGNATURE64}
        for validator_id in validator_ids
    ]


def make_qc(
    *,
    genesis_hash: bytes,
    chain_id: str,
    protocol_version: int,
    epoch: int,
    validator_set_hash: bytes,
    view: int,
    height: int,
    certified_block_id: bytes,
    signer_ids: Iterable[bytes],
) -> dict[str, object]:
    return {
        "schema_version": 0,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "protocol_version": protocol_version,
        "epoch": epoch,
        "validator_set_hash": validator_set_hash,
        "view": view,
        "height": height,
        "block_id": certified_block_id,
        "signatures": shares(signer_ids),
    }


def make_tc(
    *,
    genesis_hash: bytes,
    chain_id: str,
    protocol_version: int,
    epoch: int,
    validator_set_hash: bytes,
    timed_out_view: int,
    high_qc: dict[str, object],
    signer_ids: Iterable[bytes],
) -> dict[str, object]:
    summary = high_qc_summary(high_qc)
    return {
        "schema_version": 0,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "protocol_version": protocol_version,
        "epoch": epoch,
        "validator_set_hash": validator_set_hash,
        "timed_out_view": timed_out_view,
        "entries": [
            {
                "signer_id": signer_id,
                "high_qc": dict(summary),
                "signature": FIXED_SIGNATURE64,
            }
            for signer_id in signer_ids
        ],
        "referenced_qcs": [high_qc],
        "selected_high_qc_digest": qc_digest(high_qc),
    }


def make_header(
    *,
    genesis_hash: bytes,
    chain_id: str,
    protocol_version: int,
    epoch: int,
    view: int,
    height: int,
    block_kind: int,
    parent_block_id: bytes,
    proposer_id: bytes,
    validator_set_hash: bytes,
    parameters_hash: bytes,
    label: str,
    state_root: bytes | None = None,
    timestamp_ms: int,
    next_epoch_commitment_hash: bytes | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 0,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "protocol_version": protocol_version,
        "epoch": epoch,
        "view": view,
        "height": height,
        "block_kind": block_kind,
        "parent_block_id": parent_block_id,
        "proposer_id": proposer_id,
        "active_validator_set_hash": validator_set_hash,
        "consensus_parameters_hash": parameters_hash,
        "payload_root": fixture_hash(f"{label}:payload"),
        "state_root": (
            fixture_hash(f"{label}:state") if state_root is None else state_root
        ),
        "receipts_root": fixture_hash(f"{label}:receipts"),
        "evidence_root": fixture_hash(f"{label}:evidence"),
        "timestamp_ms": timestamp_ms,
        "next_epoch_commitment_hash": next_epoch_commitment_hash,
    }


def require_strict_ids(
    items: Iterable[dict[str, object]], key: str, label: str
) -> None:
    ids = [item[key] for item in items]
    if any(not isinstance(item, bytes) for item in ids):
        raise LogicalValidationError(f"{label} contains a non-byte identifier")
    if any(left >= right for left, right in zip(ids, ids[1:])):
        raise LogicalValidationError(f"{label} is not strictly ordered and unique")


def validate_qc(
    qc: dict[str, object],
    *,
    authorized_anchor_digests: set[bytes],
    label: str,
) -> None:
    if qc["schema_version"] != 0:
        raise LogicalValidationError(f"{label} schema_version is not 0")
    encode_qc(qc)
    require_strict_ids(qc["signatures"], "validator_id", f"{label} signatures")
    if not qc["signatures"] and qc_digest(qc) not in authorized_anchor_digests:
        raise LogicalValidationError(
            f"{label} is an unauthorized empty-signature synthetic QC"
        )


def validate_qc_certifies_header(
    qc: dict[str, object],
    header: dict[str, object],
    *,
    authorized_anchor_digests: set[bytes],
    label: str,
) -> None:
    validate_qc(
        qc,
        authorized_anchor_digests=authorized_anchor_digests,
        label=label,
    )
    expected = (
        header["genesis_hash"],
        header["chain_id"],
        header["protocol_version"],
        header["epoch"],
        header["active_validator_set_hash"],
        header["view"],
        header["height"],
        block_id(header),
    )
    actual = (
        qc["genesis_hash"],
        qc["chain_id"],
        qc["protocol_version"],
        qc["epoch"],
        qc["validator_set_hash"],
        qc["view"],
        qc["height"],
        qc["block_id"],
    )
    if actual != expected:
        raise LogicalValidationError(f"{label} does not certify its exact header")


def validate_tc(
    tc: dict[str, object],
    *,
    authorized_anchor_digests: set[bytes],
    label: str,
) -> None:
    if tc["schema_version"] != 0:
        raise LogicalValidationError(f"{label} schema_version is not 0")
    encode_tc(tc)
    require_strict_ids(tc["entries"], "signer_id", f"{label} entries")

    referenced = tc["referenced_qcs"]
    referenced_digests = [qc_digest(qc) for qc in referenced]
    if any(
        left >= right
        for left, right in zip(referenced_digests, referenced_digests[1:])
    ):
        raise LogicalValidationError(
            f"{label} referenced_qcs are not strictly digest-ordered and unique"
        )
    if not referenced:
        raise LogicalValidationError(f"{label} has no referenced QC")

    by_digest: dict[bytes, dict[str, object]] = {}
    by_epoch_view: dict[tuple[int, int], bytes] = {}
    tc_scope = (
        tc["genesis_hash"],
        tc["chain_id"],
        tc["protocol_version"],
        tc["epoch"],
        tc["validator_set_hash"],
    )
    for index, qc in enumerate(referenced):
        validate_qc(
            qc,
            authorized_anchor_digests=authorized_anchor_digests,
            label=f"{label} referenced_qcs[{index}]",
        )
        qc_scope = (
            qc["genesis_hash"],
            qc["chain_id"],
            qc["protocol_version"],
            qc["epoch"],
            qc["validator_set_hash"],
        )
        if qc_scope != tc_scope:
            raise LogicalValidationError(f"{label} referenced QC scope mismatch")
        key = (qc["epoch"], qc["view"])
        previous_block = by_epoch_view.get(key)
        if previous_block is not None and previous_block != qc["block_id"]:
            raise LogicalValidationError(
                f"{label} has same-view QCs for different blocks"
            )
        by_epoch_view[key] = qc["block_id"]
        by_digest[qc_digest(qc)] = qc

    counted: dict[bytes, dict[str, object]] = {}
    for index, entry in enumerate(tc["entries"]):
        summary = entry["high_qc"]
        candidate = by_digest.get(summary["qc_digest"])
        if candidate is None or summary != high_qc_summary(candidate):
            raise LogicalValidationError(
                f"{label} entries[{index}] does not match an exact referenced QC"
            )
        counted[summary["qc_digest"]] = candidate
    if not counted:
        raise LogicalValidationError(f"{label} has no counted high QC")

    selected = max(
        counted.items(),
        key=lambda item: (item[1]["view"], item[1]["block_id"], item[0]),
    )[0]
    if tc["selected_high_qc_digest"] != selected:
        raise LogicalValidationError(
            f"{label} selected_high_qc_digest is not the deterministic maximum"
        )


def validate_handoff_certificate(
    certificate: dict[str, object], *, label: str
) -> None:
    if certificate["schema_version"] != 0:
        raise LogicalValidationError(f"{label} schema_version is not 0")
    encode_handoff_certificate(certificate)
    require_strict_ids(
        certificate["old_signatures"],
        "validator_id",
        f"{label} old_signatures",
    )
    require_strict_ids(
        certificate["new_signatures"],
        "validator_id",
        f"{label} new_signatures",
    )
    if not certificate["old_signatures"] or not certificate["new_signatures"]:
        raise LogicalValidationError(f"{label} omits one handoff signer role")


def validate_epoch_anchor_authorization(
    authorization: dict[str, object], *, label: str
) -> tuple[dict[str, object], bytes]:
    terminal_header = authorization["terminal_old_header"]
    terminal_qc = authorization["terminal_old_qc"]
    certificate = authorization["handoff_certificate"]
    descriptor = certificate["descriptor"]

    validate_handoff_certificate(certificate, label=f"{label} handoff_certificate")
    validate_qc_certifies_header(
        terminal_qc,
        terminal_header,
        authorized_anchor_digests=set(),
        label=f"{label} terminal_old_qc",
    )
    if descriptor["schema_version"] != 0:
        raise LogicalValidationError(f"{label} descriptor schema_version is not 0")
    encode_handoff_descriptor(descriptor)
    if descriptor["new_epoch"] != descriptor["old_epoch"] + 1:
        raise LogicalValidationError(f"{label} descriptor epochs are not adjacent")
    if descriptor["initial_new_view"] != 1:
        raise LogicalValidationError(f"{label} descriptor initial_new_view is not 1")
    if descriptor["activation_height"] != descriptor["terminal_old_height"] + 1:
        raise LogicalValidationError(
            f"{label} descriptor activation does not follow the terminal block"
        )

    terminal_expected = (
        descriptor["genesis_hash"],
        descriptor["chain_id"],
        descriptor["old_protocol_version"],
        descriptor["old_epoch"],
        descriptor["old_validator_set_hash"],
        descriptor["old_consensus_parameters_hash"],
        descriptor["terminal_old_view"],
        descriptor["terminal_old_height"],
        descriptor["terminal_old_block_id"],
        descriptor["terminal_old_qc_digest"],
        descriptor["checkpoint_state_root"],
        descriptor["next_epoch_commitment_digest"],
    )
    terminal_actual = (
        terminal_header["genesis_hash"],
        terminal_header["chain_id"],
        terminal_header["protocol_version"],
        terminal_header["epoch"],
        terminal_header["active_validator_set_hash"],
        terminal_header["consensus_parameters_hash"],
        terminal_header["view"],
        terminal_header["height"],
        block_id(terminal_header),
        qc_digest(terminal_qc),
        terminal_header["state_root"],
        terminal_header["next_epoch_commitment_hash"],
    )
    if terminal_actual != terminal_expected:
        raise LogicalValidationError(
            f"{label} terminal header/QC does not match the descriptor"
        )
    if terminal_header["block_kind"] != 3:
        raise LogicalValidationError(f"{label} terminal block is not epoch_seal_2")

    anchor = make_qc(
        genesis_hash=descriptor["genesis_hash"],
        chain_id=descriptor["chain_id"],
        protocol_version=descriptor["new_protocol_version"],
        epoch=descriptor["new_epoch"],
        validator_set_hash=descriptor["new_validator_set_hash"],
        view=0,
        height=descriptor["terminal_old_height"],
        certified_block_id=descriptor["terminal_old_block_id"],
        signer_ids=(),
    )
    return anchor, handoff_certificate_digest(certificate)


def validate_certified_header(
    certified: dict[str, object],
    *,
    label: str,
    authorized_anchor_digests: set[bytes],
    previous: dict[str, object] | None,
) -> None:
    header = certified["header"]
    encode_block_header(header)
    fixed(certified["proposer_signature"], 64, f"{label} proposer_signature")
    validate_qc_certifies_header(
        certified["certifying_qc"],
        header,
        authorized_anchor_digests=authorized_anchor_digests,
        label=f"{label} certifying_qc",
    )
    validate_qc(
        certified["justify_qc"],
        authorized_anchor_digests=authorized_anchor_digests,
        label=f"{label} justify_qc",
    )

    justify = certified["justify_qc"]
    authorization = certified["epoch_anchor_authorization"]
    if previous is not None:
        previous_qc_digest = qc_digest(previous["certifying_qc"])
        if qc_digest(justify) != previous_qc_digest:
            raise LogicalValidationError(
                f"{label} justify_qc digest does not equal "
                f"{('finalized_block' if label == 'child' else 'child')} "
                "certifying_qc digest"
            )
        if header["parent_block_id"] != block_id(previous["header"]):
            raise LogicalValidationError(f"{label} parent is not the previous header")
        if header["height"] != previous["header"]["height"] + 1:
            raise LogicalValidationError(f"{label} height is not consecutive")

    if authorization is not None:
        anchor, _ = validate_epoch_anchor_authorization(
            authorization, label=f"{label} epoch_anchor_authorization"
        )
        descriptor = authorization["handoff_certificate"]["descriptor"]
        if encode_qc(justify) != encode_qc(anchor):
            raise LogicalValidationError(
                f"{label} justify_qc is not the exact authorized EpochAnchorQC"
            )
        expected_first = (
            descriptor["genesis_hash"],
            descriptor["chain_id"],
            descriptor["new_protocol_version"],
            descriptor["new_epoch"],
            descriptor["new_validator_set_hash"],
            descriptor["new_consensus_parameters_hash"],
            descriptor["activation_height"],
            descriptor["terminal_old_block_id"],
            4,
        )
        actual_first = (
            header["genesis_hash"],
            header["chain_id"],
            header["protocol_version"],
            header["epoch"],
            header["active_validator_set_hash"],
            header["consensus_parameters_hash"],
            header["height"],
            header["parent_block_id"],
            header["block_kind"],
        )
        if actual_first != expected_first:
            raise LogicalValidationError(
                f"{label} is not the descriptor-authorized first epoch block"
            )
    else:
        if not justify["signatures"]:
            raise LogicalValidationError(
                f"{label} uses a synthetic QC without anchor authorization"
            )
        ordinary_scope = (
            header["genesis_hash"],
            header["chain_id"],
            header["protocol_version"],
            header["epoch"],
            header["active_validator_set_hash"],
            header["height"] - 1,
            header["parent_block_id"],
        )
        justify_scope = (
            justify["genesis_hash"],
            justify["chain_id"],
            justify["protocol_version"],
            justify["epoch"],
            justify["validator_set_hash"],
            justify["height"],
            justify["block_id"],
        )
        if justify_scope != ordinary_scope:
            raise LogicalValidationError(
                f"{label} justify_qc does not certify the exact parent"
            )

    if header["view"] <= justify["view"]:
        raise LogicalValidationError(f"{label} view does not exceed justify view")
    timeout_certificate = certified["timeout_certificate"]
    if timeout_certificate is None:
        if header["view"] != justify["view"] + 1:
            raise LogicalValidationError(f"{label} skips a view without a TC")
    else:
        validate_tc(
            timeout_certificate,
            authorized_anchor_digests=authorized_anchor_digests,
            label=f"{label} timeout_certificate",
        )
        if timeout_certificate["timed_out_view"] != header["view"] - 1:
            raise LogicalValidationError(
                f"{label} timeout_certificate is not for proposal.view - 1"
            )
        if timeout_certificate["selected_high_qc_digest"] != qc_digest(justify):
            raise LogicalValidationError(
                f"{label} timeout_certificate does not select the exact justify_qc"
            )

    proposal_for_certified_header(certified)
    encode_certified_header(certified)


def validate_finality_proof(proof: dict[str, object]) -> None:
    if proof["schema_version"] != 0:
        raise LogicalValidationError("finality proof schema_version is not 0")
    finalized = proof["finalized_block"]
    child = proof["child"]
    grandchild = proof["grandchild"]
    authorization = finalized["epoch_anchor_authorization"]
    if authorization is None:
        raise LogicalValidationError(
            "fixture finalized_block is missing epoch-anchor authorization"
        )
    anchor, _ = validate_epoch_anchor_authorization(
        authorization, label="finalized_block epoch_anchor_authorization"
    )
    anchors = {qc_digest(anchor)}

    validate_certified_header(
        finalized,
        label="finalized_block",
        authorized_anchor_digests=anchors,
        previous=None,
    )
    validate_certified_header(
        child,
        label="child",
        authorized_anchor_digests=anchors,
        previous=finalized,
    )
    validate_certified_header(
        grandchild,
        label="grandchild",
        authorized_anchor_digests=anchors,
        previous=child,
    )

    expected_scope = (
        proof["genesis_hash"],
        proof["chain_id"],
        proof["protocol_version"],
        proof["epoch"],
        proof["validator_set_hash"],
        proof["consensus_parameters_hash"],
    )
    for label, certified in (
        ("finalized_block", finalized),
        ("child", child),
        ("grandchild", grandchild),
    ):
        header = certified["header"]
        actual_scope = (
            header["genesis_hash"],
            header["chain_id"],
            header["protocol_version"],
            header["epoch"],
            header["active_validator_set_hash"],
            header["consensus_parameters_hash"],
        )
        if actual_scope != expected_scope:
            raise LogicalValidationError(f"{label} proof scope mismatch")

    qc_views = tuple(
        item["certifying_qc"]["view"]
        for item in (finalized, child, grandchild)
    )
    if not qc_views[0] < qc_views[1] < qc_views[2]:
        raise LogicalValidationError("certifying QC views are not increasing")
    if child["epoch_anchor_authorization"] is not None:
        raise LogicalValidationError("child repeats epoch-anchor authorization")
    if grandchild["epoch_anchor_authorization"] is not None:
        raise LogicalValidationError("grandchild repeats epoch-anchor authorization")
    encode_finality_proof(proof)


def validate_genesis_skipped_proposal(
    *,
    header: dict[str, object],
    genesis_qc: dict[str, object],
    timeout_certificate: dict[str, object],
    proposal: dict[str, object],
) -> None:
    expected_genesis_qc = make_qc(
        genesis_hash=header["genesis_hash"],
        chain_id=header["chain_id"],
        protocol_version=header["protocol_version"],
        epoch=0,
        validator_set_hash=header["active_validator_set_hash"],
        view=0,
        height=0,
        certified_block_id=header["genesis_hash"],
        signer_ids=(),
    )
    if encode_qc(genesis_qc) != encode_qc(expected_genesis_qc):
        raise LogicalValidationError("GenesisQC is not the exact trusted preimage")
    if header["epoch"] != 0 or header["height"] != 1:
        raise LogicalValidationError("genesis first block has the wrong epoch/height")
    if header["view"] <= 1:
        raise LogicalValidationError("genesis skipped-view fixture does not skip view 1")
    if header["parent_block_id"] != header["genesis_hash"]:
        raise LogicalValidationError("genesis first block does not extend genesis_hash")
    genesis_digest = qc_digest(genesis_qc)
    validate_tc(
        timeout_certificate,
        authorized_anchor_digests={genesis_digest},
        label="genesis timeout_certificate",
    )
    if timeout_certificate["timed_out_view"] != header["view"] - 1:
        raise LogicalValidationError("genesis TC is not for proposal.view - 1")
    if timeout_certificate["selected_high_qc_digest"] != genesis_digest:
        raise LogicalValidationError("genesis TC does not select GenesisQC")

    expected_proposal = {
        "context": {
            "schema_version": 0,
            "genesis_hash": header["genesis_hash"],
            "chain_id": header["chain_id"],
            "protocol_version": header["protocol_version"],
            "epoch": 0,
            "validator_set_hash": header["active_validator_set_hash"],
            "view": header["view"],
            "message_kind": 0,
        },
        "height": 1,
        "block_id": block_id(header),
        "justify_qc_digest": genesis_digest,
        "timeout_certificate_digest": tc_digest(timeout_certificate),
        "handoff_certificate_digest": None,
    }
    if encode_proposal_sign(proposal) != encode_proposal_sign(expected_proposal):
        raise LogicalValidationError(
            "genesis ProposalSignV0 does not bind the exact GenesisQC and TC"
        )


def build_fixture() -> dict[str, object]:
    chain_id = "trnm-anchor-0"
    genesis_hash = fixture_hash("genesis")
    old_set_hash = fixture_hash("old-validator-set")
    new_set_hash = fixture_hash("new-validator-set")
    old_parameters_hash = fixture_hash("old-parameters")
    new_parameters_hash = fixture_hash("new-parameters")
    checkpoint_state_root = fixture_hash("checkpoint-state")
    next_epoch_commitment_digest = fixture_hash("next-epoch-commitment")
    base_timestamp = 1_800_000_000_000

    old_signers = (b"old-a", b"old-b", b"old-c")
    new_signers = (b"new-a", b"new-b", b"new-c")

    genesis_qc = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=0,
        validator_set_hash=old_set_hash,
        view=0,
        height=0,
        certified_block_id=genesis_hash,
        signer_ids=(),
    )
    genesis_header = make_header(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=0,
        view=3,
        height=1,
        block_kind=0,
        parent_block_id=genesis_hash,
        proposer_id=b"old-c",
        validator_set_hash=old_set_hash,
        parameters_hash=old_parameters_hash,
        label="genesis-first-view-3",
        timestamp_ms=base_timestamp,
    )
    genesis_tc = make_tc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=0,
        validator_set_hash=old_set_hash,
        timed_out_view=2,
        high_qc=genesis_qc,
        signer_ids=old_signers,
    )
    genesis_proposal = {
        "context": {
            "schema_version": 0,
            "genesis_hash": genesis_hash,
            "chain_id": chain_id,
            "protocol_version": 0,
            "epoch": 0,
            "validator_set_hash": old_set_hash,
            "view": 3,
            "message_kind": 0,
        },
        "height": 1,
        "block_id": block_id(genesis_header),
        "justify_qc_digest": qc_digest(genesis_qc),
        "timeout_certificate_digest": tc_digest(genesis_tc),
        "handoff_certificate_digest": None,
    }

    terminal_header = make_header(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=0,
        view=12,
        height=10,
        block_kind=3,
        parent_block_id=fixture_hash("old-seal-1-block"),
        proposer_id=b"old-d",
        validator_set_hash=old_set_hash,
        parameters_hash=old_parameters_hash,
        label="terminal-old-seal-2",
        state_root=checkpoint_state_root,
        timestamp_ms=base_timestamp + 10_000,
        next_epoch_commitment_hash=next_epoch_commitment_digest,
    )
    terminal_qc = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=0,
        validator_set_hash=old_set_hash,
        view=12,
        height=10,
        certified_block_id=block_id(terminal_header),
        signer_ids=old_signers,
    )
    descriptor = {
        "schema_version": 0,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "old_epoch": 0,
        "new_epoch": 1,
        "old_protocol_version": 0,
        "new_protocol_version": 0,
        "old_validator_set_hash": old_set_hash,
        "new_validator_set_hash": new_set_hash,
        "old_consensus_parameters_hash": old_parameters_hash,
        "new_consensus_parameters_hash": new_parameters_hash,
        "checkpoint_height": 8,
        "checkpoint_block_id": fixture_hash("old-checkpoint-block"),
        "checkpoint_state_root": checkpoint_state_root,
        "next_epoch_commitment_digest": next_epoch_commitment_digest,
        "terminal_old_height": 10,
        "terminal_old_block_id": block_id(terminal_header),
        "terminal_old_qc_digest": qc_digest(terminal_qc),
        "terminal_old_view": 12,
        "activation_height": 11,
        "initial_new_view": 1,
    }
    handoff_certificate = {
        "schema_version": 0,
        "descriptor": descriptor,
        "old_signatures": shares(old_signers),
        "new_signatures": shares(new_signers),
    }
    authorization = {
        "terminal_old_header": terminal_header,
        "terminal_old_qc": terminal_qc,
        "handoff_certificate": handoff_certificate,
    }
    epoch_anchor_qc = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        view=0,
        height=10,
        certified_block_id=block_id(terminal_header),
        signer_ids=(),
    )
    first_epoch_tc = make_tc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        timed_out_view=1,
        high_qc=epoch_anchor_qc,
        signer_ids=new_signers,
    )

    finalized_header = make_header(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        view=2,
        height=11,
        block_kind=4,
        parent_block_id=block_id(terminal_header),
        proposer_id=b"new-b",
        validator_set_hash=new_set_hash,
        parameters_hash=new_parameters_hash,
        label="new-epoch-first-view-2",
        timestamp_ms=base_timestamp + 11_000,
    )
    q0 = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        view=2,
        height=11,
        certified_block_id=block_id(finalized_header),
        signer_ids=new_signers,
    )
    q0_alternate_subset = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        view=2,
        height=11,
        certified_block_id=block_id(finalized_header),
        signer_ids=(b"new-b", b"new-c", b"new-d"),
    )
    finalized = {
        "header": finalized_header,
        "justify_qc": epoch_anchor_qc,
        "timeout_certificate": first_epoch_tc,
        "epoch_anchor_authorization": authorization,
        "proposer_signature": FIXED_SIGNATURE64,
        "certifying_qc": q0,
    }

    child_header = make_header(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        view=4,
        height=12,
        block_kind=0,
        parent_block_id=block_id(finalized_header),
        proposer_id=b"new-d",
        validator_set_hash=new_set_hash,
        parameters_hash=new_parameters_hash,
        label="finality-child-view-4",
        timestamp_ms=base_timestamp + 12_000,
    )
    child_tc = make_tc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        timed_out_view=3,
        high_qc=q0,
        signer_ids=new_signers,
    )
    q1 = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        view=4,
        height=12,
        certified_block_id=block_id(child_header),
        signer_ids=new_signers,
    )
    child = {
        "header": child_header,
        "justify_qc": q0,
        "timeout_certificate": child_tc,
        "epoch_anchor_authorization": None,
        "proposer_signature": FIXED_SIGNATURE64,
        "certifying_qc": q1,
    }

    grandchild_header = make_header(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        view=5,
        height=13,
        block_kind=0,
        parent_block_id=block_id(child_header),
        proposer_id=b"new-a",
        validator_set_hash=new_set_hash,
        parameters_hash=new_parameters_hash,
        label="finality-grandchild-view-5",
        timestamp_ms=base_timestamp + 13_000,
    )
    q2 = make_qc(
        genesis_hash=genesis_hash,
        chain_id=chain_id,
        protocol_version=0,
        epoch=1,
        validator_set_hash=new_set_hash,
        view=5,
        height=13,
        certified_block_id=block_id(grandchild_header),
        signer_ids=new_signers,
    )
    grandchild = {
        "header": grandchild_header,
        "justify_qc": q1,
        "timeout_certificate": None,
        "epoch_anchor_authorization": None,
        "proposer_signature": FIXED_SIGNATURE64,
        "certifying_qc": q2,
    }
    proof = {
        "schema_version": 0,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "protocol_version": 0,
        "epoch": 1,
        "validator_set_hash": new_set_hash,
        "consensus_parameters_hash": new_parameters_hash,
        "finalized_block": finalized,
        "child": child,
        "grandchild": grandchild,
    }

    return {
        "genesis_qc": genesis_qc,
        "genesis_header": genesis_header,
        "genesis_tc": genesis_tc,
        "genesis_proposal": genesis_proposal,
        "descriptor": descriptor,
        "handoff_certificate": handoff_certificate,
        "authorization": authorization,
        "epoch_anchor_qc": epoch_anchor_qc,
        "proof": proof,
        "q0_alternate_subset": q0_alternate_subset,
    }


def artifact(encoded: bytes, *, domain: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "cev0_hex": encoded.hex(),
        "length": len(encoded),
    }
    if domain is not None:
        result["digest_hex"] = digest(domain, encoded).hex()
        result["digest_domain"] = domain
    return result


def certified_header_artifact(certified: dict[str, object]) -> dict[str, object]:
    proposal = proposal_for_certified_header(certified)
    timeout_certificate = certified["timeout_certificate"]
    authorization = certified["epoch_anchor_authorization"]
    result = artifact(encode_certified_header(certified))
    result.update(
        {
            "block_id_hex": block_id(certified["header"]).hex(),
            "justify_qc_digest_hex": qc_digest(certified["justify_qc"]).hex(),
            "timeout_certificate_present": timeout_certificate is not None,
            "timeout_certificate_digest_hex": (
                None
                if timeout_certificate is None
                else tc_digest(timeout_certificate).hex()
            ),
            "epoch_anchor_authorization_present": authorization is not None,
            "handoff_certificate_digest_hex": (
                None
                if authorization is None
                else handoff_certificate_digest(
                    authorization["handoff_certificate"]
                ).hex()
            ),
            "proposal_signing_root_hex": proposal_signing_root(proposal).hex(),
            "certifying_qc_digest_hex": qc_digest(
                certified["certifying_qc"]
            ).hex(),
        }
    )
    return result


def rejected_mutations(fixture: dict[str, object]) -> list[dict[str, object]]:
    proof = fixture["proof"]
    alternate_qc = fixture["q0_alternate_subset"]
    cases: list[tuple[str, dict[str, object], str, dict[str, object]]] = []

    replaced = copy.deepcopy(proof)
    replaced["child"]["justify_qc"] = copy.deepcopy(alternate_qc)
    cases.append(
        (
            "replace_child_justify_qc_signer_subset",
            replaced,
            "child justify_qc digest does not equal finalized_block "
            "certifying_qc digest",
            {
                "original_qc_digest_hex": qc_digest(
                    proof["finalized_block"]["certifying_qc"]
                ).hex(),
                "replacement_qc_digest_hex": qc_digest(alternate_qc).hex(),
            },
        )
    )

    missing_signature = copy.deepcopy(proof)
    missing_signature["child"]["proposer_signature"] = b""
    cases.append(
        (
            "delete_child_proposer_signature",
            missing_signature,
            "child proposer_signature must contain exactly 64 bytes",
            {"mutated_length": 0},
        )
    )

    wrong_selected = copy.deepcopy(proof)
    mutated_selected = fixture_hash("mutated-selected-high-qc")
    wrong_selected["child"]["timeout_certificate"][
        "selected_high_qc_digest"
    ] = mutated_selected
    cases.append(
        (
            "mismatch_child_tc_selected_high_qc_digest",
            wrong_selected,
            "child timeout_certificate selected_high_qc_digest is not the "
            "deterministic maximum",
            {
                "expected_selected_digest_hex": qc_digest(
                    proof["finalized_block"]["certifying_qc"]
                ).hex(),
                "mutated_selected_digest_hex": mutated_selected.hex(),
            },
        )
    )

    results = []
    for name, mutated_proof, expected_error, metadata in cases:
        try:
            validate_finality_proof(mutated_proof)
        except LogicalValidationError as error:
            if str(error) != expected_error:
                raise VectorError(
                    f"mutation {name} failed for the wrong reason: {error}"
                ) from error
        else:
            raise VectorError(f"mutation {name} was accepted")
        results.append(
            {
                "name": name,
                "accepted_by_relational_validator": False,
                "expected_error": expected_error,
                **metadata,
            }
        )
    return results


def build_vectors() -> dict[str, object]:
    fixture = build_fixture()
    validate_genesis_skipped_proposal(
        header=fixture["genesis_header"],
        genesis_qc=fixture["genesis_qc"],
        timeout_certificate=fixture["genesis_tc"],
        proposal=fixture["genesis_proposal"],
    )
    validate_finality_proof(fixture["proof"])
    mutations = rejected_mutations(fixture)

    genesis_qc = fixture["genesis_qc"]
    genesis_tc = fixture["genesis_tc"]
    genesis_proposal = fixture["genesis_proposal"]
    descriptor = fixture["descriptor"]
    handoff_certificate = fixture["handoff_certificate"]
    authorization = fixture["authorization"]
    epoch_anchor_qc = fixture["epoch_anchor_qc"]
    proof = fixture["proof"]

    genesis_proposal_artifact = artifact(encode_proposal_sign(genesis_proposal))
    genesis_proposal_artifact.update(
        {
            "block_view": fixture["genesis_header"]["view"],
            "justify_qc_digest_hex": qc_digest(genesis_qc).hex(),
            "timeout_certificate_digest_hex": tc_digest(genesis_tc).hex(),
            "handoff_certificate_digest_hex": None,
            "signing_root_hex": proposal_signing_root(genesis_proposal).hex(),
        }
    )

    finality_artifact = artifact(
        encode_finality_proof(proof), domain=FINALITY_PROOF_DOMAIN
    )
    finality_artifact["finalized_block_id_hex"] = block_id(
        proof["finalized_block"]["header"]
    ).hex()

    return {
        "schema": "trnm_poco_bft_anchor_finality_vectors_v0",
        "protocol_version": 0,
        "canonical_codec": "CEV0",
        "hash_algorithm": "sha256",
        "hash_prefix_ascii": HASH_PREFIX.decode("ascii"),
        "scope": (
            "Independent canonical-encoding, digest, and relational-validation "
            "vectors for trusted anchors, handoff nesting, and one epoch-local "
            "three-certified-header finality proof."
        ),
        "signature_fixture": {
            "signature64_hex": FIXED_SIGNATURE64.hex(),
            "source": "vectors/ed25519-v0.json valid.signature_hex",
            "cryptographic_validity_claimed_for_composite_objects": False,
            "note": (
                "The bytes are reused only as an opaque fixed-width "
                "Signature64 fixture; this standard-library checker does not "
                "verify Ed25519 signatures or quorum weight."
            ),
        },
        "validation_profile": {
            "checks": [
                "exact frozen field order and CEV0 widths",
                "domain-separated SHA-256 digests",
                "strict signer and referenced-QC ordering",
                "authorized empty-signature GenesisQC and EpochAnchorQC shape",
                "TC referenced-QC summaries and deterministic selection",
                "epoch-anchor authorization/descriptor/terminal-QC linkage",
                "full CertifiedHeader proposal/justify/TC/authorization nesting",
                "three-chain parent, height, view, and exact QC-digest linkage",
            ],
            "does_not_check": [
                "Ed25519 signature validity",
                "validator membership or weighted quorum thresholds",
                "checkpoint/two-seal finality or checkpoint ancestry",
                "NextEpochCommitment reconstruction and committed set/parameter preimages",
                "complete handoff authorization, upgrade governance, or activation policy",
                "payload execution or application-state validity",
            ],
        },
        "vectors": {
            "genesis_qc": artifact(encode_qc(genesis_qc), domain=QC_DOMAIN),
            "genesis_view_3_timeout_certificate": artifact(
                encode_tc(genesis_tc), domain=TC_DOMAIN
            ),
            "genesis_view_3_proposal_sign": genesis_proposal_artifact,
            "handoff_descriptor": artifact(
                encode_handoff_descriptor(descriptor),
                domain=HANDOFF_DESCRIPTOR_DOMAIN,
            ),
            "handoff_certificate": artifact(
                encode_handoff_certificate(handoff_certificate),
                domain=HANDOFF_CERTIFICATE_DOMAIN,
            ),
            "epoch_anchor_authorization": {
                **artifact(encode_epoch_anchor_authorization(authorization)),
                "independent_digest_domain": None,
                "note": "Nested logical value; the frozen spec assigns no independent domain.",
            },
            "epoch_anchor_qc": artifact(
                encode_qc(epoch_anchor_qc), domain=QC_DOMAIN
            ),
            "certified_headers": {
                "finalized_block": certified_header_artifact(
                    proof["finalized_block"]
                ),
                "child": certified_header_artifact(proof["child"]),
                "grandchild": certified_header_artifact(proof["grandchild"]),
            },
            "finality_proof": finality_artifact,
        },
        "invalid_mutations": mutations,
    }


def verify_signature_fixture_source() -> None:
    try:
        with ED25519_VECTOR.open("r", encoding="utf-8") as source:
            ed25519_vector = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise VectorError(f"Ed25519 fixture source could not be loaded: {error}")
    source_hex = ed25519_vector.get("valid", {}).get("signature_hex")
    if source_hex != FIXED_SIGNATURE64.hex():
        raise VectorError(
            "fixed Signature64 no longer matches ed25519-v0.json valid.signature_hex"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--print-expected",
        action="store_true",
        help="print the independently reconstructed JSON",
    )
    args = parser.parse_args()

    try:
        verify_signature_fixture_source()
        expected = build_vectors()
    except (LogicalValidationError, VectorError) as error:
        print(f"anchor/finality vector construction failed: {error}", file=sys.stderr)
        return 1

    if args.print_expected:
        print(json.dumps(expected, indent=2, sort_keys=True))
        return 0

    try:
        with args.vector.open("r", encoding="utf-8") as source:
            committed = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        print(f"anchor/finality vector could not be loaded: {error}", file=sys.stderr)
        return 1

    if committed != expected:
        print(
            "committed anchor/finality vector differs from independent "
            "reconstruction; run with --print-expected and review the "
            "protocol change",
            file=sys.stderr,
        )
        return 1

    proof = expected["vectors"]["finality_proof"]
    print(
        "[ok] PoCO-BFT v0 anchor/finality vectors: "
        f"proof={proof['digest_hex']} mutations=3 "
        "(composite signature validity not claimed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
