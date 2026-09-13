#!/usr/bin/env python3
"""Bounded cross-version carrier for one v0 -> v1 activation finality proof.

This checker deliberately does not reinterpret frozen-v0 EpochHandoffProof
field 13 or 14 as CEV1.  It exact-decodes field 12 as UpgradePlanV0, requires
the two v0-only target fields to be absent, and then verifies a separately
versioned CEV1 carrier containing a signed V0ActivationFirst proposal witness
and its three-QC finality proof.

The carrier is candidate evidence, not production wire authority.  In
particular it does not prove governance-state membership or execute migration.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any, Callable, NoReturn


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-cross-version-activation-proof-kernel-v1.json"
VECTOR_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-cross-version-activation-proof-kernel-v1.json"
SOURCE_VECTOR_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/v0-to-v1-activation-kernel-v1.json"
SOURCE_CHECKER_PATH = ROOT / "scripts/ci/check_poco_ai_native_v1_upgrade_kernel.py"
SOURCE_SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/v0-to-v1-activation-kernel-v1.json"

SOURCE_PATHS = (SOURCE_SCHEMA_PATH, SOURCE_VECTOR_PATH, SOURCE_CHECKER_PATH)

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)
U64_MAX = 2**64 - 1
STRICT_ED25519 = 0

V0_PLAN_DOMAIN = "trnm.poco-bft.upgrade-plan.v0"
BLOCK_DOMAIN = "trnm.poco-ai.order-block.v1"
VOTE_DOMAIN = "trnm.poco-ai.order-vote-signature.v1"
QC_DOMAIN = "trnm.poco-ai.order-qc.v1"
PROPOSAL_DOMAIN = "trnm.poco-ai.v0-activation-first-proposal-carrier.v1"
PROPOSAL_SIGNATURE_DOMAIN = "trnm.poco-ai.v0-activation-first-proposal-carrier-signature.v1"
FINALITY_DOMAIN = "trnm.poco-ai.v0-activation-order-finality-proof.v1"
ACTIVATION_PROOF_DOMAIN = "trnm.poco-ai.v0-to-v1-activation-proof.v1"


class EvidenceError(Exception):
    """Expected fail-closed parser, relation, or crypto rejection."""


def reject(code: str, detail: str = "") -> NoReturn:
    raise EvidenceError(code if not detail else f"{code}: {detail}")


def require(condition: bool, code: str, detail: str = "") -> None:
    if not condition:
        reject(code, detail)


def exact_keys(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    require(isinstance(value, dict), code)
    require(set(value) == keys, code, f"missing={sorted(keys-set(value))} extra={sorted(set(value)-keys)}")
    return value


def raw_json_sha256(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).digest()


def digest_v0(domain: str, encoded: bytes) -> bytes:
    frame = lambda raw: len(raw).to_bytes(4, "big") + raw
    return hashlib.sha256(frame(b"trnm.cev0.hash.v0") + frame(domain.encode("ascii")) + frame(encoded)).digest()


def digest_v1(domain: str, encoded: bytes) -> bytes:
    raw_domain = domain.encode("ascii")
    return hashlib.sha256(len(raw_domain).to_bytes(4, "little") + raw_domain + encoded).digest()


def point_inv(value: int) -> int:
    return pow(value % P, P - 2, P)


def recover_x(y: int) -> int:
    square = ((y * y - 1) * point_inv(D * y * y + 1)) % P
    x = pow(square, (P + 3) // 8, P)
    if (x * x - square) % P:
        x = (x * SQRT_M1) % P
    require((x * x - square) % P == 0, "ed25519_point")
    return P - x if x & 1 else x


BASE_Y = (4 * point_inv(5)) % P
BASE_X = recover_x(BASE_Y)
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)


def point_add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = ((y1 - x1) * (y2 - x2)) % P
    bb = ((y1 + x1) * (y2 + x2)) % P
    cc = 2 * D * t1 * t2 % P
    dd = 2 * z1 * z2 % P
    ee, ff, gg, hh = (bb - aa) % P, (dd - cc) % P, (dd + cc) % P, (bb + aa) % P
    return ee * ff % P, gg * hh % P, ff * gg % P, ee * hh % P


def point_mul(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result, current = IDENTITY, point
    while scalar:
        if scalar & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        scalar >>= 1
    return result


def point_eq(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def encode_point(point: tuple[int, int, int, int]) -> bytes:
    z_inv = point_inv(point[2])
    x, y = point[0] * z_inv % P, point[1] * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_point(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    encoded = int.from_bytes(raw, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= P:
        return None
    try:
        x = recover_x(y)
    except EvidenceError:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = P - x
    return x, y, 1, x * y % P


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded[:32], "little"), bytes(expanded[32:])


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = secret_scalar(seed)
    return encode_point(point_mul(BASE, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = secret_scalar(seed)
    public = ed25519_public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    encoded_r = encode_point(point_mul(BASE, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    return encoded_r + ((nonce + challenge * scalar) % L).to_bytes(32, "little")


def ed25519_verify(message: bytes, public_key: bytes, signature: bytes) -> bool:
    if len(message) != 32 or len(public_key) != 32 or len(signature) != 64:
        return False
    public, r_point = decode_point(public_key), decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if public is None or r_point is None or scalar >= L:
        return False
    if point_eq(point_mul(public, 8), IDENTITY) or point_eq(point_mul(r_point, 8), IDENTITY):
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return point_eq(point_mul(BASE, scalar), point_add(r_point, point_mul(public, challenge)))


def fixture_seed(index: int) -> bytes:
    require(0 <= index < 8, "fixture_seed")
    return bytes((index + offset) & 0xFF for offset in range(32))


class Cursor:
    def __init__(self, raw: bytes, endian: str):
        self.raw, self.at, self.endian = raw, 0, endian

    def take(self, size: int, code: str = "truncated") -> bytes:
        require(size >= 0 and self.at + size <= len(self.raw), code)
        result = self.raw[self.at:self.at + size]
        self.at += size
        return result

    def uint(self, bits: int) -> int:
        return int.from_bytes(self.take(bits // 8), self.endian)

    def bytes(self, maximum: int = 16 * 1024 * 1024) -> bytes:
        size = self.uint(32)
        require(size <= maximum, "bytes_bound")
        return self.take(size)

    def string(self, length_bits: int, maximum: int = 4096) -> str:
        size = self.uint(length_bits)
        require(size <= maximum, "string_bound")
        raw = self.take(size)
        try:
            return raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            reject("string")

    def hash32(self) -> bytes:
        return self.take(32)

    def option_hash(self) -> bytes | None:
        tag = self.uint(8)
        require(tag in (0, 1), "option_tag")
        return None if tag == 0 else self.hash32()

    def finish(self) -> None:
        require(self.at == len(self.raw), "trailing")


def be_u(value: int, bits: int) -> bytes:
    require(type(value) is int and 0 <= value < 2**bits, "integer")
    return value.to_bytes(bits // 8, "big")


def le_u(value: int, bits: int) -> bytes:
    require(type(value) is int and 0 <= value < 2**bits, "integer")
    return value.to_bytes(bits // 8, "little")


def fixed(value: bytes, size: int, code: str = "fixed") -> bytes:
    require(isinstance(value, bytes) and len(value) == size, code)
    return value


def le_bytes(value: bytes) -> bytes:
    require(isinstance(value, bytes) and len(value) < 2**32, "bytes")
    return le_u(len(value), 32) + value


def le_string(value: str) -> bytes:
    raw = value.encode("utf-8", "strict")
    require(len(raw) <= 4096, "string_bound")
    return le_u(len(raw), 32) + raw


def option_hash(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + fixed(value, 32)


V0_PLAN_KEYS = {
    "schema_version", "genesis_hash", "chain_id", "governance_decision_id",
    "current_protocol_version", "target_protocol_version", "approval_epoch",
    "approval_height", "activation_epoch", "activation_height",
    "artifact_manifest_hash", "target_consensus_parameters_hash", "state_migration_hash",
}


def enc_v0_plan(value: dict[str, Any]) -> bytes:
    exact_keys(value, V0_PLAN_KEYS, "v0_plan_fields")
    chain = value["chain_id"].encode("utf-8", "strict")
    require(len(chain) <= 128, "v0_plan_chain_bound")
    migration = value["state_migration_hash"]
    return b"".join((
        be_u(value["schema_version"], 16), fixed(value["genesis_hash"], 32),
        be_u(len(chain), 16), chain, fixed(value["governance_decision_id"], 32),
        be_u(value["current_protocol_version"], 32), be_u(value["target_protocol_version"], 32),
        be_u(value["approval_epoch"], 64), be_u(value["approval_height"], 64),
        be_u(value["activation_epoch"], 64), be_u(value["activation_height"], 64),
        fixed(value["artifact_manifest_hash"], 32), fixed(value["target_consensus_parameters_hash"], 32),
        b"\x00" if migration is None else b"\x01" + fixed(migration, 32),
    ))


def dec_v0_plan(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw, "big")
    value = {
        "schema_version": cursor.uint(16), "genesis_hash": cursor.hash32(),
        "chain_id": cursor.string(16, 128), "governance_decision_id": cursor.hash32(),
        "current_protocol_version": cursor.uint(32), "target_protocol_version": cursor.uint(32),
        "approval_epoch": cursor.uint(64), "approval_height": cursor.uint(64),
        "activation_epoch": cursor.uint(64), "activation_height": cursor.uint(64),
        "artifact_manifest_hash": cursor.hash32(), "target_consensus_parameters_hash": cursor.hash32(),
    }
    tag = cursor.uint(8)
    require(tag in (0, 1), "v0_plan_migration_tag")
    value["state_migration_hash"] = None if tag == 0 else cursor.hash32()
    cursor.finish()
    require(enc_v0_plan(value) == raw, "v0_plan_reencode")
    return value


CONTEXT_KEYS = {"schema_version", "genesis_hash", "chain_id", "protocol_version", "stack_profile_hash"}


def enc_context(value: dict[str, Any]) -> bytes:
    exact_keys(value, CONTEXT_KEYS, "context_fields")
    return b"".join((le_u(value["schema_version"], 16), fixed(value["genesis_hash"], 32),
                     le_string(value["chain_id"]), le_u(value["protocol_version"], 32),
                     fixed(value["stack_profile_hash"], 32)))


def dec_context(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.uint(16), "genesis_hash": cursor.hash32(),
            "chain_id": cursor.string(32), "protocol_version": cursor.uint(32),
            "stack_profile_hash": cursor.hash32()}


def enc_parent(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "parent_fields")
    if value["variant"] == "V1Block":
        body = exact_keys(value["value"], {"block_id"}, "v1_parent")
        return b"\x01" + fixed(body["block_id"], 32)
    if value["variant"] == "V0TerminalBlock":
        body = exact_keys(value["value"], {"block_id_bytes", "handoff_certificate_digest", "activation_statement_id"}, "v0_parent")
        return b"\x02" + fixed(body["block_id_bytes"], 32) + fixed(body["handoff_certificate_digest"], 32) + fixed(body["activation_statement_id"], 32)
    reject("parent_variant")


def dec_parent(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.uint(8)
    if tag == 1:
        return {"variant": "V1Block", "value": {"block_id": cursor.hash32()}}
    if tag == 2:
        return {"variant": "V0TerminalBlock", "value": {"block_id_bytes": cursor.hash32(), "handoff_certificate_digest": cursor.hash32(), "activation_statement_id": cursor.hash32()}}
    reject("parent_variant")


HEADER_ROOTS = (
    "batch_refs_root", "protocol_objects_root", "post_state_root",
    "transaction_execution_receipts_root", "evidence_root", "consumption_rollups_root",
    "settlement_root", "resource_usage_root",
)
HEADER_KEYS = {
    "schema_version", "context", "epoch", "view", "height", "block_kind", "parent",
    "proposer_id", "epoch_descriptor_id", "justify_qc_id", "timeout_certificate_id",
    *HEADER_ROOTS, "next_epoch_descriptor_id", "upgrade_plan_id", "epoch_handoff_id",
}
KIND_TO_TAG = {"Ordinary": 1, "V0ActivationFirst": 5}
TAG_TO_KIND = {value: key for key, value in KIND_TO_TAG.items()}


def enc_header(value: dict[str, Any]) -> bytes:
    exact_keys(value, HEADER_KEYS, "header_fields")
    require(value["block_kind"] in KIND_TO_TAG, "block_kind")
    return b"".join((
        le_u(value["schema_version"], 16), enc_context(value["context"]), le_u(value["epoch"], 64),
        le_u(value["view"], 64), le_u(value["height"], 64), le_u(KIND_TO_TAG[value["block_kind"]], 8),
        enc_parent(value["parent"]), le_bytes(value["proposer_id"]), fixed(value["epoch_descriptor_id"], 32),
        option_hash(value["justify_qc_id"]), option_hash(value["timeout_certificate_id"]),
        *(fixed(value[name], 32) for name in HEADER_ROOTS),
        option_hash(value["next_epoch_descriptor_id"]), option_hash(value["upgrade_plan_id"]),
        option_hash(value["epoch_handoff_id"]),
    ))


def dec_header(cursor: Cursor) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": cursor.uint(16), "context": dec_context(cursor), "epoch": cursor.uint(64),
        "view": cursor.uint(64), "height": cursor.uint(64),
    }
    tag = cursor.uint(8)
    require(tag in TAG_TO_KIND, "block_kind")
    value.update({"block_kind": TAG_TO_KIND[tag], "parent": dec_parent(cursor),
                  "proposer_id": cursor.bytes(128), "epoch_descriptor_id": cursor.hash32(),
                  "justify_qc_id": cursor.option_hash(), "timeout_certificate_id": cursor.option_hash()})
    value.update({name: cursor.hash32() for name in HEADER_ROOTS})
    value.update({"next_epoch_descriptor_id": cursor.option_hash(), "upgrade_plan_id": cursor.option_hash(),
                  "epoch_handoff_id": cursor.option_hash()})
    return value


CONSENSUS_KEYS = {"schema_version", "context", "runtime_profile_hash", "epoch", "validator_set_hash", "consensus_parameters_hash", "view", "message_kind"}
VOTE_KEYS = {"schema_version", "consensus_context", "block_id", "height", "epoch_descriptor_id", "post_state_root", "batch_refs_root", "transaction_execution_receipts_root"}
SIG_KEYS = {"voter_id", "signature_scheme", "signature"}


def enc_consensus(value: dict[str, Any]) -> bytes:
    exact_keys(value, CONSENSUS_KEYS, "consensus_fields")
    return b"".join((le_u(value["schema_version"], 16), enc_context(value["context"]),
                     fixed(value["runtime_profile_hash"], 32), le_u(value["epoch"], 64),
                     fixed(value["validator_set_hash"], 32), fixed(value["consensus_parameters_hash"], 32),
                     le_u(value["view"], 64), le_u(value["message_kind"], 8)))


def dec_consensus(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.uint(16), "context": dec_context(cursor),
            "runtime_profile_hash": cursor.hash32(), "epoch": cursor.uint(64),
            "validator_set_hash": cursor.hash32(), "consensus_parameters_hash": cursor.hash32(),
            "view": cursor.uint(64), "message_kind": cursor.uint(8)}


def enc_vote(value: dict[str, Any]) -> bytes:
    exact_keys(value, VOTE_KEYS, "vote_fields")
    return b"".join((le_u(value["schema_version"], 16), enc_consensus(value["consensus_context"]),
                     fixed(value["block_id"], 32), le_u(value["height"], 64),
                     fixed(value["epoch_descriptor_id"], 32), fixed(value["post_state_root"], 32),
                     fixed(value["batch_refs_root"], 32), fixed(value["transaction_execution_receipts_root"], 32)))


def dec_vote(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.uint(16), "consensus_context": dec_consensus(cursor),
            "block_id": cursor.hash32(), "height": cursor.uint(64),
            "epoch_descriptor_id": cursor.hash32(), "post_state_root": cursor.hash32(),
            "batch_refs_root": cursor.hash32(), "transaction_execution_receipts_root": cursor.hash32()}


def enc_sig(value: dict[str, Any]) -> bytes:
    exact_keys(value, SIG_KEYS, "signature_fields")
    return le_bytes(value["voter_id"]) + le_u(value["signature_scheme"], 16) + le_bytes(value["signature"])


def dec_sig(cursor: Cursor) -> dict[str, Any]:
    return {"voter_id": cursor.bytes(128), "signature_scheme": cursor.uint(16), "signature": cursor.bytes(128)}


def enc_qc(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "statement", "signatures", "quorum_certificate_id"}, "qc_fields")
    signatures = value["signatures"]
    require(isinstance(signatures, list) and len(signatures) < 2**32, "qc_signer_count")
    body = le_u(value["schema_version"], 16) + enc_vote(value["statement"]) + le_u(len(signatures), 32) + b"".join(enc_sig(item) for item in signatures)
    return body + fixed(value["quorum_certificate_id"], 32)


def dec_qc(cursor: Cursor) -> dict[str, Any]:
    version, statement, count = cursor.uint(16), dec_vote(cursor), cursor.uint(32)
    require(1 <= count <= 100, "qc_signer_count")
    return {"schema_version": version, "statement": statement,
            "signatures": [dec_sig(cursor) for _ in range(count)],
            "quorum_certificate_id": cursor.hash32()}


PROPOSAL_BODY_KEYS = {
    "schema_version", "context", "header", "activation_statement_id", "activation_anchor_id",
    "migration_receipt_id", "source_upgrade_plan_hash", "handoff_certificate_digest_v0",
    "terminal_qc_digest_v0", "batch_ref_count", "protocol_sidecar_count",
}


def enc_proposal_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, PROPOSAL_BODY_KEYS, "proposal_body_fields")
    return b"".join((
        le_u(value["schema_version"], 16), enc_context(value["context"]), enc_header(value["header"]),
        fixed(value["activation_statement_id"], 32), fixed(value["activation_anchor_id"], 32),
        fixed(value["migration_receipt_id"], 32), fixed(value["source_upgrade_plan_hash"], 32),
        fixed(value["handoff_certificate_digest_v0"], 32), fixed(value["terminal_qc_digest_v0"], 32),
        le_u(value["batch_ref_count"], 32), le_u(value["protocol_sidecar_count"], 32),
    ))


def dec_proposal_body(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.uint(16), "context": dec_context(cursor), "header": dec_header(cursor),
            "activation_statement_id": cursor.hash32(), "activation_anchor_id": cursor.hash32(),
            "migration_receipt_id": cursor.hash32(), "source_upgrade_plan_hash": cursor.hash32(),
            "handoff_certificate_digest_v0": cursor.hash32(), "terminal_qc_digest_v0": cursor.hash32(),
            "batch_ref_count": cursor.uint(32), "protocol_sidecar_count": cursor.uint(32)}


def enc_proposal(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "proposal_id", "proposer_id", "signature_scheme", "signature"}, "proposal_fields")
    return enc_proposal_body(value["body"]) + fixed(value["proposal_id"], 32) + le_bytes(value["proposer_id"]) + le_u(value["signature_scheme"], 16) + le_bytes(value["signature"])


def dec_proposal(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw, "little")
    value = {"body": dec_proposal_body(cursor), "proposal_id": cursor.hash32(),
             "proposer_id": cursor.bytes(128), "signature_scheme": cursor.uint(16),
             "signature": cursor.bytes(128)}
    cursor.finish()
    require(enc_proposal(value) == raw, "proposal_reencode")
    return value


def enc_certified(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"header", "block_id", "certifying_qc"}, "certified_fields")
    return enc_header(value["header"]) + fixed(value["block_id"], 32) + enc_qc(value["certifying_qc"])


def dec_certified(cursor: Cursor) -> dict[str, Any]:
    return {"header": dec_header(cursor), "block_id": cursor.hash32(), "certifying_qc": dec_qc(cursor)}


FINALITY_KEYS = {"schema_version", "context", "activation_statement_id", "epoch_descriptor_id", "validator_set_hash", "consensus_parameters_hash", "target_block_id", "target_height", "target_header", "certified_chain", "proof_id"}


def enc_finality_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, FINALITY_KEYS, "finality_fields")
    chain = value["certified_chain"]
    require(isinstance(chain, list) and len(chain) < 2**32, "finality_chain_count")
    return b"".join((le_u(value["schema_version"], 16), enc_context(value["context"]),
                     fixed(value["activation_statement_id"], 32), fixed(value["epoch_descriptor_id"], 32),
                     fixed(value["validator_set_hash"], 32), fixed(value["consensus_parameters_hash"], 32),
                     fixed(value["target_block_id"], 32), le_u(value["target_height"], 64),
                     enc_header(value["target_header"]), le_u(len(chain), 32),
                     *(enc_certified(item) for item in chain)))


def enc_finality(value: dict[str, Any]) -> bytes:
    return enc_finality_body(value) + fixed(value["proof_id"], 32)


def dec_finality(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw, "little")
    value: dict[str, Any] = {"schema_version": cursor.uint(16), "context": dec_context(cursor),
                            "activation_statement_id": cursor.hash32(), "epoch_descriptor_id": cursor.hash32(),
                            "validator_set_hash": cursor.hash32(), "consensus_parameters_hash": cursor.hash32(),
                            "target_block_id": cursor.hash32(), "target_height": cursor.uint(64),
                            "target_header": dec_header(cursor)}
    count = cursor.uint(32)
    require(1 <= count <= 8, "finality_chain_count")
    value["certified_chain"] = [dec_certified(cursor) for _ in range(count)]
    value["proof_id"] = cursor.hash32()
    cursor.finish()
    require(enc_finality(value) == raw, "finality_reencode")
    return value


ACTIVATION_PROOF_KEYS = {"schema_version", "source_handoff_evidence_sha256", "source_upgrade_plan_cev0", "frozen_v0_field13_present", "frozen_v0_field14_present", "activation_statement_id", "activation_anchor_id", "migration_receipt_id", "first_v1_proposal_cev1", "first_v1_finality_proof_cev1", "proof_id"}


def enc_activation_proof_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, ACTIVATION_PROOF_KEYS, "activation_proof_fields")
    return b"".join((le_u(value["schema_version"], 16), fixed(value["source_handoff_evidence_sha256"], 32),
                     le_bytes(value["source_upgrade_plan_cev0"]),
                     le_u(int(value["frozen_v0_field13_present"]), 8), le_u(int(value["frozen_v0_field14_present"]), 8),
                     fixed(value["activation_statement_id"], 32), fixed(value["activation_anchor_id"], 32),
                     fixed(value["migration_receipt_id"], 32), le_bytes(value["first_v1_proposal_cev1"]),
                     le_bytes(value["first_v1_finality_proof_cev1"])))


def enc_activation_proof(value: dict[str, Any]) -> bytes:
    return enc_activation_proof_body(value) + fixed(value["proof_id"], 32)


def dec_activation_proof(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw, "little")
    value = {"schema_version": cursor.uint(16), "source_handoff_evidence_sha256": cursor.hash32(),
             "source_upgrade_plan_cev0": cursor.bytes(),
             "frozen_v0_field13_present": bool(cursor.uint(8)), "frozen_v0_field14_present": bool(cursor.uint(8)),
             "activation_statement_id": cursor.hash32(), "activation_anchor_id": cursor.hash32(),
             "migration_receipt_id": cursor.hash32(), "first_v1_proposal_cev1": cursor.bytes(),
             "first_v1_finality_proof_cev1": cursor.bytes(), "proof_id": cursor.hash32()}
    cursor.finish()
    require(enc_activation_proof(value) == raw, "activation_proof_reencode")
    return value


def load_source_module() -> Any:
    spec = importlib.util.spec_from_file_location("trnm_v1_activation_source", SOURCE_CHECKER_PATH)
    require(spec is not None and spec.loader is not None, "source_checker_import")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_fixture() -> tuple[Any, dict[str, Any], dict[str, str]]:
    module = load_source_module()
    schema = json.loads(SOURCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    vectors = json.loads(SOURCE_VECTOR_PATH.read_text(encoding="utf-8"))
    domains = module.verify_schema(schema)
    fixture = copy.deepcopy(vectors["positive_cases"][0]["fixture"])
    module.verify_fixture(fixture, domains)
    return module, fixture, domains


def resign_source_fixture(module: Any, fixture: dict[str, Any], domains: dict[str, str], plan_hash: bytes) -> None:
    plan_hex = plan_hash.hex()
    fixture["frozen_v0_evidence_projection"]["source_upgrade_plan_hash"] = plan_hex
    statement = fixture["activation_statement"]
    statement["body"]["source_upgrade_plan_hash"] = plan_hex
    statement_id = bytes.fromhex(module.digest(domains["activation_statement"], module.encode_statement(statement["body"])))
    statement["id"] = statement_id.hex()
    certificate = fixture["activation_certificate"]
    certificate["statement_id"] = statement_id.hex()
    for role, key, seed_indices in ((0, "old_set_signatures", (0, 1)), (1, "new_set_signatures", (4, 5))):
        domain = domains["activation_old_signature" if role == 0 else "activation_new_signature"]
        root = bytes.fromhex(module.digest(domain, statement_id))
        descriptor = fixture["old_signing_set" if role == 0 else "new_signing_set"]["descriptor"]
        source_members = descriptor["validators"] if role == 0 else descriptor["definition"]["members"]
        public_by_id = {
            member["validator_id"]: member["consensus_public_key"] for member in source_members
        }
        for entry, seed_index in zip(certificate[key], seed_indices, strict=True):
            require(
                public_by_id.get(entry["signer_id"])
                == ed25519_public_key(fixture_seed(seed_index)).hex(),
                "fixture_key_internal",
            )
            entry["signature"] = ed25519_sign(fixture_seed(seed_index), root).hex()
    anchor = fixture["activation_anchor"]
    anchor["body"]["activation_statement_id"] = statement_id.hex()
    anchor_id = bytes.fromhex(module.digest(domains["activation_anchor"], module.encode_anchor(anchor["body"])))
    anchor["id"] = anchor_id.hex()
    block = fixture["first_v1_block_projection"]
    block["parent_activation_statement_id"] = statement_id.hex()
    block["activation_statement_id"] = statement_id.hex()
    block["activation_anchor_id"] = anchor_id.hex()


def target_members(fixture: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    members = fixture["new_signing_set"]["descriptor"]["definition"]["members"]
    result = []
    total = 0
    for index, member in enumerate(members):
        public = bytes.fromhex(member["consensus_public_key"])
        require(public == ed25519_public_key(fixture_seed(index + 4)), "target_fixture_key")
        weight = member["voting_weight"]
        total += weight
        result.append({"id": bytes.fromhex(member["validator_id"]), "public": public, "weight": weight, "seed": fixture_seed(index + 4)})
    return result, (2 * total) // 3 + 1


def header_from_projection(block: dict[str, Any], proposer_id: bytes) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "context": {"schema_version": 1, "genesis_hash": bytes.fromhex(block["context"]["genesis_hash"]),
                    "chain_id": block["context"]["chain_id"], "protocol_version": 1,
                    "stack_profile_hash": bytes.fromhex(block["context"]["stack_profile_hash"])},
        "epoch": block["epoch"], "view": block["view"], "height": block["height"],
        "block_kind": "V0ActivationFirst",
        "parent": {"variant": "V0TerminalBlock", "value": {
            "block_id_bytes": bytes.fromhex(block["parent_block_id"]),
            "handoff_certificate_digest": bytes.fromhex(block["parent_handoff_certificate_digest_v0"]),
            "activation_statement_id": bytes.fromhex(block["parent_activation_statement_id"]),
        }},
        "proposer_id": proposer_id, "epoch_descriptor_id": bytes.fromhex(block["epoch_descriptor_id"]),
        "justify_qc_id": None, "timeout_certificate_id": None,
        **{name: bytes.fromhex(block[name]) for name in HEADER_ROOTS},
        "next_epoch_descriptor_id": None, "upgrade_plan_id": None, "epoch_handoff_id": None,
    }


def make_qc(header: dict[str, Any], block_id: bytes, fixture: dict[str, Any], members: list[dict[str, Any]]) -> dict[str, Any]:
    plan = fixture["plan_projection"]
    vote = {"schema_version": 1, "consensus_context": {
        "schema_version": 1, "context": copy.deepcopy(header["context"]),
        "runtime_profile_hash": bytes.fromhex(plan["target_runtime_profile_hash"]),
        "epoch": header["epoch"], "validator_set_hash": bytes.fromhex(plan["target_v1_validator_set_hash"]),
        "consensus_parameters_hash": bytes.fromhex(plan["target_v1_consensus_parameters_hash"]),
        "view": header["view"], "message_kind": 1,
    }, "block_id": block_id, "height": header["height"], "epoch_descriptor_id": header["epoch_descriptor_id"],
        "post_state_root": header["post_state_root"], "batch_refs_root": header["batch_refs_root"],
        "transaction_execution_receipts_root": header["transaction_execution_receipts_root"]}
    root = digest_v1(VOTE_DOMAIN, enc_vote(vote))
    signatures = [{"voter_id": member["id"], "signature_scheme": STRICT_ED25519,
                   "signature": ed25519_sign(member["seed"], root)} for member in members]
    body = le_u(1, 16) + enc_vote(vote) + le_u(len(signatures), 32) + b"".join(enc_sig(item) for item in signatures)
    return {"schema_version": 1, "statement": vote, "signatures": signatures,
            "quorum_certificate_id": digest_v1(QC_DOMAIN, body)}


def make_ordinary(previous_header: dict[str, Any], previous_block_id: bytes, previous_qc_id: bytes,
                  proposer_id: bytes, label: int) -> dict[str, Any]:
    header = copy.deepcopy(previous_header)
    header.update({"view": previous_header["view"] + 1, "height": previous_header["height"] + 1,
                   "block_kind": "Ordinary", "parent": {"variant": "V1Block", "value": {"block_id": previous_block_id}},
                   "proposer_id": proposer_id, "justify_qc_id": previous_qc_id})
    # The bounded successors are empty ordinary blocks preserving the migrated state.
    return header


def build_positive() -> tuple[dict[str, Any], dict[str, Any]]:
    module, fixture, domains = source_fixture()
    source = fixture["frozen_v0_evidence_projection"]
    plan = fixture["plan_projection"]
    v0_plan = {
        "schema_version": 0, "genesis_hash": bytes.fromhex(plan["source_v0_genesis_hash"]),
        "chain_id": plan["source_v0_chain_id"], "governance_decision_id": hashlib.sha256(b"trnm:v0-to-v1:governance-decision").digest(),
        "current_protocol_version": 0, "target_protocol_version": 1,
        "approval_epoch": plan["source_epoch"], "approval_height": plan["source_terminal_height"] - 99,
        "activation_epoch": plan["activation_epoch"], "activation_height": plan["activation_height"],
        "artifact_manifest_hash": bytes.fromhex(fixture["artifact_manifest"]["hash"]),
        "target_consensus_parameters_hash": bytes.fromhex(plan["source_v0_target_consensus_parameters_hash"]),
        "state_migration_hash": bytes.fromhex(plan["migration_program_hash"]),
    }
    plan_raw = enc_v0_plan(v0_plan)
    plan_hash = digest_v0(V0_PLAN_DOMAIN, plan_raw)
    resign_source_fixture(module, fixture, domains, plan_hash)
    module.verify_fixture(fixture, domains)

    members, _ = target_members(fixture)
    block_projection = fixture["first_v1_block_projection"]
    header0 = header_from_projection(block_projection, members[0]["id"])
    block0 = digest_v1(BLOCK_DOMAIN, enc_header(header0))
    qc0 = make_qc(header0, block0, fixture, members)
    header1 = make_ordinary(header0, block0, qc0["quorum_certificate_id"], members[1]["id"], 1)
    block1 = digest_v1(BLOCK_DOMAIN, enc_header(header1))
    qc1 = make_qc(header1, block1, fixture, members)
    header2 = make_ordinary(header1, block1, qc1["quorum_certificate_id"], members[2]["id"], 2)
    block2 = digest_v1(BLOCK_DOMAIN, enc_header(header2))
    qc2 = make_qc(header2, block2, fixture, members)

    statement_id = bytes.fromhex(fixture["activation_statement"]["id"])
    anchor_id = bytes.fromhex(fixture["activation_anchor"]["id"])
    migration_id = bytes.fromhex(fixture["migration_receipt"]["id"])
    proposal_body = {"schema_version": 1, "context": copy.deepcopy(header0["context"]), "header": header0,
                     "activation_statement_id": statement_id, "activation_anchor_id": anchor_id,
                     "migration_receipt_id": migration_id, "source_upgrade_plan_hash": plan_hash,
                     "handoff_certificate_digest_v0": bytes.fromhex(source["handoff_certificate_digest_v0"]),
                     "terminal_qc_digest_v0": bytes.fromhex(source["terminal_qc_digest_v0"]),
                     "batch_ref_count": 0, "protocol_sidecar_count": 0}
    proposal_id = digest_v1(PROPOSAL_DOMAIN, enc_proposal_body(proposal_body))
    proposal_root = digest_v1(PROPOSAL_SIGNATURE_DOMAIN, enc_proposal_body(proposal_body))
    proposal = {"body": proposal_body, "proposal_id": proposal_id, "proposer_id": members[0]["id"],
                "signature_scheme": STRICT_ED25519, "signature": ed25519_sign(members[0]["seed"], proposal_root)}
    proposal_raw = enc_proposal(proposal)

    finality = {"schema_version": 1, "context": copy.deepcopy(header0["context"]),
                "activation_statement_id": statement_id, "epoch_descriptor_id": header0["epoch_descriptor_id"],
                "validator_set_hash": bytes.fromhex(plan["target_v1_validator_set_hash"]),
                "consensus_parameters_hash": bytes.fromhex(plan["target_v1_consensus_parameters_hash"]),
                "target_block_id": block0, "target_height": header0["height"], "target_header": header0,
                "certified_chain": [{"header": header0, "block_id": block0, "certifying_qc": qc0},
                                    {"header": header1, "block_id": block1, "certifying_qc": qc1},
                                    {"header": header2, "block_id": block2, "certifying_qc": qc2}],
                "proof_id": b"\x00" * 32}
    finality["proof_id"] = digest_v1(FINALITY_DOMAIN, enc_finality_body(finality))
    finality_raw = enc_finality(finality)
    evidence_hash = raw_json_sha256(fixture["frozen_v0_evidence_projection"])
    activation_proof = {"schema_version": 1, "source_handoff_evidence_sha256": evidence_hash,
                        "source_upgrade_plan_cev0": plan_raw, "frozen_v0_field13_present": False,
                        "frozen_v0_field14_present": False, "activation_statement_id": statement_id,
                        "activation_anchor_id": anchor_id, "migration_receipt_id": migration_id,
                        "first_v1_proposal_cev1": proposal_raw,
                        "first_v1_finality_proof_cev1": finality_raw, "proof_id": b"\x00" * 32}
    activation_proof["proof_id"] = digest_v1(ACTIVATION_PROOF_DOMAIN, enc_activation_proof_body(activation_proof))
    expected = {"source_upgrade_plan_hash": plan_hash.hex(), "activation_statement_id": statement_id.hex(),
                "activation_anchor_id": anchor_id.hex(), "migration_receipt_id": migration_id.hex(),
                "first_block_id": block0.hex(), "first_proposal_id": proposal_id.hex(),
                "finality_proof_id": finality["proof_id"].hex(), "activation_proof_id": activation_proof["proof_id"].hex(),
                "finalized_height": header0["height"], "qc_signatures": 12, "proposal_signatures": 1,
                "frozen_v0_fields_13_14": "forbidden-for-cross-version"}
    return {"source_fixture": fixture, "activation_proof": activation_proof}, expected


def verify_v0_plan(raw: bytes, fixture: dict[str, Any]) -> bytes:
    value = dec_v0_plan(raw)
    plan, v0 = fixture["plan_projection"], fixture["frozen_v0_evidence_projection"]
    require(value["schema_version"] == 0, "v0_plan_schema")
    require(value["genesis_hash"].hex() == plan["source_v0_genesis_hash"], "v0_plan_genesis")
    require(value["chain_id"] == plan["source_v0_chain_id"], "v0_plan_chain")
    require(value["current_protocol_version"] == 0 and value["target_protocol_version"] == 1, "v0_plan_version")
    require(value["approval_epoch"] <= plan["source_epoch"] and value["approval_height"] < plan["activation_height"], "v0_plan_approval")
    require(value["activation_epoch"] == plan["activation_epoch"] and value["activation_height"] == plan["activation_height"], "v0_plan_activation")
    require(value["artifact_manifest_hash"].hex() == fixture["artifact_manifest"]["hash"], "v0_plan_artifact")
    require(value["target_consensus_parameters_hash"].hex() == plan["source_v0_target_consensus_parameters_hash"], "v0_plan_parameters")
    require(value["state_migration_hash"] is not None and value["state_migration_hash"].hex() == plan["migration_program_hash"], "v0_plan_migration")
    plan_hash = digest_v0(V0_PLAN_DOMAIN, raw)
    require(plan_hash.hex() == v0["source_upgrade_plan_hash"], "v0_plan_hash")
    return plan_hash


def verify_qc(qc: dict[str, Any], header: dict[str, Any], block_id: bytes, fixture: dict[str, Any], members: list[dict[str, Any]], threshold: int) -> bytes:
    require(qc["schema_version"] == 1, "qc_schema")
    vote = qc["statement"]
    context = vote["consensus_context"]
    plan = fixture["plan_projection"]
    require(vote["schema_version"] == 1 and context["schema_version"] == 1 and context["message_kind"] == 1, "qc_vote_kind")
    require(context["context"] == header["context"] and context["epoch"] == header["epoch"] and context["view"] == header["view"], "qc_context")
    require(context["runtime_profile_hash"].hex() == plan["target_runtime_profile_hash"], "qc_runtime_profile")
    require(context["validator_set_hash"].hex() == plan["target_v1_validator_set_hash"] and context["consensus_parameters_hash"].hex() == plan["target_v1_consensus_parameters_hash"], "qc_authority")
    require(vote["block_id"] == block_id and vote["height"] == header["height"] and vote["epoch_descriptor_id"] == header["epoch_descriptor_id"], "qc_block")
    require(vote["post_state_root"] == header["post_state_root"] and vote["batch_refs_root"] == header["batch_refs_root"] and vote["transaction_execution_receipts_root"] == header["transaction_execution_receipts_root"], "qc_roots")
    ids = [entry["voter_id"] for entry in qc["signatures"]]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "qc_signer_order")
    member_map = {member["id"]: member for member in members}
    root = digest_v1(VOTE_DOMAIN, enc_vote(vote))
    weight = 0
    for entry in qc["signatures"]:
        member = member_map.get(entry["voter_id"])
        require(member is not None, "qc_unknown_signer")
        require(entry["signature_scheme"] == STRICT_ED25519 and len(entry["signature"]) == 64, "qc_signature_shape")
        require(ed25519_verify(root, member["public"], entry["signature"]), "qc_signature")
        weight += member["weight"]
    require(weight >= threshold, "qc_quorum")
    body = le_u(qc["schema_version"], 16) + enc_vote(vote) + le_u(len(qc["signatures"]), 32) + b"".join(enc_sig(item) for item in qc["signatures"])
    qc_id = digest_v1(QC_DOMAIN, body)
    require(qc["quorum_certificate_id"] == qc_id, "qc_id")
    return qc_id


def verify_activation_proof(raw: bytes, fixture: dict[str, Any]) -> dict[str, Any]:
    value = dec_activation_proof(raw)
    require(value["schema_version"] == 1, "activation_proof_schema")
    require(not value["frozen_v0_field13_present"], "frozen_v0_field13_forbidden")
    require(not value["frozen_v0_field14_present"], "frozen_v0_field14_forbidden")
    require(value["source_handoff_evidence_sha256"] == raw_json_sha256(fixture["frozen_v0_evidence_projection"]), "source_handoff_binding")
    plan_hash = verify_v0_plan(value["source_upgrade_plan_cev0"], fixture)
    statement_id = bytes.fromhex(fixture["activation_statement"]["id"])
    anchor_id = bytes.fromhex(fixture["activation_anchor"]["id"])
    migration_id = bytes.fromhex(fixture["migration_receipt"]["id"])
    require(value["activation_statement_id"] == statement_id, "activation_statement_binding")
    require(value["activation_anchor_id"] == anchor_id, "activation_anchor_binding")
    require(value["migration_receipt_id"] == migration_id, "migration_receipt_binding")

    members, threshold = target_members(fixture)
    proposal = dec_proposal(value["first_v1_proposal_cev1"])
    body = proposal["body"]
    require(body["schema_version"] == 1 and body["context"]["protocol_version"] == 1, "proposal_schema")
    proposal_id = digest_v1(PROPOSAL_DOMAIN, enc_proposal_body(body))
    require(proposal["proposal_id"] == proposal_id, "proposal_id")
    require(proposal["proposer_id"] == body["header"]["proposer_id"], "proposal_proposer")
    member_map = {member["id"]: member for member in members}
    proposer = member_map.get(proposal["proposer_id"])
    require(proposer is not None, "proposal_unknown_proposer")
    require(proposal["signature_scheme"] == STRICT_ED25519 and len(proposal["signature"]) == 64, "proposal_signature_shape")
    proposal_root = digest_v1(PROPOSAL_SIGNATURE_DOMAIN, enc_proposal_body(body))
    require(ed25519_verify(proposal_root, proposer["public"], proposal["signature"]), "proposal_signature")
    header0 = body["header"]
    block = fixture["first_v1_block_projection"]
    require(body["context"] == header0["context"], "proposal_context")
    require(header0["block_kind"] == "V0ActivationFirst", "proposal_block_kind")
    require(header0["epoch"] == block["epoch"] and header0["height"] == block["height"] and header0["view"] == block["initial_view"], "proposal_boundary")
    require(header0["parent"] == {"variant": "V0TerminalBlock", "value": {"block_id_bytes": bytes.fromhex(block["parent_block_id"]), "handoff_certificate_digest": bytes.fromhex(block["parent_handoff_certificate_digest_v0"]), "activation_statement_id": statement_id}}, "proposal_parent")
    require(header0["justify_qc_id"] is None and header0["timeout_certificate_id"] is None, "proposal_justification")
    require(body["activation_statement_id"] == statement_id and body["activation_anchor_id"] == anchor_id and body["migration_receipt_id"] == migration_id, "proposal_activation_binding")
    require(body["source_upgrade_plan_hash"] == plan_hash, "proposal_plan_binding")
    require(body["handoff_certificate_digest_v0"].hex() == fixture["frozen_v0_evidence_projection"]["handoff_certificate_digest_v0"] and body["terminal_qc_digest_v0"].hex() == fixture["frozen_v0_evidence_projection"]["terminal_qc_digest_v0"], "proposal_terminal_binding")
    require(body["batch_ref_count"] == 0 and body["protocol_sidecar_count"] == 0, "proposal_empty_payload")
    require(header0["post_state_root"].hex() == fixture["migration_receipt"]["body"]["migration_output_root"], "proposal_migration_output")
    for name in HEADER_ROOTS:
        if name != "post_state_root":
            require(header0[name].hex() == block[name], "proposal_root_binding", name)

    finality = dec_finality(value["first_v1_finality_proof_cev1"])
    require(finality["schema_version"] == 1, "finality_schema")
    require(finality["context"] == header0["context"] and finality["activation_statement_id"] == statement_id, "finality_context")
    require(finality["epoch_descriptor_id"] == header0["epoch_descriptor_id"], "finality_descriptor")
    require(finality["validator_set_hash"].hex() == fixture["plan_projection"]["target_v1_validator_set_hash"] and finality["consensus_parameters_hash"].hex() == fixture["plan_projection"]["target_v1_consensus_parameters_hash"], "finality_authority")
    require(len(finality["certified_chain"]) == 3, "finality_chain_count")
    block_ids: list[bytes] = []
    qc_ids: list[bytes] = []
    for index, certified in enumerate(finality["certified_chain"]):
        header = certified["header"]
        require(header["context"] == header0["context"] and header["epoch"] == header0["epoch"], "finality_header_context")
        require(header["epoch_descriptor_id"] == header0["epoch_descriptor_id"], "finality_header_descriptor")
        block_id = digest_v1(BLOCK_DOMAIN, enc_header(header))
        require(certified["block_id"] == block_id, "finality_block_id")
        qc_id = verify_qc(certified["certifying_qc"], header, block_id, fixture, members, threshold)
        block_ids.append(block_id)
        qc_ids.append(qc_id)
        if index == 0:
            require(header == header0, "finality_first_header")
        else:
            previous = finality["certified_chain"][index - 1]["header"]
            require(header["block_kind"] == "Ordinary", "finality_successor_kind")
            require(header["parent"] == {"variant": "V1Block", "value": {"block_id": block_ids[index - 1]}}, "finality_parent")
            require(header["height"] == previous["height"] + 1, "finality_height")
            require(header["view"] == previous["view"] + 1, "finality_view")
            require(header["justify_qc_id"] == qc_ids[index - 1], "finality_justify")
    require(finality["target_block_id"] == block_ids[0] and finality["target_height"] == header0["height"] and finality["target_header"] == header0, "finality_target")
    proof_id = digest_v1(FINALITY_DOMAIN, enc_finality_body(finality))
    require(finality["proof_id"] == proof_id, "finality_proof_id")
    require(digest_v1(ACTIVATION_PROOF_DOMAIN, enc_activation_proof_body(value)) == value["proof_id"], "activation_proof_id")
    return {"source_upgrade_plan_hash": plan_hash.hex(), "activation_statement_id": statement_id.hex(),
            "activation_anchor_id": anchor_id.hex(), "migration_receipt_id": migration_id.hex(),
            "first_block_id": block_ids[0].hex(), "first_proposal_id": proposal_id.hex(),
            "finality_proof_id": proof_id.hex(), "activation_proof_id": value["proof_id"].hex(),
            "finalized_height": header0["height"], "qc_signatures": sum(len(item["certifying_qc"]["signatures"]) for item in finality["certified_chain"]),
            "proposal_signatures": 1, "frozen_v0_fields_13_14": "forbidden-for-cross-version"}


MUTANTS: tuple[tuple[str, str], ...] = (
    ("v0_plan_trailing", "trailing"), ("v0_plan_truncated", "truncated"),
    ("v0_plan_wrong_schema", "v0_plan_schema"), ("v0_plan_wrong_genesis", "v0_plan_genesis"),
    ("v0_plan_wrong_chain", "v0_plan_chain"), ("v0_plan_wrong_version", "v0_plan_version"),
    ("v0_plan_wrong_approval", "v0_plan_approval"), ("v0_plan_wrong_activation", "v0_plan_activation"),
    ("v0_plan_wrong_artifact", "v0_plan_artifact"), ("v0_plan_wrong_parameters", "v0_plan_parameters"),
    ("v0_plan_missing_migration", "v0_plan_migration"), ("v0_plan_wrong_migration", "v0_plan_migration"),
    ("frozen_v0_field13_present", "frozen_v0_field13_forbidden"),
    ("frozen_v0_field14_present", "frozen_v0_field14_forbidden"),
    ("source_handoff_substitution", "source_handoff_binding"),
    ("activation_statement_substitution", "activation_statement_binding"),
    ("activation_anchor_substitution", "activation_anchor_binding"),
    ("migration_receipt_substitution", "migration_receipt_binding"),
    ("proposal_trailing", "trailing"), ("proposal_truncated", "truncated"),
    ("proposal_id_flip", "proposal_id"), ("proposal_signature_flip", "proposal_signature"),
    ("proposal_wrong_proposer", "proposal_proposer"), ("proposal_wrong_kind", "proposal_id"),
    ("proposal_wrong_parent", "proposal_id"), ("proposal_has_payload", "proposal_id"),
    ("proposal_wrong_plan", "proposal_id"), ("proposal_wrong_state", "proposal_id"),
    ("finality_trailing", "trailing"), ("finality_truncated", "truncated"),
    ("finality_wrong_context", "finality_context"), ("finality_wrong_target", "finality_target"),
    ("finality_chain_short", "finality_chain_count"), ("finality_block_id_flip", "finality_block_id"),
    ("qc_signature_flip", "qc_signature"), ("qc_duplicate_signer", "qc_signer_order"),
    ("qc_under_quorum", "qc_quorum"), ("qc_wrong_set", "qc_authority"),
    ("qc_block_substitution", "qc_block"), ("finality_parent_break", "finality_parent"),
    ("finality_height_gap", "finality_height"), ("finality_view_gap", "finality_view"),
    ("finality_justify_substitution", "finality_justify"),
    ("activation_proof_id_flip", "activation_proof_id"),
)


def reid_proposal(proposal: dict[str, Any], resign: bool = False) -> None:
    proposal["proposal_id"] = digest_v1(PROPOSAL_DOMAIN, enc_proposal_body(proposal["body"]))
    if resign:
        proposal["signature"] = ed25519_sign(fixture_seed(4), digest_v1(PROPOSAL_SIGNATURE_DOMAIN, enc_proposal_body(proposal["body"])))


def reid_qc(qc: dict[str, Any]) -> None:
    body = le_u(qc["schema_version"], 16) + enc_vote(qc["statement"]) + le_u(len(qc["signatures"]), 32) + b"".join(enc_sig(item) for item in qc["signatures"])
    qc["quorum_certificate_id"] = digest_v1(QC_DOMAIN, body)


def reid_finality(finality: dict[str, Any]) -> None:
    finality["proof_id"] = digest_v1(FINALITY_DOMAIN, enc_finality_body(finality))


def refresh_certified(finality: dict[str, Any], index: int) -> None:
    """Rebuild one certified header so relation mutants reach relation checks."""
    certified = finality["certified_chain"][index]
    header = certified["header"]
    block_id = digest_v1(BLOCK_DOMAIN, enc_header(header))
    certified["block_id"] = block_id
    qc = certified["certifying_qc"]
    vote = qc["statement"]
    vote["consensus_context"]["context"] = copy.deepcopy(header["context"])
    vote["consensus_context"]["epoch"] = header["epoch"]
    vote["consensus_context"]["view"] = header["view"]
    vote["block_id"] = block_id
    vote["height"] = header["height"]
    vote["epoch_descriptor_id"] = header["epoch_descriptor_id"]
    vote["post_state_root"] = header["post_state_root"]
    vote["batch_refs_root"] = header["batch_refs_root"]
    vote["transaction_execution_receipts_root"] = header["transaction_execution_receipts_root"]
    root = digest_v1(VOTE_DOMAIN, enc_vote(vote))
    for seed_index, entry in enumerate(qc["signatures"], start=4):
        entry["signature"] = ed25519_sign(fixture_seed(seed_index), root)
    reid_qc(qc)


def reid_activation(value: dict[str, Any]) -> None:
    value["proof_id"] = digest_v1(ACTIVATION_PROOF_DOMAIN, enc_activation_proof_body(value))


def mutate(raw: bytes, name: str) -> bytes:
    value = dec_activation_proof(raw)
    if name.startswith("v0_plan_"):
        plan_raw = value["source_upgrade_plan_cev0"]
        if name == "v0_plan_trailing": value["source_upgrade_plan_cev0"] = plan_raw + b"\x00"
        elif name == "v0_plan_truncated": value["source_upgrade_plan_cev0"] = plan_raw[:-1]
        else:
            plan = dec_v0_plan(plan_raw)
            if name == "v0_plan_wrong_schema": plan["schema_version"] = 1
            elif name == "v0_plan_wrong_genesis": plan["genesis_hash"] = b"\x00" * 32
            elif name == "v0_plan_wrong_chain": plan["chain_id"] = "wrong-chain"
            elif name == "v0_plan_wrong_version": plan["target_protocol_version"] = 2
            elif name == "v0_plan_wrong_approval": plan["approval_height"] = plan["activation_height"]
            elif name == "v0_plan_wrong_activation": plan["activation_height"] += 1
            elif name == "v0_plan_wrong_artifact": plan["artifact_manifest_hash"] = b"\x00" * 32
            elif name == "v0_plan_wrong_parameters": plan["target_consensus_parameters_hash"] = b"\x00" * 32
            elif name == "v0_plan_missing_migration": plan["state_migration_hash"] = None
            elif name == "v0_plan_wrong_migration": plan["state_migration_hash"] = b"\x00" * 32
            value["source_upgrade_plan_cev0"] = enc_v0_plan(plan)
        reid_activation(value)
        return enc_activation_proof(value)
    if name == "frozen_v0_field13_present": value["frozen_v0_field13_present"] = True
    elif name == "frozen_v0_field14_present": value["frozen_v0_field14_present"] = True
    elif name == "source_handoff_substitution": value["source_handoff_evidence_sha256"] = b"\x00" * 32
    elif name == "activation_statement_substitution": value["activation_statement_id"] = b"\x00" * 32
    elif name == "activation_anchor_substitution": value["activation_anchor_id"] = b"\x00" * 32
    elif name == "migration_receipt_substitution": value["migration_receipt_id"] = b"\x00" * 32
    elif name == "proposal_trailing": value["first_v1_proposal_cev1"] += b"\x00"
    elif name == "proposal_truncated": value["first_v1_proposal_cev1"] = value["first_v1_proposal_cev1"][:-1]
    elif name.startswith("proposal_"):
        proposal = dec_proposal(value["first_v1_proposal_cev1"])
        if name == "proposal_id_flip": proposal["proposal_id"] = b"\x00" * 32
        elif name == "proposal_signature_flip": proposal["signature"] = bytes([proposal["signature"][0] ^ 1]) + proposal["signature"][1:]
        elif name == "proposal_wrong_proposer": proposal["proposer_id"] = b"new-x"
        elif name == "proposal_wrong_kind": proposal["body"]["header"]["block_kind"] = "Ordinary"
        elif name == "proposal_wrong_parent": proposal["body"]["header"]["parent"]["value"]["block_id_bytes"] = b"\x00" * 32
        elif name == "proposal_has_payload": proposal["body"]["batch_ref_count"] = 1
        elif name == "proposal_wrong_plan": proposal["body"]["source_upgrade_plan_hash"] = b"\x00" * 32
        elif name == "proposal_wrong_state": proposal["body"]["header"]["post_state_root"] = b"\x00" * 32
        value["first_v1_proposal_cev1"] = enc_proposal(proposal)
    elif name == "finality_trailing": value["first_v1_finality_proof_cev1"] += b"\x00"
    elif name == "finality_truncated": value["first_v1_finality_proof_cev1"] = value["first_v1_finality_proof_cev1"][:-1]
    elif name.startswith("finality_") or name.startswith("qc_"):
        finality = dec_finality(value["first_v1_finality_proof_cev1"])
        if name == "finality_wrong_context": finality["context"]["chain_id"] = "wrong-chain"
        elif name == "finality_wrong_target": finality["target_block_id"] = b"\x00" * 32
        elif name == "finality_chain_short": finality["certified_chain"] = finality["certified_chain"][:2]
        elif name == "finality_block_id_flip": finality["certified_chain"][1]["block_id"] = b"\x00" * 32
        elif name == "qc_signature_flip":
            sig = finality["certified_chain"][1]["certifying_qc"]["signatures"][0]["signature"]
            finality["certified_chain"][1]["certifying_qc"]["signatures"][0]["signature"] = bytes([sig[0] ^ 1]) + sig[1:]
        elif name == "qc_duplicate_signer":
            entries = finality["certified_chain"][1]["certifying_qc"]["signatures"]
            entries[1] = copy.deepcopy(entries[0]); reid_qc(finality["certified_chain"][1]["certifying_qc"])
        elif name == "qc_under_quorum":
            qc = finality["certified_chain"][1]["certifying_qc"]
            qc["signatures"] = qc["signatures"][-1:]; reid_qc(qc)
        elif name == "qc_wrong_set":
            qc = finality["certified_chain"][1]["certifying_qc"]
            qc["statement"]["consensus_context"]["validator_set_hash"] = b"\x00" * 32; reid_qc(qc)
        elif name == "qc_block_substitution":
            qc = finality["certified_chain"][1]["certifying_qc"]
            qc["statement"]["block_id"] = b"\x00" * 32; reid_qc(qc)
        elif name == "finality_parent_break":
            finality["certified_chain"][1]["header"]["parent"]["value"]["block_id"] = b"\x00" * 32
            refresh_certified(finality, 1)
        elif name == "finality_height_gap":
            finality["certified_chain"][1]["header"]["height"] += 1
            refresh_certified(finality, 1)
        elif name == "finality_view_gap":
            finality["certified_chain"][1]["header"]["view"] += 1
            refresh_certified(finality, 1)
        elif name == "finality_justify_substitution":
            finality["certified_chain"][1]["header"]["justify_qc_id"] = b"\x00" * 32
            refresh_certified(finality, 1)
        if name not in {"finality_wrong_context", "finality_wrong_target", "finality_chain_short"}:
            # Keep the outer proof identity current so the intended inner relation is exercised.
            reid_finality(finality)
        value["first_v1_finality_proof_cev1"] = enc_finality(finality)
    elif name == "activation_proof_id_flip": value["proof_id"] = b"\x00" * 32
    else: reject("unknown_mutant", name)
    if name != "activation_proof_id_flip": reid_activation(value)
    return enc_activation_proof(value)


def source_inventory() -> list[dict[str, str]]:
    return [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in SOURCE_PATHS]


def build_vector() -> dict[str, Any]:
    built, expected = build_positive()
    raw = enc_activation_proof(built["activation_proof"])
    return {
        "artifact": "poco-ai-native-v1-cross-version-activation-proof-corpus",
        "artifact_version": 1,
        "status": "candidate-non-normative",
        "schema": "../schema/cev1-cross-version-activation-proof-kernel-v1.json",
        "source_activation_kernel": source_inventory(),
        "positive_cases": [{"case_id": "exact_field12_and_separate_cev1_activation_finality",
                            "activation_proof_cev1_hex": raw.hex(), "expected": expected}],
        "negative_cases": [{"case_id": f"reject_{name}", "mutation": name, "expected_error": error} for name, error in MUTANTS],
        "explicit_exclusions": [
            "frozen-v0 EpochHandoffProof fields 13 and 14 are forbidden on this cross-version path; they are not reinterpreted as CEV1",
            "governance-state membership/finality for UpgradePlanV0 is not proved",
            "migration execution, complete source-state authentication, audit/conservation recomputation, and output construction are not proved",
            "the proposal carrier is a bounded candidate witness binding the exact V0ActivationFirst header and activation IDs; full OrderProposalV1 admission/transport remains outside this tranche",
            "delayed first-view TC, arbitrary multi-hop light-client updates, signer durability, implementation, activation, production, release readiness, and normative freeze are not proved",
        ],
    }


def build_openssl_manifest() -> dict[str, Any]:
    built, _ = build_positive()
    fixture = built["source_fixture"]
    value = built["activation_proof"]
    proposal = dec_proposal(value["first_v1_proposal_cev1"])
    finality = dec_finality(value["first_v1_finality_proof_cev1"])
    members, _ = target_members(fixture)
    member_map = {member["id"]: member for member in members}
    records = [{
        "label": "V0ActivationFirst-proposal-carrier",
        "public_key": member_map[proposal["proposer_id"]]["public"].hex(),
        "message": digest_v1(PROPOSAL_SIGNATURE_DOMAIN, enc_proposal_body(proposal["body"])).hex(),
        "signature": proposal["signature"].hex(),
    }]
    for qc_index, certified in enumerate(finality["certified_chain"]):
        qc = certified["certifying_qc"]
        root = digest_v1(VOTE_DOMAIN, enc_vote(qc["statement"]))
        for signer_index, entry in enumerate(qc["signatures"]):
            records.append({
                "label": f"QC{qc_index}-signer{signer_index}",
                "public_key": member_map[entry["voter_id"]]["public"].hex(),
                "message": root.hex(),
                "signature": entry["signature"].hex(),
            })
    bad = copy.deepcopy(records[0])
    signature = bytes.fromhex(bad["signature"])
    bad["label"] = "invalid-proposal-bitflip"
    bad["signature"] = (bytes([signature[0] ^ 1]) + signature[1:]).hex()
    return {"valid": records, "invalid": bad}


def verify_schema(schema: Any) -> None:
    require(schema.get("schema") == "trnm.poco-ai.cev1-cross-version-activation-proof-kernel.v1", "schema_identity")
    require(schema.get("schema_version") == 1 and schema.get("status") == "candidate-non-normative", "schema_status")
    require(schema.get("frozen_v0_field_policy") == {"field_12": "exact-raw-CEV0-required", "field_13": "forbidden-for-v0-to-v1", "field_14": "forbidden-for-v0-to-v1"}, "schema_field_policy")
    require(schema.get("global_completion_flags") == {"complete_v0_authority_verification": False, "complete_migration_verification": False, "upgrade_contract_complete": False, "normative_freeze": False}, "schema_completion_flags")


def run(schema_path: Path, vector_path: Path) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    verify_schema(schema)
    corpus = json.loads(vector_path.read_text(encoding="utf-8"))
    require(corpus["source_activation_kernel"] == source_inventory(), "source_inventory")
    require(corpus["explicit_exclusions"] == schema["explicit_exclusions"], "exclusion_inventory")
    require(len(corpus["positive_cases"]) == 1 and len(corpus["negative_cases"]) == len(MUTANTS), "case_inventory")
    built, expected = build_positive()
    expected_raw = enc_activation_proof(built["activation_proof"])
    committed = corpus["positive_cases"][0]
    raw = bytes.fromhex(committed["activation_proof_cev1_hex"])
    require(raw == expected_raw, "positive_vector_drift")
    result = verify_activation_proof(raw, built["source_fixture"])
    require(result == expected == committed["expected"], "positive_result_drift")
    for case, (name, error) in zip(corpus["negative_cases"], MUTANTS, strict=True):
        require(case == {"case_id": f"reject_{name}", "mutation": name, "expected_error": error}, "negative_inventory")
        candidate = mutate(raw, name)
        try:
            verify_activation_proof(candidate, built["source_fixture"])
        except EvidenceError as exc:
            actual = str(exc).split(":", 1)[0]
            require(actual == error, "negative_error", f"{name}: expected {error}, got {actual}")
        else:
            reject("negative_accepted", name)
    print(
        "cross-version activation proof: "
        f"1 positive + {len(MUTANTS)} exact-error negatives passed; "
        "raw-field12=exact; frozen-fields13-14=forbidden; "
        "proposal-signatures=1; qc-signatures=12; three-chain=true; "
        "complete-v0-authority=false; migration-execution=false; freeze=false"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTOR_PATH)
    parser.add_argument("--write-vectors", action="store_true")
    parser.add_argument("--emit-openssl-manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.write_vectors:
            args.vectors.write_text(json.dumps(build_vector(), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        if args.emit_openssl_manifest is not None:
            args.emit_openssl_manifest.write_text(
                json.dumps(build_openssl_manifest(), indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        run(args.schema, args.vectors)
    except (EvidenceError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"cross-version activation proof FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
