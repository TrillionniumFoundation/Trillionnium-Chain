#!/usr/bin/env python3
"""Standalone bounded verifier for the candidate v0-to-v1 activation kernel."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any, NoReturn


P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)
U64_MAX = 2**64 - 1
ROOT = Path(__file__).resolve().parents[2]

FROZEN_V0_EVIDENCE_SOURCES = (
    (
        "docs/protocol/poco-bft-v0/schema/cev0-logical-schema-joint-handoff-kernel-v0.json",
        "e79fe77f0cb92be40ad5d0f2f39f9c872d1e187475d1bc80195530322b8f8da0",
    ),
    (
        "docs/protocol/poco-bft-v0/vectors/joint-handoff-composition-kernel-v0.json",
        "f57992d7e97427efd3a62f59b2cc1e2eec8a053e2649ec0ca73a47343fb6a7cf",
    ),
    (
        "scripts/ci/check_poco_bft_v0_joint_handoff_schema.mjs",
        "db3648de956ed6e2b441d67b9c7da8677ddc73e117c7c9be6e7f554402bc4d56",
    ),
)


class KernelError(Exception):
    """Expected fail-closed evidence rejection."""


def fail(code: str, detail: str = "") -> NoReturn:
    raise KernelError(f"{code}: {detail}" if detail else code)


def require(condition: bool, code: str, detail: str = "") -> None:
    if not condition:
        fail(code, detail)


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), "shape", label)
    actual = set(value)
    require(actual == keys, "shape", f"{label}: missing={sorted(keys - actual)} extra={sorted(actual - keys)}")
    return value


def uint(value: Any, bits: int, label: str) -> int:
    require(type(value) is int and 0 <= value < 2**bits, "integer", label)
    return value


def hex_bytes(value: Any, length: int | None, label: str) -> bytes:
    require(isinstance(value, str) and len(value) % 2 == 0, "hex", label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        fail("hex", label)
    if length is not None:
        require(len(raw) == length, "length", label)
    return raw


def consensus_string(value: Any, label: str) -> bytes:
    require(isinstance(value, str), "string", label)
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError:
        fail("string", label)
    require(len(raw) <= 4096, "bound", label)
    return raw


def cev_u(value: Any, bits: int, label: str) -> bytes:
    return uint(value, bits, label).to_bytes(bits // 8, "little")


def cev_hash(value: Any, label: str) -> bytes:
    return hex_bytes(value, 32, label)


def cev_bytes(value: Any, label: str) -> bytes:
    raw = hex_bytes(value, None, label)
    require(len(raw) < 2**32, "bound", label)
    return struct.pack("<I", len(raw)) + raw


def cev_string(value: Any, label: str) -> bytes:
    raw = consensus_string(value, label)
    return struct.pack("<I", len(raw)) + raw


def cev_option_hash(value: Any, label: str) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + cev_hash(value, label)


def join(*parts: bytes) -> bytes:
    return b"".join(parts)


def digest(domain: str, encoded: bytes) -> str:
    raw_domain = domain.encode("ascii", "strict")
    require(bool(raw_domain) and len(raw_domain) < 2**32, "domain", domain)
    return hashlib.sha256(struct.pack("<I", len(raw_domain)) + raw_domain + encoded).hexdigest()


def digest_v0(domain: str, encoded: bytes) -> str:
    prefix = b"trnm.cev0.hash.v0"
    raw_domain = domain.encode("ascii", "strict")
    frame = lambda raw: len(raw).to_bytes(4, "big") + raw
    return hashlib.sha256(frame(prefix) + frame(raw_domain) + frame(encoded)).hexdigest()


CONTEXT_KEYS = {"schema_version", "genesis_hash", "chain_id", "protocol_version", "stack_profile_hash"}


def encode_context(value: Any, label: str) -> bytes:
    obj = exact_keys(value, CONTEXT_KEYS, label)
    require(obj["schema_version"] == 1, "context_version", label)
    require(obj["protocol_version"] == 1, "target_version", label)
    return join(
        cev_u(obj["schema_version"], 16, f"{label}.schema_version"),
        cev_hash(obj["genesis_hash"], f"{label}.genesis_hash"),
        cev_string(obj["chain_id"], f"{label}.chain_id"),
        cev_u(obj["protocol_version"], 32, f"{label}.protocol_version"),
        cev_hash(obj["stack_profile_hash"], f"{label}.stack_profile_hash"),
    )


CONFIG_KEYS = {
    "schema_version", "source_v0_validator_set_hash", "source_v0_consensus_parameters_hash",
    "target_v1_validator_set_hash", "target_v1_consensus_parameters_hash",
    "validator_supplement_manifest_hash", "parameter_mapping_version", "migration_program_hash",
}


def encode_configuration(value: Any) -> bytes:
    obj = exact_keys(value, CONFIG_KEYS, "configuration_projection.body")
    require(obj["schema_version"] == 1, "schema_version", "configuration_projection")
    return join(
        cev_u(obj["schema_version"], 16, "configuration.schema_version"),
        *(cev_hash(obj[name], f"configuration.{name}") for name in (
            "source_v0_validator_set_hash", "source_v0_consensus_parameters_hash",
            "target_v1_validator_set_hash", "target_v1_consensus_parameters_hash",
            "validator_supplement_manifest_hash",
        )),
        cev_u(obj["parameter_mapping_version"], 32, "configuration.parameter_mapping_version"),
        cev_hash(obj["migration_program_hash"], "configuration.migration_program_hash"),
    )


ARTIFACT_KEYS = {
    "schema_version", "target_protocol_version", "upgrade_plan_id", "protocol_spec_manifest_hash",
    "schema_manifest_hash", "conformance_bundle_hash", "binary_artifact_manifest_hash", "sbom_hash",
    "provenance_hash", "cross_version_verifier_hash",
}


def encode_artifact(value: Any) -> bytes:
    obj = exact_keys(value, ARTIFACT_KEYS, "artifact_manifest.body")
    require(obj["schema_version"] == 1, "schema_version", "artifact_manifest")
    require(obj["target_protocol_version"] == 1, "target_version", "artifact_manifest")
    return join(
        cev_u(obj["schema_version"], 16, "artifact.schema_version"),
        cev_u(obj["target_protocol_version"], 32, "artifact.target_protocol_version"),
        *(cev_hash(obj[name], f"artifact.{name}") for name in (
            "upgrade_plan_id", "protocol_spec_manifest_hash", "schema_manifest_hash",
            "conformance_bundle_hash", "binary_artifact_manifest_hash", "sbom_hash",
            "provenance_hash", "cross_version_verifier_hash",
        )),
    )


MIGRATION_KEYS = {
    "schema_version", "context", "upgrade_plan_id", "source_terminal_checkpoint_id",
    "source_terminal_finality_proof_hash", "source_terminal_height", "migration_program_hash",
    "migration_input_root", "migration_output_root", "migration_receipts_root",
    "rejected_objects_root", "audit_manifest_hash",
}


def encode_migration(value: Any) -> bytes:
    obj = exact_keys(value, MIGRATION_KEYS, "migration_receipt.body")
    require(obj["schema_version"] == 1, "schema_version", "migration_receipt")
    return join(
        cev_u(obj["schema_version"], 16, "migration.schema_version"),
        encode_context(obj["context"], "migration.context"),
        *(cev_hash(obj[name], f"migration.{name}") for name in (
            "upgrade_plan_id", "source_terminal_checkpoint_id", "source_terminal_finality_proof_hash",
        )),
        cev_u(obj["source_terminal_height"], 64, "migration.source_terminal_height"),
        *(cev_hash(obj[name], f"migration.{name}") for name in (
            "migration_program_hash", "migration_input_root", "migration_output_root",
            "migration_receipts_root", "rejected_objects_root", "audit_manifest_hash",
        )),
    )


STATEMENT_KEYS = {
    "schema_version", "context", "source_v0_genesis_hash", "source_v0_chain_id",
    "source_upgrade_plan_hash", "upgrade_plan_id", "source_terminal_checkpoint_id",
    "source_terminal_block_id", "source_terminal_finality_proof_hash", "migration_receipt_id",
    "source_v0_old_validator_set_hash", "source_v0_new_validator_set_hash",
    "source_v0_target_consensus_parameters_hash", "target_v1_validator_set_hash",
    "target_v1_consensus_parameters_hash", "configuration_projection_hash",
    "target_epoch_descriptor_id", "activation_epoch", "activation_height",
}


def encode_statement(value: Any) -> bytes:
    obj = exact_keys(value, STATEMENT_KEYS, "activation_statement.body")
    require(obj["schema_version"] == 1, "schema_version", "activation_statement")
    return join(
        cev_u(obj["schema_version"], 16, "statement.schema_version"),
        encode_context(obj["context"], "statement.context"),
        cev_hash(obj["source_v0_genesis_hash"], "statement.source_v0_genesis_hash"),
        cev_string(obj["source_v0_chain_id"], "statement.source_v0_chain_id"),
        *(cev_hash(obj[name], f"statement.{name}") for name in (
            "source_upgrade_plan_hash", "upgrade_plan_id", "source_terminal_checkpoint_id",
            "source_terminal_block_id", "source_terminal_finality_proof_hash", "migration_receipt_id",
            "source_v0_old_validator_set_hash", "source_v0_new_validator_set_hash",
            "source_v0_target_consensus_parameters_hash", "target_v1_validator_set_hash",
            "target_v1_consensus_parameters_hash", "configuration_projection_hash",
            "target_epoch_descriptor_id",
        )),
        cev_u(obj["activation_epoch"], 64, "statement.activation_epoch"),
        cev_u(obj["activation_height"], 64, "statement.activation_height"),
    )


ANCHOR_KEYS = {
    "schema_version", "target_context", "activation_statement_id", "handoff_certificate_digest_v0",
    "terminal_qc_digest_v0", "source_terminal_block_id", "target_epoch_descriptor_id",
    "activation_height", "initial_view",
}


def encode_anchor(value: Any) -> bytes:
    obj = exact_keys(value, ANCHOR_KEYS, "activation_anchor.body")
    require(obj["schema_version"] == 1, "schema_version", "activation_anchor")
    return join(
        cev_u(obj["schema_version"], 16, "anchor.schema_version"),
        encode_context(obj["target_context"], "anchor.target_context"),
        *(cev_hash(obj[name], f"anchor.{name}") for name in (
            "activation_statement_id", "handoff_certificate_digest_v0", "terminal_qc_digest_v0",
            "source_terminal_block_id", "target_epoch_descriptor_id",
        )),
        cev_u(obj["activation_height"], 64, "anchor.activation_height"),
        cev_u(obj["initial_view"], 64, "anchor.initial_view"),
    )


def empty_root(root_kind: int, domain: str) -> str:
    encoded = cev_u(root_kind, 16, "root_kind") + cev_u(0, 32, "item_count") + b"\x00"
    return digest(domain, encoded)


def point_inv(value: int) -> int:
    return pow(value % P, P - 2, P)


def recover_x(y: int) -> int:
    square = ((y * y - 1) * point_inv(D * y * y + 1)) % P
    x = pow(square, (P + 3) // 8, P)
    if (x * x - square) % P:
        x = (x * SQRT_M1) % P
    if (x * x - square) % P:
        fail("ed25519_point")
    return P - x if x & 1 else x


BASE_Y = (4 * point_inv(5)) % P
BASE_X = recover_x(BASE_Y)
BASE = (BASE_X, BASE_Y, 1, (BASE_X * BASE_Y) % P)


def point_add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = ((y1 - x1) * (y2 - x2)) % P
    bb = ((y1 + x1) * (y2 + x2)) % P
    cc = (2 * D * t1 * t2) % P
    dd = (2 * z1 * z2) % P
    ee = (bb - aa) % P
    ff = (dd - cc) % P
    gg = (dd + cc) % P
    hh = (bb + aa) % P
    return (ee * ff % P, gg * hh % P, ff * gg % P, ee * hh % P)


def point_mul(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = IDENTITY
    current = point
    while scalar:
        if scalar & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        scalar >>= 1
    return result


def point_eq(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def decode_point(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    encoded = int.from_bytes(raw, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= P:
        return None
    try:
        x = recover_x(y)
    except KernelError:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def ed25519_verify(message: bytes, public_key: bytes, signature: bytes) -> bool:
    if len(message) != 32 or len(public_key) != 32 or len(signature) != 64:
        return False
    public = decode_point(public_key)
    r_point = decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if public is None or r_point is None or scalar >= L:
        return False
    if point_eq(point_mul(public, 8), IDENTITY) or point_eq(point_mul(r_point, 8), IDENTITY):
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return point_eq(point_mul(BASE, scalar), point_add(r_point, point_mul(public, challenge)))


SET_KEYS = {"format", "set_hash", "descriptor"}
V0_SET_KEYS = {"schema_version", "genesis_hash", "chain_id", "protocol_version", "epoch", "consensus_parameters_hash", "validators"}
V0_MEMBER_KEYS = {"validator_id", "consensus_public_key", "effective_weight"}
V1_SET_KEYS = {"schema_version", "context", "epoch", "definition"}
V1_DEFINITION_KEYS = {"schema_version", "members", "total_weight", "quorum_threshold"}
V1_MEMBER_KEYS = {"validator_id", "consensus_key_scheme", "consensus_public_key", "voting_weight", "network_identity_commitment", "safety_signer_policy_hash", "poco_economic_record_hash"}
ENTRY_KEYS = {"signer_id", "role", "signing_set_hash", "signature_scheme", "signature"}


def committed_set(set_value: Any, label: str) -> tuple[str, dict[str, tuple[bytes, int]], int]:
    signing_set = exact_keys(set_value, SET_KEYS, f"{label}.set")
    declared_hash = cev_hash(signing_set["set_hash"], f"{label}.set_hash").hex()
    descriptor = signing_set["descriptor"]
    if signing_set["format"] == "frozen-v0-validator-set":
        value = exact_keys(descriptor, V0_SET_KEYS, f"{label}.descriptor")
        require(value["schema_version"] == 0 and value["protocol_version"] == 0, "validator_set_version", label)
        parts = [uint(value["schema_version"], 16, "v0.schema_version").to_bytes(2, "big"), cev_hash(value["genesis_hash"], "v0.genesis_hash")]
        raw_chain = consensus_string(value["chain_id"], "v0.chain_id")
        require(re.fullmatch(rb"[a-z0-9][a-z0-9._:-]{0,127}", raw_chain) is not None, "validator_set_chain", label)
        parts.extend((len(raw_chain).to_bytes(2, "big"), raw_chain, uint(value["protocol_version"], 32, "v0.protocol_version").to_bytes(4, "big"), uint(value["epoch"], 64, "v0.epoch").to_bytes(8, "big"), cev_hash(value["consensus_parameters_hash"], "v0.parameters")))
        members = value["validators"]
        require(isinstance(members, list) and members, "validator_set", label)
        parts.append(len(members).to_bytes(4, "big"))
        member_map: dict[str, tuple[bytes, int]] = {}
        seen_keys: set[bytes] = set()
        previous: bytes | None = None
        total = 0
        for index, raw in enumerate(members):
            member = exact_keys(raw, V0_MEMBER_KEYS, f"{label}.member[{index}]")
            signer = hex_bytes(member["validator_id"], None, f"{label}.validator_id")
            require(bool(signer) and len(signer) <= 128 and (previous is None or previous < signer), "validator_set_order", label)
            previous = signer
            key = hex_bytes(member["consensus_public_key"], 32, f"{label}.public_key")
            require(key not in seen_keys, "duplicate_public_key", label)
            seen_keys.add(key)
            weight = uint(member["effective_weight"], 64, f"{label}.weight")
            require(weight > 0, "validator_weight", label)
            total += weight
            require(total < 2**128, "weight_overflow", label)
            parts.extend((len(signer).to_bytes(4, "big"), signer, key, weight.to_bytes(8, "big")))
            member_map[signer.hex()] = (key, weight)
        computed_hash = digest_v0("trnm.poco-bft.validator-set.v0", join(*parts))
    elif signing_set["format"] == "cev1-validator-set-descriptor":
        value = exact_keys(descriptor, V1_SET_KEYS, f"{label}.descriptor")
        require(value["schema_version"] == 1, "validator_set_version", label)
        definition = exact_keys(value["definition"], V1_DEFINITION_KEYS, f"{label}.definition")
        require(definition["schema_version"] == 1, "validator_set_version", label)
        members = definition["members"]
        require(isinstance(members, list) and members, "validator_set", label)
        member_encoded: list[bytes] = []
        member_map = {}
        seen_keys = set()
        previous = None
        total = 0
        for index, raw in enumerate(members):
            member = exact_keys(raw, V1_MEMBER_KEYS, f"{label}.member[{index}]")
            signer = hex_bytes(member["validator_id"], None, f"{label}.validator_id")
            require(bool(signer) and (previous is None or previous < signer), "validator_set_order", label)
            previous = signer
            require(member["consensus_key_scheme"] == 0, "signature_scheme", label)
            key = hex_bytes(member["consensus_public_key"], 32, f"{label}.public_key")
            require(key not in seen_keys, "duplicate_public_key", label)
            seen_keys.add(key)
            weight = uint(member["voting_weight"], 128, f"{label}.weight")
            require(weight > 0, "validator_weight", label)
            total += weight
            require(total < 2**128, "weight_overflow", label)
            member_encoded.append(join(
                struct.pack("<I", len(signer)), signer, cev_u(member["consensus_key_scheme"], 16, "key scheme"),
                struct.pack("<I", len(key)), key,
                cev_u(weight, 128, "weight"), cev_hash(member["network_identity_commitment"], "network"),
                cev_hash(member["safety_signer_policy_hash"], "safety"), cev_hash(member["poco_economic_record_hash"], "poco"),
            ))
            member_map[signer.hex()] = (key, weight)
        quorum = (2 * total) // 3 + 1
        require(definition["total_weight"] == total and definition["quorum_threshold"] == quorum, "validator_set_totals", label)
        definition_bytes = join(cev_u(1, 16, "definition version"), struct.pack("<I", len(members)), *member_encoded, cev_u(total, 128, "total"), cev_u(quorum, 128, "quorum"))
        descriptor_bytes = join(cev_u(1, 16, "descriptor version"), encode_context(value["context"], f"{label}.context"), cev_u(value["epoch"], 64, "epoch"), definition_bytes)
        computed_hash = digest("trnm.poco-ai.validator-set.v1", descriptor_bytes)
    else:
        fail("validator_set_format", label)
    require(declared_hash == computed_hash, "validator_set_hash", label)
    quorum = (2 * total) // 3 + 1
    return computed_hash, member_map, quorum


def verify_signature_set(set_value: Any, entries_value: Any, role: int, statement_id: str, domain: str, label: str) -> None:
    set_hash, member_map, quorum = committed_set(set_value, label)
    entries = entries_value
    require(isinstance(entries, list) and entries, "signature_list", label)
    previous = None
    signed_weight = 0
    signing_root = bytes.fromhex(digest(domain, bytes.fromhex(statement_id)))
    for index, raw in enumerate(entries):
        entry = exact_keys(raw, ENTRY_KEYS, f"{label}.signature[{index}]")
        signer = hex_bytes(entry["signer_id"], None, f"{label}.signature.signer_id")
        require(previous is None or previous < signer, "signature_order", label)
        previous = signer
        require(entry["role"] == role, "signature_role", label)
        require(entry["signing_set_hash"] == set_hash, "signature_set", label)
        require(entry["signature_scheme"] == 0, "signature_scheme", label)
        require(signer.hex() in member_map, "unknown_signer", label)
        signature = hex_bytes(entry["signature"], 64, f"{label}.signature")
        key, weight = member_map[signer.hex()]
        require(ed25519_verify(signing_root, key, signature), "invalid_signature", label)
        signed_weight += weight
    require(signed_weight >= quorum, "insufficient_quorum", f"{label}: {signed_weight} < {quorum}")


PLAN_KEYS = {
    "upgrade_plan_id", "source_protocol_version", "target_protocol_version", "source_v0_genesis_hash",
    "source_v0_chain_id", "activation_epoch", "activation_height", "source_epoch",
    "source_epoch_start_height", "epoch_length_blocks", "source_terminal_height",
    "target_stack_profile_hash", "target_runtime_profile_hash", "source_v0_target_validator_set_hash",
    "source_v0_target_consensus_parameters_hash", "target_v1_validator_set_hash",
    "target_v1_consensus_parameters_hash", "configuration_projection_hash",
    "target_epoch_descriptor_id", "target_chain_descriptor_hash", "migration_program_hash",
    "conformance_bundle_hash", "rollback_policy",
}
V0_KEYS = {
    "source_upgrade_plan_hash", "current_protocol_version", "target_protocol_version", "activation_epoch",
    "activation_height", "target_validator_set_hash", "target_consensus_parameters_hash",
    "state_migration_hash", "artifact_manifest_hash", "source_terminal_checkpoint_id",
    "source_terminal_block_id", "source_terminal_finality_proof_hash", "terminal_qc_digest_v0",
    "handoff_certificate_digest_v0", "old_validator_set_hash", "new_validator_set_hash",
    "evidence_contract", "source_artifacts", "authorization_output",
    "deferred_transport_fields",
}
FIRST_KEYS = {
    "block_kind", "context", "epoch", "height", "view", "initial_view", "parent_kind",
    "parent_block_id", "parent_handoff_certificate_digest_v0", "parent_activation_statement_id",
    "epoch_descriptor_id", "justify_qc_id", "timeout_certificate_id", "batch_ref_count",
    "protocol_sidecar_count", "batch_refs_root", "protocol_objects_root", "post_state_root",
    "transaction_execution_receipts_root", "evidence_root", "consumption_rollups_root",
    "settlement_root", "resource_usage_root", "next_epoch_descriptor_id", "upgrade_plan_id",
    "epoch_handoff_id", "activation_statement_id", "activation_anchor_id",
    "handoff_certificate_digest_v0", "terminal_qc_digest_v0", "migration_receipt_id",
}
FIXTURE_KEYS = {
    "plan_projection", "frozen_v0_evidence_projection", "configuration_projection",
    "artifact_manifest", "migration_receipt", "activation_statement", "old_signing_set",
    "new_signing_set", "activation_certificate", "activation_anchor", "first_v1_block_projection",
}


def same_context(left: Any, right: Any, label: str) -> None:
    encode_context(left, f"{label}.left")
    encode_context(right, f"{label}.right")
    require(left == right, "context_mismatch", label)


def verify_fixture(raw: Any, domains: dict[str, str]) -> None:
    fixture = exact_keys(raw, FIXTURE_KEYS, "fixture")
    plan = exact_keys(fixture["plan_projection"], PLAN_KEYS, "plan_projection")
    v0 = exact_keys(fixture["frozen_v0_evidence_projection"], V0_KEYS, "frozen_v0_evidence_projection")

    require(plan["source_protocol_version"] == 0, "source_version")
    require(plan["target_protocol_version"] == 1, "target_version")
    require(plan["rollback_policy"] == 0, "downgrade_or_fallback")
    for name in ("source_epoch", "source_epoch_start_height", "epoch_length_blocks", "source_terminal_height", "activation_epoch", "activation_height"):
        uint(plan[name], 64, f"plan.{name}")
    require(plan["epoch_length_blocks"] > 0, "activation_geometry")
    require(plan["source_epoch"] < U64_MAX and plan["activation_epoch"] == plan["source_epoch"] + 1, "activation_epoch")
    expected_height = plan["source_epoch_start_height"] + plan["epoch_length_blocks"]
    require(expected_height <= U64_MAX and plan["activation_height"] == expected_height, "activation_height")
    require(plan["activation_height"] > 0 and plan["source_terminal_height"] == plan["activation_height"] - 1, "terminal_height")

    require(
        v0["evidence_contract"] == "bounded-v0-epoch-handoff-fields-1-through-11",
        "v0_evidence_contract",
    )
    require(v0["authorization_output"] is False, "v0_evidence_authority_boundary")
    require(v0["deferred_transport_fields"] == [12, 13, 14], "v0_evidence_deferred_fields")
    expected_sources = [
        {"path": path, "sha256": expected_hash}
        for path, expected_hash in FROZEN_V0_EVIDENCE_SOURCES
    ]
    require(v0["source_artifacts"] == expected_sources, "v0_evidence_source_inventory")
    for path, expected_hash in FROZEN_V0_EVIDENCE_SOURCES:
        source_path = ROOT / path
        require(source_path.is_file(), "v0_evidence_source_missing", path)
        require(
            hashlib.sha256(source_path.read_bytes()).hexdigest() == expected_hash,
            "v0_evidence_source_hash",
            path,
        )
    require(v0["current_protocol_version"] == 0 and v0["target_protocol_version"] == 1, "v0_version")
    for field in ("activation_epoch", "activation_height"):
        require(v0[field] == plan[field], "v0_plan_binding", field)
    require(v0["target_validator_set_hash"] == plan["source_v0_target_validator_set_hash"], "v0_plan_binding", "validator_set")
    require(v0["target_consensus_parameters_hash"] == plan["source_v0_target_consensus_parameters_hash"], "v0_plan_binding", "parameters")
    require(v0["state_migration_hash"] == plan["migration_program_hash"], "v0_plan_binding", "migration")
    require(v0["new_validator_set_hash"] == plan["source_v0_target_validator_set_hash"], "v0_plan_binding", "new_set")

    config = exact_keys(fixture["configuration_projection"], {"body", "hash"}, "configuration_projection")
    config_hash = digest(domains["configuration_projection"], encode_configuration(config["body"]))
    require(config["hash"] == config_hash == plan["configuration_projection_hash"], "configuration_projection_hash")
    require(config["body"]["source_v0_validator_set_hash"] == plan["source_v0_target_validator_set_hash"], "configuration_projection_binding", "source set")
    require(config["body"]["source_v0_consensus_parameters_hash"] == plan["source_v0_target_consensus_parameters_hash"], "configuration_projection_binding", "source parameters")
    require(config["body"]["target_v1_validator_set_hash"] == plan["target_v1_validator_set_hash"], "configuration_projection_binding", "target set")
    require(config["body"]["target_v1_consensus_parameters_hash"] == plan["target_v1_consensus_parameters_hash"], "configuration_projection_binding", "target parameters")
    require(config["body"]["migration_program_hash"] == plan["migration_program_hash"], "configuration_projection_binding", "migration")

    artifact = exact_keys(fixture["artifact_manifest"], {"body", "hash"}, "artifact_manifest")
    artifact_hash = digest(domains["artifact_manifest"], encode_artifact(artifact["body"]))
    require(artifact["hash"] == artifact_hash == v0["artifact_manifest_hash"], "artifact_manifest_hash")
    require(artifact["body"]["upgrade_plan_id"] == plan["upgrade_plan_id"], "upgrade_plan_binding", "artifact")
    require(artifact["body"]["conformance_bundle_hash"] == plan["conformance_bundle_hash"], "artifact_plan_binding", "conformance")

    migration = exact_keys(fixture["migration_receipt"], {"body", "id"}, "migration_receipt")
    migration_id = digest(domains["migration_receipt"], encode_migration(migration["body"]))
    require(migration["id"] == migration_id, "migration_receipt_id")
    mbody = migration["body"]
    require(mbody["upgrade_plan_id"] == plan["upgrade_plan_id"], "upgrade_plan_binding", "migration")
    require(mbody["source_terminal_checkpoint_id"] == v0["source_terminal_checkpoint_id"], "terminal_binding", "checkpoint")
    require(mbody["source_terminal_finality_proof_hash"] == v0["source_terminal_finality_proof_hash"], "terminal_binding", "finality")
    require(mbody["source_terminal_height"] == plan["source_terminal_height"], "terminal_binding", "height")
    require(mbody["migration_program_hash"] == plan["migration_program_hash"], "migration_binding")

    statement = exact_keys(fixture["activation_statement"], {"body", "id"}, "activation_statement")
    statement_id = digest(domains["activation_statement"], encode_statement(statement["body"]))
    require(statement["id"] == statement_id, "activation_statement_id")
    sbody = statement["body"]
    same_context(mbody["context"], sbody["context"], "migration_statement")
    require(sbody["context"]["genesis_hash"] == plan["target_chain_descriptor_hash"], "target_chain_binding")
    require(sbody["context"]["stack_profile_hash"] == plan["target_stack_profile_hash"], "target_profile_binding")
    require(sbody["source_v0_genesis_hash"] == plan["source_v0_genesis_hash"], "source_chain_binding", "genesis")
    require(sbody["source_v0_chain_id"] == plan["source_v0_chain_id"], "source_chain_binding", "chain_id")
    require(sbody["source_upgrade_plan_hash"] == v0["source_upgrade_plan_hash"], "v0_plan_binding", "plan hash")
    require(sbody["upgrade_plan_id"] == plan["upgrade_plan_id"], "upgrade_plan_binding", "statement")
    require(sbody["source_terminal_checkpoint_id"] == v0["source_terminal_checkpoint_id"], "terminal_binding", "statement checkpoint")
    require(sbody["source_terminal_block_id"] == v0["source_terminal_block_id"], "terminal_binding", "statement block")
    require(sbody["source_terminal_finality_proof_hash"] == v0["source_terminal_finality_proof_hash"], "terminal_binding", "statement finality")
    require(sbody["migration_receipt_id"] == migration_id, "migration_binding", "statement receipt")
    require(sbody["source_v0_old_validator_set_hash"] == v0["old_validator_set_hash"], "set_binding", "old")
    require(sbody["source_v0_new_validator_set_hash"] == v0["new_validator_set_hash"], "set_binding", "new")
    require(sbody["source_v0_target_consensus_parameters_hash"] == plan["source_v0_target_consensus_parameters_hash"], "parameter_binding", "source")
    require(sbody["target_v1_validator_set_hash"] == plan["target_v1_validator_set_hash"], "set_binding", "target")
    require(sbody["target_v1_consensus_parameters_hash"] == plan["target_v1_consensus_parameters_hash"], "parameter_binding", "target")
    require(sbody["configuration_projection_hash"] == config_hash, "configuration_projection_binding", "statement")
    require(sbody["target_epoch_descriptor_id"] == plan["target_epoch_descriptor_id"], "descriptor_binding")
    require(sbody["activation_epoch"] == plan["activation_epoch"] and sbody["activation_height"] == plan["activation_height"], "activation_binding")

    certificate = exact_keys(fixture["activation_certificate"], {"statement_id", "old_set_signatures", "new_set_signatures"}, "activation_certificate")
    require(certificate["statement_id"] == statement_id, "activation_certificate_statement")
    old_descriptor = fixture["old_signing_set"]["descriptor"]
    new_descriptor = fixture["new_signing_set"]["descriptor"]
    require(old_descriptor["genesis_hash"] == plan["source_v0_genesis_hash"] and old_descriptor["chain_id"] == plan["source_v0_chain_id"], "signing_set_context", "old")
    require(old_descriptor["epoch"] == plan["source_epoch"], "signing_set_context", "old")
    same_context(new_descriptor["context"], sbody["context"], "new_signing_set")
    require(new_descriptor["epoch"] == plan["activation_epoch"], "signing_set_context", "new")
    require(fixture["old_signing_set"]["set_hash"] == sbody["source_v0_old_validator_set_hash"], "set_binding", "old signing set")
    require(fixture["new_signing_set"]["set_hash"] == sbody["target_v1_validator_set_hash"], "set_binding", "new signing set")
    verify_signature_set(fixture["old_signing_set"], certificate["old_set_signatures"], 0, statement_id, domains["activation_old_signature"], "old")
    verify_signature_set(fixture["new_signing_set"], certificate["new_set_signatures"], 1, statement_id, domains["activation_new_signature"], "new")

    anchor = exact_keys(fixture["activation_anchor"], {"body", "id"}, "activation_anchor")
    anchor_id = digest(domains["activation_anchor"], encode_anchor(anchor["body"]))
    require(anchor["id"] == anchor_id, "activation_anchor_id")
    abody = anchor["body"]
    same_context(abody["target_context"], sbody["context"], "anchor_statement")
    require(abody["activation_statement_id"] == statement_id, "activation_anchor_binding", "statement")
    require(abody["handoff_certificate_digest_v0"] == v0["handoff_certificate_digest_v0"], "activation_anchor_binding", "handoff")
    require(abody["terminal_qc_digest_v0"] == v0["terminal_qc_digest_v0"], "activation_anchor_binding", "terminal qc")
    require(abody["source_terminal_block_id"] == v0["source_terminal_block_id"], "activation_anchor_binding", "terminal block")
    require(abody["target_epoch_descriptor_id"] == plan["target_epoch_descriptor_id"], "activation_anchor_binding", "descriptor")
    require(abody["activation_height"] == plan["activation_height"], "activation_anchor_binding", "height")
    require(uint(abody["initial_view"], 64, "anchor.initial_view") > 0, "initial_view")

    block = exact_keys(fixture["first_v1_block_projection"], FIRST_KEYS, "first_v1_block_projection")
    same_context(block["context"], sbody["context"], "block_statement")
    require(block["block_kind"] == 5, "first_block_kind")
    require(block["parent_kind"] == 2, "first_block_parent_kind")
    require(block["epoch"] == plan["activation_epoch"] and block["height"] == plan["activation_height"], "first_block_activation")
    require(block["initial_view"] == abody["initial_view"] and block["view"] == abody["initial_view"], "first_block_view")
    require(block["parent_block_id"] == v0["source_terminal_block_id"], "first_block_parent")
    require(block["parent_handoff_certificate_digest_v0"] == v0["handoff_certificate_digest_v0"], "first_block_handoff")
    require(block["parent_activation_statement_id"] == statement_id, "first_block_statement")
    require(block["epoch_descriptor_id"] == plan["target_epoch_descriptor_id"], "first_block_descriptor")
    require(block["justify_qc_id"] is None and block["timeout_certificate_id"] is None, "first_block_justification")
    require(block["batch_ref_count"] == 0 and block["protocol_sidecar_count"] == 0, "first_block_payload")
    root_fields = (
        "batch_refs_root", "protocol_objects_root", "transaction_execution_receipts_root",
        "evidence_root", "consumption_rollups_root", "settlement_root", "resource_usage_root",
    )
    for root_kind, field in enumerate(root_fields):
        require(block[field] == empty_root(root_kind, domains["merkle_list_root"]), "first_block_empty_root", field)
    require(block["post_state_root"] == mbody["migration_output_root"], "first_block_state")
    require(block["next_epoch_descriptor_id"] is None and block["upgrade_plan_id"] is None and block["epoch_handoff_id"] is None, "first_block_forbidden_option")
    require(block["activation_statement_id"] == statement_id, "first_block_bundle", "statement")
    require(block["activation_anchor_id"] == anchor_id, "first_block_bundle", "anchor")
    require(block["handoff_certificate_digest_v0"] == v0["handoff_certificate_digest_v0"], "first_block_bundle", "handoff")
    require(block["terminal_qc_digest_v0"] == v0["terminal_qc_digest_v0"], "first_block_bundle", "terminal qc")
    require(block["migration_receipt_id"] == migration_id, "first_block_bundle", "migration")


EXPECTED_SCHEMA_TYPES = {
    "ProtocolContextV1": [["schema_version", "u16"], ["genesis_hash", "Hash32"], ["chain_id", "ConsensusString"], ["protocol_version", "u32"], ["stack_profile_hash", "Hash32"]],
    "ValidatorMemberV1": [["validator_id", "Bytes"], ["consensus_key_scheme", "u16"], ["consensus_public_key", "Bytes"], ["voting_weight", "u128"], ["network_identity_commitment", "Hash32"], ["safety_signer_policy_hash", "Hash32"], ["poco_economic_record_hash", "Hash32"]],
    "ValidatorSetDefinitionV1": [["schema_version", "u16"], ["members", "List<ValidatorMemberV1>"], ["total_weight", "u128"], ["quorum_threshold", "u128"]],
    "ValidatorSetDescriptorV1": [["schema_version", "u16"], ["context", "ProtocolContextV1"], ["epoch", "u64"], ["definition", "ValidatorSetDefinitionV1"]],
    "V0ToV1ConfigurationProjectionV1": [["schema_version", "u16"], ["source_v0_validator_set_hash", "Hash32"], ["source_v0_consensus_parameters_hash", "Hash32"], ["target_v1_validator_set_hash", "Hash32"], ["target_v1_consensus_parameters_hash", "Hash32"], ["validator_supplement_manifest_hash", "Hash32"], ["parameter_mapping_version", "u32"], ["migration_program_hash", "Hash32"]],
    "V0ToV1ArtifactManifestBodyV1": [["schema_version", "u16"], ["target_protocol_version", "u32"], ["upgrade_plan_id", "Hash32"], ["protocol_spec_manifest_hash", "Hash32"], ["schema_manifest_hash", "Hash32"], ["conformance_bundle_hash", "Hash32"], ["binary_artifact_manifest_hash", "Hash32"], ["sbom_hash", "Hash32"], ["provenance_hash", "Hash32"], ["cross_version_verifier_hash", "Hash32"]],
    "MigrationReceiptBodyV1": [["schema_version", "u16"], ["context", "ProtocolContextV1"], ["upgrade_plan_id", "Hash32"], ["source_terminal_checkpoint_id", "Hash32"], ["source_terminal_finality_proof_hash", "Hash32"], ["source_terminal_height", "u64"], ["migration_program_hash", "Hash32"], ["migration_input_root", "Hash32"], ["migration_output_root", "Hash32"], ["migration_receipts_root", "Hash32"], ["rejected_objects_root", "Hash32"], ["audit_manifest_hash", "Hash32"]],
    "V0ToV1ActivationStatementBodyV1": [["schema_version", "u16"], ["context", "ProtocolContextV1"], ["source_v0_genesis_hash", "Hash32"], ["source_v0_chain_id", "ConsensusString"], ["source_upgrade_plan_hash", "Hash32"], ["upgrade_plan_id", "Hash32"], ["source_terminal_checkpoint_id", "Hash32"], ["source_terminal_block_id", "Hash32"], ["source_terminal_finality_proof_hash", "Hash32"], ["migration_receipt_id", "Hash32"], ["source_v0_old_validator_set_hash", "Hash32"], ["source_v0_new_validator_set_hash", "Hash32"], ["source_v0_target_consensus_parameters_hash", "Hash32"], ["target_v1_validator_set_hash", "Hash32"], ["target_v1_consensus_parameters_hash", "Hash32"], ["configuration_projection_hash", "Hash32"], ["target_epoch_descriptor_id", "Hash32"], ["activation_epoch", "u64"], ["activation_height", "u64"]],
    "ActivationAnchorBodyV1": [["schema_version", "u16"], ["target_context", "ProtocolContextV1"], ["activation_statement_id", "Hash32"], ["handoff_certificate_digest_v0", "Hash32"], ["terminal_qc_digest_v0", "Hash32"], ["source_terminal_block_id", "Hash32"], ["target_epoch_descriptor_id", "Hash32"], ["activation_height", "u64"], ["initial_view", "u64"]],
    "MerkleListRootBodyV1": [["root_kind", "u16"], ["item_count", "u32"], ["tree_root", "Option<Hash32>"]],
}


def verify_schema(schema: Any) -> dict[str, str]:
    require(isinstance(schema, dict), "schema_shape")
    require(schema.get("schema") == "trnm.poco-ai.v0-to-v1-activation-kernel.v1", "schema_identity")
    require(schema.get("schema_version") == 1 and schema.get("status") == "candidate-non-normative", "schema_status")
    require(schema.get("cev1_types") == EXPECTED_SCHEMA_TYPES, "schema_types")
    require(schema.get("frozen_v0_types") == {
        "digest": "SHA256(Frame(trnm.cev0.hash.v0) || Frame(domain) || Frame(CEV0(value))); Frame uses u32 big-endian length",
        "integer_endianness": "big-endian",
        "ValidatorV0": [["validator_id", "Bytes"], ["consensus_public_key", "PublicKey32"], ["effective_weight", "u64"]],
        "ValidatorSetV0": [["schema_version", "u16=0"], ["genesis_hash", "Hash32"], ["chain_id", "ConsensusString-u16-length"], ["protocol_version", "u32=0"], ["epoch", "u64"], ["consensus_parameters_hash", "Hash32"], ["validators", "List<ValidatorV0>"]],
        "validator_set_domain": "trnm.poco-bft.validator-set.v0",
    }, "schema_v0_types")
    domains = schema.get("domains")
    require(isinstance(domains, dict) and set(domains) == {
        "configuration_projection", "artifact_manifest", "migration_receipt", "activation_statement",
        "activation_old_signature", "activation_new_signature", "activation_anchor", "merkle_list_root",
    }, "schema_domains")
    require(all(isinstance(value, str) and value.startswith("trnm.poco-ai.") for value in domains.values()), "schema_domains")
    require(isinstance(schema.get("explicit_exclusions"), list) and len(schema["explicit_exclusions"]) == 7, "schema_exclusions")
    return domains


def mutate(fixture: dict[str, Any], mutation: str) -> None:
    plan = fixture["plan_projection"]
    v0 = fixture["frozen_v0_evidence_projection"]
    statement = fixture["activation_statement"]
    block = fixture["first_v1_block_projection"]
    if mutation == "source_version_is_one":
        plan["source_protocol_version"] = 1
    elif mutation == "target_version_downgrade":
        plan["target_protocol_version"] = 0
    elif mutation == "fallback_enabled":
        plan["rollback_policy"] = 1
    elif mutation == "activation_epoch_skip":
        plan["activation_epoch"] += 1
    elif mutation == "activation_height_shift":
        plan["activation_height"] += 1
    elif mutation == "terminal_height_not_boundary_minus_one":
        plan["source_terminal_height"] -= 1
    elif mutation == "v0_evidence_source_hash_flip":
        v0["source_artifacts"][0]["sha256"] = "00" * 32
    elif mutation == "artifact_manifest_digest_flip":
        fixture["artifact_manifest"]["hash"] = "00" * 32
    elif mutation == "configuration_projection_digest_flip":
        fixture["configuration_projection"]["hash"] = "00" * 32
    elif mutation == "migration_receipt_digest_flip":
        fixture["migration_receipt"]["id"] = "00" * 32
    elif mutation == "activation_statement_digest_flip":
        statement["id"] = "00" * 32
    elif mutation == "cross_chain_replay":
        statement["body"]["source_v0_chain_id"] = "other-v0-chain"
    elif mutation == "old_signature_bitflip":
        entry = fixture["activation_certificate"]["old_set_signatures"][0]
        entry["signature"] = (bytes([bytes.fromhex(entry["signature"])[0] ^ 1]) + bytes.fromhex(entry["signature"])[1:]).hex()
    elif mutation == "new_signature_wrong_role":
        fixture["activation_certificate"]["new_set_signatures"][0]["role"] = 0
    elif mutation == "old_signature_wrong_set":
        fixture["activation_certificate"]["old_set_signatures"][0]["signing_set_hash"] = "00" * 32
    elif mutation == "old_under_quorum":
        fixture["activation_certificate"]["old_set_signatures"] = fixture["activation_certificate"]["old_set_signatures"][:1]
    elif mutation == "new_under_quorum":
        fixture["activation_certificate"]["new_set_signatures"] = fixture["activation_certificate"]["new_set_signatures"][:1]
    elif mutation == "duplicate_old_signer":
        entries = fixture["activation_certificate"]["old_set_signatures"]
        entries[1] = copy.deepcopy(entries[0])
    elif mutation == "activation_anchor_digest_flip":
        fixture["activation_anchor"]["id"] = "00" * 32
    elif mutation == "anchor_terminal_qc_substitution":
        fixture["activation_anchor"]["body"]["terminal_qc_digest_v0"] = "00" * 32
    elif mutation == "first_block_parent_substitution":
        block["parent_block_id"] = "00" * 32
    elif mutation == "first_block_wrong_kind":
        block["block_kind"] = 1
    elif mutation == "first_block_has_payload":
        block["batch_ref_count"] = 1
    elif mutation == "first_block_nonempty_root":
        block["batch_refs_root"] = "00" * 32
    elif mutation == "first_block_state_substitution":
        block["post_state_root"] = "00" * 32
    elif mutation == "first_block_has_justify_qc":
        block["justify_qc_id"] = "00" * 32
    elif mutation == "first_block_late_without_tc":
        block["view"] += 1
    elif mutation == "target_set_substitution":
        statement["body"]["target_v1_validator_set_hash"] = "00" * 32
    elif mutation == "plan_id_substitution":
        fixture["artifact_manifest"]["body"]["upgrade_plan_id"] = "00" * 32
    elif mutation == "old_membership_substitution_under_committed_hash":
        fixture["old_signing_set"]["descriptor"]["validators"][0]["effective_weight"] += 1
    elif mutation == "new_duplicate_public_key":
        members = fixture["new_signing_set"]["descriptor"]["definition"]["members"]
        members[1]["consensus_public_key"] = members[0]["consensus_public_key"]
    else:
        fail("unknown_mutation", mutation)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail("json", f"{path}: {exc}")


def run(schema_path: Path, vectors_path: Path) -> None:
    domains = verify_schema(load_json(schema_path))
    corpus = load_json(vectors_path)
    exact_keys(corpus, {"artifact", "artifact_version", "status", "schema", "positive_cases", "negative_cases", "explicit_exclusions"}, "corpus")
    require(corpus["artifact"] == "poco-ai-native-v1-v0-to-v1-activation-kernel-corpus", "corpus_identity")
    require(corpus["artifact_version"] == 1 and corpus["status"] == "candidate-non-normative", "corpus_status")
    require(corpus["schema"] == "../schema/v0-to-v1-activation-kernel-v1.json", "corpus_schema")
    positives = corpus["positive_cases"]
    require(isinstance(positives, list) and len(positives) == 1, "positive_cases")
    positive = exact_keys(positives[0], {"case_id", "fixture"}, "positive_case")
    require(positive["case_id"] == "exact_epoch_boundary_activation", "positive_case")
    verify_fixture(positive["fixture"], domains)
    negatives = corpus["negative_cases"]
    require(isinstance(negatives, list) and len(negatives) == 31, "negative_cases")
    seen: set[str] = set()
    for index, raw in enumerate(negatives):
        case = exact_keys(raw, {"case_id", "mutation", "expected_error"}, f"negative[{index}]")
        require(case["case_id"] not in seen, "duplicate_case", case["case_id"])
        seen.add(case["case_id"])
        mutated = copy.deepcopy(positive["fixture"])
        mutate(mutated, case["mutation"])
        try:
            verify_fixture(mutated, domains)
        except KernelError as exc:
            actual = str(exc).split(":", 1)[0]
            require(actual == case["expected_error"], "negative_error", f"{case['case_id']}: {actual}")
        else:
            fail("negative_accepted", case["case_id"])
    require(corpus["explicit_exclusions"] == load_json(schema_path)["explicit_exclusions"], "corpus_exclusions")
    print(f"v0-to-v1 activation kernel: 1 positive + {len(negatives)} negative cases passed (candidate-non-normative)")


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=root / "docs/protocol/poco-ai-native-v1/schema/v0-to-v1-activation-kernel-v1.json")
    parser.add_argument("--vectors", type=Path, default=root / "docs/protocol/poco-ai-native-v1/vectors/v0-to-v1-activation-kernel-v1.json")
    args = parser.parse_args()
    try:
        run(args.schema, args.vectors)
    except KernelError as exc:
        print(f"v0-to-v1 activation kernel FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
