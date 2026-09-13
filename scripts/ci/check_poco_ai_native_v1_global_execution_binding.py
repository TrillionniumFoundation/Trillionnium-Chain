#!/usr/bin/env python3
"""Independently reproduce the candidate tag-50 CEV1 corpus.

This standard-library-only checker intentionally does not import a TRNM crate.
It covers the listed GlobalExecutionBindingV1 value/key/sparse-membership/claim
kernel only. A fully valid fixture reaches the positive binding-carrier
terminal once its modeled Order authority has authenticated the exact strict
ancestor and finalized root. This script itself does not verify that external
Order proof and is not evidence of G2 completion, a global wire freeze,
production readiness, or activation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-global-execution-binding-kernel-v1.json"
VECTORS = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-global-execution-binding-kernel-v1.json"

BINDING_DOMAIN = "trnm.poco-ai.global-execution-binding.v1"
STATE_KEY_DOMAIN = "trnm.poco-ai.state-key.v1"
STATE_LEAF_DOMAIN = "trnm.poco-ai.state-leaf.v1"
STATE_NODE_DOMAIN = "trnm.poco-ai.state-node.v1"
CLAIM_DOMAIN = "trnm.poco-ai.global-execution-order-state-binding.claim.candidate.v1"
OBJECT_KIND = 50
STATE_TREE_VERSION = 0
STATE_TREE_DEPTH = 256
OBJECT_VERSION = 0
MAX_CLAIM_BYTES = 4 * 1024 * 1024
MAX_WITNESSES = 16
MAX_CHAIN_ID_BYTES = 1024
ZERO = bytes(32)


class Reject(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def require(condition: bool, code: str, detail: str = "") -> None:
    if not condition:
        raise Reject(code, detail)


def u16(value: int) -> bytes:
    require(0 <= value <= 0xFFFF, "integer_bound")
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    require(0 <= value <= 0xFFFFFFFF, "integer_bound")
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    require(0 <= value <= 0xFFFFFFFFFFFFFFFF, "integer_bound")
    return struct.pack("<Q", value)


def cev_bytes(value: bytes) -> bytes:
    return u32(len(value)) + value


def digest(domain: str, encoded: bytes) -> bytes:
    raw_domain = domain.encode("ascii")
    return hashlib.sha256(u32(len(raw_domain)) + raw_domain + encoded).digest()


def encode_context(value: dict[str, Any]) -> bytes:
    return b"".join(
        (
            u16(value["schema_version"]),
            value["genesis_hash"],
            cev_bytes(value["chain_id"]),
            u32(value["protocol_version"]),
            value["stack_profile_hash"],
        )
    )


def encode_binding_body(value: dict[str, Any]) -> bytes:
    return b"".join(
        (
            u16(value["schema_version"]),
            encode_context(value["context"]),
            u64(value["candidate_height"]),
            value["candidate_block_id"],
            value["candidate_composite_root"],
            value["final_execution_root"],
        )
    )


def encode_binding(value: dict[str, Any]) -> bytes:
    return encode_binding_body(value["body"]) + value["binding_id"]


def encode_binding_state(value: dict[str, Any]) -> bytes:
    return u16(value["schema_version"]) + value["binding_id"] + u64(value["version"])


def encode_envelope(value: dict[str, Any]) -> bytes:
    return b"".join(
        (
            u16(value["schema_version"]),
            u16(value["object_kind"]),
            value["object_id"],
            cev_bytes(value["immutable"]),
            cev_bytes(value["mutable"]),
        )
    )


def encode_witness(value: dict[str, Any]) -> bytes:
    return b"".join(
        (
            u16(value["state_tree_version"]),
            u16(value["object_kind"]),
            value["object_id"],
            u64(value["object_version"]),
            cev_bytes(value["value_bytes"]),
            u32(len(value["siblings"])),
            b"".join(value["siblings"]),
        )
    )


def encode_claim_body(value: dict[str, Any]) -> bytes:
    return b"".join(
        (
            u16(value["schema_version"]),
            value["order_proof_id"],
            cev_bytes(value["chain_id"]),
            value["genesis_hash"],
            u32(value["protocol_version"]),
            value["stack_profile_hash"],
            u64(value["finalized_epoch"]),
            value["finalized_block_id"],
            u64(value["finalized_height"]),
            value["finalized_post_state_root"],
            u64(value["candidate_height"]),
            value["candidate_block_id"],
            value["candidate_composite_root"],
            value["final_execution_root"],
            u32(len(value["witnesses"])),
            b"".join(encode_witness(item) for item in value["witnesses"]),
        )
    )


def encode_claim(value: dict[str, Any]) -> bytes:
    return encode_claim_body(value["body"]) + value["claim_id"]


class Cursor:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        require(end >= self.offset and end <= len(self.raw), "truncated")
        result = self.raw[self.offset:end]
        self.offset = end
        return result

    def integer(self, width: int) -> int:
        return int.from_bytes(self.take(width), "little")

    def u16(self) -> int:
        return self.integer(2)

    def u32(self) -> int:
        return self.integer(4)

    def u64(self) -> int:
        return self.integer(8)

    def hash32(self) -> bytes:
        return self.take(32)

    def bytes(self, maximum: int = MAX_CLAIM_BYTES) -> bytes:
        length = self.u32()
        require(length <= maximum, "parser_bound")
        return self.take(length)

    def finish(self) -> None:
        require(self.offset == len(self.raw), "trailing_bytes")


def decode_context(cursor: Cursor) -> dict[str, Any]:
    schema_version = cursor.u16()
    genesis_hash = cursor.hash32()
    chain_id = cursor.bytes(MAX_CHAIN_ID_BYTES)
    try:
        chain_id.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Reject("noncanonical_utf8") from error
    return {
        "schema_version": schema_version,
        "genesis_hash": genesis_hash,
        "chain_id": chain_id,
        "protocol_version": cursor.u32(),
        "stack_profile_hash": cursor.hash32(),
    }


def decode_binding(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw)
    body = {
        "schema_version": cursor.u16(),
        "context": decode_context(cursor),
        "candidate_height": cursor.u64(),
        "candidate_block_id": cursor.hash32(),
        "candidate_composite_root": cursor.hash32(),
        "final_execution_root": cursor.hash32(),
    }
    value = {"body": body, "binding_id": cursor.hash32()}
    cursor.finish()
    require(encode_binding(value) == raw, "noncanonical")
    return value


def decode_binding_state(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw)
    value = {
        "schema_version": cursor.u16(),
        "binding_id": cursor.hash32(),
        "version": cursor.u64(),
    }
    cursor.finish()
    require(encode_binding_state(value) == raw, "noncanonical")
    return value


def decode_envelope(raw: bytes) -> dict[str, Any]:
    cursor = Cursor(raw)
    value = {
        "schema_version": cursor.u16(),
        "object_kind": cursor.u16(),
        "object_id": cursor.hash32(),
        "immutable": cursor.bytes(),
        "mutable": cursor.bytes(),
    }
    cursor.finish()
    require(encode_envelope(value) == raw, "noncanonical")
    return value


def decode_witness(cursor: Cursor) -> dict[str, Any]:
    value = {
        "state_tree_version": cursor.u16(),
        "object_kind": cursor.u16(),
        "object_id": cursor.hash32(),
        "object_version": cursor.u64(),
        "value_bytes": cursor.bytes(),
    }
    sibling_count = cursor.u32()
    require(sibling_count <= STATE_TREE_DEPTH, "parser_bound")
    value["siblings"] = [cursor.hash32() for _ in range(sibling_count)]
    return value


def decode_claim(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_CLAIM_BYTES, "parser_bound")
    cursor = Cursor(raw)
    body = {
        "schema_version": cursor.u16(),
        "order_proof_id": cursor.hash32(),
    }
    chain_id = cursor.bytes(MAX_CHAIN_ID_BYTES)
    try:
        chain_id.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Reject("noncanonical_utf8") from error
    body.update(
        {
            "chain_id": chain_id,
            "genesis_hash": cursor.hash32(),
            "protocol_version": cursor.u32(),
            "stack_profile_hash": cursor.hash32(),
            "finalized_epoch": cursor.u64(),
            "finalized_block_id": cursor.hash32(),
            "finalized_height": cursor.u64(),
            "finalized_post_state_root": cursor.hash32(),
            "candidate_height": cursor.u64(),
            "candidate_block_id": cursor.hash32(),
            "candidate_composite_root": cursor.hash32(),
            "final_execution_root": cursor.hash32(),
        }
    )
    witness_count = cursor.u32()
    require(witness_count <= MAX_WITNESSES, "parser_bound")
    body["witnesses"] = [decode_witness(cursor) for _ in range(witness_count)]
    value = {"body": body, "claim_id": cursor.hash32()}
    cursor.finish()
    require(encode_claim(value) == raw, "noncanonical")
    return value


def state_key(object_kind: int, object_id: bytes) -> bytes:
    return digest(STATE_KEY_DOMAIN, u16(object_kind) + object_id)


def sparse_membership(
    object_kind: int,
    object_id: bytes,
    object_version: int,
    value_bytes: bytes,
    siblings: list[bytes],
) -> tuple[bytes, bytes, bytes]:
    require(len(siblings) == STATE_TREE_DEPTH, "sparse_depth")
    key = state_key(object_kind, object_id)
    leaf = digest(
        STATE_LEAF_DOMAIN,
        key + u16(object_kind) + u64(object_version) + cev_bytes(value_bytes),
    )
    running = leaf
    for level, sibling in enumerate(siblings):
        bit_index = 255 - level
        bit = (key[bit_index // 8] >> (7 - (bit_index % 8))) & 1
        left, right = (running, sibling) if bit == 0 else (sibling, running)
        running = digest(STATE_NODE_DOMAIN, u16(level) + left + right)
    return key, leaf, running


def seal_claim_body(body: dict[str, Any]) -> dict[str, Any]:
    return {"body": body, "claim_id": digest(CLAIM_DOMAIN, encode_claim_body(body))}


def fixture_model() -> tuple[dict[str, Any], dict[str, Any], int]:
    context = {
        "schema_version": 1,
        "genesis_hash": bytes.fromhex("11" * 32),
        "chain_id": b"trnm-tag50-machine-schema",
        "protocol_version": 1,
        "stack_profile_hash": bytes.fromhex("22" * 32),
    }
    binding_body = {
        "schema_version": 1,
        "context": context,
        "candidate_height": 6,
        "candidate_block_id": bytes.fromhex("33" * 32),
        "candidate_composite_root": bytes.fromhex("44" * 32),
        "final_execution_root": bytes.fromhex("55" * 32),
    }
    binding_id = digest(BINDING_DOMAIN, encode_binding_body(binding_body))
    binding = {"body": binding_body, "binding_id": binding_id}
    state = {"schema_version": 1, "binding_id": binding_id, "version": 0}
    envelope = {
        "schema_version": 1,
        "object_kind": OBJECT_KIND,
        "object_id": binding_id,
        "immutable": encode_binding(binding),
        "mutable": encode_binding_state(state),
    }
    siblings = [bytes([level % 251]) * 32 for level in range(STATE_TREE_DEPTH)]
    witness = {
        "state_tree_version": 0,
        "object_kind": OBJECT_KIND,
        "object_id": binding_id,
        "object_version": 0,
        "value_bytes": encode_envelope(envelope),
        "siblings": siblings,
    }
    key, leaf, root = sparse_membership(
        OBJECT_KIND, binding_id, 0, witness["value_bytes"], siblings
    )
    body = {
        "schema_version": 1,
        "order_proof_id": bytes.fromhex("66" * 32),
        "chain_id": context["chain_id"],
        "genesis_hash": context["genesis_hash"],
        "protocol_version": context["protocol_version"],
        "stack_profile_hash": context["stack_profile_hash"],
        "finalized_epoch": 0,
        "finalized_block_id": bytes.fromhex("77" * 32),
        "finalized_height": 9,
        "finalized_post_state_root": root,
        "candidate_height": binding_body["candidate_height"],
        "candidate_block_id": binding_body["candidate_block_id"],
        "candidate_composite_root": binding_body["candidate_composite_root"],
        "final_execution_root": binding_body["final_execution_root"],
        "witnesses": [witness],
    }
    claim = seal_claim_body(body)
    authority = {
        key: copy.deepcopy(body[key])
        for key in (
            "order_proof_id",
            "chain_id",
            "genesis_hash",
            "protocol_version",
            "stack_profile_hash",
            "finalized_epoch",
            "finalized_block_id",
            "finalized_height",
            "finalized_post_state_root",
            "candidate_height",
            "candidate_block_id",
            "candidate_composite_root",
            "final_execution_root",
        )
    }
    authority["strict_ancestor_authenticated"] = True
    authority["expected_state_key"] = key
    authority["expected_leaf"] = leaf
    return claim, authority, 7


def validate_claim(
    raw: bytes,
    authority: dict[str, Any],
    materialized_at_height: int,
) -> dict[str, bytes]:
    claim = decode_claim(raw)
    body = claim["body"]
    require(body["schema_version"] == 1, "claim_schema")
    require(claim["claim_id"] == digest(CLAIM_DOMAIN, encode_claim_body(body)), "claim_id")
    for field in (
        "order_proof_id",
        "chain_id",
        "genesis_hash",
        "protocol_version",
        "stack_profile_hash",
        "finalized_epoch",
        "finalized_block_id",
        "finalized_height",
        "finalized_post_state_root",
    ):
        require(body[field] == authority[field], "order_binding")
    for field in (
        "candidate_height",
        "candidate_block_id",
        "candidate_composite_root",
        "final_execution_root",
    ):
        require(body[field] == authority[field], "candidate_binding")
    nonzero_fields = (
        "order_proof_id",
        "genesis_hash",
        "finalized_block_id",
        "finalized_post_state_root",
        "candidate_block_id",
        "candidate_composite_root",
        "final_execution_root",
    )
    require(all(body[field] != ZERO for field in nonzero_fields), "candidate_binding")
    require(body["protocol_version"] != 0 and body["candidate_height"] != 0, "candidate_binding")
    require(
        authority["strict_ancestor_authenticated"]
        and body["candidate_height"] < body["finalized_height"],
        "candidate_ancestry",
    )
    require(materialized_at_height > body["candidate_height"], "materialization_height")
    require(len(body["witnesses"]) == 1, "witness_cardinality")
    witness = body["witnesses"][0]
    require(witness["state_tree_version"] == STATE_TREE_VERSION, "state_tree_version")
    require(witness["object_kind"] == OBJECT_KIND, "object_kind")
    require(witness["object_version"] == OBJECT_VERSION, "object_version")
    require(witness["object_id"] != ZERO, "object_id")
    require(len(witness["siblings"]) == STATE_TREE_DEPTH, "sparse_depth")

    envelope = decode_envelope(witness["value_bytes"])
    require(
        envelope["schema_version"] == 1
        and envelope["object_kind"] == witness["object_kind"]
        and envelope["object_id"] == witness["object_id"]
        and envelope["immutable"]
        and envelope["mutable"],
        "envelope_identity",
    )
    binding = decode_binding(envelope["immutable"])
    state = decode_binding_state(envelope["mutable"])
    binding_body = binding["body"]
    context = binding_body["context"]
    require(
        binding_body["schema_version"] == 1
        and context["schema_version"] == 1
        and context["protocol_version"] == 1
        and bool(context["chain_id"])
        and context["genesis_hash"] != ZERO
        and context["stack_profile_hash"] != ZERO
        and context["chain_id"] == body["chain_id"]
        and context["genesis_hash"] == body["genesis_hash"]
        and context["protocol_version"] == body["protocol_version"]
        and context["stack_profile_hash"] == body["stack_profile_hash"]
        and binding_body["candidate_height"] == body["candidate_height"]
        and binding_body["candidate_block_id"] == body["candidate_block_id"]
        and binding_body["candidate_composite_root"] == body["candidate_composite_root"]
        and binding_body["final_execution_root"] == body["final_execution_root"],
        "binding_value",
    )
    expected_binding_id = digest(BINDING_DOMAIN, encode_binding_body(binding_body))
    require(
        binding["binding_id"] == expected_binding_id
        and binding["binding_id"] == witness["object_id"],
        "binding_id",
    )
    require(
        state["schema_version"] == 1
        and state["binding_id"] == binding["binding_id"]
        and state["version"] == 0,
        "binding_state",
    )
    key, leaf, root = sparse_membership(
        witness["object_kind"],
        witness["object_id"],
        witness["object_version"],
        witness["value_bytes"],
        witness["siblings"],
    )
    require(root == body["finalized_post_state_root"], "state_root")
    require(key == authority["expected_state_key"], "state_key")
    require(leaf == authority["expected_leaf"], "state_leaf")
    return {"binding_id": expected_binding_id, "state_key": key, "leaf": leaf, "root": root}


def nested_parts(claim: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    witness = claim["body"]["witnesses"][0]
    envelope = decode_envelope(witness["value_bytes"])
    binding = decode_binding(envelope["immutable"])
    state = decode_binding_state(envelope["mutable"])
    return envelope, binding, state


def replace_parts(
    claim: dict[str, Any],
    envelope: dict[str, Any],
    binding: dict[str, Any],
    state: dict[str, Any],
) -> None:
    envelope["immutable"] = encode_binding(binding)
    envelope["mutable"] = encode_binding_state(state)
    claim["body"]["witnesses"][0]["value_bytes"] = encode_envelope(envelope)


def opposite_orientation_root(witness: dict[str, Any], reversed_level: int) -> bytes:
    key, leaf, _ = sparse_membership(
        witness["object_kind"], witness["object_id"], witness["object_version"],
        witness["value_bytes"], witness["siblings"],
    )
    running = leaf
    for level, sibling in enumerate(witness["siblings"]):
        bit_index = 255 - level
        bit = (key[bit_index // 8] >> (7 - (bit_index % 8))) & 1
        left, right = (running, sibling) if bit == 0 else (sibling, running)
        if level == reversed_level:
            left, right = right, left
        running = digest(STATE_NODE_DOMAIN, u16(level) + left + right)
    return running


NEGATIVE_CASES: list[tuple[str, str]] = [
    ("claim_trailing_byte", "trailing_bytes"),
    ("claim_truncated", "truncated"),
    ("claim_schema_version", "claim_schema"),
    ("claim_id_substitution", "claim_id"),
    ("order_proof_id_substitution", "order_binding"),
    ("chain_id_substitution", "order_binding"),
    ("genesis_hash_substitution", "order_binding"),
    ("protocol_version_substitution", "order_binding"),
    ("stack_profile_hash_substitution", "order_binding"),
    ("finalized_epoch_substitution", "order_binding"),
    ("finalized_block_id_substitution", "order_binding"),
    ("finalized_height_substitution", "order_binding"),
    ("finalized_post_state_root_substitution", "order_binding"),
    ("candidate_height_zero", "candidate_binding"),
    ("candidate_height_not_strict_ancestor", "candidate_ancestry"),
    ("candidate_block_id_substitution", "candidate_binding"),
    ("candidate_composite_root_substitution", "candidate_binding"),
    ("final_execution_root_substitution", "candidate_binding"),
    ("materialized_at_candidate_height", "materialization_height"),
    ("empty_witnesses", "witness_cardinality"),
    ("duplicate_witness", "witness_cardinality"),
    ("witness_parser_count_17", "parser_bound"),
    ("state_tree_version_substitution", "state_tree_version"),
    ("object_kind_substitution", "object_kind"),
    ("witness_object_id_substitution", "envelope_identity"),
    ("object_version_substitution", "object_version"),
    ("sparse_path_255", "sparse_depth"),
    ("sparse_path_257", "parser_bound"),
    ("sparse_sibling_substitution", "state_root"),
    ("sparse_orientation_substitution", "state_root"),
    ("strict_ancestor_authority_absent", "candidate_ancestry"),
    ("envelope_schema_substitution", "envelope_identity"),
    ("envelope_kind_substitution", "envelope_identity"),
    ("envelope_id_substitution", "envelope_identity"),
    ("envelope_trailing_byte", "trailing_bytes"),
    ("immutable_trailing_byte", "trailing_bytes"),
    ("binding_body_schema_substitution", "binding_value"),
    ("binding_context_schema_substitution", "binding_value"),
    ("binding_context_chain_id_substitution", "binding_value"),
    ("binding_context_genesis_hash_substitution", "binding_value"),
    ("binding_context_protocol_version_substitution", "binding_value"),
    ("binding_context_stack_profile_hash_substitution", "binding_value"),
    ("binding_candidate_height_substitution", "binding_value"),
    ("binding_candidate_block_id_substitution", "binding_value"),
    ("binding_candidate_root_substitution", "binding_value"),
    ("binding_final_execution_root_substitution", "binding_value"),
    ("binding_id_substitution", "binding_id"),
    ("binding_state_schema_substitution", "binding_state"),
    ("binding_state_id_substitution", "binding_state"),
    ("binding_state_version_substitution", "binding_state"),
    ("claim_absolute_input_bound", "parser_bound"),
]


def mutate(case_id: str) -> tuple[bytes, dict[str, Any], int]:
    base, authority, materialized = fixture_model()
    claim = copy.deepcopy(base)
    body = claim["body"]
    raw_override: bytes | None = None
    reseal = True
    if case_id == "claim_trailing_byte":
        raw_override = encode_claim(claim) + b"\x00"
    elif case_id == "claim_truncated":
        raw_override = encode_claim(claim)[:-1]
    elif case_id == "claim_schema_version":
        body["schema_version"] = 2
    elif case_id == "claim_id_substitution":
        claim["claim_id"] = bytes([claim["claim_id"][0] ^ 1]) + claim["claim_id"][1:]
        reseal = False
    elif case_id == "order_proof_id_substitution":
        body["order_proof_id"] = bytes.fromhex("65" * 32)
    elif case_id == "chain_id_substitution":
        body["chain_id"] = b"trnm-tag50-other-chain"
    elif case_id == "genesis_hash_substitution":
        body["genesis_hash"] = bytes.fromhex("10" * 32)
    elif case_id == "protocol_version_substitution":
        body["protocol_version"] = 2
    elif case_id == "stack_profile_hash_substitution":
        body["stack_profile_hash"] = bytes.fromhex("21" * 32)
    elif case_id == "finalized_epoch_substitution":
        body["finalized_epoch"] = 1
    elif case_id == "finalized_block_id_substitution":
        body["finalized_block_id"] = bytes.fromhex("76" * 32)
    elif case_id == "finalized_height_substitution":
        body["finalized_height"] = 10
    elif case_id == "finalized_post_state_root_substitution":
        body["finalized_post_state_root"] = bytes.fromhex("78" * 32)
    elif case_id == "candidate_height_zero":
        body["candidate_height"] = 0
        authority["candidate_height"] = 0
    elif case_id == "candidate_height_not_strict_ancestor":
        body["candidate_height"] = body["finalized_height"]
        authority["candidate_height"] = body["candidate_height"]
    elif case_id == "candidate_block_id_substitution":
        body["candidate_block_id"] = bytes.fromhex("32" * 32)
    elif case_id == "candidate_composite_root_substitution":
        body["candidate_composite_root"] = bytes.fromhex("43" * 32)
    elif case_id == "final_execution_root_substitution":
        body["final_execution_root"] = bytes.fromhex("54" * 32)
    elif case_id == "materialized_at_candidate_height":
        materialized = body["candidate_height"]
    elif case_id == "empty_witnesses":
        body["witnesses"] = []
    elif case_id == "duplicate_witness":
        body["witnesses"].append(copy.deepcopy(body["witnesses"][0]))
    elif case_id == "witness_parser_count_17":
        body["witnesses"] = [copy.deepcopy(body["witnesses"][0]) for _ in range(17)]
    elif case_id == "state_tree_version_substitution":
        body["witnesses"][0]["state_tree_version"] = 1
    elif case_id == "object_kind_substitution":
        body["witnesses"][0]["object_kind"] = 49
    elif case_id == "witness_object_id_substitution":
        body["witnesses"][0]["object_id"] = bytes.fromhex("99" * 32)
    elif case_id == "object_version_substitution":
        body["witnesses"][0]["object_version"] = 1
    elif case_id == "sparse_path_255":
        body["witnesses"][0]["siblings"].pop()
    elif case_id == "sparse_path_257":
        body["witnesses"][0]["siblings"].append(bytes.fromhex("aa" * 32))
    elif case_id == "sparse_sibling_substitution":
        sibling = body["witnesses"][0]["siblings"][128]
        body["witnesses"][0]["siblings"][128] = bytes([sibling[0] ^ 1]) + sibling[1:]
    elif case_id == "sparse_orientation_substitution":
        wrong = opposite_orientation_root(body["witnesses"][0], 73)
        body["finalized_post_state_root"] = wrong
        authority["finalized_post_state_root"] = wrong
    elif case_id == "strict_ancestor_authority_absent":
        authority["strict_ancestor_authenticated"] = False
    elif case_id.startswith("envelope_") or case_id.startswith("immutable_") or case_id.startswith("binding_"):
        envelope, binding, state = nested_parts(claim)
        if case_id == "envelope_schema_substitution":
            envelope["schema_version"] = 2
        elif case_id == "envelope_kind_substitution":
            envelope["object_kind"] = 49
        elif case_id == "envelope_id_substitution":
            envelope["object_id"] = bytes.fromhex("98" * 32)
        elif case_id == "envelope_trailing_byte":
            body["witnesses"][0]["value_bytes"] += b"\x00"
            envelope = binding = state = None
        elif case_id == "immutable_trailing_byte":
            envelope["immutable"] += b"\x00"
            body["witnesses"][0]["value_bytes"] = encode_envelope(envelope)
            envelope = binding = state = None
        elif case_id == "binding_body_schema_substitution":
            binding["body"]["schema_version"] = 2
        elif case_id == "binding_context_schema_substitution":
            binding["body"]["context"]["schema_version"] = 2
        elif case_id == "binding_context_chain_id_substitution":
            binding["body"]["context"]["chain_id"] = b"trnm-tag50-other-chain"
        elif case_id == "binding_context_genesis_hash_substitution":
            binding["body"]["context"]["genesis_hash"] = bytes.fromhex("10" * 32)
        elif case_id == "binding_context_protocol_version_substitution":
            binding["body"]["context"]["protocol_version"] = 2
        elif case_id == "binding_context_stack_profile_hash_substitution":
            binding["body"]["context"]["stack_profile_hash"] = bytes.fromhex("21" * 32)
        elif case_id == "binding_candidate_height_substitution":
            binding["body"]["candidate_height"] = 5
        elif case_id == "binding_candidate_block_id_substitution":
            binding["body"]["candidate_block_id"] = bytes.fromhex("32" * 32)
        elif case_id == "binding_candidate_root_substitution":
            binding["body"]["candidate_composite_root"] = bytes.fromhex("45" * 32)
        elif case_id == "binding_final_execution_root_substitution":
            binding["body"]["final_execution_root"] = bytes.fromhex("54" * 32)
        elif case_id == "binding_id_substitution":
            binding["binding_id"] = bytes.fromhex("97" * 32)
        elif case_id == "binding_state_schema_substitution":
            state["schema_version"] = 2
        elif case_id == "binding_state_id_substitution":
            state["binding_id"] = bytes.fromhex("96" * 32)
        elif case_id == "binding_state_version_substitution":
            state["version"] = 1
        if envelope is not None:
            replace_parts(claim, envelope, binding, state)
    elif case_id == "claim_absolute_input_bound":
        raw_override = b"\x5a" * (MAX_CLAIM_BYTES + 1)
    else:
        raise AssertionError(f"unknown mutant {case_id}")
    if raw_override is None:
        if reseal:
            claim = seal_claim_body(body)
        raw_override = encode_claim(claim)
    return raw_override, authority, materialized


def reference_document(schema_sha256: str) -> dict[str, Any]:
    claim, authority, materialized = fixture_model()
    raw = encode_claim(claim)
    witness = claim["body"]["witnesses"][0]
    envelope = decode_envelope(witness["value_bytes"])
    binding = decode_binding(envelope["immutable"])
    state = decode_binding_state(envelope["mutable"])
    result = validate_claim(raw, authority, materialized)
    inputs = {
        "chain_id": claim["body"]["chain_id"].decode("utf-8"),
        "genesis_hash": claim["body"]["genesis_hash"].hex(),
        "protocol_version": claim["body"]["protocol_version"],
        "stack_profile_hash": claim["body"]["stack_profile_hash"].hex(),
        "candidate_height": claim["body"]["candidate_height"],
        "candidate_block_id": claim["body"]["candidate_block_id"].hex(),
        "candidate_composite_root": claim["body"]["candidate_composite_root"].hex(),
        "final_execution_root": claim["body"]["final_execution_root"].hex(),
        "materialized_at_height": materialized,
        "order_proof_id": claim["body"]["order_proof_id"].hex(),
        "finalized_epoch": claim["body"]["finalized_epoch"],
        "finalized_block_id": claim["body"]["finalized_block_id"].hex(),
        "finalized_height": claim["body"]["finalized_height"],
        "strict_ancestor_authenticated_external_input": True,
    }
    expected = {
        "binding_body_cev1": encode_binding_body(binding["body"]).hex(),
        "binding_id": binding["binding_id"].hex(),
        "immutable_object_cev1": encode_binding(binding).hex(),
        "mutable_state_cev1": encode_binding_state(state).hex(),
        "application_object_value_cev1": witness["value_bytes"].hex(),
        "state_key": result["state_key"].hex(),
        "state_leaf": result["leaf"].hex(),
        "finalized_post_state_root": result["root"].hex(),
        "claim_body_cev1": encode_claim_body(claim["body"]).hex(),
        "claim_id": claim["claim_id"].hex(),
        "claim_cev1": raw.hex(),
        "claim_sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_outcome": "VerifiedOrderStateExecutionBindingV1",
    }
    return {
        "schema_version": 1,
        "status": "candidate-non-normative",
        "scope": "tag-50-value-key-leaf-sparse-membership-and-candidate-claim-only",
        "schema_sha256": schema_sha256,
        "canonical_case": {
            "case_id": "registered_tag50_exact_membership_issues_binding_carrier",
            "inputs": inputs,
            "siblings_hex": b"".join(witness["siblings"]).hex(),
            "expected": expected,
        },
        "positive_inventory": [
            "global_execution_binding_body_and_typed_id",
            "immutable_object_and_create_once_state",
            "application_object_envelope_and_typed_state_key",
            "domain_separated_state_leaf",
            "exact_256_level_sparse_membership",
            "strict_candidate_claim_exact_reencode_issues_binding_carrier",
        ],
        "negative_cases": [
            {"case_id": case_id, "expected": "must_reject", "expected_error_code": code}
            for case_id, code in NEGATIVE_CASES
        ],
        "authority_boundary": {
            "external_order_proof_verified_by_this_checker": False,
            "strict_ancestor_authority_supplied_by_fixture": True,
            "authoritative_order_state_writer": True,
            "normal_execution_binding_issuer": True,
            "order_state_membership_binding": True,
            "g2_global_complete": False,
            "global_wire_schema_complete": False,
            "global_conformance_vectors_complete": False,
            "normative_freeze": False,
            "production_candidate": False,
            "activation": False,
        },
    }


def check_schema(document: dict[str, Any]) -> None:
    require(document.get("schema_version") == 1, "schema_document")
    require(document.get("status") == "candidate-non-normative", "schema_document")
    require(document.get("closed_for_listed_types_only") is True, "schema_document")
    require(document.get("domains") == {
        "binding_id": BINDING_DOMAIN,
        "state_key": STATE_KEY_DOMAIN,
        "state_leaf": STATE_LEAF_DOMAIN,
        "state_node": STATE_NODE_DOMAIN,
        "claim_id": CLAIM_DOMAIN,
    }, "schema_document")
    require(document.get("constants") == {
        "object_kind": OBJECT_KIND,
        "state_tree_version": STATE_TREE_VERSION,
        "state_tree_depth": STATE_TREE_DEPTH,
        "object_version": OBJECT_VERSION,
        "maximum_claim_input_bytes": MAX_CLAIM_BYTES,
        "maximum_witnesses_before_semantic_narrowing": MAX_WITNESSES,
        "required_witnesses": 1,
        "maximum_chain_id_bytes": MAX_CHAIN_ID_BYTES,
    }, "schema_document")
    required_types = {
        "ProtocolContextV1", "GlobalExecutionBindingBodyV1", "GlobalExecutionBindingV1",
        "GlobalExecutionBindingStateV1", "ApplicationObjectValueV1",
        "ExecutionBindingStateWitnessV1", "ExecutionBindingClaimBodyV1",
        "ExecutionBindingClaimV1", "GlobalExecutionBindingCreateMaterialV1",
    }
    require(required_types <= set(document.get("types", {})), "schema_document")
    expected_field_order = {
        "TypedObjectIdV1": ["object_kind", "object_id"],
        "ProtocolContextV1": [
            "schema_version", "genesis_hash", "chain_id", "protocol_version",
            "stack_profile_hash",
        ],
        "GlobalExecutionBindingBodyV1": [
            "schema_version", "context", "candidate_height", "candidate_block_id",
            "candidate_composite_root", "final_execution_root",
        ],
        "GlobalExecutionBindingV1": ["body", "binding_id"],
        "GlobalExecutionBindingStateV1": ["schema_version", "binding_id", "version"],
        "ApplicationObjectValueV1": [
            "schema_version", "object_id", "immutable_object_bytes", "mutable_state_bytes",
        ],
        "ExecutionBindingStateWitnessV1": [
            "state_tree_version", "object_kind", "object_id", "object_version",
            "value_bytes", "siblings",
        ],
        "ExecutionBindingClaimBodyV1": [
            "schema_version", "order_proof_id", "chain_id", "genesis_hash",
            "protocol_version", "stack_profile_hash", "finalized_epoch",
            "finalized_block_id", "finalized_height", "finalized_post_state_root",
            "candidate_height", "candidate_block_id", "candidate_composite_root",
            "final_execution_root", "witnesses",
        ],
        "ExecutionBindingClaimV1": ["body", "claim_id"],
        "GlobalExecutionBindingCreateMaterialV1": [
            "materialized_at_height", "object_kind", "object_id", "object_version",
            "state_key", "value_bytes",
        ],
    }
    for type_name, field_order in expected_field_order.items():
        actual = [item.get("name") for item in document["types"][type_name].get("fields", [])]
        require(actual == field_order, "schema_field_order", type_name)
    require(document.get("derivations") == {
        "DigestV1": "SHA-256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))",
        "binding_id": "DigestV1(domains.binding_id, GlobalExecutionBindingBodyV1)",
        "state_key": "DigestV1(domains.state_key, (object_kind:u16, object_id:Hash32))",
        "state_leaf": "DigestV1(domains.state_leaf, (state_key:Hash32, object_kind:u16, object_version:u64, value_bytes:Bytes))",
        "state_node": "DigestV1(domains.state_node, (level:u16, left:Hash32, right:Hash32))",
        "claim_id": "DigestV1(domains.claim_id, ExecutionBindingClaimBodyV1)",
        "sparse_path": "siblings are leaf-to-root; level 0 uses state-key bit 255, level 255 uses bit 0; bit 0 places running hash left",
    }, "schema_derivations")
    boundary = document.get("authority_boundary", {})
    for key in (
        "authoritative_order_state_writer", "normal_execution_binding_issuer",
        "order_state_membership_binding",
    ):
        require(boundary.get(key) is True, "schema_truth_boundary")
    for key in (
        "g2_global_complete", "global_wire_schema_complete",
        "global_conformance_vectors_complete", "normative_freeze",
        "production_candidate", "activation",
    ):
        require(boundary.get(key) is False, "schema_truth_boundary")


def main() -> int:
    schema_bytes = SCHEMA.read_bytes()
    schema = json.loads(schema_bytes)
    check_schema(schema)
    expected = reference_document(hashlib.sha256(schema_bytes).hexdigest())
    actual = json.loads(VECTORS.read_text(encoding="utf-8"))
    require(actual == expected, "vector_document")
    canonical = bytes.fromhex(actual["canonical_case"]["expected"]["claim_cev1"])
    claim, authority, materialized = fixture_model()
    require(canonical == encode_claim(claim), "vector_document")
    result = validate_claim(canonical, authority, materialized)
    require(result["root"] == claim["body"]["finalized_post_state_root"], "positive_terminal")
    negative_expected = {item["case_id"]: item["expected_error_code"] for item in actual["negative_cases"]}
    require(negative_expected == dict(NEGATIVE_CASES), "negative_inventory")
    for case_id, expected_code in NEGATIVE_CASES:
        raw, mutant_authority, mutant_height = mutate(case_id)
        try:
            validate_claim(raw, mutant_authority, mutant_height)
        except Reject as error:
            require(error.code == expected_code, "negative_error", f"{case_id}: {error.code}")
        else:
            raise Reject("negative_accepted", case_id)
    print(
        "tag50_global_execution_binding_vectors=passed "
        f"positives={len(actual['positive_inventory'])} negatives={len(NEGATIVE_CASES)} "
        "terminal=VerifiedOrderStateExecutionBindingV1 "
        "normative_freeze=false g2_complete=false"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, Reject, ValueError) as error:
        print(f"tag50 global-execution-binding checker failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
