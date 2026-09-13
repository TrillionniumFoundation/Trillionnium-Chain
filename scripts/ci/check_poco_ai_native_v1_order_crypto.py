#!/usr/bin/env python3
"""Independent strict-Ed25519 checker for the bounded PoCO v1 order corpus.

This checker intentionally does not import the CEV1 authoring/vector checker or
any TRNM implementation crate.  It implements only the closed CEV1 records
needed to bind validator keys, Vote statements, and Timeout statements, plus a
small strict Ed25519 verifier.  The evidence is deliberately bounded: it does
not validate the full v1 wire, complete QC/TC semantics, light-client proofs,
upgrade behavior, implementation activation, or normative freeze.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json"
FOUNDATION_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-foundation-order-kernel-v1.json"
CORPUS_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-order-signature-crypto-v1.json"

VOTE_DOMAIN = "trnm.poco-ai.order-vote-signature.v1"
TIMEOUT_DOMAIN = "trnm.poco-ai.order-timeout-signature.v1"
VALIDATOR_SET_DEFINITION_DOMAIN = "trnm.poco-ai.validator-set-definition.v1"
VALIDATOR_SET_DOMAIN = "trnm.poco-ai.validator-set.v1"
STRICT_ED25519_SCHEME = 0

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


class EvidenceError(Exception):
    """A corpus or conformance invariant failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: top level must be an object")
    return value


def exact_hex(value: Any, length: int, label: str) -> bytes:
    require(isinstance(value, str), f"{label}: expected hexadecimal string")
    require(len(value) == length * 2 and value == value.lower(), f"{label}: non-canonical length/case")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise EvidenceError(f"{label}: invalid hexadecimal") from exc
    require(len(raw) == length, f"{label}: wrong decoded length")
    return raw


def bounded_hex(value: Any, minimum: int, maximum: int, label: str) -> bytes:
    require(isinstance(value, str), f"{label}: expected hexadecimal string")
    require(value == value.lower() and len(value) % 2 == 0, f"{label}: non-canonical hexadecimal")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise EvidenceError(f"{label}: invalid hexadecimal") from exc
    require(minimum <= len(raw) <= maximum, f"{label}: length outside bound")
    return raw


def uint(value: Any, bits: int, label: str) -> bytes:
    require(type(value) is int and 0 <= value < 2**bits, f"{label}: invalid u{bits}")
    return value.to_bytes(bits // 8, "little")


def cev_bytes(raw: bytes) -> bytes:
    require(len(raw) < 2**32, "CEV1 Bytes length overflow")
    return struct.pack("<I", len(raw)) + raw


def cev_string(value: Any, label: str) -> bytes:
    require(isinstance(value, str), f"{label}: expected string")
    raw = value.encode("utf-8")
    require(raw.decode("utf-8") == value, f"{label}: non-canonical UTF-8")
    return cev_bytes(raw)


def hash32(value: Any, label: str) -> bytes:
    return exact_hex(value, 32, label)


def digest(domain: str, encoded: bytes) -> bytes:
    raw_domain = domain.encode("ascii")
    require(raw_domain and len(raw_domain) < 2**32, "digest domain bound")
    return hashlib.sha256(struct.pack("<I", len(raw_domain)) + raw_domain + encoded).digest()


def encode_protocol_context(value: dict[str, Any], label: str) -> bytes:
    require(set(value) == {"schema_version", "genesis_hash", "chain_id", "protocol_version", "stack_profile_hash"}, f"{label}: fields")
    return b"".join(
        (
            uint(value["schema_version"], 16, f"{label}.schema_version"),
            hash32(value["genesis_hash"], f"{label}.genesis_hash"),
            cev_string(value["chain_id"], f"{label}.chain_id"),
            uint(value["protocol_version"], 32, f"{label}.protocol_version"),
            hash32(value["stack_profile_hash"], f"{label}.stack_profile_hash"),
        )
    )


def encode_validator_member(value: dict[str, Any], label: str) -> bytes:
    expected = {
        "validator_id", "consensus_key_scheme", "consensus_public_key", "voting_weight",
        "network_identity_commitment", "safety_signer_policy_hash", "poco_economic_record_hash",
    }
    require(set(value) == expected, f"{label}: fields")
    return b"".join(
        (
            cev_bytes(bounded_hex(value["validator_id"], 1, 128, f"{label}.validator_id")),
            uint(value["consensus_key_scheme"], 16, f"{label}.consensus_key_scheme"),
            cev_bytes(exact_hex(value["consensus_public_key"], 32, f"{label}.consensus_public_key")),
            uint(value["voting_weight"], 128, f"{label}.voting_weight"),
            hash32(value["network_identity_commitment"], f"{label}.network_identity_commitment"),
            hash32(value["safety_signer_policy_hash"], f"{label}.safety_signer_policy_hash"),
            hash32(value["poco_economic_record_hash"], f"{label}.poco_economic_record_hash"),
        )
    )


def encode_validator_definition(value: dict[str, Any]) -> bytes:
    require(set(value) == {"schema_version", "members", "total_weight", "quorum_threshold"}, "validator definition fields")
    members = value["members"]
    require(isinstance(members, list) and 1 <= len(members) <= 256, "validator members bound")
    ids = [bounded_hex(member["validator_id"], 1, 128, "validator_id") for member in members]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "validator IDs must be strictly ordered and unique")
    keys = [exact_hex(member["consensus_public_key"], 32, "consensus_public_key") for member in members]
    require(len(keys) == len(set(keys)), "validator public keys must be unique")
    weights = [member["voting_weight"] for member in members]
    require(all(type(weight) is int and 0 < weight < 2**128 for weight in weights), "validator weights")
    total = sum(weights)
    require(total < 2**128 and value["total_weight"] == total, "validator total weight")
    require(value["quorum_threshold"] == (2 * total) // 3 + 1, "validator quorum threshold")
    return b"".join(
        (
            uint(value["schema_version"], 16, "validator_definition.schema_version"),
            struct.pack("<I", len(members)),
            *(encode_validator_member(member, f"validator_definition.members[{index}]") for index, member in enumerate(members)),
            uint(total, 128, "validator_definition.total_weight"),
            uint(value["quorum_threshold"], 128, "validator_definition.quorum_threshold"),
        )
    )


def encode_validator_descriptor(context: dict[str, Any], epoch: int, definition: dict[str, Any]) -> bytes:
    return b"".join(
        (
            uint(1, 16, "validator_descriptor.schema_version"),
            encode_protocol_context(context, "validator_descriptor.context"),
            uint(epoch, 64, "validator_descriptor.epoch"),
            encode_validator_definition(definition),
        )
    )


def encode_consensus_context(value: dict[str, Any], label: str) -> bytes:
    expected = {
        "schema_version", "context", "runtime_profile_hash", "epoch", "validator_set_hash",
        "consensus_parameters_hash", "view", "message_kind",
    }
    require(set(value) == expected, f"{label}: fields")
    return b"".join(
        (
            uint(value["schema_version"], 16, f"{label}.schema_version"),
            encode_protocol_context(value["context"], f"{label}.context"),
            hash32(value["runtime_profile_hash"], f"{label}.runtime_profile_hash"),
            uint(value["epoch"], 64, f"{label}.epoch"),
            hash32(value["validator_set_hash"], f"{label}.validator_set_hash"),
            hash32(value["consensus_parameters_hash"], f"{label}.consensus_parameters_hash"),
            uint(value["view"], 64, f"{label}.view"),
            uint(value["message_kind"], 8, f"{label}.message_kind"),
        )
    )


def encode_vote_statement(value: dict[str, Any]) -> bytes:
    expected = {
        "schema_version", "consensus_context", "block_id", "height", "epoch_descriptor_id",
        "post_state_root", "batch_refs_root", "transaction_execution_receipts_root",
    }
    require(set(value) == expected, "vote statement fields")
    require(value["schema_version"] == 1, "vote schema version")
    require(value["consensus_context"]["message_kind"] == 1, "vote message kind")
    return b"".join(
        (
            uint(value["schema_version"], 16, "vote.schema_version"),
            encode_consensus_context(value["consensus_context"], "vote.consensus_context"),
            hash32(value["block_id"], "vote.block_id"),
            uint(value["height"], 64, "vote.height"),
            hash32(value["epoch_descriptor_id"], "vote.epoch_descriptor_id"),
            hash32(value["post_state_root"], "vote.post_state_root"),
            hash32(value["batch_refs_root"], "vote.batch_refs_root"),
            hash32(value["transaction_execution_receipts_root"], "vote.transaction_execution_receipts_root"),
        )
    )


def encode_high_justification(value: dict[str, Any]) -> bytes:
    require(value.get("variant") == "EpochStart" and isinstance(value.get("value"), dict), "bounded timeout high justification")
    body = value["value"]
    require(set(body) == {"anchor_kind", "anchor_id", "anchor_view"}, "epoch-start ref fields")
    return b"".join(
        (
            uint(1, 8, "high_justification.variant"),
            uint(body["anchor_kind"], 8, "high_justification.anchor_kind"),
            hash32(body["anchor_id"], "high_justification.anchor_id"),
            uint(body["anchor_view"], 64, "high_justification.anchor_view"),
        )
    )


def encode_finalized_anchor(value: dict[str, Any]) -> bytes:
    require(value.get("variant") == "FreshGenesis" and isinstance(value.get("value"), dict), "bounded timeout finalized anchor")
    body = value["value"]
    require(set(body) == {"genesis_derived_state_hash"}, "fresh-genesis anchor fields")
    return uint(0, 8, "finalized_anchor.variant") + hash32(body["genesis_derived_state_hash"], "finalized_anchor.genesis_derived_state_hash")


def encode_timeout_statement(value: dict[str, Any]) -> bytes:
    expected = {
        "schema_version", "consensus_context", "high_justification", "locked_qc_id",
        "locked_qc_view", "last_finalized_anchor", "pacemaker_generation",
    }
    require(set(value) == expected, "timeout statement fields")
    require(value["schema_version"] == 1, "timeout schema version")
    require(value["consensus_context"]["message_kind"] == 2, "timeout message kind")
    require(value["locked_qc_id"] is None and value["locked_qc_view"] == 0, "bounded timeout lock base case")
    return b"".join(
        (
            uint(value["schema_version"], 16, "timeout.schema_version"),
            encode_consensus_context(value["consensus_context"], "timeout.consensus_context"),
            encode_high_justification(value["high_justification"]),
            uint(0, 8, "timeout.locked_qc_id.option"),
            uint(value["locked_qc_view"], 64, "timeout.locked_qc_view"),
            encode_finalized_anchor(value["last_finalized_anchor"]),
            uint(value["pacemaker_generation"], 64, "timeout.pacemaker_generation"),
        )
    )


def inv(value: int) -> int:
    return pow(value % P, P - 2, P)


def x_recover(y: int) -> int:
    xx = ((y * y - 1) * inv(D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    require((x * x - xx) % P == 0, "Ed25519 point is not on curve")
    if x & 1:
        x = P - x
    return x


BASE_Y = (4 * inv(5)) % P
BASE = (x_recover(BASE_Y), BASE_Y, 1, (x_recover(BASE_Y) * BASE_Y) % P)


def point_add(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * D * t1 * t2) % P
    d_value = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d_value - c) % P
    g = (d_value + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = IDENTITY
    addend = point
    remaining = scalar
    while remaining:
        if remaining & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        remaining >>= 1
    return result


def point_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return (left[0] * right[2] - right[0] * left[2]) % P == 0 and (left[1] * right[2] - right[1] * left[2]) % P == 0


def decode_point(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    encoded = int.from_bytes(raw, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= P:
        return None
    try:
        x = x_recover(y)
    except EvidenceError:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def small_order(point: tuple[int, int, int, int]) -> bool:
    return point_equal(scalar_mult(point, 8), IDENTITY)


def strict_ed25519_verify(message: bytes, public_key: bytes, signature: bytes) -> bool:
    if len(message) != 32 or len(public_key) != 32 or len(signature) != 64:
        return False
    public = decode_point(public_key)
    r_point = decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if public is None or r_point is None or scalar >= L:
        return False
    if small_order(public) or small_order(r_point):
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return point_equal(scalar_mult(BASE, scalar), point_add(r_point, scalar_mult(public, challenge)))


def rfc8032_control() -> None:
    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    require(strict_ed25519_verify(b"".ljust(32, b"\0"), public_key, signature) is False, "RFC control must bind exact message")
    # RFC 8032 vector 1 signs the empty message; the protocol signs 32 bytes.
    # Verify it with a general-message copy of the equation to anchor the math.
    public = decode_point(public_key)
    r_point = decode_point(signature[:32])
    require(public is not None and r_point is not None, "RFC control point decode")
    scalar = int.from_bytes(signature[32:], "little")
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key).digest(), "little") % L
    require(point_equal(scalar_mult(BASE, scalar), point_add(r_point, scalar_mult(public, challenge))), "RFC 8032 vector 1")


def find_case(foundation: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = foundation.get("positive_cases")
    require(isinstance(cases, list), "foundation positive_cases")
    matches = [case for case in cases if case.get("case_id") == case_id]
    require(len(matches) == 1, f"foundation case {case_id}")
    return matches[0]


def schema_contract(schema: dict[str, Any]) -> None:
    domains = schema.get("domains")
    require(isinstance(domains, dict), "schema domains")
    require(domains.get("vote_signature") == VOTE_DOMAIN, "schema Vote signature domain")
    require(domains.get("timeout_signature") == TIMEOUT_DOMAIN, "schema Timeout signature domain")
    require(domains.get("validator_set_definition") == VALIDATOR_SET_DEFINITION_DOMAIN, "schema validator definition domain")
    require(domains.get("validator_set") == VALIDATOR_SET_DOMAIN, "schema validator set domain")
    types = schema.get("types")
    require(isinstance(types, dict), "schema types")
    expected_vote_fields = ["schema_version", "consensus_context", "block_id", "height", "epoch_descriptor_id", "post_state_root", "batch_refs_root", "transaction_execution_receipts_root"]
    expected_timeout_fields = ["schema_version", "consensus_context", "high_justification", "locked_qc_id", "locked_qc_view", "last_finalized_anchor", "pacemaker_generation"]
    expected_vote_entry = ["voter_id", "signature_scheme", "signature"]
    expected_timeout_entry = ["validator_id", "statement", "signature_scheme", "signature"]
    for type_name, expected in (
        ("VoteStatementBodyV1", expected_vote_fields),
        ("TimeoutStatementBodyV1", expected_timeout_fields),
        ("VoteSignatureEntryV1", expected_vote_entry),
        ("TimeoutSignatureEntryV1", expected_timeout_entry),
    ):
        actual = types.get(type_name)
        require(isinstance(actual, dict) and actual.get("kind") == "record", f"schema {type_name}")
        require([field.get("name") for field in actual.get("fields", [])] == expected, f"schema {type_name} field order")


def high_justification_identity(value: dict[str, Any], label: str) -> tuple[int, int, int, bytes]:
    encoded = encode_high_justification(value)
    require(encoded, f"{label}: empty high-justification encoding")
    body = value["value"]
    return (
        body["anchor_view"],
        1,
        body["anchor_kind"],
        exact_hex(body["anchor_id"], 32, f"{label}.anchor_id"),
    )


def project_foundation_justification(value: dict[str, Any], label: str) -> dict[str, Any]:
    require(set(value) == {"variant", "value"}, f"{label}: fields")
    require(value.get("variant") == "EpochStart", f"{label}: bounded fixture requires EpochStart")
    epoch_start = value.get("value")
    require(isinstance(epoch_start, dict) and set(epoch_start) == {"variant", "value"}, f"{label}: epoch-start object")
    require(epoch_start.get("variant") == "GenesisAnchor", f"{label}: bounded fixture requires GenesisAnchor")
    anchor = epoch_start.get("value")
    require(isinstance(anchor, dict) and set(anchor) == {"body", "genesis_anchor_id"}, f"{label}: genesis anchor")
    body = anchor.get("body")
    require(isinstance(body, dict), f"{label}: genesis anchor body")
    initial_view = body.get("initial_view")
    require(type(initial_view) is int and 0 < initial_view < 2**64, f"{label}: genesis initial view")
    return {
        "variant": "EpochStart",
        "value": {
            "anchor_kind": 0,
            "anchor_id": anchor.get("genesis_anchor_id"),
            "anchor_view": initial_view - 1,
        },
    }


def build_timeout_authority(
    foundation_tc: dict[str, Any], validator_set_hash: bytes
) -> dict[str, Any]:
    expected_fields = {
        "schema_version", "context", "runtime_profile_hash", "epoch", "validator_set_hash",
        "consensus_parameters_hash", "timed_out_view", "target_view", "justifications", "entries",
    }
    require(set(foundation_tc) == expected_fields, "foundation timeout certificate fields")
    require(foundation_tc["schema_version"] == 1, "foundation timeout certificate schema version")
    timed_out_view = foundation_tc["timed_out_view"]
    require(type(timed_out_view) is int and 0 <= timed_out_view < 2**64 - 1, "foundation timed-out view")
    require(foundation_tc["target_view"] == timed_out_view + 1, "foundation timeout target view")

    justifications = foundation_tc["justifications"]
    require(isinstance(justifications, list) and justifications, "foundation timeout justifications")
    projected = [
        project_foundation_justification(item, f"foundation_tc.justifications[{index}]")
        for index, item in enumerate(justifications)
    ]
    projected_identities = [
        high_justification_identity(item, f"foundation_tc.projected[{index}]")
        for index, item in enumerate(projected)
    ]
    require(len(projected_identities) == len(set(projected_identities)), "foundation timeout justification duplicates")

    original_context = {
        "schema_version": 1,
        "context": foundation_tc["context"],
        "runtime_profile_hash": foundation_tc["runtime_profile_hash"],
        "epoch": foundation_tc["epoch"],
        "validator_set_hash": foundation_tc["validator_set_hash"],
        "consensus_parameters_hash": foundation_tc["consensus_parameters_hash"],
        "view": timed_out_view,
        "message_kind": 2,
    }
    entries = foundation_tc["entries"]
    require(isinstance(entries, list) and entries, "foundation timeout entries")
    referenced: set[tuple[int, int, int, bytes]] = set()
    base_statement: dict[str, Any] | None = None
    for index, entry in enumerate(entries):
        require(isinstance(entry, dict) and "statement" in entry, f"foundation_tc.entries[{index}]")
        statement = entry["statement"]
        encode_timeout_statement(statement)
        require(statement["consensus_context"] == original_context, f"foundation_tc.entries[{index}]: context projection")
        identity = high_justification_identity(
            statement["high_justification"], f"foundation_tc.entries[{index}].high_justification"
        )
        require(identity in set(projected_identities), f"foundation_tc.entries[{index}]: unresolved justification")
        referenced.add(identity)
        comparable = copy.deepcopy(statement)
        comparable.pop("pacemaker_generation")
        if base_statement is None:
            base_statement = copy.deepcopy(statement)
        else:
            expected_base = copy.deepcopy(base_statement)
            expected_base.pop("pacemaker_generation")
            require(comparable == expected_base, f"foundation_tc.entries[{index}]: bounded statement base drift")
    require(referenced == set(projected_identities), "foundation timeout justification projection incomplete")
    require(base_statement is not None, "foundation timeout base statement")
    base_statement["consensus_context"]["validator_set_hash"] = validator_set_hash.hex()
    projected_context = copy.deepcopy(original_context)
    projected_context["validator_set_hash"] = validator_set_hash.hex()
    return {
        "consensus_context": projected_context,
        "base_statement": base_statement,
        "justification_identities": set(projected_identities),
        "timed_out_view": timed_out_view,
        "target_view": foundation_tc["target_view"],
    }


def build_inputs(
    foundation: dict[str, Any], corpus: dict[str, Any]
) -> tuple[dict[str, Any], bytes, bytes, bytes, dict[str, Any]]:
    fixture = corpus.get("fixture")
    require(isinstance(fixture, dict), "corpus fixture")
    base_definition = copy.deepcopy(find_case(foundation, fixture.get("validator_definition_case_id"))["value"])
    validators = fixture.get("validators")
    require(isinstance(validators, list) and len(validators) == len(base_definition["members"]), "fixture validator cardinality")
    by_id = {item.get("validator_id"): item for item in validators if isinstance(item, dict)}
    require(len(by_id) == len(validators), "fixture validator IDs unique")
    for member in base_definition["members"]:
        replacement = by_id.get(member["validator_id"])
        require(isinstance(replacement, dict), "fixture member correspondence")
        require(replacement.get("weight") == member["voting_weight"], "fixture weight correspondence")
        member["consensus_key_scheme"] = replacement.get("signature_scheme")
        member["consensus_public_key"] = replacement.get("public_key")
    definition_bytes = encode_validator_definition(base_definition)
    definition_hash = digest(VALIDATOR_SET_DEFINITION_DOMAIN, definition_bytes)

    descriptor_case = find_case(foundation, fixture.get("validator_descriptor_case_id"))
    descriptor_value = descriptor_case["value"]
    descriptor_bytes = encode_validator_descriptor(descriptor_value["context"], descriptor_value["epoch"], base_definition)
    validator_set_hash = digest(VALIDATOR_SET_DOMAIN, descriptor_bytes)
    expected = corpus.get("expected")
    require(isinstance(expected, dict), "corpus expected")
    require(
        set(expected) == {
            "validator_set_definition_hash", "validator_set_hash", "vote_statement_cev1_hex",
            "vote_signature_root", "timeout_statement_claims",
        },
        "corpus expected fields",
    )
    require(definition_hash == exact_hex(expected.get("validator_set_definition_hash"), 32, "expected.validator_set_definition_hash"), "validator definition digest")
    require(validator_set_hash == exact_hex(expected.get("validator_set_hash"), 32, "expected.validator_set_hash"), "validator set digest")

    vote = copy.deepcopy(find_case(foundation, fixture.get("vote_statement_case_id"))["value"])
    vote["consensus_context"]["validator_set_hash"] = validator_set_hash.hex()
    vote_bytes = encode_vote_statement(vote)
    vote_root = digest(VOTE_DOMAIN, vote_bytes)
    require(vote_bytes == bounded_hex(expected.get("vote_statement_cev1_hex"), 1, 65536, "expected.vote_statement_cev1_hex"), "Vote statement CEV1")
    require(vote_root == exact_hex(expected.get("vote_signature_root"), 32, "expected.vote_signature_root"), "Vote signature root")

    foundation_tc = copy.deepcopy(find_case(foundation, fixture.get("timeout_certificate_case_id"))["value"])
    timeout_authority = build_timeout_authority(foundation_tc, validator_set_hash)
    singleton_timeout = copy.deepcopy(find_case(foundation, fixture.get("timeout_statement_case_id"))["value"])
    singleton_timeout["consensus_context"]["validator_set_hash"] = validator_set_hash.hex()
    require(singleton_timeout == timeout_authority["base_statement"], "foundation timeout singleton/TC projection drift")
    return base_definition, validator_set_hash, vote_bytes, vote_root, timeout_authority


def verify_signature_entry(
    entry: dict[str, Any],
    root: bytes,
    member_by_id: dict[bytes, dict[str, Any]],
    label: str,
    id_field: str,
    exact_fields: set[str],
) -> int:
    require(isinstance(entry, dict), f"{label}: entry")
    require(set(entry) == exact_fields, f"{label}: exact entry fields")
    validator_id = bounded_hex(entry.get(id_field), 1, 128, f"{label}.{id_field}")
    member = member_by_id.get(validator_id)
    require(member is not None, f"{label}: unknown validator")
    require(entry.get("signature_scheme") == STRICT_ED25519_SCHEME, f"{label}: unsupported signature scheme")
    public_key = exact_hex(member["consensus_public_key"], 32, f"{label}.public_key")
    signature = exact_hex(entry.get("signature"), 64, f"{label}.signature")
    require(strict_ed25519_verify(root, public_key, signature), f"{label}: invalid strict Ed25519 signature")
    return member["voting_weight"]


def verify_vote_entry(
    entry: dict[str, Any],
    root: bytes,
    member_by_id: dict[bytes, dict[str, Any]],
    label: str,
) -> int:
    return verify_signature_entry(
        entry,
        root,
        member_by_id,
        label,
        "voter_id",
        {"voter_id", "signature_scheme", "signature"},
    )


def verify_vote_certificate(
    entries: Any,
    root: bytes,
    definition: dict[str, Any],
    label: str,
) -> None:
    require(isinstance(entries, list) and entries, f"{label}: entries")
    ids = [bounded_hex(entry.get("voter_id"), 1, 128, f"{label}.voter_id") for entry in entries]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), f"{label}: signer IDs must be strictly ordered and duplicate-free")
    member_by_id = {bounded_hex(member["validator_id"], 1, 128, "member.validator_id"): member for member in definition["members"]}
    weight = 0
    for index, entry in enumerate(entries):
        weight += verify_vote_entry(entry, root, member_by_id, f"{label}[{index}]")
        require(weight < 2**128, f"{label}: weight overflow")
    require(weight >= definition["quorum_threshold"], f"{label}: insufficient quorum weight")


def verify_timeout_statement_authority(
    statement: dict[str, Any], authority: dict[str, Any], label: str
) -> tuple[bytes, bytes, tuple[int, int, int, bytes]]:
    require(isinstance(statement, dict), f"{label}: statement")
    encoded = encode_timeout_statement(statement)
    require(statement["consensus_context"] == authority["consensus_context"], f"{label}: foundation TC context projection")
    identity = high_justification_identity(statement["high_justification"], f"{label}.high_justification")
    require(identity in authority["justification_identities"], f"{label}: foundation TC justification projection")
    base = authority["base_statement"]
    for field in (
        "schema_version", "consensus_context", "high_justification", "locked_qc_id",
        "locked_qc_view", "last_finalized_anchor",
    ):
        require(statement[field] == base[field], f"{label}: bounded foundation TC {field} projection")
    return encoded, digest(TIMEOUT_DOMAIN, encoded), identity


def verify_timeout_entry(
    entry: dict[str, Any],
    authority: dict[str, Any],
    member_by_id: dict[bytes, dict[str, Any]],
    label: str,
) -> tuple[int, bytes, bytes, tuple[int, int, int, bytes]]:
    require(isinstance(entry, dict), f"{label}: entry")
    require(
        set(entry) == {"validator_id", "statement", "signature_scheme", "signature"},
        f"{label}: exact TimeoutSignatureEntryV1 fields",
    )
    encoded, root, identity = verify_timeout_statement_authority(entry["statement"], authority, f"{label}.statement")
    weight = verify_signature_entry(
        entry,
        root,
        member_by_id,
        label,
        "validator_id",
        {"validator_id", "statement", "signature_scheme", "signature"},
    )
    return weight, encoded, root, identity


def verify_timeout_certificate(
    entries: Any,
    definition: dict[str, Any],
    authority: dict[str, Any],
    label: str,
) -> list[tuple[bytes, bytes, bytes]]:
    require(isinstance(entries, list) and entries, f"{label}: entries")
    ids = [bounded_hex(entry.get("validator_id"), 1, 128, f"{label}.validator_id") for entry in entries]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), f"{label}: signer IDs must be strictly ordered and duplicate-free")
    member_by_id = {bounded_hex(member["validator_id"], 1, 128, "member.validator_id"): member for member in definition["members"]}
    weight = 0
    referenced: set[tuple[int, int, int, bytes]] = set()
    records: list[tuple[bytes, bytes, bytes]] = []
    for index, entry in enumerate(entries):
        entry_weight, encoded, root, identity = verify_timeout_entry(
            entry, authority, member_by_id, f"{label}[{index}]"
        )
        weight += entry_weight
        require(weight < 2**128, f"{label}: weight overflow")
        referenced.add(identity)
        records.append((ids[index], encoded, root))
    require(weight >= definition["quorum_threshold"], f"{label}: insufficient quorum weight")
    require(referenced == authority["justification_identities"], f"{label}: foundation TC justification references incomplete")
    require(len({record[1] for record in records}) >= 2, f"{label}: requires at least two distinct valid Timeout statements")
    return records


def verify_expected_timeout_records(expected: Any, records: list[tuple[bytes, bytes, bytes]]) -> None:
    require(isinstance(expected, list) and len(expected) == len(records), "expected timeout statement claim cardinality")
    for index, (claim, record) in enumerate(zip(expected, records, strict=True)):
        require(isinstance(claim, dict), f"expected.timeout_statement_claims[{index}]")
        require(set(claim) == {"validator_id", "cev1_hex", "signature_root"}, f"expected.timeout_statement_claims[{index}]: fields")
        validator_id, encoded, root = record
        require(
            validator_id == bounded_hex(claim["validator_id"], 1, 128, f"expected.timeout_statement_claims[{index}].validator_id"),
            f"expected.timeout_statement_claims[{index}]: validator ID",
        )
        require(
            encoded == bounded_hex(claim["cev1_hex"], 1, 65536, f"expected.timeout_statement_claims[{index}].cev1_hex"),
            f"expected.timeout_statement_claims[{index}]: CEV1",
        )
        require(
            root == exact_hex(claim["signature_root"], 32, f"expected.timeout_statement_claims[{index}].signature_root"),
            f"expected.timeout_statement_claims[{index}]: signature root",
        )


def expect_reject(label: str, action: Any) -> None:
    try:
        action()
    except EvidenceError:
        return
    raise EvidenceError(f"negative {label} was accepted")


def run_negatives(
    corpus: dict[str, Any],
    definition: dict[str, Any],
    vote_root: bytes,
    timeout_authority: dict[str, Any],
) -> int:
    claims = corpus["claims"]
    qc = claims["quorum_certificate_signatures"]
    tc = claims["timeout_certificate_signatures"]
    member_by_id = {bounded_hex(member["validator_id"], 1, 128, "member.validator_id"): member for member in definition["members"]}
    first_vote = qc[0]
    first_timeout = tc[0]
    negatives = corpus.get("negative_cases")
    require(isinstance(negatives, list), "negative_cases")
    expected_ids = {
        "vote_wrong_domain", "timeout_wrong_domain", "vote_wrong_key", "timeout_wrong_key",
        "vote_signature_bitflip", "timeout_signature_truncated", "vote_noncanonical_s",
        "vote_small_order_key", "qc_duplicate_signer", "tc_duplicate_signer",
        "qc_unsorted_signers", "tc_insufficient_weight", "qc_unknown_signature_scheme",
        "tc_statement_mutation", "tc_statement_swap", "tc_statement_substitution",
        "tc_entry_missing_statement", "tc_statement_missing_pacemaker_generation",
    }
    require({case.get("case_id") for case in negatives} == expected_ids, "negative case inventory")
    count = 0
    for case in negatives:
        case_id = case["case_id"]
        if case_id == "vote_wrong_domain":
            expect_reject(
                case_id,
                lambda: verify_signature_entry(
                    first_vote,
                    digest(TIMEOUT_DOMAIN, bytes.fromhex(corpus["expected"]["vote_statement_cev1_hex"])),
                    member_by_id,
                    case_id,
                    "voter_id",
                    {"voter_id", "signature_scheme", "signature"},
                ),
            )
        elif case_id == "timeout_wrong_domain":
            timeout_bytes = encode_timeout_statement(first_timeout["statement"])
            expect_reject(
                case_id,
                lambda: verify_signature_entry(
                    first_timeout,
                    digest(VOTE_DOMAIN, timeout_bytes),
                    member_by_id,
                    case_id,
                    "validator_id",
                    {"validator_id", "statement", "signature_scheme", "signature"},
                ),
            )
        elif case_id in ("vote_wrong_key", "timeout_wrong_key"):
            source = copy.deepcopy(first_vote if case_id.startswith("vote") else first_timeout)
            id_field = "voter_id" if case_id.startswith("vote") else "validator_id"
            source[id_field] = qc[3]["voter_id"]
            if case_id.startswith("vote"):
                expect_reject(case_id, lambda: verify_vote_entry(source, vote_root, member_by_id, case_id))
            else:
                expect_reject(
                    case_id,
                    lambda: verify_timeout_entry(source, timeout_authority, member_by_id, case_id),
                )
        elif case_id == "vote_signature_bitflip":
            source = copy.deepcopy(first_vote)
            signature = bytearray.fromhex(source["signature"])
            signature[17] ^= 1
            source["signature"] = bytes(signature).hex()
            expect_reject(case_id, lambda: verify_vote_entry(source, vote_root, member_by_id, case_id))
        elif case_id == "timeout_signature_truncated":
            source = copy.deepcopy(first_timeout)
            source["signature"] = source["signature"][:-2]
            expect_reject(
                case_id,
                lambda: verify_timeout_entry(source, timeout_authority, member_by_id, case_id),
            )
        elif case_id == "vote_noncanonical_s":
            source = copy.deepcopy(first_vote)
            signature = bytearray.fromhex(source["signature"])
            signature[32:] = L.to_bytes(32, "little")
            source["signature"] = bytes(signature).hex()
            expect_reject(case_id, lambda: verify_vote_entry(source, vote_root, member_by_id, case_id))
        elif case_id == "vote_small_order_key":
            source = copy.deepcopy(first_vote)
            small_definition = copy.deepcopy(definition)
            small_definition["members"][0]["consensus_public_key"] = "01" + "00" * 31
            small_members = {bounded_hex(member["validator_id"], 1, 128, "member.validator_id"): member for member in small_definition["members"]}
            expect_reject(case_id, lambda: verify_vote_entry(source, vote_root, small_members, case_id))
        elif case_id == "qc_duplicate_signer":
            source = copy.deepcopy(qc)
            source[1] = copy.deepcopy(source[0])
            expect_reject(case_id, lambda: verify_vote_certificate(source, vote_root, definition, case_id))
        elif case_id == "tc_duplicate_signer":
            source = copy.deepcopy(tc)
            source[1] = copy.deepcopy(source[0])
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "qc_unsorted_signers":
            source = copy.deepcopy(qc)
            source[0], source[1] = source[1], source[0]
            expect_reject(case_id, lambda: verify_vote_certificate(source, vote_root, definition, case_id))
        elif case_id == "tc_insufficient_weight":
            source = copy.deepcopy(tc[:2])
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "qc_unknown_signature_scheme":
            source = copy.deepcopy(qc)
            source[0]["signature_scheme"] = 1
            expect_reject(case_id, lambda: verify_vote_certificate(source, vote_root, definition, case_id))
        elif case_id == "tc_statement_mutation":
            source = copy.deepcopy(tc)
            source[0]["statement"]["pacemaker_generation"] += 1
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "tc_statement_swap":
            source = copy.deepcopy(tc)
            source[0]["statement"], source[1]["statement"] = source[1]["statement"], source[0]["statement"]
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "tc_statement_substitution":
            source = copy.deepcopy(tc)
            source[0]["statement"]["consensus_context"]["view"] -= 1
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "tc_entry_missing_statement":
            source = copy.deepcopy(tc)
            del source[0]["statement"]
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        elif case_id == "tc_statement_missing_pacemaker_generation":
            source = copy.deepcopy(tc)
            del source[0]["statement"]["pacemaker_generation"]
            expect_reject(
                case_id,
                lambda: verify_timeout_certificate(source, definition, timeout_authority, case_id),
            )
        else:
            raise EvidenceError(f"unhandled negative {case_id}")
        count += 1
    return count


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="run all positive and negative controls")
    args = parser.parse_args()
    require(args.self_test, "--self-test is required")

    schema = load_json(SCHEMA_PATH)
    foundation = load_json(FOUNDATION_PATH)
    corpus = load_json(CORPUS_PATH)
    schema_contract(schema)
    rfc8032_control()
    require(corpus.get("status") == "candidate-non-normative", "corpus status")
    require(corpus.get("signature_scheme") == "strict-ed25519-v1-draft", "corpus signature scheme")

    definition, validator_set_hash, _vote_bytes, vote_root, timeout_authority = build_inputs(foundation, corpus)
    claims = corpus.get("claims")
    require(isinstance(claims, dict), "claims")
    require(set(claims) == {"quorum_certificate_signatures", "timeout_certificate_signatures"}, "claims fields")
    qc = claims.get("quorum_certificate_signatures")
    tc = claims.get("timeout_certificate_signatures")
    verify_vote_certificate(qc, vote_root, definition, "QC signature claims")
    timeout_records = verify_timeout_certificate(tc, definition, timeout_authority, "TC signature claims")
    verify_expected_timeout_records(corpus["expected"]["timeout_statement_claims"], timeout_records)

    member_by_id = {bounded_hex(member["validator_id"], 1, 128, "member.validator_id"): member for member in definition["members"]}
    verify_vote_entry(qc[0], vote_root, member_by_id, "Vote signature claim")
    verify_timeout_entry(tc[0], timeout_authority, member_by_id, "Timeout signature claim")
    negative_count = run_negatives(corpus, definition, vote_root, timeout_authority)

    exclusions = corpus.get("explicit_exclusions")
    require(isinstance(exclusions, list) and len(exclusions) >= 6, "explicit exclusions")
    print(
        "PASS: bounded PoCO AI-native v1 strict-Ed25519 order evidence "
        f"(Vote=1 distinct_Timeout={len({record[1] for record in timeout_records})} "
        f"QC={len(qc)} TC_entries={len(tc)} negatives={negative_count} "
        f"validator_set={validator_set_hash.hex()}); candidate-only, no full wire/complete QC-TC transition semantics/"
        "light-client/upgrade/freeze/activation/release claim"
    )


if __name__ == "__main__":
    try:
        run()
    except EvidenceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
