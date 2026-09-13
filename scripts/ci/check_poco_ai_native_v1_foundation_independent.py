#!/usr/bin/env python3
"""Independent CEV1 foundation/order candidate parser and corpus verifier.

This checker intentionally has no dependency on a TRNM Rust crate, generated
types, or another corpus authoring implementation.  It consumes only the
checked-in candidate schema and vectors and implements CEV1 framing, strict
decoding, candidate semantic checks, and SHA-256 commitments with Python's
standard library.

The evidence is deliberately bounded.  Signature bytes are opaque carriers in
the current corpus, so this file does not claim Ed25519 verification, complete
v1 wire coverage, light-client or upgrade verification, normative freeze, or
implementation interoperability.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


STANDARD_LIBRARY_ONLY = True
INDEPENDENT_IMPLEMENTATION = True

SCHEMA_REL = Path(
    "docs/protocol/poco-ai-native-v1/schema/"
    "cev1-foundation-order-kernel-v1.json"
)
VECTORS_REL = Path(
    "docs/protocol/poco-ai-native-v1/vectors/"
    "cev1-foundation-order-kernel-v1.json"
)

MAX_U128 = (1 << 128) - 1
INTEGER_WIDTHS = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16}


class ContractError(ValueError):
    """A stable candidate-contract rejection class."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def fail(code: str, detail: str = "") -> None:
    raise ContractError(code, detail)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail("artifact_read", f"{path}: {exc}")
    if not isinstance(value, dict):
        fail("artifact_shape", f"{path} must contain a JSON object")
    return value


def hex_bytes(value: Any, *, exact: int | None = None) -> bytes:
    if not isinstance(value, str):
        fail("hex_format", "hex value is not a string")
    if value != value.lower() or value.startswith("0x") or len(value) % 2:
        fail("hex_format", "hex must be lowercase, even-length, and unprefixed")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        fail("hex_format", "invalid hexadecimal")
    if raw.hex() != value:
        fail("hex_format", "non-canonical hexadecimal")
    if exact is not None and len(raw) != exact:
        fail("hex_length", f"expected {exact} bytes, got {len(raw)}")
    return raw


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            fail("truncated")
        start = self.offset
        self.offset += count
        return self.data[start : start + count]

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "little", signed=False)

    def finish(self) -> None:
        if self.offset != len(self.data):
            fail("trailing_bytes")


class Cev1Codec:
    """Schema-driven strict CEV1 encoder/decoder written independently."""

    def __init__(self, schema: dict[str, Any], limits: dict[str, Any]) -> None:
        self.types = schema.get("types")
        if not isinstance(self.types, dict):
            fail("schema_shape", "types must be an object")
        self.max_string = self._limit(limits, "max_consensus_string_bytes")
        self.max_bytes = self._limit(limits, "max_bytes_bytes")
        self.max_list = self._limit(limits, "max_list_items")
        self.max_depth = self._limit(limits, "max_nesting")

    @staticmethod
    def _limit(limits: dict[str, Any], name: str) -> int:
        value = limits.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            fail("fixture_shape", f"invalid {name}")
        return value

    def encode(self, type_ref: Any, value: Any, depth: int = 0) -> bytes:
        self._depth(depth)
        if isinstance(type_ref, dict):
            if set(type_ref) == {"option"}:
                if value is None:
                    return b"\x00"
                return b"\x01" + self.encode(type_ref["option"], value, depth + 1)
            if set(type_ref) == {"list"}:
                if not isinstance(value, list):
                    fail("value_type", "list expected")
                if len(value) > self.max_list:
                    fail("bound_list")
                body = b"".join(
                    self.encode(type_ref["list"], item, depth + 1) for item in value
                )
                return len(value).to_bytes(4, "little") + body
            fail("schema_shape", f"unsupported type expression {type_ref!r}")
        if not isinstance(type_ref, str):
            fail("schema_shape", "type reference must be a string or object")
        if type_ref in INTEGER_WIDTHS:
            return self._encode_uint(type_ref, value)
        if type_ref == "bool":
            if type(value) is not bool:
                fail("value_type", "bool expected")
            return b"\x01" if value else b"\x00"
        if type_ref == "Hash32":
            return hex_bytes(value, exact=32)
        if type_ref == "Bytes":
            raw = hex_bytes(value)
            if len(raw) > self.max_bytes:
                fail("bound_bytes")
            return len(raw).to_bytes(4, "little") + raw
        if type_ref == "ConsensusString":
            if not isinstance(value, str):
                fail("value_type", "ConsensusString expected")
            raw = value.encode("utf-8")
            if len(raw) > self.max_string:
                fail("bound_consensus_string")
            return len(raw).to_bytes(4, "little") + raw
        definition = self.types.get(type_ref)
        if not isinstance(definition, dict):
            fail("unknown_type", type_ref)
        kind = definition.get("kind")
        if kind == "alias":
            return self.encode(definition.get("target"), value, depth + 1)
        if kind == "record":
            if not isinstance(value, dict):
                fail("value_type", f"{type_ref} record expected")
            fields = definition.get("fields")
            if not isinstance(fields, list):
                fail("schema_shape", f"{type_ref}.fields")
            names = [field.get("name") for field in fields]
            if set(value) != set(names) or len(value) != len(names):
                fail("record_fields", type_ref)
            return b"".join(
                self.encode(field.get("type"), value[field["name"]], depth + 1)
                for field in fields
            )
        if kind == "enum":
            if not isinstance(value, dict) or "variant" not in value:
                fail("value_type", f"{type_ref} enum expected")
            variants = definition.get("variants")
            if not isinstance(variants, list):
                fail("schema_shape", f"{type_ref}.variants")
            match = next(
                (item for item in variants if item.get("name") == value["variant"]),
                None,
            )
            if match is None:
                fail("unknown_enum_variant", f"{type_ref}.{value['variant']}")
            body_type = match.get("body")
            expected_keys = {"variant", "value"} if body_type is not None else {"variant"}
            if set(value) != expected_keys:
                fail("enum_fields", type_ref)
            tag = self._encode_uint(definition.get("repr"), match.get("tag"))
            if body_type is None:
                return tag
            return tag + self.encode(body_type, value["value"], depth + 1)
        fail("schema_shape", f"unsupported kind {kind!r} for {type_ref}")

    def decode_exact(self, type_ref: Any, data: bytes) -> Any:
        reader = Reader(data)
        value = self._decode(type_ref, reader, 0)
        reader.finish()
        return value

    def _decode(self, type_ref: Any, reader: Reader, depth: int) -> Any:
        self._depth(depth)
        if isinstance(type_ref, dict):
            if set(type_ref) == {"option"}:
                tag = reader.uint(1)
                if tag == 0:
                    return None
                if tag == 1:
                    return self._decode(type_ref["option"], reader, depth + 1)
                fail("invalid_option_tag")
            if set(type_ref) == {"list"}:
                count = reader.uint(4)
                if count > self.max_list:
                    fail("bound_list")
                return [
                    self._decode(type_ref["list"], reader, depth + 1)
                    for _ in range(count)
                ]
            fail("schema_shape", f"unsupported type expression {type_ref!r}")
        if not isinstance(type_ref, str):
            fail("schema_shape", "invalid type reference")
        if type_ref in INTEGER_WIDTHS:
            return reader.uint(INTEGER_WIDTHS[type_ref])
        if type_ref == "bool":
            raw = reader.uint(1)
            if raw not in (0, 1):
                fail("invalid_bool")
            return raw == 1
        if type_ref == "Hash32":
            return reader.take(32).hex()
        if type_ref in ("Bytes", "ConsensusString"):
            size = reader.uint(4)
            limit = self.max_bytes if type_ref == "Bytes" else self.max_string
            if size > limit:
                fail("bound_bytes" if type_ref == "Bytes" else "bound_consensus_string")
            raw = reader.take(size)
            if type_ref == "Bytes":
                return raw.hex()
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                fail("invalid_utf8")
        definition = self.types.get(type_ref)
        if not isinstance(definition, dict):
            fail("unknown_type", type_ref)
        kind = definition.get("kind")
        if kind == "alias":
            return self._decode(definition.get("target"), reader, depth + 1)
        if kind == "record":
            fields = definition.get("fields")
            if not isinstance(fields, list):
                fail("schema_shape", f"{type_ref}.fields")
            return {
                field["name"]: self._decode(field.get("type"), reader, depth + 1)
                for field in fields
            }
        if kind == "enum":
            width = INTEGER_WIDTHS.get(definition.get("repr"))
            if width is None:
                fail("schema_shape", f"bad enum repr for {type_ref}")
            tag = reader.uint(width)
            variants = definition.get("variants")
            if not isinstance(variants, list):
                fail("schema_shape", f"{type_ref}.variants")
            match = next((item for item in variants if item.get("tag") == tag), None)
            if match is None:
                fail("unknown_enum_discriminant")
            result = {"variant": match["name"]}
            if match.get("body") is not None:
                result["value"] = self._decode(match["body"], reader, depth + 1)
            return result
        fail("schema_shape", f"unsupported kind {kind!r} for {type_ref}")

    @staticmethod
    def _encode_uint(type_name: Any, value: Any) -> bytes:
        width = INTEGER_WIDTHS.get(type_name)
        if width is None:
            fail("schema_shape", f"unknown integer {type_name!r}")
        if isinstance(value, bool) or not isinstance(value, int):
            fail("value_type", f"{type_name} expected")
        if value < 0 or value >= 1 << (width * 8):
            fail("integer_range", type_name)
        return value.to_bytes(width, "little", signed=False)

    def _depth(self, depth: int) -> None:
        if depth > self.max_depth:
            fail("bound_nesting")


class CandidateContract:
    """Semantic checks for the currently closed foundation/order candidate."""

    def __init__(
        self,
        schema: dict[str, Any],
        vectors: dict[str, Any],
        codec: Cev1Codec,
    ) -> None:
        self.schema = schema
        self.vectors = vectors
        self.codec = codec
        self.types = schema["types"]
        self.domains = schema.get("domains", {})
        self.fixtures = vectors.get("fixtures", {})
        self.max_signature = self.fixtures["limits"]["max_signature_bytes"]
        self.root_tags = {
            item["tag"] for item in schema.get("registries", {}).get("RootKindV1", [])
        }
        self.object_tags = {
            item["tag"] for item in schema.get("registries", {}).get("ObjectKindV1", [])
        }
        self.validator_sets: dict[str, dict[str, Any]] = {}
        for prefix in ("source", "target"):
            descriptor = self.fixtures[f"{prefix}_validator_set_descriptor"]
            expected_hash = self.fixtures[f"{prefix}_validator_set_hash"]
            actual_hash = self.digest("validator_set", "ValidatorSetDescriptorV1", descriptor)
            if actual_hash != expected_hash:
                fail("fixture_digest", f"{prefix} validator set")
            self.validator_sets[expected_hash] = descriptor["definition"]

    def digest(self, domain_key: str, type_name: str, value: Any) -> str:
        domain = self.domains.get(domain_key)
        if not isinstance(domain, str):
            fail("schema_domain", domain_key)
        return self.digest_literal(domain, type_name, value)

    def digest_literal(self, domain: str, type_name: str, value: Any) -> str:
        try:
            domain_bytes = domain.encode("ascii")
        except UnicodeEncodeError:
            fail("schema_domain", "domain must be ASCII")
        if not domain_bytes:
            fail("schema_domain", "domain must be nonempty")
        preimage = len(domain_bytes).to_bytes(4, "little") + domain_bytes
        preimage += self.codec.encode(type_name, value)
        return hashlib.sha256(preimage).hexdigest()

    def validate(self, type_ref: Any, value: Any, depth: int = 0) -> None:
        if depth > self.codec.max_depth:
            fail("bound_nesting")
        if isinstance(type_ref, dict):
            if "option" in type_ref:
                if value is not None:
                    self.validate(type_ref["option"], value, depth + 1)
                return
            if "list" in type_ref:
                for item in value:
                    self.validate(type_ref["list"], item, depth + 1)
                return
            fail("schema_shape")
        if type_ref in INTEGER_WIDTHS or type_ref in (
            "bool",
            "Hash32",
            "Bytes",
            "ConsensusString",
        ):
            self.codec.encode(type_ref, value, depth)
            return
        definition = self.types.get(type_ref)
        if not isinstance(definition, dict):
            fail("unknown_type", str(type_ref))
        if definition["kind"] == "alias":
            self.validate(definition["target"], value, depth + 1)
            return
        if definition["kind"] == "record":
            self.codec.encode(type_ref, value, depth)
            for field in definition["fields"]:
                self.validate(field["type"], value[field["name"]], depth + 1)
        elif definition["kind"] == "enum":
            self.codec.encode(type_ref, value, depth)
            variant = next(
                item for item in definition["variants"] if item["name"] == value["variant"]
            )
            if variant.get("body") is not None:
                self.validate(variant["body"], value["value"], depth + 1)
        else:
            fail("schema_shape", str(type_ref))
        self._validate_named(type_ref, value)

    def _validate_named(self, type_name: str, value: dict[str, Any]) -> None:
        if "schema_version" in value and value["schema_version"] != 1:
            fail("schema_version")
        if type_name == "ProtocolContextV1":
            if value["protocol_version"] != 1:
                fail("protocol_version")
        elif type_name == "ValidatorSetDefinitionV1":
            self._validator_definition(value)
        elif type_name == "TypedObjectIdV1":
            self._object_kind(value["object_kind"])
        elif type_name == "MerkleLeafBodyV1":
            self._root_kind(value["root_kind"])
            self._object_kind(value["item_kind"])
        elif type_name in ("MerkleNodeBodyV1", "MerkleListRootBodyV1"):
            self._root_kind(value["root_kind"])
        elif type_name == "ConsensusContextV1":
            if value["message_kind"] not in (0, 1, 2, 3, 4):
                fail("message_kind")
        elif type_name == "VoteStatementBodyV1":
            if value["consensus_context"]["message_kind"] != 1:
                fail("vote_context")
        elif type_name == "VoteIdentityBodyV1":
            self._member(value["statement"]["consensus_context"]["validator_set_hash"], value["voter_id"])
        elif type_name == "VoteSignatureEntryV1":
            self._signature_carrier(value["signature_scheme"], value["signature"])
        elif type_name == "QuorumCertificateBodyV1":
            context = value["statement"]["consensus_context"]
            self._certificate_signers(
                value["signatures"], "voter_id", context["validator_set_hash"]
            )
        elif type_name == "QuorumCertificateV1":
            actual = self.digest("quorum_certificate", "QuorumCertificateBodyV1", value["body"])
            if value["quorum_certificate_id"] != actual:
                fail("digest_mismatch", "qc_id")
        elif type_name == "GenesisAnchorV1":
            actual = self.digest("genesis_anchor", "GenesisAnchorBodyV1", value["body"])
            if value["genesis_anchor_id"] != actual:
                fail("digest_mismatch", "genesis_anchor_id")
        elif type_name == "ActivationAnchorV1":
            actual = self.digest("activation_anchor", "ActivationAnchorBodyV1", value["body"])
            if value["activation_anchor_id"] != actual:
                fail("digest_mismatch", "activation_anchor_id")
        elif type_name == "TimeoutStatementBodyV1":
            if value["consensus_context"]["message_kind"] != 2:
                fail("timeout_context")
        elif type_name == "TimeoutSignatureEntryV1":
            self._signature_carrier(value["signature_scheme"], value["signature"])
        elif type_name == "TimeoutIdentityBodyV1":
            self._member(
                value["statement"]["consensus_context"]["validator_set_hash"],
                value["validator_id"],
            )
        elif type_name == "TimeoutCertificateBodyV1":
            self._timeout_certificate(value)
        elif type_name == "EpochHandoffBodyV1":
            self._handoff_body(value)
        elif type_name == "EpochHandoffSignStatementV1":
            if value["consensus_context"]["message_kind"] not in (3, 4):
                fail("wrong_handoff_role")
        elif type_name == "EpochHandoffSignatureEntryV1":
            self._signature_carrier(value["signature_scheme"], value["signature"])
        elif type_name == "EpochHandoffV1":
            self._handoff(value)

    def _validator_definition(self, value: dict[str, Any]) -> None:
        members = value["members"]
        if not members:
            fail("empty_validator_set")
        previous: bytes | None = None
        public_keys: set[bytes] = set()
        total = 0
        for member in members:
            validator_id = hex_bytes(member["validator_id"])
            if not validator_id:
                fail("empty_validator_id")
            if previous is not None and validator_id == previous:
                fail("duplicate_validator")
            if previous is not None and validator_id < previous:
                fail("validator_order")
            previous = validator_id
            public_key = hex_bytes(member["consensus_public_key"])
            if public_key in public_keys:
                fail("duplicate_consensus_key")
            public_keys.add(public_key)
            if member["voting_weight"] <= 0:
                fail("zero_weight")
            total = self._checked_add(total, member["voting_weight"])
        if total != value["total_weight"]:
            fail("total_weight_mismatch")
        threshold = total - ((total - 1) // 3)
        if value["quorum_threshold"] != threshold:
            fail("quorum_threshold_mismatch")

    @staticmethod
    def _checked_add(left: int, right: int) -> int:
        result = left + right
        if result > MAX_U128:
            fail("checked_overflow")
        return result

    def _root_kind(self, tag: int) -> None:
        if tag not in self.root_tags:
            fail("unknown_root_kind")

    def _object_kind(self, tag: int) -> None:
        if tag not in self.object_tags:
            fail("unknown_object_kind")

    def _set(self, set_hash: str) -> dict[str, Any]:
        definition = self.validator_sets.get(set_hash)
        if definition is None:
            fail("unknown_validator_set")
        return definition

    def _member(self, set_hash: str, validator_id: str) -> dict[str, Any]:
        raw_id = hex_bytes(validator_id)
        for member in self._set(set_hash)["members"]:
            if hex_bytes(member["validator_id"]) == raw_id:
                return member
        fail("unknown_signer")

    def _signature_carrier(self, scheme: int, signature: str) -> None:
        raw = hex_bytes(signature)
        if len(raw) > self.max_signature:
            fail("bound_signature")
        if scheme != 0:
            fail("signature_scheme")

    def _certificate_signers(
        self,
        entries: list[dict[str, Any]],
        id_field: str,
        set_hash: str,
        *,
        expected_role: int | None = None,
    ) -> None:
        previous: bytes | None = None
        weight = 0
        for entry in entries:
            if expected_role is not None and entry.get("role") != expected_role:
                fail("wrong_handoff_role")
            signer = hex_bytes(entry[id_field])
            if previous is not None and signer == previous:
                fail("duplicate_signer")
            if previous is not None and signer < previous:
                fail("signer_order")
            previous = signer
            member = self._member(set_hash, entry[id_field])
            if entry["signature_scheme"] != member["consensus_key_scheme"]:
                fail("signature_scheme")
            self._signature_carrier(entry["signature_scheme"], entry["signature"])
            weight = self._checked_add(weight, member["voting_weight"])
        if weight < self._set(set_hash)["quorum_threshold"]:
            fail("insufficient_quorum")

    def _timeout_certificate(self, value: dict[str, Any]) -> None:
        if value["timed_out_view"] == (1 << 64) - 1:
            fail("checked_overflow")
        if value["target_view"] != value["timed_out_view"] + 1:
            fail("target_view")
        top = {
            "schema_version": 1,
            "context": value["context"],
            "runtime_profile_hash": value["runtime_profile_hash"],
            "epoch": value["epoch"],
            "validator_set_hash": value["validator_set_hash"],
            "consensus_parameters_hash": value["consensus_parameters_hash"],
            "view": value["timed_out_view"],
            "message_kind": 2,
        }
        available: set[tuple[str, int, str, int]] = set()
        for item in value["justifications"]:
            if item["variant"] == "QC":
                qc = item["value"]
                available.add(
                    (
                        "QC",
                        0,
                        qc["quorum_certificate_id"],
                        qc["body"]["statement"]["consensus_context"]["view"],
                    )
                )
                continue
            epoch_start = item["value"]
            kind, anchor_id, anchor_view, anchor_context = self._epoch_start(epoch_start)
            if anchor_context != value["context"]:
                fail("epoch_start_context_mismatch")
            available.add(("EpochStart", kind, anchor_id, anchor_view))
        previous: bytes | None = None
        weight = 0
        for entry in value["entries"]:
            signer = hex_bytes(entry["validator_id"])
            if previous is not None and signer == previous:
                fail("duplicate_signer")
            if previous is not None and signer < previous:
                fail("signer_order")
            previous = signer
            if entry["statement"]["consensus_context"] != top:
                fail("timeout_context")
            ref = entry["statement"]["high_justification"]
            if ref["variant"] == "QC":
                body = ref["value"]
                key = ("QC", 0, body["qc_id"], body["qc_view"])
            else:
                body = ref["value"]
                key = (
                    "EpochStart",
                    body["anchor_kind"],
                    body["anchor_id"],
                    body["anchor_view"],
                )
            if key not in available:
                fail("unresolved_justification")
            member = self._member(value["validator_set_hash"], entry["validator_id"])
            if entry["signature_scheme"] != member["consensus_key_scheme"]:
                fail("signature_scheme")
            self._signature_carrier(entry["signature_scheme"], entry["signature"])
            weight = self._checked_add(weight, member["voting_weight"])
        if weight < self._set(value["validator_set_hash"])["quorum_threshold"]:
            fail("insufficient_quorum")

    def _epoch_start(
        self, value: dict[str, Any]
    ) -> tuple[int, str, int, dict[str, Any]]:
        variant = value["variant"]
        body = value["value"]
        if variant == "GenesisAnchor":
            return 0, body["genesis_anchor_id"], 0, body["body"]["target_context"]
        if variant == "ActivationAnchor":
            return 1, body["activation_anchor_id"], 0, body["body"]["target_context"]
        if variant == "EpochHandoff":
            return (
                2,
                body["handoff_id"],
                body["body"]["initial_new_view"],
                body["body"]["target_context"],
            )
        fail("unknown_enum_variant", variant)

    @staticmethod
    def _handoff_body(value: dict[str, Any]) -> None:
        if value["old_epoch"] == (1 << 64) - 1 or value["terminal_height"] == (1 << 64) - 1:
            fail("checked_overflow")
        if value["new_epoch"] != value["old_epoch"] + 1:
            fail("handoff_epoch")
        if value["activation_height"] != value["terminal_height"] + 1:
            fail("handoff_height")
        if value["initial_new_view"] != 1:
            fail("handoff_initial_view")
        source = value["source_context"]
        target = value["target_context"]
        for field in ("genesis_hash", "chain_id", "protocol_version"):
            if source[field] != target[field]:
                fail("handoff_context")

    def _handoff(self, value: dict[str, Any]) -> None:
        body = value["body"]
        actual_id = self.digest("epoch_handoff", "EpochHandoffBodyV1", body)
        if value["handoff_id"] != actual_id:
            fail("digest_mismatch", "handoff_id")
        self._validate_handoff_entries(value["old_set_signatures"], value, 0)
        self._validate_handoff_entries(value["new_set_signatures"], value, 1)

    def _validate_handoff_entries(
        self,
        entries: list[dict[str, Any]],
        handoff: dict[str, Any],
        role: int,
    ) -> None:
        body = handoff["body"]
        if role == 0:
            set_hash = body["old_validator_set_hash"]
            expected_context = body["source_context"]
            expected_runtime = self.fixtures["source_runtime_profile_hash"]
            expected_epoch = body["old_epoch"]
            expected_params = body["old_consensus_parameters_hash"]
            expected_view = body["terminal_view"]
            message_kind = 3
        else:
            set_hash = body["new_validator_set_hash"]
            expected_context = body["target_context"]
            expected_runtime = self.fixtures["target_runtime_profile_hash"]
            expected_epoch = body["new_epoch"]
            expected_params = body["new_consensus_parameters_hash"]
            expected_view = body["initial_new_view"]
            message_kind = 4
        for entry in entries:
            if entry["role"] != role:
                fail("wrong_handoff_role")
            statement = entry["statement"]
            expected_statement_context = {
                "schema_version": 1,
                "context": expected_context,
                "runtime_profile_hash": expected_runtime,
                "epoch": expected_epoch,
                "validator_set_hash": set_hash,
                "consensus_parameters_hash": expected_params,
                "view": expected_view,
                "message_kind": message_kind,
            }
            if statement["consensus_context"] != expected_statement_context:
                fail("handoff_context")
            if statement["handoff_id"] != handoff["handoff_id"]:
                fail("digest_mismatch", "handoff statement")
        self._certificate_signers(
            entries, "signer_id", set_hash, expected_role=role
        )


DIGEST_LABELS = {
    "validator_set_definition_hash": "validator_set_definition",
    "validator_set_hash": "validator_set",
    "consensus_parameters_hash": "consensus_parameters",
    "leaf_hash": "merkle_leaf",
    "node_hash": "merkle_node",
    "list_root": "merkle_list_root",
    "block_id": "block_id",
    "vote_signature_root": "vote_signature",
    "vote_id": "vote_id",
    "qc_id": "quorum_certificate",
    "genesis_anchor_id": "genesis_anchor",
    "timeout_signature_root": "timeout_signature",
    "timeout_id": "timeout_id",
    "tc_id": "timeout_certificate",
    "handoff_id": "epoch_handoff",
    "old_set_signature_root": "epoch_handoff_old_signature",
    "new_set_signature_root": "epoch_handoff_new_signature",
}


class CorpusVerifier:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.schema = load_json(root / SCHEMA_REL)
        self.vectors = load_json(root / VECTORS_REL)
        self._artifact_boundary()
        limits = self.vectors.get("fixtures", {}).get("limits")
        if not isinstance(limits, dict):
            fail("fixture_shape", "limits")
        self.codec = Cev1Codec(self.schema, limits)
        self.contract = CandidateContract(self.schema, self.vectors, self.codec)

    def _artifact_boundary(self) -> None:
        if self.schema.get("artifact") != "trnm.poco-ai.cev1-foundation-order-kernel.v1":
            fail("artifact_identity", "schema")
        if self.vectors.get("schema_artifact") != self.schema.get("artifact"):
            fail("artifact_identity", "vector schema reference")
        for artifact in (self.schema, self.vectors):
            status = artifact.get("status")
            if not isinstance(status, dict):
                fail("artifact_shape", "status")
            required_false = (
                "normative_freeze",
                "global_wire_schema_complete",
                "semantic_consistency_proven",
                "implementation_or_activation_evidence",
                "cryptographic_interoperability_evidence",
            )
            if status.get("classification") != "candidate_non_normative":
                fail("artifact_status", "classification")
            if status.get("closed_for_listed_types_only") is not True:
                fail("artifact_status", "closed scope")
            if any(status.get(key) is not False for key in required_false):
                fail("artifact_status", "global evidence must remain false")
        if len(self.vectors.get("positive_cases", [])) != 27:
            fail("corpus_count", "positive")
        if len(self.vectors.get("derived_cases", [])) != 1:
            fail("corpus_count", "derived")
        if len(self.vectors.get("negative_cases", [])) != 24:
            fail("corpus_count", "negative")

    def verify(self, *, self_test: bool) -> tuple[int, int, int, int]:
        positive = self._positive()
        derived = self._derived()
        negative = self._negative()
        mutations = self._self_test() if self_test else 0
        return positive, derived, negative, mutations

    def _positive(self) -> int:
        seen: set[str] = set()
        for case in self.vectors["positive_cases"]:
            case_id = case.get("case_id")
            if not isinstance(case_id, str) or not case_id or case_id in seen:
                fail("case_identity", "positive")
            seen.add(case_id)
            type_name = case["type"]
            value = case["value"]
            expected = hex_bytes(case["cev1_hex"])
            encoded = self.codec.encode(type_name, value)
            if encoded != expected:
                fail("encoding_mismatch", case_id)
            decoded = self.codec.decode_exact(type_name, expected)
            if decoded != value:
                fail("roundtrip_mismatch", case_id)
            if self.codec.encode(type_name, decoded) != expected:
                fail("noncanonical_roundtrip", case_id)
            self.contract.validate(type_name, decoded)
            for digest in case.get("digests", []):
                label = digest.get("label")
                domain_key = DIGEST_LABELS.get(label)
                if domain_key is None:
                    fail("digest_label", f"{case_id}: {label}")
                if digest.get("domain") != self.schema["domains"].get(domain_key):
                    fail("schema_domain", f"{case_id}: {label}")
                actual = self.contract.digest(domain_key, type_name, decoded)
                if actual != digest.get("digest_hex"):
                    fail("digest_mismatch", f"{case_id}: {label}")
        return len(seen)

    def _derived(self) -> int:
        cases = self.vectors["derived_cases"]
        for case in cases:
            if case.get("case_id") != "ordered_root_three_items_odd_duplication":
                fail("case_identity", "unexpected derived case")
            root_kind = case["root_kind"]
            self.contract._root_kind(root_kind)
            computed_leaves: list[dict[str, Any]] = []
            layer: list[str] = []
            for index, item in enumerate(case["items"]):
                body = {
                    "root_kind": root_kind,
                    "index": index,
                    "item_kind": item["item_kind"],
                    "item_id": item["item_id"],
                    "item_commitment": item["item_commitment"],
                }
                self.contract.validate("MerkleLeafBodyV1", body)
                digest = self.contract.digest("merkle_leaf", "MerkleLeafBodyV1", body)
                computed_leaves.append({"body": body, "digest_hex": digest})
                layer.append(digest)
            if computed_leaves != case["leaves"]:
                fail("derived_mismatch", "leaves")
            computed_levels: list[dict[str, Any]] = []
            level = 0
            while len(layer) > 1:
                nodes: list[dict[str, Any]] = []
                next_layer: list[str] = []
                for offset in range(0, len(layer), 2):
                    left = layer[offset]
                    right = layer[offset + 1] if offset + 1 < len(layer) else left
                    body = {
                        "root_kind": root_kind,
                        "level": level,
                        "left": left,
                        "right": right,
                    }
                    digest = self.contract.digest("merkle_node", "MerkleNodeBodyV1", body)
                    nodes.append({"body": body, "digest_hex": digest})
                    next_layer.append(digest)
                computed_levels.append({"level": level, "nodes": nodes})
                layer = next_layer
                level += 1
            if computed_levels != case["levels"]:
                fail("derived_mismatch", "levels")
            root_body = {
                "root_kind": root_kind,
                "item_count": len(case["items"]),
                "tree_root": layer[0] if layer else None,
            }
            if root_body != case["root_body"]:
                fail("derived_mismatch", "root body")
            root_digest = self.contract.digest(
                "merkle_list_root", "MerkleListRootBodyV1", root_body
            )
            if root_digest != case["root_digest_hex"]:
                fail("derived_mismatch", "root digest")
        return len(cases)

    def _negative(self) -> int:
        seen: set[str] = set()
        for case in self.vectors["negative_cases"]:
            case_id = case.get("case_id")
            if not isinstance(case_id, str) or not case_id or case_id in seen:
                fail("case_identity", "negative")
            seen.add(case_id)
            expected = case["expected_error"]
            try:
                self._run_negative(case)
            except ContractError as exc:
                if exc.code != expected:
                    fail(
                        "negative_error_mismatch",
                        f"{case_id}: expected {expected}, got {exc.code}",
                    )
            else:
                fail("negative_accepted", case_id)
        return len(seen)

    def _run_negative(self, case: dict[str, Any]) -> None:
        mode = case["mode"]
        type_name = case["type"]
        if mode == "decode":
            decoded = self.codec.decode_exact(type_name, hex_bytes(case["encoded_hex"]))
            self.contract.validate(type_name, decoded)
            return
        if mode == "decode_equals":
            decoded = self.codec.decode_exact(type_name, hex_bytes(case["encoded_hex"]))
            if decoded != case["expected_value"]:
                fail("decoded_value_mismatch")
            return
        if mode == "value":
            encoded = self.codec.encode(type_name, case["value"])
            decoded = self.codec.decode_exact(type_name, encoded)
            self.contract.validate(type_name, decoded)
            return
        if mode == "context_binding":
            encoded = self.codec.encode(type_name, case["value"])
            decoded = self.codec.decode_exact(type_name, encoded)
            self.contract.validate(type_name, decoded)
            if decoded != case["expected_context"]:
                fail("context_binding_mismatch")
            return
        if mode == "digest":
            self.contract.validate(type_name, case["value"])
            actual = self.contract.digest_literal(case["domain"], type_name, case["value"])
            if actual != case["declared_digest_hex"]:
                fail("digest_mismatch")
            return
        if mode == "root_binding":
            self.contract.validate(type_name, case["value"])
            if case["value"]["root_kind"] != case["expected_root_kind"]:
                fail("root_kind_mismatch")
            return
        fail("negative_mode", str(mode))

    def _self_test(self) -> int:
        positives = self.vectors["positive_cases"]
        tests = 0
        for case in positives:
            raw = hex_bytes(case["cev1_hex"])
            for mutated in (raw + b"\x00", raw[:-1]):
                try:
                    self.codec.decode_exact(case["type"], mutated)
                except ContractError:
                    tests += 1
                else:
                    fail("self_test_accepted", case["case_id"])
        direct = [
            ("bool", b"\x02", "invalid_bool"),
            ({"option": "Hash32"}, b"\x02", "invalid_option_tag"),
            ({"list": "u8"}, (self.codec.max_list + 1).to_bytes(4, "little"), "bound_list"),
            (
                "ConsensusString",
                (self.codec.max_string + 1).to_bytes(4, "little"),
                "bound_consensus_string",
            ),
        ]
        for type_ref, raw, expected in direct:
            try:
                self.codec.decode_exact(type_ref, raw)
            except ContractError as exc:
                if exc.code != expected:
                    fail("self_test_error", f"expected {expected}, got {exc.code}")
                tests += 1
            else:
                fail("self_test_accepted", expected)
        duplicate = copy.deepcopy(
            next(
                case["value"]
                for case in positives
                if case["case_id"] == "quorum_certificate"
            )
        )
        duplicate["signatures"][1]["voter_id"] = duplicate["signatures"][0]["voter_id"]
        try:
            self.contract.validate("QuorumCertificateBodyV1", duplicate)
        except ContractError as exc:
            if exc.code != "duplicate_signer":
                fail("self_test_error", f"duplicate signer produced {exc.code}")
            tests += 1
        else:
            fail("self_test_accepted", "duplicate signer")
        return tests


def repository_root(script: Path) -> Path:
    root = script.resolve().parents[2]
    if not (root / SCHEMA_REL).is_file() or not (root / VECTORS_REL).is_file():
        fail("repository_root", str(root))
    return root


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="also execute checker-owned malformed-input mutants",
    )
    args = parser.parse_args(argv)
    try:
        verifier = CorpusVerifier(repository_root(Path(__file__)))
        positive, derived, negative, mutations = verifier.verify(self_test=args.self_test)
    except ContractError as exc:
        print(f"poco-ai-v1 independent foundation/order checker: FAIL: {exc}", file=sys.stderr)
        return 1
    suffix = f" + {mutations} self-test rejects" if args.self_test else ""
    print(
        "poco-ai-v1 independent foundation/order checker: "
        f"PASS ({positive} positive + {derived} derived + {negative} negative{suffix})"
    )
    print(
        "boundary: candidate-only; opaque signatures; no global schema, crypto, "
        "light-client, upgrade, freeze, activation, or release evidence"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
