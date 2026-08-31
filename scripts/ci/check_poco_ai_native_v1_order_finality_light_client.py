#!/usr/bin/env python3
"""Independent bounded PoCO v1 OrderFinalityProof light-client checker.

The checker deliberately imports neither another PoCO checker nor any TRNM
implementation crate.  It strict-decodes raw CEV1 trust/proof bytes, re-encodes
them byte-for-byte, implements strict Ed25519 in the Python standard library,
and verifies the bounded fresh-genesis/ordinary-target, one-epoch three-chain
tranche assigned by its paired candidate schema, including one skipped-view
TimeoutCertificate path.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-order-finality-light-client-kernel-v1.json"
FOUNDATION_SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json"
CORPUS_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json"
TRUST_PATH_SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-order-trust-path-iterator-v1.json"
TRUST_PATH_CORPUS_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-order-trust-path-iterator-v1.json"
WEAK_SUBJECTIVITY_SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
WEAK_SUBJECTIVITY_CORPUS_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
ORDINARY_ADVANCE_SCHEMA_PATH = ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-order-ordinary-finality-advance-v1.json"
ORDINARY_ADVANCE_CORPUS_PATH = ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-order-ordinary-finality-advance-v1.json"

VALIDATOR_SET_DEFINITION_DOMAIN = "trnm.poco-ai.validator-set-definition.v1"
VALIDATOR_SET_DOMAIN = "trnm.poco-ai.validator-set.v1"
CONSENSUS_PARAMETERS_DOMAIN = "trnm.poco-ai.consensus-parameters.v1"
EPOCH_DESCRIPTOR_DOMAIN = "trnm.poco-ai.epoch-descriptor.v1"
BLOCK_DOMAIN = "trnm.poco-ai.order-block.v1"
VOTE_DOMAIN = "trnm.poco-ai.order-vote-signature.v1"
QC_DOMAIN = "trnm.poco-ai.order-qc.v1"
TIMEOUT_SIGNATURE_DOMAIN = "trnm.poco-ai.order-timeout-signature.v1"
TC_DOMAIN = "trnm.poco-ai.order-tc.v1"
EPOCH_CHECKPOINT_DOMAIN = "trnm.poco-ai.epoch-checkpoint.v1"
EPOCH_HANDOFF_DOMAIN = "trnm.poco-ai.epoch-handoff.v1"
EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN = "trnm.poco-ai.epoch-handoff-old-signature.v1"
EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN = "trnm.poco-ai.epoch-handoff-new-signature.v1"
PROOF_DOMAIN = "trnm.poco-ai.order-finality-proof.v1"
MERKLE_LIST_ROOT_DOMAIN = "trnm.poco-ai.merkle-list-root.v1"
MERKLE_LEAF_DOMAIN = "trnm.poco-ai.merkle-leaf.v1"
MERKLE_NODE_DOMAIN = "trnm.poco-ai.merkle-node.v1"
PROTOCOL_SIDECAR_CONTENT_DOMAIN = "trnm.poco-ai.protocol-sidecar-content.v1"
TRUSTED_ORDER_STATE_DOMAIN = "trnm.poco-ai.trusted-order-state.v1"
CHECKPOINT_TRANSITION_STEP_DOMAIN = "trnm.poco-ai.checkpoint-anchored-transition-step.v1"
ORDER_TRUST_PATH_DOMAIN = "trnm.poco-ai.order-trust-path.v1"
WEAK_SUBJECTIVITY_ANCHOR_DOMAIN = "trnm.poco-ai.weak-subjectivity-anchor.v1"
WEAK_SUBJECTIVITY_POLICY_DOMAIN = "trnm.poco-ai.weak-subjectivity-renewal-policy.v1"
WEAK_SUBJECTIVITY_RENEWAL_DOMAIN = "trnm.poco-ai.weak-subjectivity-renewal.v1"
ORDINARY_FINALITY_ADVANCE_DOMAIN = "trnm.poco-ai.order-ordinary-finality-advance.v1"

STRICT_ED25519 = 0
U64_MAX = 2**64 - 1
U128_MAX = 2**128 - 1
MAX_PARSER_VALIDATORS = 256
MAX_PARSER_CERTIFICATE_SIGNERS = 256
MAX_PARSER_CONSENSUS_STRING_BYTES = 1024
MAX_PARSER_SIGNATURE_BYTES = 128
REQUIRED_TRANCHE_CEV1_NESTING = 8
MAX_TRUST_PATH_STEPS = 3
PROTOCOL_OBJECTS_ROOT_KIND = 1
EPOCH_HANDOFF_OBJECT_KIND = 30
EPOCH_HANDOFF_SIDECAR_TAG = 2

FOUNDATION_TYPE_SNAPSHOT_SHA256 = {
    "BlockHeaderV1": "c5bc9828cb0f716b204f3c8927f3b034f3debd083019f2d68499c8d8cf35cac3",
    "BlockIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "BlockKindV1": "273446a1a37542080178c159c4456960d8c9d82ac2903640374c2d18e8e29a01",
    "ConsensusContextV1": "836c0f613d91d57a6b3cfc37600f8ed551ad63d06f343c8cc243b45339e3da43",
    "ConsensusParametersV1": "a50bc645ebcc1f4f1db664dd289dc73c1c8bae1ad4e91a9edceb33d8a6144d93",
    "EpochDescriptorIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "EpochHandoffIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "EpochHandoffBodyV1": "ea07e9afedc2ea2b5f6784685f887725a51e601d256135fa75e447867d193996",
    "EpochHandoffSignStatementV1": "a66507c26992a91084368f37e03f67c1ce7f4f1bea9919e9c591765adb074aec",
    "EpochHandoffSignatureEntryV1": "a3c5c1f8df6451172282e049f6644ed9d3847eb09d69037fe1cf5e1d7016d8c2",
    "EpochHandoffV1": "12b91912bfb40524a7aaa31a6dc3b0c4f78e5d52ac0e376b6fe4a630adafa674",
    "EpochCheckpointIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "EpochCheckpointFinalizedAnchorBodyV1": "2a9c193b064825e3c1223da725936fc1e3dcac440f02407a0e071f0b7718be75",
    "EpochStartJustificationRefBodyV1": "70a1a47645b1d5515d88db5ca9d2be2d43dfb546be1a5a030405f4f0fd005ddf",
    "FinalizedAnchorRefV1": "de36ce8fee22a395e7a2ed2d5653f23fc050b2a347b87e596930e6fdac42059c",
    "FreshGenesisFinalizedAnchorBodyV1": "68a80b21450e049c8217537a68315e3f6e02fd4e8ceb64aac6f4a4f658562c0f",
    "GenesisParentBodyV1": "fc0835475a09fd04ad4c6fed7e6610d73c1fc83cc33430eae24e6b6a70925af0",
    "ParentBlockRefV1": "a6004e6d8b2bf0712f2343349a387d0e169278904cc7cfb64ceddd581b2151eb",
    "ProtocolContextV1": "8e2376f3bb007825ef541e47c387384fe43561c70db010c0973887d389c1ef85",
    "QcJustificationRefBodyV1": "494aefbd6f5b6fa7ee73e7fab11e89a2446ef164ce1fb9879319af2c46c32853",
    "QuorumCertificateBodyV1": "949db40562522d2688bc8b1f42d256546d9e452cdd1e2091fb1c9859255e8409",
    "QuorumCertificateIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "QuorumCertificateV1": "0d7f3516dcd240c415206933159d033015700efacbccd9ce9fea3dfef659f896",
    "TimeoutCertificateIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "HighJustificationObjectV1": "6a8c43ca071a71f83020f77ed61792e60fb06989cf43be4e960f6c20792b76f5",
    "HighJustificationRefV1": "fe93716c7b28a418447416a04b2417ff7201748ca878fd6fec2bae945072cfcc",
    "TimeoutCertificateBodyV1": "3fde9a3df3ac0396dfda66eea07fbd217ec24da3dc834fcf6daa4116d999c345",
    "TimeoutSignatureEntryV1": "d2ff070ad2bfbc39499b6657a34998884d388f673e6d66423d969a400b6de09c",
    "TimeoutStatementBodyV1": "3454ee0b2788755b9bfe5c4ff0140e70cb14b659f273d5b41c0dff68bbd54fd9",
    "UpgradePlanIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "V0TerminalBlockParentBodyV1": "fd818e93788a39af789f4cfa2f4d42b857a2eecbeb2976605413c7d2f813fb0e",
    "V0ToV1ActivationStatementIdV1": "cd0d93470883c4124552fbfbe1e4c31577e02bca63f9ceacffccf1d6bc2e0b29",
    "V0ActivationFinalizedAnchorBodyV1": "3b74b9ff144c41827b8643c482e7882902924fcf613073047aae380e890fe7c6",
    "V1BlockParentBodyV1": "36a6af33b771a5f03083f613f5bb9314a6f1b41dba73c85a9e1ba66c0055e3a1",
    "ValidatorMemberV1": "4341be3dd55331b5bf8c3905181b7dcd5ed17cc4d4b0ea696e16bb7893f761f0",
    "ValidatorSetDefinitionV1": "47746442ae057b60a02e5cb61f99dbfad348c7df3a4b784b9eba28a1d7f1e530",
    "ValidatorSetDescriptorV1": "ac1bfd193c53c1926678c4fa652656dcc7c7e74746fe2c20444cc679601a7935",
    "VoteSignatureEntryV1": "316ed36127a19478629450785592d7af17c564ff0245f5dd5d03cd5788f1285f",
    "VoteStatementBodyV1": "cf860ddcbb750e175376ea9ad0d098d70bfbbd51269ff5860fd664b1ee567e49",
}
FOUNDATION_DOMAINS_SNAPSHOT_SHA256 = "3546963c0db790eabd51041ee41a4af79bca928ebd0007b0f18059c89ece4847"
FOUNDATION_REGISTRIES_SNAPSHOT_SHA256 = "d638890c70302188e76fffc502c602b0bf06b0369330b6b79adae70433446a28"
FOUNDATION_CONSTRAINTS_SNAPSHOT_SHA256 = "462568a3b8b8af936beb5af94da3bf6a8ad7cd474cca4b3994fb5dfeed486efa"

FIELD = 2**255 - 19
GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD - 2, FIELD)) % FIELD
SQRT_MINUS_ONE = pow(2, (FIELD - 1) // 4, FIELD)
IDENTITY = (0, 1, 1, 0)


class EvidenceError(Exception):
    """Fail-closed parser, crypto, or semantic rejection."""


def reject(code: str, detail: str = "") -> None:
    raise EvidenceError(code if not detail else f"{code}: {detail}")


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object names instead of accepting last-wins JSON."""
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            reject("json_duplicate_key", key)
        value[key] = child
    return value


def load_json_document(path: Path, label: str) -> Any:
    """Parse one UTF-8 source artifact with an unambiguous object mapping."""
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_json_object,
        )
    except UnicodeError as exc:
        raise EvidenceError(f"{label}_json_utf8") from exc


def assert_strict_json_loader() -> None:
    """Keep duplicate-key rejection live in every checker execution mode."""
    require(
        json.loads(
            '{"outer":{"left":1,"right":2}}',
            object_pairs_hook=strict_json_object,
        ) == {"outer": {"left": 1, "right": 2}},
        "json_unique_key_control",
    )
    try:
        json.loads(
            '{"outer":{"same":1,"same":2}}',
            object_pairs_hook=strict_json_object,
        )
    except EvidenceError as exc:
        require(str(exc) == "json_duplicate_key: same", "json_duplicate_key_error")
    else:
        reject("json_duplicate_key_accepted")


def require(condition: bool, code: str, detail: str = "") -> None:
    if not condition:
        reject(code, detail)


def exact_keys(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == keys, code)
    return value


def structural_sha256(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def uint(value: Any, bits: int, code: str) -> int:
    require(type(value) is int and 0 <= value < 2**bits, code)
    return value


def digest(domain: str, encoded: bytes) -> bytes:
    raw = domain.encode("ascii")
    require(raw and len(raw) < 2**32, "domain")
    return hashlib.sha256(struct.pack("<I", len(raw)) + raw + encoded).digest()


def label_hash(label: str) -> bytes:
    return hashlib.sha256(b"trnm.poco-ai.light-client.public-fixture.v1:" + label.encode("ascii")).digest()


def enc_u(value: int, bits: int) -> bytes:
    return uint(value, bits, "encode_uint").to_bytes(bits // 8, "little")


def enc_bytes(value: bytes) -> bytes:
    require(isinstance(value, bytes) and len(value) < 2**32, "encode_bytes")
    return struct.pack("<I", len(value)) + value


def enc_string(value: str) -> bytes:
    require(isinstance(value, str), "encode_string")
    raw = value.encode("utf-8")
    require(raw.decode("utf-8") == value, "encode_string_utf8")
    return enc_bytes(raw)


def enc_hash(value: bytes) -> bytes:
    require(isinstance(value, bytes) and len(value) == 32, "encode_hash")
    return value


def enc_option_hash(value: bytes | None) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + enc_hash(value)


def empty_ordered_root(root_kind: int) -> bytes:
    return digest(
        MERKLE_LIST_ROOT_DOMAIN,
        enc_u(root_kind, 16) + enc_u(0, 32) + b"\x00",
    )


def enc_list(values: list[Any], encoder: Callable[[Any], bytes]) -> bytes:
    require(isinstance(values, list) and len(values) < 2**32, "encode_list")
    return struct.pack("<I", len(values)) + b"".join(encoder(value) for value in values)


class Cursor:
    def __init__(self, raw: bytes, label: str) -> None:
        self.raw = raw
        self.pos = 0
        self.label = label

    def take(self, size: int) -> bytes:
        require(type(size) is int and size >= 0, "decode_size")
        if self.pos + size > len(self.raw):
            reject("truncated", self.label)
        value = self.raw[self.pos : self.pos + size]
        self.pos += size
        return value

    def u(self, bits: int) -> int:
        return int.from_bytes(self.take(bits // 8), "little")

    def hash32(self) -> bytes:
        return self.take(32)

    def bytes(self, maximum: int, code: str) -> bytes:
        length = self.u(32)
        require(length <= maximum, code)
        return self.take(length)

    def string(self, maximum: int, code: str) -> str:
        raw = self.bytes(maximum, code)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvidenceError(f"{code}: UTF-8") from exc
        require(value.encode("utf-8") == raw, code)
        return value

    def option_hash(self) -> bytes | None:
        tag = self.u(8)
        if tag == 0:
            return None
        require(tag == 1, "unknown_option_tag")
        return self.hash32()

    def finish(self) -> None:
        require(self.pos == len(self.raw), "trailing_bytes", self.label)


def enc_protocol_context(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "genesis_hash", "chain_id", "protocol_version", "stack_profile_hash"}, "context_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_hash(value["genesis_hash"]),
        enc_string(value["chain_id"]), enc_u(value["protocol_version"], 32),
        enc_hash(value["stack_profile_hash"]),
    ))


def dec_protocol_context(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "genesis_hash": cursor.hash32(),
        "chain_id": cursor.string(MAX_PARSER_CONSENSUS_STRING_BYTES, "chain_id_parser_bound"),
        "protocol_version": cursor.u(32), "stack_profile_hash": cursor.hash32(),
    }


def enc_validator_member(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"validator_id", "consensus_key_scheme", "consensus_public_key", "voting_weight", "network_identity_commitment", "safety_signer_policy_hash", "poco_economic_record_hash"}, "validator_member_fields")
    return b"".join((
        enc_bytes(value["validator_id"]), enc_u(value["consensus_key_scheme"], 16),
        enc_bytes(value["consensus_public_key"]), enc_u(value["voting_weight"], 128),
        enc_hash(value["network_identity_commitment"]), enc_hash(value["safety_signer_policy_hash"]),
        enc_hash(value["poco_economic_record_hash"]),
    ))


def dec_validator_member(cursor: Cursor) -> dict[str, Any]:
    return {
        "validator_id": cursor.bytes(128, "validator_id_bound"),
        "consensus_key_scheme": cursor.u(16),
        "consensus_public_key": cursor.bytes(64, "validator_key_bound"),
        "voting_weight": cursor.u(128),
        "network_identity_commitment": cursor.hash32(),
        "safety_signer_policy_hash": cursor.hash32(),
        "poco_economic_record_hash": cursor.hash32(),
    }


def enc_validator_definition(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "members", "total_weight", "quorum_threshold"}, "validator_definition_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_list(value["members"], enc_validator_member),
        enc_u(value["total_weight"], 128), enc_u(value["quorum_threshold"], 128),
    ))


def dec_validator_definition(cursor: Cursor) -> dict[str, Any]:
    version = cursor.u(16)
    count = cursor.u(32)
    require(1 <= count <= MAX_PARSER_VALIDATORS, "validator_count_parser_bound")
    members = [dec_validator_member(cursor) for _ in range(count)]
    return {"schema_version": version, "members": members, "total_weight": cursor.u(128), "quorum_threshold": cursor.u(128)}


def enc_validator_set(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "context", "epoch", "definition"}, "validator_set_fields")
    return enc_u(value["schema_version"], 16) + enc_protocol_context(value["context"]) + enc_u(value["epoch"], 64) + enc_validator_definition(value["definition"])


def dec_validator_set(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.u(16), "context": dec_protocol_context(cursor), "epoch": cursor.u(64), "definition": dec_validator_definition(cursor)}


PARAMETER_FIELDS: tuple[tuple[str, int | str], ...] = (
    ("schema_version", 16), ("quorum_numerator", 16), ("quorum_denominator", 16),
    ("finality_chain_length", 8), ("execute_coordination_before_vote", "bool"),
    ("max_validators", 32), ("max_consensus_string_bytes", 32), ("max_cev1_nesting", 16),
    ("max_cev1_value_bytes", 64), ("max_signature_bytes", 32), ("max_certificate_signers", 32),
    ("max_epoch", 64), ("max_view", 64), ("max_height", 64), ("max_retained_views", 32),
    ("epoch_length_blocks", 64), ("checkpoint_offset_blocks", 64), ("seal_1_offset_blocks", 64),
    ("seal_2_offset_blocks", 64), ("max_block_ordered_bytes", 64), ("max_batch_refs_per_block", 32),
    ("max_protocol_objects_per_block", 32), ("max_transactions_per_batch", 32),
    ("max_transaction_bytes", 64), ("max_block_execution_units", 128), ("base_view_timeout_ms", 64),
    ("maximum_view_timeout_ms", 64), ("timeout_multiplier_numerator", 32),
    ("timeout_multiplier_denominator", 32), ("max_evidence_items_per_block", 32),
    ("max_evidence_bytes_per_block", 64),
)


def enc_parameters(value: dict[str, Any]) -> bytes:
    exact_keys(value, {name for name, _ in PARAMETER_FIELDS}, "parameter_fields")
    parts = []
    for name, width in PARAMETER_FIELDS:
        if width == "bool":
            require(type(value[name]) is bool, "parameter_bool")
            parts.append(b"\x01" if value[name] else b"\x00")
        else:
            parts.append(enc_u(value[name], int(width)))
    return b"".join(parts)


def dec_parameters(cursor: Cursor) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, width in PARAMETER_FIELDS:
        if width == "bool":
            tag = cursor.u(8)
            require(tag in (0, 1), "parameter_bool")
            result[name] = tag == 1
        else:
            result[name] = cursor.u(int(width))
    return result


EPOCH_BODY_HASH_FIELDS = (
    "validator_set_hash", "consensus_parameters_hash", "runtime_profile_hash", "snapshot_policy_hash",
    "da_policy_hash", "da_committee_set_root", "verification_registry_hash", "fee_schedule_hash",
    "state_schema_hash", "leader_schedule_id", "upgrade_authority_root",
)


def enc_epoch_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "context", "epoch", *EPOCH_BODY_HASH_FIELDS}, "epoch_body_fields")
    return enc_u(value["schema_version"], 16) + enc_protocol_context(value["context"]) + enc_u(value["epoch"], 64) + b"".join(enc_hash(value[name]) for name in EPOCH_BODY_HASH_FIELDS)


def dec_epoch_body(cursor: Cursor) -> dict[str, Any]:
    result = {"schema_version": cursor.u(16), "context": dec_protocol_context(cursor), "epoch": cursor.u(64)}
    result.update({name: cursor.hash32() for name in EPOCH_BODY_HASH_FIELDS})
    return result


def enc_epoch_descriptor(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "epoch_descriptor_id"}, "epoch_descriptor_fields")
    return enc_epoch_body(value["body"]) + enc_hash(value["epoch_descriptor_id"])


def dec_epoch_descriptor(cursor: Cursor) -> dict[str, Any]:
    return {"body": dec_epoch_body(cursor), "epoch_descriptor_id": cursor.hash32()}


def enc_parent(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "parent_fields")
    if value["variant"] == "GenesisAnchor":
        body = exact_keys(value["value"], {"genesis_derived_state_hash", "application_state_root"}, "genesis_parent_fields")
        return b"\x00" + enc_hash(body["genesis_derived_state_hash"]) + enc_hash(body["application_state_root"])
    if value["variant"] == "V1Block":
        body = exact_keys(value["value"], {"block_id"}, "v1_parent_fields")
        return b"\x01" + enc_hash(body["block_id"])
    reject("parent_variant")


def dec_parent(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.u(8)
    if tag == 0:
        return {"variant": "GenesisAnchor", "value": {"genesis_derived_state_hash": cursor.hash32(), "application_state_root": cursor.hash32()}}
    if tag == 1:
        return {"variant": "V1Block", "value": {"block_id": cursor.hash32()}}
    reject("parent_variant")


HEADER_ROOT_FIELDS = (
    "batch_refs_root", "protocol_objects_root", "post_state_root", "transaction_execution_receipts_root",
    "evidence_root", "consumption_rollups_root", "settlement_root", "resource_usage_root",
)


def enc_header(value: dict[str, Any]) -> bytes:
    keys = {"schema_version", "context", "epoch", "view", "height", "block_kind", "parent", "proposer_id", "epoch_descriptor_id", "justify_qc_id", "timeout_certificate_id", *HEADER_ROOT_FIELDS, "next_epoch_descriptor_id", "upgrade_plan_id", "epoch_handoff_id"}
    exact_keys(value, keys, "header_fields")
    kind = {
        "FreshGenesis": 0, "Ordinary": 1, "EpochCheckpoint": 2,
        "EpochSeal1": 3, "EpochSeal2": 4, "V0ActivationFirst": 5,
        "V1HandoffFirst": 6,
    }.get(value["block_kind"])
    require(kind is not None, "block_kind")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]), enc_u(value["epoch"], 64),
        enc_u(value["view"], 64), enc_u(value["height"], 64), enc_u(kind, 8), enc_parent(value["parent"]),
        enc_bytes(value["proposer_id"]), enc_hash(value["epoch_descriptor_id"]), enc_option_hash(value["justify_qc_id"]),
        enc_option_hash(value["timeout_certificate_id"]), *(enc_hash(value[name]) for name in HEADER_ROOT_FIELDS),
        enc_option_hash(value["next_epoch_descriptor_id"]), enc_option_hash(value["upgrade_plan_id"]), enc_option_hash(value["epoch_handoff_id"]),
    ))


def dec_header(cursor: Cursor) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor), "epoch": cursor.u(64),
        "view": cursor.u(64), "height": cursor.u(64),
    }
    kind = cursor.u(8)
    kinds = (
        "FreshGenesis", "Ordinary", "EpochCheckpoint", "EpochSeal1",
        "EpochSeal2", "V0ActivationFirst", "V1HandoffFirst",
    )
    require(kind < len(kinds), "block_kind")
    result["block_kind"] = kinds[kind]
    result.update({
        "parent": dec_parent(cursor), "proposer_id": cursor.bytes(128, "proposer_id_bound"),
        "epoch_descriptor_id": cursor.hash32(), "justify_qc_id": cursor.option_hash(),
        "timeout_certificate_id": cursor.option_hash(),
    })
    result.update({name: cursor.hash32() for name in HEADER_ROOT_FIELDS})
    result.update({"next_epoch_descriptor_id": cursor.option_hash(), "upgrade_plan_id": cursor.option_hash(), "epoch_handoff_id": cursor.option_hash()})
    return result


def enc_consensus_context(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "context", "runtime_profile_hash", "epoch", "validator_set_hash", "consensus_parameters_hash", "view", "message_kind"}, "consensus_context_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]), enc_hash(value["runtime_profile_hash"]),
        enc_u(value["epoch"], 64), enc_hash(value["validator_set_hash"]), enc_hash(value["consensus_parameters_hash"]),
        enc_u(value["view"], 64), enc_u(value["message_kind"], 8),
    ))


def dec_consensus_context(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor), "runtime_profile_hash": cursor.hash32(),
        "epoch": cursor.u(64), "validator_set_hash": cursor.hash32(), "consensus_parameters_hash": cursor.hash32(),
        "view": cursor.u(64), "message_kind": cursor.u(8),
    }


def enc_vote(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "consensus_context", "block_id", "height", "epoch_descriptor_id", "post_state_root", "batch_refs_root", "transaction_execution_receipts_root"}, "vote_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_consensus_context(value["consensus_context"]), enc_hash(value["block_id"]),
        enc_u(value["height"], 64), enc_hash(value["epoch_descriptor_id"]), enc_hash(value["post_state_root"]),
        enc_hash(value["batch_refs_root"]), enc_hash(value["transaction_execution_receipts_root"]),
    ))


def dec_vote(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "consensus_context": dec_consensus_context(cursor), "block_id": cursor.hash32(),
        "height": cursor.u(64), "epoch_descriptor_id": cursor.hash32(), "post_state_root": cursor.hash32(),
        "batch_refs_root": cursor.hash32(), "transaction_execution_receipts_root": cursor.hash32(),
    }


def enc_signature(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"voter_id", "signature_scheme", "signature"}, "signature_fields")
    return enc_bytes(value["voter_id"]) + enc_u(value["signature_scheme"], 16) + enc_bytes(value["signature"])


def dec_signature(cursor: Cursor) -> dict[str, Any]:
    return {"voter_id": cursor.bytes(128, "voter_id_bound"), "signature_scheme": cursor.u(16), "signature": cursor.bytes(MAX_PARSER_SIGNATURE_BYTES, "signature_parser_bound")}


def enc_qc_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "statement", "signatures"}, "qc_body_fields")
    return enc_u(value["schema_version"], 16) + enc_vote(value["statement"]) + enc_list(value["signatures"], enc_signature)


def dec_qc_body(cursor: Cursor) -> dict[str, Any]:
    version = cursor.u(16)
    statement = dec_vote(cursor)
    count = cursor.u(32)
    require(1 <= count <= MAX_PARSER_CERTIFICATE_SIGNERS, "qc_signer_count_parser_bound")
    return {"schema_version": version, "statement": statement, "signatures": [dec_signature(cursor) for _ in range(count)]}


def enc_qc(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "quorum_certificate_id"}, "qc_fields")
    return enc_qc_body(value["body"]) + enc_hash(value["quorum_certificate_id"])


def dec_qc(cursor: Cursor) -> dict[str, Any]:
    return {"body": dec_qc_body(cursor), "quorum_certificate_id": cursor.hash32()}


def enc_high_justification_ref(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "high_justification_ref_fields")
    if value["variant"] == "QC":
        body = exact_keys(value["value"], {"qc_id", "qc_view"}, "qc_justification_ref_fields")
        return b"\x00" + enc_hash(body["qc_id"]) + enc_u(body["qc_view"], 64)
    require(value["variant"] == "EpochStart", "high_justification_ref_variant")
    body = exact_keys(
        value["value"], {"anchor_kind", "anchor_id", "anchor_view"},
        "epoch_start_justification_ref_fields",
    )
    return b"\x01" + enc_u(body["anchor_kind"], 8) + enc_hash(body["anchor_id"]) + enc_u(body["anchor_view"], 64)


def dec_high_justification_ref(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.u(8)
    if tag == 0:
        return {"variant": "QC", "value": {"qc_id": cursor.hash32(), "qc_view": cursor.u(64)}}
    require(tag == 1, "high_justification_ref_variant")
    return {
        "variant": "EpochStart",
        "value": {
            "anchor_kind": cursor.u(8), "anchor_id": cursor.hash32(),
            "anchor_view": cursor.u(64),
        },
    }


def enc_finalized_anchor(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "finalized_anchor_fields")
    if value["variant"] == "FreshGenesis":
        body = exact_keys(value["value"], {"genesis_derived_state_hash"}, "fresh_genesis_finalized_anchor_fields")
        return b"\x00" + enc_hash(body["genesis_derived_state_hash"])
    require(value["variant"] == "EpochCheckpoint", "finalized_anchor_variant")
    body = exact_keys(value["value"], {"checkpoint_id"}, "epoch_checkpoint_finalized_anchor_fields")
    return b"\x02" + enc_hash(body["checkpoint_id"])


def dec_finalized_anchor(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.u(8)
    if tag == 0:
        return {"variant": "FreshGenesis", "value": {"genesis_derived_state_hash": cursor.hash32()}}
    require(tag == 2, "finalized_anchor_variant")
    return {"variant": "EpochCheckpoint", "value": {"checkpoint_id": cursor.hash32()}}


def enc_timeout_statement(value: dict[str, Any]) -> bytes:
    exact_keys(value, {
        "schema_version", "consensus_context", "high_justification", "locked_qc_id",
        "locked_qc_view", "last_finalized_anchor", "pacemaker_generation",
    }, "timeout_statement_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_consensus_context(value["consensus_context"]),
        enc_high_justification_ref(value["high_justification"]), enc_option_hash(value["locked_qc_id"]),
        enc_u(value["locked_qc_view"], 64), enc_finalized_anchor(value["last_finalized_anchor"]),
        enc_u(value["pacemaker_generation"], 64),
    ))


def dec_timeout_statement(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "consensus_context": dec_consensus_context(cursor),
        "high_justification": dec_high_justification_ref(cursor), "locked_qc_id": cursor.option_hash(),
        "locked_qc_view": cursor.u(64), "last_finalized_anchor": dec_finalized_anchor(cursor),
        "pacemaker_generation": cursor.u(64),
    }


def enc_timeout_entry(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"validator_id", "statement", "signature_scheme", "signature"}, "timeout_entry_fields")
    return enc_bytes(value["validator_id"]) + enc_timeout_statement(value["statement"]) + enc_u(value["signature_scheme"], 16) + enc_bytes(value["signature"])


def dec_timeout_entry(cursor: Cursor) -> dict[str, Any]:
    return {
        "validator_id": cursor.bytes(128, "timeout_validator_id_bound"),
        "statement": dec_timeout_statement(cursor), "signature_scheme": cursor.u(16),
        "signature": cursor.bytes(MAX_PARSER_SIGNATURE_BYTES, "timeout_signature_parser_bound"),
    }


def enc_high_justification_object(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "high_justification_object_fields")
    if value["variant"] == "QC":
        return b"\x00" + enc_qc(value["value"])
    require(value["variant"] == "EpochStart", "high_justification_object_variant")
    return b"\x01" + enc_epoch_start_justification(value["value"])


def dec_high_justification_object(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.u(8)
    if tag == 0:
        return {"variant": "QC", "value": dec_qc(cursor)}
    require(tag == 1, "high_justification_object_variant")
    return {"variant": "EpochStart", "value": dec_epoch_start_justification(cursor)}


def enc_tc_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, {
        "schema_version", "context", "runtime_profile_hash", "epoch", "validator_set_hash",
        "consensus_parameters_hash", "timed_out_view", "target_view", "justifications", "entries",
    }, "tc_body_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]),
        enc_hash(value["runtime_profile_hash"]), enc_u(value["epoch"], 64),
        enc_hash(value["validator_set_hash"]), enc_hash(value["consensus_parameters_hash"]),
        enc_u(value["timed_out_view"], 64), enc_u(value["target_view"], 64),
        enc_list(value["justifications"], enc_high_justification_object),
        enc_list(value["entries"], enc_timeout_entry),
    ))


def dec_tc_body(cursor: Cursor) -> dict[str, Any]:
    result = {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor),
        "runtime_profile_hash": cursor.hash32(), "epoch": cursor.u(64),
        "validator_set_hash": cursor.hash32(), "consensus_parameters_hash": cursor.hash32(),
        "timed_out_view": cursor.u(64), "target_view": cursor.u(64),
    }
    justification_count = cursor.u(32)
    require(1 <= justification_count <= MAX_PARSER_CERTIFICATE_SIGNERS, "tc_justification_count_parser_bound")
    result["justifications"] = [dec_high_justification_object(cursor) for _ in range(justification_count)]
    entry_count = cursor.u(32)
    require(1 <= entry_count <= MAX_PARSER_CERTIFICATE_SIGNERS, "tc_entry_count_parser_bound")
    result["entries"] = [dec_timeout_entry(cursor) for _ in range(entry_count)]
    return result


def enc_tc(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "timeout_certificate_id"}, "tc_fields")
    return enc_tc_body(value["body"]) + enc_hash(value["timeout_certificate_id"])


def dec_tc(cursor: Cursor) -> dict[str, Any]:
    return {"body": dec_tc_body(cursor), "timeout_certificate_id": cursor.hash32()}


def enc_option_tc(value: dict[str, Any] | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + enc_tc(value)


def dec_option_tc(cursor: Cursor) -> dict[str, Any] | None:
    tag = cursor.u(8)
    if tag == 0:
        return None
    require(tag == 1, "unknown_option_tag")
    return dec_tc(cursor)


def enc_certified(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"header", "block_id", "certifying_qc", "timeout_certificate"}, "certified_fields")
    return enc_header(value["header"]) + enc_hash(value["block_id"]) + enc_qc(value["certifying_qc"]) + enc_option_tc(value["timeout_certificate"])


def dec_certified(cursor: Cursor) -> dict[str, Any]:
    return {
        "header": dec_header(cursor), "block_id": cursor.hash32(),
        "certifying_qc": dec_qc(cursor), "timeout_certificate": dec_option_tc(cursor),
    }


def enc_anchor(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "value"}, "anchor_fields")
    require(value["variant"] == "FreshGenesis", "anchor_variant")
    body = exact_keys(value["value"], {"genesis_derived_state_hash", "trusted_genesis_header"}, "anchor_body_fields")
    return b"\x00" + enc_hash(body["genesis_derived_state_hash"]) + enc_header(body["trusted_genesis_header"])


def dec_anchor(cursor: Cursor) -> dict[str, Any]:
    require(cursor.u(8) == 0, "anchor_variant")
    return {"variant": "FreshGenesis", "value": {"genesis_derived_state_hash": cursor.hash32(), "trusted_genesis_header": dec_header(cursor)}}


def enc_proof(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "context", "trusted_anchor", "target_block_id", "target_height", "target_header", "certified_chain", "epoch_handoffs"}, "proof_fields")
    require(value["epoch_handoffs"] == [], "epoch_handoffs_unsupported")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]), enc_anchor(value["trusted_anchor"]),
        enc_hash(value["target_block_id"]), enc_u(value["target_height"], 64), enc_header(value["target_header"]),
        enc_list(value["certified_chain"], enc_certified), struct.pack("<I", 0),
    ))


def dec_proof(cursor: Cursor) -> dict[str, Any]:
    version = cursor.u(16)
    context = dec_protocol_context(cursor)
    anchor = dec_anchor(cursor)
    target_block_id = cursor.hash32()
    target_height = cursor.u(64)
    target_header = dec_header(cursor)
    count = cursor.u(32)
    require(count <= 16, "certified_chain_bound")
    chain = [dec_certified(cursor) for _ in range(count)]
    handoff_count = cursor.u(32)
    require(handoff_count == 0, "epoch_handoffs_unsupported")
    return {"schema_version": version, "context": context, "trusted_anchor": anchor, "target_block_id": target_block_id, "target_height": target_height, "target_header": target_header, "certified_chain": chain, "epoch_handoffs": []}


def enc_trust(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "context", "genesis_derived_state_hash", "genesis_validator_set_definition_hash", "trusted_genesis_header", "epoch_descriptor", "validator_set", "consensus_parameters"}, "trust_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]), enc_hash(value["genesis_derived_state_hash"]),
        enc_hash(value["genesis_validator_set_definition_hash"]),
        enc_header(value["trusted_genesis_header"]), enc_epoch_descriptor(value["epoch_descriptor"]),
        enc_validator_set(value["validator_set"]), enc_parameters(value["consensus_parameters"]),
    ))


def dec_trust(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor), "genesis_derived_state_hash": cursor.hash32(),
        "genesis_validator_set_definition_hash": cursor.hash32(),
        "trusted_genesis_header": dec_header(cursor), "epoch_descriptor": dec_epoch_descriptor(cursor),
        "validator_set": dec_validator_set(cursor), "consensus_parameters": dec_parameters(cursor),
    }


CHECKPOINT_HASH_FIELDS = (
    "validator_set_hash", "consensus_parameters_hash", "application_state_root",
    "da_committee_set_root", "verification_registry_hash", "stack_profile_hash",
    "fee_schedule_hash", "state_schema_hash", "snapshot_policy_hash",
)


def enc_checkpoint_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, {
        "schema_version", "context", "epoch", "checkpoint_height", "checkpoint_block_id",
        "checkpoint_header", "epoch_descriptor_id", *CHECKPOINT_HASH_FIELDS,
        "next_epoch_descriptor_id", "upgrade_plan_id",
    }, "checkpoint_body_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]),
        enc_u(value["epoch"], 64), enc_u(value["checkpoint_height"], 64),
        enc_hash(value["checkpoint_block_id"]), enc_header(value["checkpoint_header"]),
        enc_hash(value["epoch_descriptor_id"]),
        *(enc_hash(value[name]) for name in CHECKPOINT_HASH_FIELDS),
        enc_option_hash(value["next_epoch_descriptor_id"]), enc_option_hash(value["upgrade_plan_id"]),
    ))


def dec_checkpoint_body(cursor: Cursor) -> dict[str, Any]:
    result = {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor),
        "epoch": cursor.u(64), "checkpoint_height": cursor.u(64),
        "checkpoint_block_id": cursor.hash32(), "checkpoint_header": dec_header(cursor),
        "epoch_descriptor_id": cursor.hash32(),
    }
    result.update({name: cursor.hash32() for name in CHECKPOINT_HASH_FIELDS})
    result["next_epoch_descriptor_id"] = cursor.option_hash()
    result["upgrade_plan_id"] = cursor.option_hash()
    return result


def enc_checkpoint(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "checkpoint_id"}, "checkpoint_fields")
    return enc_checkpoint_body(value["body"]) + enc_hash(value["checkpoint_id"])


def dec_checkpoint(cursor: Cursor) -> dict[str, Any]:
    return {"body": dec_checkpoint_body(cursor), "checkpoint_id": cursor.hash32()}


def enc_checkpoint_attachment(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"checkpoint_id", "order_finality_proof"}, "checkpoint_attachment_fields")
    return enc_hash(value["checkpoint_id"]) + enc_proof(value["order_finality_proof"])


def dec_checkpoint_attachment(cursor: Cursor) -> dict[str, Any]:
    return {"checkpoint_id": cursor.hash32(), "order_finality_proof": dec_proof(cursor)}


HANDOFF_BODY_FIELDS = (
    "schema_version", "source_context", "target_context", "old_epoch", "new_epoch",
    "old_epoch_checkpoint_id", "old_epoch_descriptor_id", "new_epoch_descriptor_id",
    "old_validator_set_hash", "new_validator_set_hash", "old_consensus_parameters_hash",
    "new_consensus_parameters_hash", "terminal_block_id", "terminal_height", "terminal_view",
    "activation_height", "initial_new_view",
)


def enc_handoff_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, set(HANDOFF_BODY_FIELDS), "handoff_body_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["source_context"]),
        enc_protocol_context(value["target_context"]), enc_u(value["old_epoch"], 64),
        enc_u(value["new_epoch"], 64), enc_hash(value["old_epoch_checkpoint_id"]),
        enc_hash(value["old_epoch_descriptor_id"]), enc_hash(value["new_epoch_descriptor_id"]),
        enc_hash(value["old_validator_set_hash"]), enc_hash(value["new_validator_set_hash"]),
        enc_hash(value["old_consensus_parameters_hash"]), enc_hash(value["new_consensus_parameters_hash"]),
        enc_hash(value["terminal_block_id"]), enc_u(value["terminal_height"], 64),
        enc_u(value["terminal_view"], 64), enc_u(value["activation_height"], 64),
        enc_u(value["initial_new_view"], 64),
    ))


def dec_handoff_body(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "source_context": dec_protocol_context(cursor),
        "target_context": dec_protocol_context(cursor), "old_epoch": cursor.u(64),
        "new_epoch": cursor.u(64), "old_epoch_checkpoint_id": cursor.hash32(),
        "old_epoch_descriptor_id": cursor.hash32(), "new_epoch_descriptor_id": cursor.hash32(),
        "old_validator_set_hash": cursor.hash32(), "new_validator_set_hash": cursor.hash32(),
        "old_consensus_parameters_hash": cursor.hash32(), "new_consensus_parameters_hash": cursor.hash32(),
        "terminal_block_id": cursor.hash32(), "terminal_height": cursor.u(64),
        "terminal_view": cursor.u(64), "activation_height": cursor.u(64),
        "initial_new_view": cursor.u(64),
    }


def enc_handoff_statement(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"schema_version", "consensus_context", "handoff_id"}, "handoff_statement_fields")
    return enc_u(value["schema_version"], 16) + enc_consensus_context(value["consensus_context"]) + enc_hash(value["handoff_id"])


def dec_handoff_statement(cursor: Cursor) -> dict[str, Any]:
    return {"schema_version": cursor.u(16), "consensus_context": dec_consensus_context(cursor), "handoff_id": cursor.hash32()}


def enc_handoff_entry(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"signer_id", "role", "statement", "signature_scheme", "signature"}, "handoff_entry_fields")
    return enc_bytes(value["signer_id"]) + enc_u(value["role"], 8) + enc_handoff_statement(value["statement"]) + enc_u(value["signature_scheme"], 16) + enc_bytes(value["signature"])


def dec_handoff_entry(cursor: Cursor) -> dict[str, Any]:
    return {
        "signer_id": cursor.bytes(128, "handoff_signer_id_bound"), "role": cursor.u(8),
        "statement": dec_handoff_statement(cursor), "signature_scheme": cursor.u(16),
        "signature": cursor.bytes(MAX_PARSER_SIGNATURE_BYTES, "handoff_signature_parser_bound"),
    }


def enc_handoff(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"body", "handoff_id", "old_set_signatures", "new_set_signatures"}, "handoff_fields")
    return enc_handoff_body(value["body"]) + enc_hash(value["handoff_id"]) + enc_list(value["old_set_signatures"], enc_handoff_entry) + enc_list(value["new_set_signatures"], enc_handoff_entry)


def dec_handoff(cursor: Cursor) -> dict[str, Any]:
    body = dec_handoff_body(cursor)
    handoff_id = cursor.hash32()
    old_count = cursor.u(32)
    require(1 <= old_count <= MAX_PARSER_CERTIFICATE_SIGNERS, "old_handoff_signer_count_parser_bound")
    old_entries = [dec_handoff_entry(cursor) for _ in range(old_count)]
    new_count = cursor.u(32)
    require(1 <= new_count <= MAX_PARSER_CERTIFICATE_SIGNERS, "new_handoff_signer_count_parser_bound")
    new_entries = [dec_handoff_entry(cursor) for _ in range(new_count)]
    return {"body": body, "handoff_id": handoff_id, "old_set_signatures": old_entries, "new_set_signatures": new_entries}


def enc_epoch_start_justification(value: dict[str, Any]) -> bytes:
    """Encode the bounded EpochHandoff variant of EpochStartJustificationV1."""
    exact_keys(value, {"variant", "value"}, "epoch_start_justification_fields")
    require(value["variant"] == "EpochHandoff", "epoch_start_justification_variant")
    return b"\x02" + enc_handoff(value["value"])


def dec_epoch_start_justification(cursor: Cursor) -> dict[str, Any]:
    require(cursor.u(8) == 2, "epoch_start_justification_variant")
    return {"variant": "EpochHandoff", "value": dec_handoff(cursor)}


def enc_epoch_handoff_protocol_sidecar(handoff: dict[str, Any]) -> bytes:
    """Encode ProtocolObjectSidecarV1::EpochHandoff with its complete wrapper."""
    return enc_u(EPOCH_HANDOFF_SIDECAR_TAG, 8) + enc_handoff(handoff)


def single_item_ordered_root(
    *, root_kind: int, item_kind: int, item_id: bytes, item_commitment: bytes,
) -> bytes:
    leaf_body = b"".join((
        enc_u(root_kind, 16), enc_u(0, 32), enc_u(item_kind, 16),
        enc_hash(item_id), enc_hash(item_commitment),
    ))
    leaf = digest(MERKLE_LEAF_DOMAIN, leaf_body)
    return digest(
        MERKLE_LIST_ROOT_DOMAIN,
        enc_u(root_kind, 16) + enc_u(1, 32) + b"\x01" + enc_hash(leaf),
    )


def epoch_handoff_protocol_objects_root(handoff: dict[str, Any]) -> bytes:
    sidecar = enc_epoch_handoff_protocol_sidecar(handoff)
    return single_item_ordered_root(
        root_kind=PROTOCOL_OBJECTS_ROOT_KIND,
        item_kind=EPOCH_HANDOFF_OBJECT_KIND,
        item_id=handoff["handoff_id"],
        item_commitment=digest(PROTOCOL_SIDECAR_CONTENT_DOMAIN, sidecar),
    )


def verify_handoff_first_roots(
    header: dict[str, Any], handoff: dict[str, Any], *, prefix: str,
) -> None:
    require(
        header["protocol_objects_root"] == epoch_handoff_protocol_objects_root(handoff),
        f"{prefix}_handoff_sidecar_root",
    )
    for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
        if field == "protocol_objects_root":
            continue
        require(header[field] == empty_ordered_root(root_kind), f"{prefix}_empty_payload")


def enc_epoch_transition(value: dict[str, Any]) -> bytes:
    exact_keys(value, {
        "schema_version", "old_trust_bundle", "checkpoint_finality_proof", "checkpoint",
        "checkpoint_attachment", "new_epoch_descriptor", "new_validator_set",
        "new_consensus_parameters", "handoff", "new_epoch_certified_chain",
    }, "epoch_transition_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_trust(value["old_trust_bundle"]),
        enc_proof(value["checkpoint_finality_proof"]), enc_checkpoint(value["checkpoint"]),
        enc_checkpoint_attachment(value["checkpoint_attachment"]),
        enc_epoch_descriptor(value["new_epoch_descriptor"]), enc_validator_set(value["new_validator_set"]),
        enc_parameters(value["new_consensus_parameters"]), enc_handoff(value["handoff"]),
        enc_list(value["new_epoch_certified_chain"], enc_certified),
    ))


def dec_epoch_transition(cursor: Cursor) -> dict[str, Any]:
    result = {
        "schema_version": cursor.u(16), "old_trust_bundle": dec_trust(cursor),
        "checkpoint_finality_proof": dec_proof(cursor), "checkpoint": dec_checkpoint(cursor),
        "checkpoint_attachment": dec_checkpoint_attachment(cursor),
        "new_epoch_descriptor": dec_epoch_descriptor(cursor), "new_validator_set": dec_validator_set(cursor),
        "new_consensus_parameters": dec_parameters(cursor), "handoff": dec_handoff(cursor),
    }
    count = cursor.u(32)
    require(count == 4, "new_epoch_chain_cardinality")
    result["new_epoch_certified_chain"] = [dec_certified(cursor) for _ in range(count)]
    return result


# The trust-path iterator is a separately versioned candidate layered on top
# of the existing FreshGenesis-only EpochTransitionV1 bytes.  Variant 0 is
# accepted exactly once at position zero.  Later steps use a new checkpoint-
# anchored carrier; the old FreshGenesis tag is never reinterpreted.
TRUSTED_ORDER_STATE_KEYS = {
    "schema_version", "context", "epoch", "epoch_start_height",
    "finalized_height", "finalized_header", "finalized_block_id",
    "certified_head_header", "certified_head_block_id", "certified_head_qc_id",
    "epoch_descriptor", "validator_set", "consensus_parameters",
    "latest_checkpoint_id", "latest_handoff_id", "state_id",
}


def enc_trusted_order_state_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, TRUSTED_ORDER_STATE_KEYS, "trusted_order_state_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]),
        enc_u(value["epoch"], 64), enc_u(value["epoch_start_height"], 64),
        enc_u(value["finalized_height"], 64), enc_header(value["finalized_header"]),
        enc_hash(value["finalized_block_id"]), enc_header(value["certified_head_header"]),
        enc_hash(value["certified_head_block_id"]), enc_hash(value["certified_head_qc_id"]),
        enc_epoch_descriptor(value["epoch_descriptor"]), enc_validator_set(value["validator_set"]),
        enc_parameters(value["consensus_parameters"]),
        enc_option_hash(value["latest_checkpoint_id"]), enc_option_hash(value["latest_handoff_id"]),
    ))


def enc_trusted_order_state(value: dict[str, Any]) -> bytes:
    return enc_trusted_order_state_body(value) + enc_hash(value["state_id"])


def dec_trusted_order_state(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor),
        "epoch": cursor.u(64), "epoch_start_height": cursor.u(64),
        "finalized_height": cursor.u(64), "finalized_header": dec_header(cursor),
        "finalized_block_id": cursor.hash32(), "certified_head_header": dec_header(cursor),
        "certified_head_block_id": cursor.hash32(), "certified_head_qc_id": cursor.hash32(),
        "epoch_descriptor": dec_epoch_descriptor(cursor), "validator_set": dec_validator_set(cursor),
        "consensus_parameters": dec_parameters(cursor),
        "latest_checkpoint_id": cursor.option_hash(), "latest_handoff_id": cursor.option_hash(),
        "state_id": cursor.hash32(),
    }


CHECKPOINT_TRANSITION_STEP_KEYS = {
    "schema_version", "input_state_id", "checkpoint_certified_chain", "checkpoint",
    "new_epoch_descriptor", "new_validator_set", "new_consensus_parameters", "handoff",
    "new_epoch_certified_chain", "output_state", "step_id",
}


def enc_checkpoint_transition_step_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, CHECKPOINT_TRANSITION_STEP_KEYS, "checkpoint_transition_step_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_hash(value["input_state_id"]),
        enc_list(value["checkpoint_certified_chain"], enc_certified),
        enc_checkpoint(value["checkpoint"]), enc_epoch_descriptor(value["new_epoch_descriptor"]),
        enc_validator_set(value["new_validator_set"]), enc_parameters(value["new_consensus_parameters"]),
        enc_handoff(value["handoff"]), enc_list(value["new_epoch_certified_chain"], enc_certified),
        enc_trusted_order_state(value["output_state"]),
    ))


def enc_checkpoint_transition_step(value: dict[str, Any]) -> bytes:
    return enc_checkpoint_transition_step_body(value) + enc_hash(value["step_id"])


def dec_checkpoint_transition_step(cursor: Cursor) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": cursor.u(16), "input_state_id": cursor.hash32(),
    }
    checkpoint_count = cursor.u(32)
    require(checkpoint_count <= 16, "checkpoint_chain_parser_bound")
    result["checkpoint_certified_chain"] = [dec_certified(cursor) for _ in range(checkpoint_count)]
    result.update({
        "checkpoint": dec_checkpoint(cursor), "new_epoch_descriptor": dec_epoch_descriptor(cursor),
        "new_validator_set": dec_validator_set(cursor),
        "new_consensus_parameters": dec_parameters(cursor), "handoff": dec_handoff(cursor),
    })
    new_count = cursor.u(32)
    require(new_count <= 16, "checkpoint_new_chain_parser_bound")
    result["new_epoch_certified_chain"] = [dec_certified(cursor) for _ in range(new_count)]
    result["output_state"] = dec_trusted_order_state(cursor)
    result["step_id"] = cursor.hash32()
    return result


ORDINARY_ADVANCE_KEYS = {
    "schema_version", "input_state", "certified_chain", "output_state",
    "advance_id",
}


def enc_ordinary_advance_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, ORDINARY_ADVANCE_KEYS, "ordinary_advance_fields")
    return b"".join((
        enc_u(value["schema_version"], 16),
        enc_trusted_order_state(value["input_state"]),
        enc_list(value["certified_chain"], enc_certified),
        enc_trusted_order_state(value["output_state"]),
    ))


def enc_ordinary_advance(value: dict[str, Any]) -> bytes:
    return enc_ordinary_advance_body(value) + enc_hash(value["advance_id"])


def dec_ordinary_advance(cursor: Cursor) -> dict[str, Any]:
    result = {
        "schema_version": cursor.u(16),
        "input_state": dec_trusted_order_state(cursor),
    }
    count = cursor.u(32)
    require(count <= 16, "ordinary_advance_chain_parser_bound")
    result["certified_chain"] = [dec_certified(cursor) for _ in range(count)]
    result["output_state"] = dec_trusted_order_state(cursor)
    result["advance_id"] = cursor.hash32()
    return result


TRUST_PATH_VARIANT_TO_TAG = {
    "ExistingFreshGenesisTransition": 0,
    "CheckpointAnchoredTransition": 1,
}
TRUST_PATH_TAG_TO_VARIANT = {tag: variant for variant, tag in TRUST_PATH_VARIANT_TO_TAG.items()}


def enc_trust_path_step(value: dict[str, Any]) -> bytes:
    exact_keys(value, {"variant", "raw_step_cev1"}, "trust_path_step_fields")
    require(value["variant"] in TRUST_PATH_VARIANT_TO_TAG, "trust_path_step_variant")
    return enc_u(TRUST_PATH_VARIANT_TO_TAG[value["variant"]], 8) + enc_bytes(value["raw_step_cev1"])


def dec_trust_path_step(cursor: Cursor) -> dict[str, Any]:
    tag = cursor.u(8)
    require(tag in TRUST_PATH_TAG_TO_VARIANT, "trust_path_step_variant")
    return {
        "variant": TRUST_PATH_TAG_TO_VARIANT[tag],
        "raw_step_cev1": cursor.bytes(16 * 1024 * 1024, "trust_path_step_bytes_bound"),
    }


TRUST_PATH_KEYS = {"schema_version", "initial_state", "steps", "path_id"}


def enc_trust_path_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, TRUST_PATH_KEYS, "trust_path_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_trusted_order_state(value["initial_state"]),
        enc_list(value["steps"], enc_trust_path_step),
    ))


def enc_trust_path(value: dict[str, Any]) -> bytes:
    return enc_trust_path_body(value) + enc_hash(value["path_id"])


def dec_trust_path(cursor: Cursor) -> dict[str, Any]:
    result = {"schema_version": cursor.u(16), "initial_state": dec_trusted_order_state(cursor)}
    count = cursor.u(32)
    require(count <= 16, "trust_path_steps_parser_bound")
    result["steps"] = [dec_trust_path_step(cursor) for _ in range(count)]
    result["path_id"] = cursor.hash32()
    return result


WEAK_SUBJECTIVITY_ANCHOR_KEYS = {
    "schema_version", "context", "checkpoint_id", "checkpoint_epoch",
    "checkpoint_height", "checkpoint_block_id", "validator_set_hash",
    "consensus_parameters_hash", "application_state_root", "state_schema_hash",
    "anchor_id",
}


def enc_weak_subjectivity_anchor_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, WEAK_SUBJECTIVITY_ANCHOR_KEYS, "weak_subjectivity_anchor_fields")
    return b"".join((
        enc_u(value["schema_version"], 16), enc_protocol_context(value["context"]),
        enc_hash(value["checkpoint_id"]), enc_u(value["checkpoint_epoch"], 64),
        enc_u(value["checkpoint_height"], 64), enc_hash(value["checkpoint_block_id"]),
        enc_hash(value["validator_set_hash"]), enc_hash(value["consensus_parameters_hash"]),
        enc_hash(value["application_state_root"]), enc_hash(value["state_schema_hash"]),
    ))


def enc_weak_subjectivity_anchor(value: dict[str, Any]) -> bytes:
    return enc_weak_subjectivity_anchor_body(value) + enc_hash(value["anchor_id"])


def dec_weak_subjectivity_anchor(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16), "context": dec_protocol_context(cursor),
        "checkpoint_id": cursor.hash32(), "checkpoint_epoch": cursor.u(64),
        "checkpoint_height": cursor.u(64), "checkpoint_block_id": cursor.hash32(),
        "validator_set_hash": cursor.hash32(),
        "consensus_parameters_hash": cursor.hash32(),
        "application_state_root": cursor.hash32(), "state_schema_hash": cursor.hash32(),
        "anchor_id": cursor.hash32(),
    }


WEAK_SUBJECTIVITY_POLICY_KEYS = {
    "schema_version", "max_checkpoint_age_epochs", "max_checkpoint_age_blocks",
    "min_finalized_height_advance", "policy_id",
}


def enc_weak_subjectivity_policy_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, WEAK_SUBJECTIVITY_POLICY_KEYS, "weak_subjectivity_policy_fields")
    return b"".join((
        enc_u(value["schema_version"], 16),
        enc_u(value["max_checkpoint_age_epochs"], 64),
        enc_u(value["max_checkpoint_age_blocks"], 64),
        enc_u(value["min_finalized_height_advance"], 64),
    ))


def enc_weak_subjectivity_policy(value: dict[str, Any]) -> bytes:
    return enc_weak_subjectivity_policy_body(value) + enc_hash(value["policy_id"])


def dec_weak_subjectivity_policy(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16),
        "max_checkpoint_age_epochs": cursor.u(64),
        "max_checkpoint_age_blocks": cursor.u(64),
        "min_finalized_height_advance": cursor.u(64),
        "policy_id": cursor.hash32(),
    }


WEAK_SUBJECTIVITY_RENEWAL_KEYS = {
    "schema_version", "prior_anchor", "terminal_trusted_state",
    "terminal_checkpoint", "policy", "observed_finalized_epoch",
    "observed_finalized_height", "renewed_anchor", "renewal_id",
}


def enc_weak_subjectivity_renewal_body(value: dict[str, Any]) -> bytes:
    exact_keys(value, WEAK_SUBJECTIVITY_RENEWAL_KEYS, "weak_subjectivity_renewal_fields")
    return b"".join((
        enc_u(value["schema_version"], 16),
        enc_weak_subjectivity_anchor(value["prior_anchor"]),
        enc_trusted_order_state(value["terminal_trusted_state"]),
        enc_checkpoint(value["terminal_checkpoint"]),
        enc_weak_subjectivity_policy(value["policy"]),
        enc_u(value["observed_finalized_epoch"], 64),
        enc_u(value["observed_finalized_height"], 64),
        enc_weak_subjectivity_anchor(value["renewed_anchor"]),
    ))


def enc_weak_subjectivity_renewal(value: dict[str, Any]) -> bytes:
    return enc_weak_subjectivity_renewal_body(value) + enc_hash(value["renewal_id"])


def dec_weak_subjectivity_renewal(cursor: Cursor) -> dict[str, Any]:
    return {
        "schema_version": cursor.u(16),
        "prior_anchor": dec_weak_subjectivity_anchor(cursor),
        "terminal_trusted_state": dec_trusted_order_state(cursor),
        "terminal_checkpoint": dec_checkpoint(cursor),
        "policy": dec_weak_subjectivity_policy(cursor),
        "observed_finalized_epoch": cursor.u(64),
        "observed_finalized_height": cursor.u(64),
        "renewed_anchor": dec_weak_subjectivity_anchor(cursor),
        "renewal_id": cursor.hash32(),
    }


def decode_exact(raw: bytes, label: str, decoder: Callable[[Cursor], dict[str, Any]], encoder: Callable[[dict[str, Any]], bytes]) -> dict[str, Any]:
    cursor = Cursor(raw, label)
    value = decoder(cursor)
    cursor.finish()
    require(encoder(value) == raw, "noncanonical_reencode", label)
    return value


def inv(value: int) -> int:
    return pow(value % FIELD, FIELD - 2, FIELD)


def recover_x(y: int, sign: int) -> int | None:
    numerator = (y * y - 1) % FIELD
    denominator = (CURVE_D * y * y + 1) % FIELD
    square = numerator * inv(denominator) % FIELD
    x = pow(square, (FIELD + 3) // 8, FIELD)
    if (x * x - square) % FIELD != 0:
        x = x * SQRT_MINUS_ONE % FIELD
    if (x * x - square) % FIELD != 0 or (x == 0 and sign):
        return None
    return FIELD - x if (x & 1) != sign else x


BASE_Y = 4 * inv(5) % FIELD
BASE_X = recover_x(BASE_Y, 0)
if BASE_X is None:  # pragma: no cover
    raise RuntimeError("Ed25519 base point")
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % FIELD)


def point_add(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % FIELD
    b = (y1 + x1) * (y2 + x2) % FIELD
    c = 2 * CURVE_D * t1 * t2 % FIELD
    d_value = 2 * z1 * z2 % FIELD
    e, f, g, h = (b - a) % FIELD, (d_value - c) % FIELD, (d_value + c) % FIELD, (b + a) % FIELD
    return e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD


def scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result, addend = IDENTITY, point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def point_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return (left[0] * right[2] - right[0] * left[2]) % FIELD == 0 and (left[1] * right[2] - right[1] * left[2]) % FIELD == 0


def encode_point(point: tuple[int, int, int, int]) -> bytes:
    z_inv = inv(point[2])
    x, y = point[0] * z_inv % FIELD, point[1] * z_inv % FIELD
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_point(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    value = int.from_bytes(raw, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    if y >= FIELD:
        return None
    x = recover_x(y, sign)
    if x is None:
        return None
    point = (x, y, 1, x * y % FIELD)
    return None if point_equal(scalar_mult(point, 8), IDENTITY) else point


def strict_ed25519_verify(message: bytes, public_key: bytes, signature: bytes) -> bool:
    if len(message) != 32 or len(public_key) != 32 or len(signature) != 64:
        return False
    public, r_point = decode_point(public_key), decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if public is None or r_point is None or scalar >= GROUP_ORDER:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % GROUP_ORDER
    return point_equal(scalar_mult(BASE, scalar), point_add(r_point, scalar_mult(public, challenge)))


def fixture_seed(index: int) -> bytes:
    require(0 <= index < 4, "fixture_seed_index")
    return bytes(range(index * 32, (index + 1) * 32))


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded[:32], "little"), bytes(expanded[32:])


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = secret_scalar(seed)
    return encode_point(scalar_mult(BASE, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = secret_scalar(seed)
    public = ed25519_public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % GROUP_ORDER
    encoded_r = encode_point(scalar_mult(BASE, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % GROUP_ORDER
    return encoded_r + ((nonce + challenge * scalar) % GROUP_ORDER).to_bytes(32, "little")


def validate_context(context: dict[str, Any], parameters: dict[str, Any] | None = None) -> None:
    require(context["schema_version"] == 1, "context_schema_version")
    require(context["protocol_version"] == 1, "context_protocol_version")
    chain_id_bytes = context["chain_id"].encode("utf-8")
    require(len(chain_id_bytes) > 0, "chain_id_nonempty")
    if parameters is not None:
        require(len(chain_id_bytes) <= parameters["max_consensus_string_bytes"], "chain_id_committed_bound")


def validate_validator_set(value: dict[str, Any], context: dict[str, Any], epoch: int, parameters: dict[str, Any]) -> tuple[bytes, bytes, dict[bytes, dict[str, Any]]]:
    require(value["schema_version"] == 1, "validator_set_schema_version")
    require(value["context"] == context, "validator_set_context")
    require(value["epoch"] == epoch, "validator_set_epoch")
    definition = value["definition"]
    require(definition["schema_version"] == 1, "validator_definition_version")
    members = definition["members"]
    require(1 <= len(members) <= parameters["max_validators"], "validator_count")
    ids = [member["validator_id"] for member in members]
    require(all(ids), "validator_id_nonempty")
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "validator_order")
    keys = [member["consensus_public_key"] for member in members]
    require(len(keys) == len(set(keys)), "validator_key_unique")
    total = 0
    for member in members:
        require(member["consensus_key_scheme"] == STRICT_ED25519, "validator_key_scheme")
        require(len(member["consensus_public_key"]) == 32, "validator_key_shape")
        require(decode_point(member["consensus_public_key"]) is not None, "validator_key_strict")
        require(0 < member["voting_weight"] <= U128_MAX - total, "validator_weight")
        total += member["voting_weight"]
    require(total <= U128_MAX // 2, "validator_quorum_multiplication_overflow")
    threshold = parameters["quorum_numerator"] * total // parameters["quorum_denominator"] + 1
    require(definition["total_weight"] == total and definition["quorum_threshold"] == threshold, "validator_quorum")
    definition_id = digest(VALIDATOR_SET_DEFINITION_DOMAIN, enc_validator_definition(definition))
    set_hash = digest(VALIDATOR_SET_DOMAIN, enc_validator_set(value))
    return set_hash, definition_id, {member["validator_id"]: member for member in members}


POSITIVE_PARAMETER_FIELDS = (
    "max_validators", "max_consensus_string_bytes", "max_cev1_nesting",
    "max_cev1_value_bytes", "max_signature_bytes", "max_certificate_signers",
    "max_epoch", "max_view", "max_height", "max_retained_views",
    "epoch_length_blocks", "checkpoint_offset_blocks", "seal_1_offset_blocks",
    "seal_2_offset_blocks", "max_block_ordered_bytes", "max_batch_refs_per_block",
    "max_protocol_objects_per_block", "max_transactions_per_batch",
    "max_transaction_bytes", "max_block_execution_units", "base_view_timeout_ms",
    "maximum_view_timeout_ms", "timeout_multiplier_numerator",
    "timeout_multiplier_denominator", "max_evidence_items_per_block",
    "max_evidence_bytes_per_block",
)


def validate_parameters(parameters: dict[str, Any]) -> bytes:
    require(parameters["schema_version"] == 1, "parameters_version")
    require(parameters["quorum_numerator"] == 2 and parameters["quorum_denominator"] == 3, "parameters_quorum")
    require(parameters["finality_chain_length"] == 3, "parameters_finality_chain_length")
    require(parameters["execute_coordination_before_vote"], "parameters_execute_before_vote")
    for name in POSITIVE_PARAMETER_FIELDS:
        require(parameters[name] > 0, f"parameter_positive_{name}")
    require(parameters["max_validators"] <= MAX_PARSER_VALIDATORS, "parameter_supported_max_validators")
    require(parameters["max_certificate_signers"] <= MAX_PARSER_CERTIFICATE_SIGNERS, "parameter_supported_max_certificate_signers")
    require(parameters["max_consensus_string_bytes"] <= MAX_PARSER_CONSENSUS_STRING_BYTES, "parameter_supported_max_consensus_string_bytes")
    require(parameters["max_signature_bytes"] <= MAX_PARSER_SIGNATURE_BYTES, "parameter_supported_max_signature_bytes")
    require(parameters["max_certificate_signers"] >= parameters["max_validators"], "parameter_certificate_capacity")
    require(parameters["max_cev1_nesting"] >= REQUIRED_TRANCHE_CEV1_NESTING, "parameter_tranche_nesting")
    require(parameters["checkpoint_offset_blocks"] < U64_MAX, "parameter_checkpoint_addition_overflow")
    require(parameters["seal_1_offset_blocks"] == parameters["checkpoint_offset_blocks"] + 1, "parameter_schedule_seal1")
    require(parameters["seal_1_offset_blocks"] < U64_MAX, "parameter_seal1_addition_overflow")
    require(parameters["seal_2_offset_blocks"] == parameters["seal_1_offset_blocks"] + 1, "parameter_schedule_seal2")
    require(parameters["seal_2_offset_blocks"] < U64_MAX, "parameter_seal2_addition_overflow")
    require(parameters["epoch_length_blocks"] == parameters["seal_2_offset_blocks"] + 1, "parameter_schedule_epoch_length")
    require(parameters["base_view_timeout_ms"] <= parameters["maximum_view_timeout_ms"], "parameter_timeout_order")
    require(parameters["timeout_multiplier_numerator"] >= parameters["timeout_multiplier_denominator"], "parameter_timeout_multiplier")
    return digest(CONSENSUS_PARAMETERS_DOMAIN, enc_parameters(parameters))


def validate_header_bounds(header: dict[str, Any], parameters: dict[str, Any]) -> None:
    require(header["schema_version"] == 1, "header_schema_version")
    validate_context(header["context"], parameters)
    require(header["epoch"] <= parameters["max_epoch"], "header_epoch_bound")
    require(header["view"] <= parameters["max_view"], "header_view_bound")
    require(header["height"] <= parameters["max_height"], "header_height_bound")
    require(len(header["proposer_id"]) > 0, "header_proposer_nonempty")
    require(len(enc_header(header)) <= parameters["max_cev1_value_bytes"], "header_cev1_value_bound")


EMPTY_HEADER_ROOT_KINDS = {
    "batch_refs_root": 0,
    "protocol_objects_root": 1,
    "transaction_execution_receipts_root": 2,
    "evidence_root": 3,
    "consumption_rollups_root": 4,
    "settlement_root": 5,
    "resource_usage_root": 6,
}


def validate_fresh_genesis(header: dict[str, Any], derived_state_hash: bytes) -> None:
    require(header["epoch"] == 0, "fresh_genesis_epoch")
    require(header["view"] == 1, "fresh_genesis_initial_view")
    require(header["block_kind"] == "FreshGenesis", "fresh_genesis_kind")
    require(header["parent"]["variant"] == "GenesisAnchor", "fresh_genesis_parent_variant")
    parent = header["parent"]["value"]
    require(parent["genesis_derived_state_hash"] == derived_state_hash, "fresh_genesis_derived_state")
    require(header["post_state_root"] == parent["application_state_root"], "fresh_genesis_application_state_root")
    require(header["justify_qc_id"] is None, "fresh_genesis_justify_absent")
    require(header["timeout_certificate_id"] is None, "fresh_genesis_timeout_absent")
    require(header["next_epoch_descriptor_id"] is None, "fresh_genesis_next_epoch_absent")
    require(header["upgrade_plan_id"] is None, "fresh_genesis_upgrade_absent")
    require(header["epoch_handoff_id"] is None, "fresh_genesis_handoff_absent")
    for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
        require(header[field] == empty_ordered_root(root_kind), f"fresh_genesis_empty_{field}")


def verify_qc(certified: dict[str, Any], *, context: dict[str, Any], epoch: int, epoch_descriptor_id: bytes, runtime_profile_hash: bytes, validator_set_hash: bytes, parameters_hash: bytes, parameters: dict[str, Any], members: dict[bytes, dict[str, Any]], threshold: int) -> tuple[bytes, bytes]:
    header = certified["header"]
    block_id = digest(BLOCK_DOMAIN, enc_header(header))
    require(certified["block_id"] == block_id, "block_id")
    qc = certified["certifying_qc"]
    body = qc["body"]
    require(body["schema_version"] == 1, "qc_version")
    qc_id = digest(QC_DOMAIN, enc_qc_body(body))
    require(qc["quorum_certificate_id"] == qc_id, "qc_id")
    require(len(enc_qc(qc)) <= parameters["max_cev1_value_bytes"], "qc_cev1_value_bound")
    vote = body["statement"]
    consensus = vote["consensus_context"]
    require(vote["schema_version"] == 1 and consensus["schema_version"] == 1 and consensus["message_kind"] == 1, "vote_version_kind")
    require(consensus["context"] == context and consensus["epoch"] == epoch, "vote_context")
    require(consensus["runtime_profile_hash"] == runtime_profile_hash and consensus["validator_set_hash"] == validator_set_hash and consensus["consensus_parameters_hash"] == parameters_hash, "vote_authority")
    require(consensus["view"] == header["view"], "vote_view")
    require(vote["block_id"] == block_id and vote["height"] == header["height"] and vote["epoch_descriptor_id"] == epoch_descriptor_id, "vote_header_identity")
    require(vote["post_state_root"] == header["post_state_root"] and vote["batch_refs_root"] == header["batch_refs_root"] and vote["transaction_execution_receipts_root"] == header["transaction_execution_receipts_root"], "vote_header_roots")
    root = digest(VOTE_DOMAIN, enc_vote(vote))
    signatures = body["signatures"]
    require(len(signatures) <= parameters["max_certificate_signers"], "qc_committed_signer_bound")
    ids = [entry["voter_id"] for entry in signatures]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "qc_signer_order")
    weight = 0
    for entry in signatures:
        member = members.get(entry["voter_id"])
        require(member is not None, "qc_unknown_signer")
        require(entry["signature_scheme"] == STRICT_ED25519, "qc_signature_scheme")
        require(len(entry["signature"]) <= parameters["max_signature_bytes"], "qc_signature_committed_bound")
        require(len(entry["signature"]) == 64, "qc_signature_shape")
        require(strict_ed25519_verify(root, member["consensus_public_key"], entry["signature"]), "qc_signature")
        require(member["voting_weight"] <= U128_MAX - weight, "qc_weight_overflow")
        weight += member["voting_weight"]
    require(weight >= threshold, "qc_quorum")
    return block_id, qc_id


def verify_tc(
    tc: dict[str, Any], *, previous_qc: dict[str, Any], previous_qc_id: bytes,
    previous_view: int, target_view: int, context: dict[str, Any], epoch: int,
    runtime_profile_hash: bytes, validator_set_hash: bytes, parameters_hash: bytes,
    genesis_derived_state_hash: bytes, parameters: dict[str, Any],
    members: dict[bytes, dict[str, Any]], threshold: int,
) -> bytes:
    body = tc["body"]
    require(body["schema_version"] == 1, "tc_version")
    tc_id = digest(TC_DOMAIN, enc_tc_body(body))
    require(tc["timeout_certificate_id"] == tc_id, "tc_id")
    require(len(enc_tc(tc)) <= parameters["max_cev1_value_bytes"], "tc_cev1_value_bound")
    require(body["context"] == context and body["epoch"] == epoch, "tc_context")
    require(
        body["runtime_profile_hash"] == runtime_profile_hash
        and body["validator_set_hash"] == validator_set_hash
        and body["consensus_parameters_hash"] == parameters_hash,
        "tc_authority",
    )
    require(previous_view < U64_MAX and target_view > previous_view, "tc_view_progression")
    require(body["target_view"] == target_view, "tc_target_view")
    require(body["timed_out_view"] < U64_MAX and body["target_view"] == body["timed_out_view"] + 1, "tc_immediate_target")
    require(body["timed_out_view"] == previous_view + 1, "tc_single_skipped_view")
    require(
        body["justifications"] == [{"variant": "QC", "value": previous_qc}],
        "tc_justification_inventory",
    )
    entries = body["entries"]
    require(len(entries) <= parameters["max_certificate_signers"], "tc_committed_signer_bound")
    ids = [entry["validator_id"] for entry in entries]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "tc_signer_order")
    weight = 0
    expected_high = {"variant": "QC", "value": {"qc_id": previous_qc_id, "qc_view": previous_view}}
    expected_anchor = {"variant": "FreshGenesis", "value": {"genesis_derived_state_hash": genesis_derived_state_hash}}
    for entry in entries:
        member = members.get(entry["validator_id"])
        require(member is not None, "tc_unknown_signer")
        statement = entry["statement"]
        consensus = statement["consensus_context"]
        require(statement["schema_version"] == 1 and consensus["schema_version"] == 1 and consensus["message_kind"] == 2, "timeout_version_kind")
        require(consensus["context"] == context and consensus["epoch"] == epoch, "timeout_context")
        require(
            consensus["runtime_profile_hash"] == runtime_profile_hash
            and consensus["validator_set_hash"] == validator_set_hash
            and consensus["consensus_parameters_hash"] == parameters_hash,
            "timeout_authority",
        )
        require(consensus["view"] == body["timed_out_view"], "timeout_view")
        require(statement["high_justification"] == expected_high, "timeout_high_justification")
        require(statement["locked_qc_id"] == previous_qc_id and statement["locked_qc_view"] == previous_view, "timeout_locked_qc")
        require(statement["last_finalized_anchor"] == expected_anchor, "timeout_finalized_anchor")
        require(statement["pacemaker_generation"] > 0, "timeout_pacemaker_generation")
        require(entry["signature_scheme"] == STRICT_ED25519, "tc_signature_scheme")
        require(len(entry["signature"]) <= parameters["max_signature_bytes"], "tc_signature_committed_bound")
        require(len(entry["signature"]) == 64, "tc_signature_shape")
        root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(statement))
        require(strict_ed25519_verify(root, member["consensus_public_key"], entry["signature"]), "tc_signature")
        require(member["voting_weight"] <= U128_MAX - weight, "tc_weight_overflow")
        weight += member["voting_weight"]
    require(weight >= threshold, "tc_quorum")
    return tc_id


def verify_checkpoint_anchored_ordinary_tc(
    tc: dict[str, Any], *, previous_qc: dict[str, Any],
    previous_qc_id: bytes, previous_view: int, target_view: int,
    context: dict[str, Any], epoch: int, runtime_profile_hash: bytes,
    validator_set_hash: bytes, parameters_hash: bytes,
    latest_checkpoint_id: bytes, parameters: dict[str, Any],
    members: dict[bytes, dict[str, Any]], threshold: int,
) -> bytes:
    """Verify one same-epoch Ordinary skipped-view TC.

    Unlike the fresh-genesis direct-proof helper, the last-finalized anchor is
    the exact checkpoint already carried by TrustedOrderStateV1.  The full
    previous QC is present in the TC justification inventory and its id/view
    are repeated in every independently signed TimeoutStatementV1.
    """
    body = tc["body"]
    require(body["schema_version"] == 1, "ordinary_tc_version")
    tc_id = digest(TC_DOMAIN, enc_tc_body(body))
    require(tc["timeout_certificate_id"] == tc_id, "ordinary_tc_id")
    require(len(enc_tc(tc)) <= parameters["max_cev1_value_bytes"], "ordinary_tc_cev1_value_bound")
    require(body["context"] == context and body["epoch"] == epoch, "ordinary_tc_context")
    require(
        body["runtime_profile_hash"] == runtime_profile_hash
        and body["validator_set_hash"] == validator_set_hash
        and body["consensus_parameters_hash"] == parameters_hash,
        "ordinary_tc_authority",
    )
    require(previous_view < U64_MAX, "ordinary_tc_view_overflow")
    require(
        body["timed_out_view"] == previous_view + 1
        and body["target_view"] == previous_view + 2
        and target_view == previous_view + 2,
        "ordinary_tc_single_skipped_view",
    )
    require(
        body["justifications"] == [{"variant": "QC", "value": previous_qc}],
        "ordinary_tc_justification_inventory",
    )
    entries = body["entries"]
    require(len(entries) <= parameters["max_certificate_signers"], "ordinary_tc_committed_signer_bound")
    ids = [entry["validator_id"] for entry in entries]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "ordinary_tc_signer_order")
    expected_high = {
        "variant": "QC",
        "value": {"qc_id": previous_qc_id, "qc_view": previous_view},
    }
    expected_anchor = {
        "variant": "EpochCheckpoint",
        "value": {"checkpoint_id": latest_checkpoint_id},
    }
    weight = 0
    for entry in entries:
        member = members.get(entry["validator_id"])
        require(member is not None, "ordinary_tc_unknown_signer")
        statement = entry["statement"]
        consensus = statement["consensus_context"]
        require(
            statement["schema_version"] == 1
            and consensus["schema_version"] == 1
            and consensus["message_kind"] == 2,
            "ordinary_timeout_version_kind",
        )
        require(
            consensus["context"] == context and consensus["epoch"] == epoch,
            "ordinary_timeout_context",
        )
        require(
            consensus["runtime_profile_hash"] == runtime_profile_hash
            and consensus["validator_set_hash"] == validator_set_hash
            and consensus["consensus_parameters_hash"] == parameters_hash,
            "ordinary_timeout_authority",
        )
        require(consensus["view"] == body["timed_out_view"], "ordinary_timeout_view")
        require(statement["high_justification"] == expected_high, "ordinary_timeout_high_justification")
        require(
            statement["locked_qc_id"] == previous_qc_id
            and statement["locked_qc_view"] == previous_view,
            "ordinary_timeout_locked_qc",
        )
        require(statement["last_finalized_anchor"] == expected_anchor, "ordinary_timeout_finalized_anchor")
        require(statement["pacemaker_generation"] > 0, "ordinary_timeout_pacemaker_generation")
        require(entry["signature_scheme"] == STRICT_ED25519, "ordinary_tc_signature_scheme")
        require(len(entry["signature"]) <= parameters["max_signature_bytes"], "ordinary_tc_signature_committed_bound")
        require(len(entry["signature"]) == 64, "ordinary_tc_signature_shape")
        root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(statement))
        require(
            strict_ed25519_verify(root, member["consensus_public_key"], entry["signature"]),
            "ordinary_tc_signature",
        )
        require(member["voting_weight"] <= U128_MAX - weight, "ordinary_tc_weight_overflow")
        weight += member["voting_weight"]
    require(weight >= threshold, "ordinary_tc_quorum")
    return tc_id


def verify_epoch_start_tc(
    tc: dict[str, Any], *, handoff: dict[str, Any], checkpoint_id: bytes,
    target_view: int, context: dict[str, Any], epoch: int,
    runtime_profile_hash: bytes, validator_set_hash: bytes,
    parameters_hash: bytes, parameters: dict[str, Any],
    members: dict[bytes, dict[str, Any]], threshold: int,
) -> bytes:
    """Verify one bounded epoch-start TC whose safe parent is the exact handoff."""
    body = tc["body"]
    require(body["schema_version"] == 1, "epoch_start_tc_version")
    tc_id = digest(TC_DOMAIN, enc_tc_body(body))
    require(tc["timeout_certificate_id"] == tc_id, "epoch_start_tc_id")
    require(len(enc_tc(tc)) <= parameters["max_cev1_value_bytes"], "epoch_start_tc_cev1_value_bound")
    require(body["context"] == context and body["epoch"] == epoch, "epoch_start_tc_context")
    require(
        body["runtime_profile_hash"] == runtime_profile_hash
        and body["validator_set_hash"] == validator_set_hash
        and body["consensus_parameters_hash"] == parameters_hash,
        "epoch_start_tc_authority",
    )
    initial_view = handoff["body"]["initial_new_view"]
    require(initial_view > 0 and initial_view < U64_MAX, "epoch_start_tc_initial_view")
    require(
        body["timed_out_view"] == initial_view
        and body["target_view"] == initial_view + 1
        and target_view == initial_view + 1,
        "epoch_start_tc_immediate_target",
    )
    expected_object = {
        "variant": "EpochStart",
        "value": {"variant": "EpochHandoff", "value": handoff},
    }
    require(body["justifications"] == [expected_object], "epoch_start_tc_justification_inventory")
    expected_high = {
        "variant": "EpochStart",
        "value": {
            "anchor_kind": 2, "anchor_id": handoff["handoff_id"],
            "anchor_view": initial_view - 1,
        },
    }
    expected_finalized = {
        "variant": "EpochCheckpoint", "value": {"checkpoint_id": checkpoint_id},
    }
    entries = body["entries"]
    require(len(entries) <= parameters["max_certificate_signers"], "epoch_start_tc_committed_signer_bound")
    ids = [entry["validator_id"] for entry in entries]
    require(ids == sorted(ids) and len(ids) == len(set(ids)), "epoch_start_tc_signer_order")
    weight = 0
    for entry in entries:
        member = members.get(entry["validator_id"])
        require(member is not None, "epoch_start_tc_unknown_signer")
        statement = entry["statement"]
        consensus = statement["consensus_context"]
        require(
            statement["schema_version"] == 1
            and consensus["schema_version"] == 1
            and consensus["message_kind"] == 2,
            "epoch_start_timeout_version_kind",
        )
        require(consensus["context"] == context and consensus["epoch"] == epoch, "epoch_start_timeout_context")
        require(
            consensus["runtime_profile_hash"] == runtime_profile_hash
            and consensus["validator_set_hash"] == validator_set_hash
            and consensus["consensus_parameters_hash"] == parameters_hash,
            "epoch_start_timeout_authority",
        )
        require(consensus["view"] == initial_view, "epoch_start_timeout_view")
        require(statement["high_justification"] == expected_high, "epoch_start_timeout_high_justification")
        require(statement["locked_qc_id"] is None and statement["locked_qc_view"] == 0, "epoch_start_timeout_lock_absent")
        require(statement["last_finalized_anchor"] == expected_finalized, "epoch_start_timeout_finalized_anchor")
        require(statement["pacemaker_generation"] > 0, "epoch_start_timeout_pacemaker_generation")
        require(entry["signature_scheme"] == STRICT_ED25519, "epoch_start_tc_signature_scheme")
        require(len(entry["signature"]) <= parameters["max_signature_bytes"], "epoch_start_tc_signature_committed_bound")
        require(len(entry["signature"]) == 64, "epoch_start_tc_signature_shape")
        root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(statement))
        require(
            strict_ed25519_verify(root, member["consensus_public_key"], entry["signature"]),
            "epoch_start_tc_signature",
        )
        require(member["voting_weight"] <= U128_MAX - weight, "epoch_start_tc_weight_overflow")
        weight += member["voting_weight"]
    require(weight >= threshold, "epoch_start_tc_quorum")
    return tc_id


def verify_light_client(trust_raw: bytes, proof_raw: bytes, prior: tuple[int, bytes] | None = None) -> dict[str, Any]:
    trust = decode_exact(trust_raw, "trust", dec_trust, enc_trust)
    proof = decode_exact(proof_raw, "proof", dec_proof, enc_proof)
    require(trust["schema_version"] == 1, "trust_schema_version")
    require(proof["schema_version"] == 1, "proof_schema_version")
    validate_context(trust["context"])
    parameters = trust["consensus_parameters"]
    parameters_hash = validate_parameters(parameters)
    validate_context(trust["context"], parameters)
    require(len(trust_raw) <= parameters["max_cev1_value_bytes"], "trust_cev1_value_bound")
    require(len(proof_raw) <= parameters["max_cev1_value_bytes"], "proof_cev1_value_bound")
    require(proof["context"] == trust["context"], "proof_context")
    epoch_descriptor = trust["epoch_descriptor"]
    body = epoch_descriptor["body"]
    require(body["schema_version"] == 1, "epoch_descriptor_schema_version")
    require(body["context"] == trust["context"], "epoch_descriptor_context")
    epoch = body["epoch"]
    require(epoch <= parameters["max_epoch"], "epoch_descriptor_epoch_bound")
    validator_set_hash, definition_hash, members = validate_validator_set(trust["validator_set"], trust["context"], epoch, parameters)
    require(trust["genesis_validator_set_definition_hash"] == definition_hash, "genesis_validator_set_definition_hash")
    require(body["validator_set_hash"] == validator_set_hash, "epoch_descriptor_validator_set_hash")
    require(body["consensus_parameters_hash"] == parameters_hash, "epoch_descriptor_parameters_hash")
    descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(body))
    require(epoch_descriptor["epoch_descriptor_id"] == descriptor_id, "epoch_descriptor_id")
    genesis = trust["trusted_genesis_header"]
    validate_header_bounds(genesis, parameters)
    require(genesis["context"] == trust["context"], "genesis_context")
    require(genesis["epoch"] == epoch, "genesis_descriptor_epoch")
    require(genesis["epoch_descriptor_id"] == descriptor_id, "genesis_epoch_descriptor_id")
    validate_fresh_genesis(genesis, trust["genesis_derived_state_hash"])
    require(genesis["proposer_id"] in members, "genesis_proposer")
    genesis_id = digest(BLOCK_DOMAIN, enc_header(genesis))
    anchor = proof["trusted_anchor"]
    require(anchor["variant"] == "FreshGenesis", "anchor_variant")
    require(anchor["value"]["genesis_derived_state_hash"] == trust["genesis_derived_state_hash"], "anchor_derived_state")
    require(anchor["value"]["trusted_genesis_header"] == genesis, "anchor_header")
    chain = proof["certified_chain"]
    require(len(chain) in (3, 4) and proof["epoch_handoffs"] == [], "direct_three_chain_cardinality")
    kinds = [item["header"]["block_kind"] for item in chain]
    ordinary_path = kinds == ["FreshGenesis"] + ["Ordinary"] * (len(chain) - 1)
    checkpoint_path = kinds == ["FreshGenesis", "EpochCheckpoint", "EpochSeal1", "EpochSeal2"]
    require(ordinary_path or checkpoint_path, "certified_chain_kinds")
    require(len(chain) <= parameters["max_retained_views"], "certified_chain_retained_view_bound")
    block_ids: list[bytes] = []
    qc_ids: list[bytes] = []
    for certified in chain:
        header = certified["header"]
        validate_header_bounds(header, parameters)
        require(header["context"] == trust["context"], "header_context")
        require(header["epoch"] == epoch, "header_epoch")
        require(header["epoch_descriptor_id"] == descriptor_id, "header_epoch_descriptor_id")
        if checkpoint_path and header["block_kind"] in {"EpochCheckpoint", "EpochSeal1", "EpochSeal2"}:
            require(header["next_epoch_descriptor_id"] is not None and header["upgrade_plan_id"] is None and header["epoch_handoff_id"] is None, "checkpoint_header_sidecars")
        else:
            require(header["next_epoch_descriptor_id"] is None and header["upgrade_plan_id"] is None and header["epoch_handoff_id"] is None, "header_bounded_sidecars")
        require(header["proposer_id"] in members, "header_proposer")
        block_id, qc_id = verify_qc(certified, context=trust["context"], epoch=epoch, epoch_descriptor_id=descriptor_id, runtime_profile_hash=body["runtime_profile_hash"], validator_set_hash=validator_set_hash, parameters_hash=parameters_hash, parameters=parameters, members=members, threshold=trust["validator_set"]["definition"]["quorum_threshold"])
        block_ids.append(block_id)
        qc_ids.append(qc_id)
    headers = [certified["header"] for certified in chain]
    require(headers[0] == genesis and block_ids[0] == genesis_id, "certified_genesis")
    require(chain[0]["timeout_certificate"] is None, "certified_genesis_timeout")
    tc_ids: list[bytes] = []
    for index in range(1, len(chain)):
        require(headers[index]["parent"] == {"variant": "V1Block", "value": {"block_id": block_ids[index - 1]}}, "chain_parent")
        require(headers[index]["justify_qc_id"] == qc_ids[index - 1], "chain_justify")
        require(headers[index - 1]["height"] < U64_MAX, "chain_height_overflow")
        require(headers[index - 1]["view"] < U64_MAX, "chain_view_overflow")
        require(headers[index]["height"] == headers[index - 1]["height"] + 1, "chain_height")
        require(headers[index]["view"] > headers[index - 1]["view"], "chain_view_order")
        tc = chain[index]["timeout_certificate"]
        if headers[index]["view"] == headers[index - 1]["view"] + 1:
            require(tc is None and headers[index]["timeout_certificate_id"] is None, "unexpected_timeout_certificate")
        else:
            require(tc is not None and headers[index]["timeout_certificate_id"] is not None, "missing_timeout_certificate")
            tc_id = verify_tc(
                tc, previous_qc=chain[index - 1]["certifying_qc"], previous_qc_id=qc_ids[index - 1],
                previous_view=headers[index - 1]["view"], target_view=headers[index]["view"],
                context=trust["context"], epoch=epoch, runtime_profile_hash=body["runtime_profile_hash"],
                validator_set_hash=validator_set_hash, parameters_hash=parameters_hash,
                genesis_derived_state_hash=trust["genesis_derived_state_hash"], parameters=parameters,
                members=members, threshold=trust["validator_set"]["definition"]["quorum_threshold"],
            )
            require(headers[index]["timeout_certificate_id"] == tc_id, "header_tc_id")
            tc_ids.append(tc_id)
    target_index = len(chain) - parameters["finality_chain_length"]
    require(target_index in (0, 1), "bounded_target_index")
    require(
        headers[target_index]["view"] < headers[target_index + 1]["view"] < headers[target_index + 2]["view"],
        "finality_qc_view_order",
    )
    require(
        proof["target_block_id"] == block_ids[target_index]
        and proof["target_height"] == headers[target_index]["height"]
        and proof["target_header"] == headers[target_index],
        "proof_target",
    )
    if checkpoint_path:
        checkpoint, seal1, seal2 = headers[1], headers[2], headers[3]
        require(
            checkpoint["height"] == parameters["checkpoint_offset_blocks"] + 1
            and seal1["height"] == parameters["seal_1_offset_blocks"] + 1
            and seal2["height"] == parameters["seal_2_offset_blocks"] + 1,
            "checkpoint_schedule",
        )
        require(
            checkpoint["next_epoch_descriptor_id"] == seal1["next_epoch_descriptor_id"] == seal2["next_epoch_descriptor_id"],
            "checkpoint_next_descriptor",
        )
        require(checkpoint["post_state_root"] == seal1["post_state_root"] == seal2["post_state_root"], "seal_state_preservation")
        for header in (checkpoint, seal1, seal2):
            for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
                require(header[field] == empty_ordered_root(root_kind), "checkpoint_empty_payload")
    if prior is not None:
        prior_height, prior_id = prior
        require(prior_height < proof["target_height"] or (prior_height == proof["target_height"] and prior_id == proof["target_block_id"]), "finalized_monotonicity")
    proof_id = digest(PROOF_DOMAIN, enc_proof(proof))
    return {
        "proof_id": proof_id, "finalized_block_id": block_ids[target_index],
        "finalized_height": headers[target_index]["height"], "target_kind": headers[target_index]["block_kind"],
        "genesis_block_id": genesis_id, "validator_set_definition_hash": definition_hash,
        "validator_set_hash": validator_set_hash, "consensus_parameters_hash": parameters_hash,
        "epoch_descriptor_id": descriptor_id, "qc_ids": qc_ids, "tc_ids": tc_ids,
    }


def verify_handoff_role(
    entries: list[dict[str, Any]], *, role: int, context: dict[str, Any],
    runtime_profile_hash: bytes, epoch: int, validator_set_hash: bytes,
    parameters_hash: bytes, view: int, handoff_id: bytes,
    parameters: dict[str, Any], members: dict[bytes, dict[str, Any]], threshold: int,
) -> int:
    """Verify one handoff role without borrowing weight or context from the other."""
    prefix = "old" if role == 0 else "new"
    require(1 <= len(entries) <= parameters["max_certificate_signers"], f"{prefix}_handoff_signer_count")
    signer_ids = [entry["signer_id"] for entry in entries]
    require(
        signer_ids == sorted(signer_ids) and len(signer_ids) == len(set(signer_ids)),
        f"{prefix}_handoff_signer_order",
    )
    expected_kind = 3 if role == 0 else 4
    signature_domain = (
        EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN
        if role == 0
        else EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN
    )
    weight = 0
    for entry in entries:
        member = members.get(entry["signer_id"])
        require(member is not None, f"{prefix}_handoff_unknown_signer")
        require(entry["role"] == role, f"{prefix}_handoff_role")
        statement = entry["statement"]
        consensus = statement["consensus_context"]
        require(
            statement["schema_version"] == 1
            and consensus["schema_version"] == 1
            and consensus["message_kind"] == expected_kind,
            f"{prefix}_handoff_role",
        )
        require(
            consensus["context"] == context and consensus["epoch"] == epoch,
            f"{prefix}_handoff_context",
        )
        require(
            consensus["runtime_profile_hash"] == runtime_profile_hash
            and consensus["validator_set_hash"] == validator_set_hash
            and consensus["consensus_parameters_hash"] == parameters_hash,
            f"{prefix}_handoff_authority",
        )
        require(consensus["view"] == view, f"{prefix}_handoff_view")
        require(statement["handoff_id"] == handoff_id, f"{prefix}_handoff_id")
        require(entry["signature_scheme"] == STRICT_ED25519, f"{prefix}_handoff_signature_scheme")
        require(
            len(entry["signature"]) <= parameters["max_signature_bytes"],
            f"{prefix}_handoff_signature_committed_bound",
        )
        require(len(entry["signature"]) == 64, f"{prefix}_handoff_signature_shape")
        signing_root = digest(signature_domain, enc_handoff_statement(statement))
        require(
            strict_ed25519_verify(signing_root, member["consensus_public_key"], entry["signature"]),
            f"{prefix}_handoff_signature",
        )
        require(member["voting_weight"] <= U128_MAX - weight, f"{prefix}_handoff_weight_overflow")
        weight += member["voting_weight"]
    require(weight >= threshold, f"{prefix}_handoff_quorum")
    return weight


def verify_epoch_transition(transition_raw: bytes) -> dict[str, Any]:
    """Verify one bounded checkpoint -> dual-quorum handoff -> Ordinary advance."""
    transition = decode_exact(
        transition_raw, "epoch_transition", dec_epoch_transition, enc_epoch_transition,
    )
    require(transition["schema_version"] == 1, "transition_schema_version")

    old_trust = transition["old_trust_bundle"]
    checkpoint_proof = transition["checkpoint_finality_proof"]
    old_trust_raw = enc_trust(old_trust)
    checkpoint_proof_raw = enc_proof(checkpoint_proof)
    checkpoint_result = verify_light_client(old_trust_raw, checkpoint_proof_raw)
    require(checkpoint_result["target_kind"] == "EpochCheckpoint", "checkpoint_finality_target_kind")

    old_context = old_trust["context"]
    old_parameters = old_trust["consensus_parameters"]
    old_parameters_hash = validate_parameters(old_parameters)
    validate_context(old_context, old_parameters)
    require(len(transition_raw) <= old_parameters["max_cev1_value_bytes"], "transition_cev1_value_bound")
    old_descriptor = old_trust["epoch_descriptor"]
    old_descriptor_body = old_descriptor["body"]
    old_epoch = old_descriptor_body["epoch"]
    old_descriptor_id = old_descriptor["epoch_descriptor_id"]
    old_validator_set_hash, _, old_members = validate_validator_set(
        old_trust["validator_set"], old_context, old_epoch, old_parameters,
    )

    checkpoint = transition["checkpoint"]
    checkpoint_body = checkpoint["body"]
    require(checkpoint_body["schema_version"] == 1, "checkpoint_schema_version")
    require(checkpoint_body["context"] == old_context, "checkpoint_context")
    require(checkpoint_body["epoch"] == old_epoch, "checkpoint_epoch")
    require(
        checkpoint_body["checkpoint_block_id"] == checkpoint_result["finalized_block_id"]
        and checkpoint_body["checkpoint_height"] == checkpoint_result["finalized_height"]
        and checkpoint_body["checkpoint_header"] == checkpoint_proof["target_header"],
        "checkpoint_target",
    )
    require(checkpoint_body["epoch_descriptor_id"] == old_descriptor_id, "checkpoint_descriptor")
    require(
        checkpoint_body["validator_set_hash"] == old_validator_set_hash
        and checkpoint_body["consensus_parameters_hash"] == old_parameters_hash,
        "checkpoint_authority",
    )
    require(
        checkpoint_body["application_state_root"]
        == checkpoint_body["checkpoint_header"]["post_state_root"],
        "checkpoint_state",
    )
    require(
        checkpoint_body["da_committee_set_root"] == old_descriptor_body["da_committee_set_root"]
        and checkpoint_body["verification_registry_hash"] == old_descriptor_body["verification_registry_hash"]
        and checkpoint_body["stack_profile_hash"] == old_context["stack_profile_hash"]
        and checkpoint_body["fee_schedule_hash"] == old_descriptor_body["fee_schedule_hash"]
        and checkpoint_body["state_schema_hash"] == old_descriptor_body["state_schema_hash"]
        and checkpoint_body["snapshot_policy_hash"] == old_descriptor_body["snapshot_policy_hash"],
        "checkpoint_policy",
    )
    require(checkpoint_body["upgrade_plan_id"] is None, "checkpoint_upgrade")
    checkpoint_id = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
    require(checkpoint["checkpoint_id"] == checkpoint_id, "checkpoint_id")
    attachment = transition["checkpoint_attachment"]
    require(attachment["checkpoint_id"] == checkpoint_id, "attachment_checkpoint_id")
    require(attachment["order_finality_proof"] == checkpoint_proof, "attachment_proof")

    new_descriptor = transition["new_epoch_descriptor"]
    new_descriptor_body = new_descriptor["body"]
    new_context = new_descriptor_body["context"]
    new_parameters = transition["new_consensus_parameters"]
    new_parameters_hash = validate_parameters(new_parameters)
    validate_context(new_context, new_parameters)
    require(len(transition_raw) <= new_parameters["max_cev1_value_bytes"], "transition_new_cev1_value_bound")
    require(
        old_context["genesis_hash"] == new_context["genesis_hash"]
        and old_context["chain_id"] == new_context["chain_id"]
        and old_context["protocol_version"] == new_context["protocol_version"] == 1,
        "handoff_context_lineage",
    )
    require(old_epoch < U64_MAX and new_descriptor_body["epoch"] == old_epoch + 1, "new_epoch_progression")
    new_epoch = new_descriptor_body["epoch"]
    new_validator_set_hash, _, new_members = validate_validator_set(
        transition["new_validator_set"], new_context, new_epoch, new_parameters,
    )
    require(new_descriptor_body["schema_version"] == 1, "new_epoch_descriptor_schema_version")
    require(new_descriptor_body["context"] == new_context, "new_epoch_descriptor_context")
    require(new_descriptor_body["validator_set_hash"] == new_validator_set_hash, "new_epoch_descriptor_validator_set_hash")
    require(new_descriptor_body["consensus_parameters_hash"] == new_parameters_hash, "new_epoch_descriptor_parameters_hash")
    new_descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(new_descriptor_body))
    require(new_descriptor["epoch_descriptor_id"] == new_descriptor_id, "new_epoch_descriptor_id")
    require(checkpoint_body["next_epoch_descriptor_id"] == new_descriptor_id, "checkpoint_next_descriptor")

    handoff = transition["handoff"]
    handoff_body = handoff["body"]
    require(handoff_body["schema_version"] == 1, "handoff_schema_version")
    require(
        handoff_body["source_context"] == old_context
        and handoff_body["target_context"] == new_context,
        "handoff_context",
    )
    require(
        handoff_body["old_epoch"] == old_epoch
        and handoff_body["new_epoch"] == new_epoch,
        "handoff_epoch",
    )
    require(handoff_body["old_epoch_checkpoint_id"] == checkpoint_id, "handoff_checkpoint")
    require(
        handoff_body["old_epoch_descriptor_id"] == old_descriptor_id
        and handoff_body["new_epoch_descriptor_id"] == new_descriptor_id,
        "handoff_descriptor",
    )
    require(
        handoff_body["old_validator_set_hash"] == old_validator_set_hash
        and handoff_body["new_validator_set_hash"] == new_validator_set_hash
        and handoff_body["old_consensus_parameters_hash"] == old_parameters_hash
        and handoff_body["new_consensus_parameters_hash"] == new_parameters_hash,
        "handoff_authority",
    )
    old_chain = checkpoint_proof["certified_chain"]
    terminal = old_chain[-1]
    require(terminal["header"]["block_kind"] == "EpochSeal2", "handoff_terminal_kind")
    require(
        handoff_body["terminal_block_id"] == terminal["block_id"]
        and handoff_body["terminal_height"] == terminal["header"]["height"]
        and handoff_body["terminal_view"] == terminal["header"]["view"]
        and terminal["certifying_qc"]["body"]["statement"]["consensus_context"]["view"]
        == handoff_body["terminal_view"],
        "handoff_terminal",
    )
    require(
        handoff_body["terminal_height"] < U64_MAX
        and handoff_body["activation_height"] == handoff_body["terminal_height"] + 1,
        "handoff_activation",
    )
    require(handoff_body["initial_new_view"] == 1, "handoff_initial_view")
    handoff_id = digest(EPOCH_HANDOFF_DOMAIN, enc_handoff_body(handoff_body))
    require(handoff["handoff_id"] == handoff_id, "handoff_id")
    old_weight = verify_handoff_role(
        handoff["old_set_signatures"], role=0, context=old_context,
        runtime_profile_hash=old_descriptor_body["runtime_profile_hash"],
        epoch=old_epoch, validator_set_hash=old_validator_set_hash,
        parameters_hash=old_parameters_hash, view=handoff_body["terminal_view"],
        handoff_id=handoff_id, parameters=old_parameters, members=old_members,
        threshold=old_trust["validator_set"]["definition"]["quorum_threshold"],
    )
    new_weight = verify_handoff_role(
        handoff["new_set_signatures"], role=1, context=new_context,
        runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
        epoch=new_epoch, validator_set_hash=new_validator_set_hash,
        parameters_hash=new_parameters_hash, view=handoff_body["initial_new_view"],
        handoff_id=handoff_id, parameters=new_parameters, members=new_members,
        threshold=transition["new_validator_set"]["definition"]["quorum_threshold"],
    )

    new_chain = transition["new_epoch_certified_chain"]
    require(
        [item["header"]["block_kind"] for item in new_chain]
        == ["V1HandoffFirst", "Ordinary", "Ordinary", "Ordinary"],
        "new_epoch_chain_kinds",
    )
    new_block_ids: list[bytes] = []
    new_qc_ids: list[bytes] = []
    for index, item in enumerate(new_chain):
        header = item["header"]
        validate_header_bounds(header, new_parameters)
        require(header["context"] == new_context, "new_epoch_header_context")
        require(header["epoch"] == new_epoch, "new_epoch_header_epoch")
        require(header["epoch_descriptor_id"] == new_descriptor_id, "new_epoch_header_descriptor")
        require(header["proposer_id"] in new_members, "new_epoch_header_proposer")
        require(header["next_epoch_descriptor_id"] is None and header["upgrade_plan_id"] is None, "new_epoch_header_sidecars")
        require(item["timeout_certificate"] is None and header["timeout_certificate_id"] is None, "new_epoch_timeout_certificate")
        block_id, qc_id = verify_qc(
            item, context=new_context, epoch=new_epoch,
            epoch_descriptor_id=new_descriptor_id,
            runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
            validator_set_hash=new_validator_set_hash,
            parameters_hash=new_parameters_hash, parameters=new_parameters,
            members=new_members,
            threshold=transition["new_validator_set"]["definition"]["quorum_threshold"],
        )
        new_block_ids.append(block_id)
        new_qc_ids.append(qc_id)

    first = new_chain[0]["header"]
    require(
        first["parent"] == {"variant": "V1Block", "value": {"block_id": terminal["block_id"]}},
        "new_epoch_first_parent",
    )
    require(first["height"] == handoff_body["activation_height"], "new_epoch_first_height")
    require(first["view"] == handoff_body["initial_new_view"], "new_epoch_first_view")
    require(first["justify_qc_id"] is None, "new_epoch_first_justify")
    require(first["epoch_handoff_id"] == handoff_id, "new_epoch_first_handoff")
    require(first["post_state_root"] == terminal["header"]["post_state_root"], "new_epoch_first_state")
    verify_handoff_first_roots(first, handoff, prefix="new_epoch_first")

    for index in range(1, len(new_chain)):
        previous = new_chain[index - 1]
        current = new_chain[index]
        previous_header = previous["header"]
        header = current["header"]
        require(header["epoch_handoff_id"] is None, "new_epoch_ordinary_handoff")
        require(
            header["parent"] == {"variant": "V1Block", "value": {"block_id": new_block_ids[index - 1]}},
            "new_epoch_chain_parent",
        )
        require(previous_header["height"] < U64_MAX and header["height"] == previous_header["height"] + 1, "new_epoch_chain_height")
        require(previous_header["view"] < U64_MAX and header["view"] == previous_header["view"] + 1, "new_epoch_chain_view")
        require(header["justify_qc_id"] == new_qc_ids[index - 1], "new_epoch_chain_justify")

    # H0-H2 finalizes the handoff anchor; H1-H3 consumes that trusted state and
    # advances finality by one Ordinary block under the independently verified
    # new descriptor/set/parameters.
    handoff_anchor = new_chain[0]
    ordinary_target = new_chain[1]
    require(
        handoff_anchor["header"]["height"] < ordinary_target["header"]["height"],
        "new_epoch_trusted_state_progression",
    )
    return {
        "checkpoint_proof_id": checkpoint_result["proof_id"],
        "checkpoint_id": checkpoint_id,
        "handoff_id": handoff_id,
        "old_terminal_block_id": terminal["block_id"],
        "old_terminal_height": terminal["header"]["height"],
        "new_epoch": new_epoch,
        "new_epoch_descriptor_id": new_descriptor_id,
        "new_validator_set_hash": new_validator_set_hash,
        "new_consensus_parameters_hash": new_parameters_hash,
        "handoff_anchor_finalized_block_id": handoff_anchor["block_id"],
        "handoff_anchor_finalized_height": handoff_anchor["header"]["height"],
        "finalized_block_id": ordinary_target["block_id"],
        "finalized_height": ordinary_target["header"]["height"],
        "finalized_kind": ordinary_target["header"]["block_kind"],
        "new_qc_ids": new_qc_ids,
        "old_handoff_weight": old_weight,
        "new_handoff_weight": new_weight,
        "old_handoff_signatures": len(handoff["old_set_signatures"]),
        "new_handoff_signatures": len(handoff["new_set_signatures"]),
        "transition_sha256": hashlib.sha256(transition_raw).digest(),
    }


def validate_trusted_order_state(value: dict[str, Any]) -> dict[str, Any]:
    require(value["schema_version"] == 1, "trusted_state_schema")
    context = value["context"]
    parameters = value["consensus_parameters"]
    parameters_hash = validate_parameters(parameters)
    validate_context(context, parameters)
    epoch = value["epoch"]
    require(epoch <= parameters["max_epoch"], "trusted_state_epoch_bound")
    descriptor = value["epoch_descriptor"]
    body = descriptor["body"]
    require(body["schema_version"] == 1, "trusted_state_descriptor_schema")
    require(body["context"] == context and body["epoch"] == epoch, "trusted_state_descriptor_context")
    validator_set_hash, definition_hash, members = validate_validator_set(
        value["validator_set"], context, epoch, parameters,
    )
    require(body["validator_set_hash"] == validator_set_hash, "trusted_state_descriptor_set")
    require(body["consensus_parameters_hash"] == parameters_hash, "trusted_state_descriptor_parameters")
    descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(body))
    require(descriptor["epoch_descriptor_id"] == descriptor_id, "trusted_state_descriptor_id")
    finalized = value["finalized_header"]
    certified_head = value["certified_head_header"]
    for label, header in (("finalized", finalized), ("certified_head", certified_head)):
        validate_header_bounds(header, parameters)
        require(header["context"] == context and header["epoch"] == epoch, f"trusted_state_{label}_context")
        require(header["epoch_descriptor_id"] == descriptor_id, f"trusted_state_{label}_descriptor")
        require(header["proposer_id"] in members, f"trusted_state_{label}_proposer")
    require(value["finalized_height"] == finalized["height"], "trusted_state_finalized_height")
    require(
        value["finalized_block_id"] == digest(BLOCK_DOMAIN, enc_header(finalized)),
        "trusted_state_finalized_block_id",
    )
    require(
        value["certified_head_block_id"] == digest(BLOCK_DOMAIN, enc_header(certified_head)),
        "trusted_state_certified_head_block_id",
    )
    require(finalized["height"] <= certified_head["height"], "trusted_state_height_order")
    require(value["epoch_start_height"] <= finalized["height"], "trusted_state_epoch_start")
    expected_state_id = digest(TRUSTED_ORDER_STATE_DOMAIN, enc_trusted_order_state_body(value))
    require(value["state_id"] == expected_state_id, "trusted_state_id")
    require(len(enc_trusted_order_state(value)) <= parameters["max_cev1_value_bytes"], "trusted_state_cev1_value_bound")
    return {
        "parameters_hash": parameters_hash,
        "validator_set_hash": validator_set_hash,
        "validator_set_definition_hash": definition_hash,
        "descriptor_id": descriptor_id,
        "members": members,
    }


def seal_trusted_order_state(value: dict[str, Any]) -> dict[str, Any]:
    value["state_id"] = digest(TRUSTED_ORDER_STATE_DOMAIN, enc_trusted_order_state_body(value))
    return value


def initial_state_from_existing_transition(transition: dict[str, Any]) -> dict[str, Any]:
    trust = transition["old_trust_bundle"]
    genesis = trust["trusted_genesis_header"]
    chain = transition["checkpoint_finality_proof"]["certified_chain"]
    require(chain and chain[0]["header"] == genesis, "trust_path_initial_genesis_chain")
    genesis_id = digest(BLOCK_DOMAIN, enc_header(genesis))
    require(chain[0]["block_id"] == genesis_id, "trust_path_initial_genesis_block")
    state = {
        "schema_version": 1, "context": copy.deepcopy(trust["context"]),
        "epoch": trust["epoch_descriptor"]["body"]["epoch"],
        "epoch_start_height": genesis["height"], "finalized_height": genesis["height"],
        "finalized_header": copy.deepcopy(genesis), "finalized_block_id": genesis_id,
        "certified_head_header": copy.deepcopy(genesis), "certified_head_block_id": genesis_id,
        "certified_head_qc_id": chain[0]["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(trust["epoch_descriptor"]),
        "validator_set": copy.deepcopy(trust["validator_set"]),
        "consensus_parameters": copy.deepcopy(trust["consensus_parameters"]),
        "latest_checkpoint_id": None, "latest_handoff_id": None, "state_id": b"\x00" * 32,
    }
    return seal_trusted_order_state(state)


def output_state_from_existing_transition(transition: dict[str, Any]) -> dict[str, Any]:
    chain = transition["new_epoch_certified_chain"]
    require(len(chain) == 4, "trust_path_initial_new_chain")
    finalized, certified_head = chain[1], chain[-1]
    state = {
        "schema_version": 1,
        "context": copy.deepcopy(transition["new_epoch_descriptor"]["body"]["context"]),
        "epoch": transition["new_epoch_descriptor"]["body"]["epoch"],
        "epoch_start_height": chain[0]["header"]["height"],
        "finalized_height": finalized["header"]["height"],
        "finalized_header": copy.deepcopy(finalized["header"]),
        "finalized_block_id": finalized["block_id"],
        "certified_head_header": copy.deepcopy(certified_head["header"]),
        "certified_head_block_id": certified_head["block_id"],
        "certified_head_qc_id": certified_head["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(transition["new_epoch_descriptor"]),
        "validator_set": copy.deepcopy(transition["new_validator_set"]),
        "consensus_parameters": copy.deepcopy(transition["new_consensus_parameters"]),
        "latest_checkpoint_id": transition["checkpoint"]["checkpoint_id"],
        "latest_handoff_id": transition["handoff"]["handoff_id"],
        "state_id": b"\x00" * 32,
    }
    return seal_trusted_order_state(state)


def verify_existing_fresh_genesis_path_step(raw: bytes, current: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    transition = decode_exact(
        raw, "trust_path_existing_transition", dec_epoch_transition, enc_epoch_transition,
    )
    result = verify_epoch_transition(raw)
    require(initial_state_from_existing_transition(transition) == current, "trust_path_initial_state_binding")
    output = output_state_from_existing_transition(transition)
    validate_trusted_order_state(output)
    parameters = output["consensus_parameters"]
    require(
        output["epoch_start_height"] <= U64_MAX - parameters["checkpoint_offset_blocks"]
        and output["epoch_start_height"] + parameters["checkpoint_offset_blocks"]
        == output["certified_head_header"]["height"] + 1,
        "trust_path_initial_future_checkpoint_schedule",
    )
    return output, result


def verify_checkpoint_anchored_transition_step(
    raw: bytes, current: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify one versioned checkpoint-anchored epoch transition.

    The input state is already trusted.  The step must nevertheless carry and
    authenticate every new header, QC, checkpoint, descriptor, handoff and
    output-state byte.  In particular, the prior certified-head QC identifier
    is consumed as the first checkpoint header's justification; it is never
    replaced by an uncommitted JSON summary.
    """
    step = decode_exact(
        raw, "checkpoint_transition_step", dec_checkpoint_transition_step,
        enc_checkpoint_transition_step,
    )
    require(step["schema_version"] == 1, "checkpoint_step_schema")
    current_meta = validate_trusted_order_state(current)
    require(step["input_state_id"] == current["state_id"], "checkpoint_step_input_state")
    old_parameters = current["consensus_parameters"]
    require(len(raw) <= old_parameters["max_cev1_value_bytes"], "checkpoint_step_old_cev1_value_bound")
    old_context = current["context"]
    old_epoch = current["epoch"]
    old_descriptor = current["epoch_descriptor"]
    old_descriptor_body = old_descriptor["body"]
    old_descriptor_id = current_meta["descriptor_id"]
    old_validator_set_hash = current_meta["validator_set_hash"]
    old_parameters_hash = current_meta["parameters_hash"]
    old_members = current_meta["members"]
    old_threshold = current["validator_set"]["definition"]["quorum_threshold"]

    checkpoint_chain = step["checkpoint_certified_chain"]
    require(len(checkpoint_chain) == 3, "checkpoint_step_chain_cardinality")
    require(
        [item["header"]["block_kind"] for item in checkpoint_chain]
        == ["EpochCheckpoint", "EpochSeal1", "EpochSeal2"],
        "checkpoint_step_chain_kinds",
    )
    checkpoint_block_ids: list[bytes] = []
    checkpoint_qc_ids: list[bytes] = []
    scheduled_heights = (
        current["epoch_start_height"] + old_parameters["checkpoint_offset_blocks"],
        current["epoch_start_height"] + old_parameters["seal_1_offset_blocks"],
        current["epoch_start_height"] + old_parameters["seal_2_offset_blocks"],
    )
    require(
        current["epoch_start_height"] <= U64_MAX - old_parameters["seal_2_offset_blocks"],
        "checkpoint_step_schedule_overflow",
    )
    require(
        scheduled_heights[0] == current["certified_head_header"]["height"] + 1,
        "checkpoint_step_schedule_continuity",
    )
    next_descriptor_id = step["new_epoch_descriptor"]["epoch_descriptor_id"]
    previous_block_id = current["certified_head_block_id"]
    previous_qc_id = current["certified_head_qc_id"]
    previous_view = current["certified_head_header"]["view"]
    for index, item in enumerate(checkpoint_chain):
        header = item["header"]
        validate_header_bounds(header, old_parameters)
        require(header["context"] == old_context, "checkpoint_step_header_context")
        require(header["epoch"] == old_epoch, "checkpoint_step_header_epoch")
        require(header["epoch_descriptor_id"] == old_descriptor_id, "checkpoint_step_header_descriptor")
        require(header["proposer_id"] in old_members, "checkpoint_step_header_proposer")
        require(
            header["parent"] == {"variant": "V1Block", "value": {"block_id": previous_block_id}},
            "checkpoint_step_chain_parent",
        )
        require(header["height"] == scheduled_heights[index], "checkpoint_step_chain_height")
        require(previous_view < U64_MAX and header["view"] == previous_view + 1, "checkpoint_step_chain_view")
        require(header["justify_qc_id"] == previous_qc_id, "checkpoint_step_chain_justify")
        require(
            header["next_epoch_descriptor_id"] == next_descriptor_id
            and header["upgrade_plan_id"] is None
            and header["epoch_handoff_id"] is None,
            "checkpoint_step_header_sidecars",
        )
        require(item["timeout_certificate"] is None and header["timeout_certificate_id"] is None, "checkpoint_step_timeout")
        require(header["post_state_root"] == current["certified_head_header"]["post_state_root"], "checkpoint_step_state")
        for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
            require(header[field] == empty_ordered_root(root_kind), "checkpoint_step_empty_payload")
        block_id, qc_id = verify_qc(
            item, context=old_context, epoch=old_epoch,
            epoch_descriptor_id=old_descriptor_id,
            runtime_profile_hash=old_descriptor_body["runtime_profile_hash"],
            validator_set_hash=old_validator_set_hash,
            parameters_hash=old_parameters_hash, parameters=old_parameters,
            members=old_members, threshold=old_threshold,
        )
        checkpoint_block_ids.append(block_id)
        checkpoint_qc_ids.append(qc_id)
        previous_block_id, previous_qc_id, previous_view = block_id, qc_id, header["view"]

    checkpoint = step["checkpoint"]
    checkpoint_body = checkpoint["body"]
    target = checkpoint_chain[0]
    require(checkpoint_body["schema_version"] == 1, "checkpoint_step_checkpoint_schema")
    require(checkpoint_body["context"] == old_context, "checkpoint_step_checkpoint_context")
    require(checkpoint_body["epoch"] == old_epoch, "checkpoint_step_checkpoint_epoch")
    require(
        checkpoint_body["checkpoint_block_id"] == target["block_id"]
        and checkpoint_body["checkpoint_height"] == target["header"]["height"]
        and checkpoint_body["checkpoint_header"] == target["header"],
        "checkpoint_step_checkpoint_target",
    )
    require(checkpoint_body["epoch_descriptor_id"] == old_descriptor_id, "checkpoint_step_checkpoint_descriptor")
    require(
        checkpoint_body["validator_set_hash"] == old_validator_set_hash
        and checkpoint_body["consensus_parameters_hash"] == old_parameters_hash,
        "checkpoint_step_checkpoint_authority",
    )
    require(
        checkpoint_body["application_state_root"] == target["header"]["post_state_root"],
        "checkpoint_step_checkpoint_state",
    )
    require(
        checkpoint_body["da_committee_set_root"] == old_descriptor_body["da_committee_set_root"]
        and checkpoint_body["verification_registry_hash"] == old_descriptor_body["verification_registry_hash"]
        and checkpoint_body["stack_profile_hash"] == old_context["stack_profile_hash"]
        and checkpoint_body["fee_schedule_hash"] == old_descriptor_body["fee_schedule_hash"]
        and checkpoint_body["state_schema_hash"] == old_descriptor_body["state_schema_hash"]
        and checkpoint_body["snapshot_policy_hash"] == old_descriptor_body["snapshot_policy_hash"],
        "checkpoint_step_checkpoint_policy",
    )
    require(checkpoint_body["next_epoch_descriptor_id"] == next_descriptor_id, "checkpoint_step_checkpoint_next_descriptor")
    require(checkpoint_body["upgrade_plan_id"] is None, "checkpoint_step_checkpoint_upgrade")
    checkpoint_id = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
    require(checkpoint["checkpoint_id"] == checkpoint_id, "checkpoint_step_checkpoint_id")

    new_descriptor = step["new_epoch_descriptor"]
    new_descriptor_body = new_descriptor["body"]
    new_context = new_descriptor_body["context"]
    new_parameters = step["new_consensus_parameters"]
    new_parameters_hash = validate_parameters(new_parameters)
    validate_context(new_context, new_parameters)
    require(len(raw) <= new_parameters["max_cev1_value_bytes"], "checkpoint_step_new_cev1_value_bound")
    require(
        old_context["genesis_hash"] == new_context["genesis_hash"]
        and old_context["chain_id"] == new_context["chain_id"]
        and old_context["protocol_version"] == new_context["protocol_version"] == 1,
        "checkpoint_step_context_lineage",
    )
    require(old_epoch < U64_MAX and new_descriptor_body["epoch"] == old_epoch + 1, "checkpoint_step_epoch_progression")
    new_epoch = new_descriptor_body["epoch"]
    new_validator_set_hash, _, new_members = validate_validator_set(
        step["new_validator_set"], new_context, new_epoch, new_parameters,
    )
    require(new_descriptor_body["schema_version"] == 1, "checkpoint_step_descriptor_schema")
    require(new_descriptor_body["validator_set_hash"] == new_validator_set_hash, "checkpoint_step_descriptor_set")
    require(new_descriptor_body["consensus_parameters_hash"] == new_parameters_hash, "checkpoint_step_descriptor_parameters")
    computed_new_descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(new_descriptor_body))
    require(new_descriptor["epoch_descriptor_id"] == computed_new_descriptor_id, "checkpoint_step_descriptor_id")
    require(next_descriptor_id == computed_new_descriptor_id, "checkpoint_step_next_descriptor_binding")

    terminal = checkpoint_chain[-1]
    handoff = step["handoff"]
    handoff_body = handoff["body"]
    require(handoff_body["schema_version"] == 1, "checkpoint_step_handoff_schema")
    require(
        handoff_body["source_context"] == old_context
        and handoff_body["target_context"] == new_context,
        "checkpoint_step_handoff_context",
    )
    require(
        handoff_body["old_epoch"] == old_epoch
        and handoff_body["new_epoch"] == new_epoch,
        "checkpoint_step_handoff_epoch",
    )
    require(handoff_body["old_epoch_checkpoint_id"] == checkpoint_id, "checkpoint_step_handoff_checkpoint")
    require(
        handoff_body["old_epoch_descriptor_id"] == old_descriptor_id
        and handoff_body["new_epoch_descriptor_id"] == computed_new_descriptor_id,
        "checkpoint_step_handoff_descriptor",
    )
    require(
        handoff_body["old_validator_set_hash"] == old_validator_set_hash
        and handoff_body["new_validator_set_hash"] == new_validator_set_hash
        and handoff_body["old_consensus_parameters_hash"] == old_parameters_hash
        and handoff_body["new_consensus_parameters_hash"] == new_parameters_hash,
        "checkpoint_step_handoff_authority",
    )
    require(
        handoff_body["terminal_block_id"] == terminal["block_id"]
        and handoff_body["terminal_height"] == terminal["header"]["height"]
        and handoff_body["terminal_view"] == terminal["header"]["view"],
        "checkpoint_step_handoff_terminal",
    )
    require(
        handoff_body["terminal_height"] < U64_MAX
        and handoff_body["activation_height"] == handoff_body["terminal_height"] + 1,
        "checkpoint_step_handoff_activation",
    )
    require(handoff_body["initial_new_view"] == 1, "checkpoint_step_handoff_initial_view")
    handoff_id = digest(EPOCH_HANDOFF_DOMAIN, enc_handoff_body(handoff_body))
    require(handoff["handoff_id"] == handoff_id, "checkpoint_step_handoff_id")
    old_weight = verify_handoff_role(
        handoff["old_set_signatures"], role=0, context=old_context,
        runtime_profile_hash=old_descriptor_body["runtime_profile_hash"], epoch=old_epoch,
        validator_set_hash=old_validator_set_hash, parameters_hash=old_parameters_hash,
        view=handoff_body["terminal_view"], handoff_id=handoff_id,
        parameters=old_parameters, members=old_members, threshold=old_threshold,
    )
    new_threshold = step["new_validator_set"]["definition"]["quorum_threshold"]
    new_weight = verify_handoff_role(
        handoff["new_set_signatures"], role=1, context=new_context,
        runtime_profile_hash=new_descriptor_body["runtime_profile_hash"], epoch=new_epoch,
        validator_set_hash=new_validator_set_hash, parameters_hash=new_parameters_hash,
        view=handoff_body["initial_new_view"], handoff_id=handoff_id,
        parameters=new_parameters, members=new_members, threshold=new_threshold,
    )

    new_chain = step["new_epoch_certified_chain"]
    require(len(new_chain) == 4, "checkpoint_step_new_chain_cardinality")
    require(
        [item["header"]["block_kind"] for item in new_chain]
        == ["V1HandoffFirst", "Ordinary", "Ordinary", "Ordinary"],
        "checkpoint_step_new_chain_kinds",
    )
    new_block_ids: list[bytes] = []
    new_qc_ids: list[bytes] = []
    for index, item in enumerate(new_chain):
        header = item["header"]
        validate_header_bounds(header, new_parameters)
        require(header["context"] == new_context, "checkpoint_step_new_header_context")
        require(header["epoch"] == new_epoch, "checkpoint_step_new_header_epoch")
        require(header["epoch_descriptor_id"] == computed_new_descriptor_id, "checkpoint_step_new_header_descriptor")
        require(header["proposer_id"] in new_members, "checkpoint_step_new_header_proposer")
        require(header["next_epoch_descriptor_id"] is None and header["upgrade_plan_id"] is None, "checkpoint_step_new_header_sidecars")
        if index > 0:
            require(
                item["timeout_certificate"] is None
                and header["timeout_certificate_id"] is None,
                "checkpoint_step_new_ordinary_timeout",
            )
        block_id, qc_id = verify_qc(
            item, context=new_context, epoch=new_epoch,
            epoch_descriptor_id=computed_new_descriptor_id,
            runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
            validator_set_hash=new_validator_set_hash,
            parameters_hash=new_parameters_hash, parameters=new_parameters,
            members=new_members, threshold=new_threshold,
        )
        new_block_ids.append(block_id)
        new_qc_ids.append(qc_id)

    first = new_chain[0]["header"]
    require(
        first["parent"] == {"variant": "V1Block", "value": {"block_id": terminal["block_id"]}},
        "checkpoint_step_new_first_parent",
    )
    require(first["height"] == handoff_body["activation_height"], "checkpoint_step_new_first_height")
    require(first["justify_qc_id"] is None, "checkpoint_step_new_first_justify")
    require(first["epoch_handoff_id"] == handoff_id, "checkpoint_step_new_first_handoff")
    require(first["post_state_root"] == terminal["header"]["post_state_root"], "checkpoint_step_new_first_state")
    verify_handoff_first_roots(first, handoff, prefix="checkpoint_step_new_first")
    first_tc = new_chain[0]["timeout_certificate"]
    initial_new_view = handoff_body["initial_new_view"]
    if first["view"] == initial_new_view:
        require(
            first_tc is None and first["timeout_certificate_id"] is None,
            "checkpoint_step_epoch_start_initial_tc_absent",
        )
    else:
        require(
            initial_new_view < U64_MAX and first["view"] == initial_new_view + 1,
            "checkpoint_step_epoch_start_single_skipped_view",
        )
        require(first_tc is not None, "checkpoint_step_epoch_start_tc_missing")
        first_tc_id = verify_epoch_start_tc(
            first_tc, handoff=handoff, checkpoint_id=checkpoint_id,
            target_view=first["view"], context=new_context, epoch=new_epoch,
            runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
            validator_set_hash=new_validator_set_hash,
            parameters_hash=new_parameters_hash, parameters=new_parameters,
            members=new_members, threshold=new_threshold,
        )
        require(
            first["timeout_certificate_id"] == first_tc_id,
            "checkpoint_step_epoch_start_tc_header_id",
        )
    for index in range(1, 4):
        previous = new_chain[index - 1]
        header = new_chain[index]["header"]
        require(header["epoch_handoff_id"] is None, "checkpoint_step_new_ordinary_handoff")
        require(
            header["parent"] == {"variant": "V1Block", "value": {"block_id": new_block_ids[index - 1]}},
            "checkpoint_step_new_chain_parent",
        )
        require(header["height"] == previous["header"]["height"] + 1, "checkpoint_step_new_chain_height")
        require(header["view"] == previous["header"]["view"] + 1, "checkpoint_step_new_chain_view")
        require(header["justify_qc_id"] == new_qc_ids[index - 1], "checkpoint_step_new_chain_justify")

    expected_output = {
        "schema_version": 1, "context": copy.deepcopy(new_context), "epoch": new_epoch,
        "epoch_start_height": first["height"],
        "finalized_height": new_chain[1]["header"]["height"],
        "finalized_header": copy.deepcopy(new_chain[1]["header"]),
        "finalized_block_id": new_chain[1]["block_id"],
        "certified_head_header": copy.deepcopy(new_chain[-1]["header"]),
        "certified_head_block_id": new_chain[-1]["block_id"],
        "certified_head_qc_id": new_chain[-1]["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(new_descriptor),
        "validator_set": copy.deepcopy(step["new_validator_set"]),
        "consensus_parameters": copy.deepcopy(new_parameters),
        "latest_checkpoint_id": checkpoint_id, "latest_handoff_id": handoff_id,
        "state_id": b"\x00" * 32,
    }
    seal_trusted_order_state(expected_output)
    require(step["output_state"]["epoch"] == current["epoch"] + 1, "checkpoint_step_output_epoch")
    require(
        step["output_state"]["finalized_height"] > current["finalized_height"],
        "checkpoint_step_output_height",
    )
    require(step["output_state"] == expected_output, "checkpoint_step_output_state")
    validate_trusted_order_state(expected_output)
    require(expected_output["epoch"] == current["epoch"] + 1, "checkpoint_step_output_epoch")
    require(expected_output["finalized_height"] > current["finalized_height"], "checkpoint_step_output_height")
    require(
        expected_output["epoch_start_height"] <= U64_MAX - new_parameters["checkpoint_offset_blocks"]
        and expected_output["epoch_start_height"] + new_parameters["checkpoint_offset_blocks"]
        == expected_output["certified_head_header"]["height"] + 1,
        "checkpoint_step_future_checkpoint_schedule",
    )
    step_id = digest(CHECKPOINT_TRANSITION_STEP_DOMAIN, enc_checkpoint_transition_step_body(step))
    require(step["step_id"] == step_id, "checkpoint_step_id")
    return expected_output, {
        "step_id": step_id, "checkpoint_id": checkpoint_id, "handoff_id": handoff_id,
        "input_state_id": current["state_id"], "output_state_id": expected_output["state_id"],
        "old_epoch": old_epoch, "new_epoch": new_epoch,
        "old_finalized_height": current["finalized_height"],
        "new_finalized_height": expected_output["finalized_height"],
        "checkpoint_qc_ids": checkpoint_qc_ids, "new_qc_ids": new_qc_ids,
        "old_handoff_weight": old_weight, "new_handoff_weight": new_weight,
        "qc_signatures_checked": sum(
            len(item["certifying_qc"]["body"]["signatures"])
            for item in checkpoint_chain + new_chain
        ),
        "tc_signatures_checked": (
            0 if first_tc is None else len(first_tc["body"]["entries"])
        ),
        "handoff_signatures_checked": len(handoff["old_set_signatures"]) + len(handoff["new_set_signatures"]),
    }


def trusted_state_from_direct_ordinary_proof(
    trust: dict[str, Any], proof: dict[str, Any],
) -> dict[str, Any]:
    """Derive the first continuation state from an already verified proof."""
    chain = proof["certified_chain"]
    target_index = len(chain) - trust["consensus_parameters"]["finality_chain_length"]
    require(target_index >= 0, "ordinary_advance_source_target_index")
    target = chain[target_index]
    require(target["header"]["block_kind"] == "Ordinary", "ordinary_advance_source_target_kind")
    head = chain[-1]
    state = {
        "schema_version": 1,
        "context": copy.deepcopy(trust["context"]),
        "epoch": trust["epoch_descriptor"]["body"]["epoch"],
        "epoch_start_height": trust["trusted_genesis_header"]["height"],
        "finalized_height": target["header"]["height"],
        "finalized_header": copy.deepcopy(target["header"]),
        "finalized_block_id": target["block_id"],
        "certified_head_header": copy.deepcopy(head["header"]),
        "certified_head_block_id": head["block_id"],
        "certified_head_qc_id": head["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(trust["epoch_descriptor"]),
        "validator_set": copy.deepcopy(trust["validator_set"]),
        "consensus_parameters": copy.deepcopy(trust["consensus_parameters"]),
        "latest_checkpoint_id": None,
        "latest_handoff_id": None,
        "state_id": b"\x00" * 32,
    }
    seal_trusted_order_state(state)
    validate_trusted_order_state(state)
    return state


def verify_ordinary_finality_advance(
    raw: bytes, *, expected_input_state_id: bytes,
    fresh_genesis_derived_state_hash: bytes | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify one bounded same-epoch Ordinary three-chain continuation.

    The first block must be the immediate child/view successor of the trusted
    certified head because TrustedOrderStateV1 intentionally stores only the
    head QC id, not a forgeable full QC wrapper.  One later edge may skip one
    view if and only if it carries a fully verified TC.  The TC's finalized
    anchor is selected from the exact trusted state: its latest checkpoint
    when present, otherwise the fresh-genesis derived-state hash supplied by
    the independently verified source proof.
    """
    advance = decode_exact(
        raw, "ordinary_finality_advance", dec_ordinary_advance,
        enc_ordinary_advance,
    )
    require(advance["schema_version"] == 1, "ordinary_advance_schema")
    current = advance["input_state"]
    meta = validate_trusted_order_state(current)
    require(current["state_id"] == expected_input_state_id, "ordinary_advance_input_state")
    parameters = current["consensus_parameters"]
    require(len(raw) <= parameters["max_cev1_value_bytes"], "ordinary_advance_cev1_value_bound")
    chain = advance["certified_chain"]
    require(len(chain) == 3, "ordinary_advance_chain_cardinality")
    require(
        [item["header"]["block_kind"] for item in chain]
        == ["Ordinary", "Ordinary", "Ordinary"],
        "ordinary_advance_chain_kinds",
    )
    require(len(chain) <= parameters["max_retained_views"], "ordinary_advance_retained_view_bound")
    context = current["context"]
    epoch = current["epoch"]
    descriptor_id = meta["descriptor_id"]
    descriptor_body = current["epoch_descriptor"]["body"]
    validator_set_hash = meta["validator_set_hash"]
    parameters_hash = meta["parameters_hash"]
    members = meta["members"]
    threshold = current["validator_set"]["definition"]["quorum_threshold"]
    block_ids: list[bytes] = []
    qc_ids: list[bytes] = []
    for item in chain:
        header = item["header"]
        validate_header_bounds(header, parameters)
        require(header["context"] == context, "ordinary_advance_header_context")
        require(header["epoch"] == epoch, "ordinary_advance_header_epoch")
        require(header["epoch_descriptor_id"] == descriptor_id, "ordinary_advance_header_descriptor")
        require(header["proposer_id"] in members, "ordinary_advance_header_proposer")
        require(
            header["next_epoch_descriptor_id"] is None
            and header["upgrade_plan_id"] is None
            and header["epoch_handoff_id"] is None,
            "ordinary_advance_header_sidecars",
        )
        block_id, qc_id = verify_qc(
            item, context=context, epoch=epoch, epoch_descriptor_id=descriptor_id,
            runtime_profile_hash=descriptor_body["runtime_profile_hash"],
            validator_set_hash=validator_set_hash, parameters_hash=parameters_hash,
            parameters=parameters, members=members, threshold=threshold,
        )
        block_ids.append(block_id)
        qc_ids.append(qc_id)

    first = chain[0]["header"]
    head = current["certified_head_header"]
    require(
        first["parent"] == {
            "variant": "V1Block",
            "value": {"block_id": current["certified_head_block_id"]},
        },
        "ordinary_advance_first_parent",
    )
    require(head["height"] < U64_MAX and first["height"] == head["height"] + 1, "ordinary_advance_first_height")
    require(head["view"] < U64_MAX and first["view"] == head["view"] + 1, "ordinary_advance_first_view")
    require(first["justify_qc_id"] == current["certified_head_qc_id"], "ordinary_advance_first_justify")
    require(
        chain[0]["timeout_certificate"] is None
        and first["timeout_certificate_id"] is None,
        "ordinary_advance_first_tc_absent",
    )

    tc_ids: list[bytes] = []
    for index in range(1, 3):
        previous = chain[index - 1]
        item = chain[index]
        previous_header = previous["header"]
        header = item["header"]
        require(
            header["parent"] == {
                "variant": "V1Block", "value": {"block_id": block_ids[index - 1]},
            },
            "ordinary_advance_chain_parent",
        )
        require(
            previous_header["height"] < U64_MAX
            and header["height"] == previous_header["height"] + 1,
            "ordinary_advance_chain_height",
        )
        require(header["justify_qc_id"] == qc_ids[index - 1], "ordinary_advance_chain_justify")
        require(previous_header["view"] < U64_MAX, "ordinary_advance_chain_view_overflow")
        tc = item["timeout_certificate"]
        if header["view"] == previous_header["view"] + 1:
            require(
                tc is None and header["timeout_certificate_id"] is None,
                "ordinary_advance_unexpected_tc",
            )
        else:
            require(
                header["view"] == previous_header["view"] + 2,
                "ordinary_advance_single_skipped_view",
            )
            require(tc is not None and header["timeout_certificate_id"] is not None, "ordinary_advance_missing_tc")
            if current["latest_checkpoint_id"] is None:
                require(
                    fresh_genesis_derived_state_hash is not None,
                    "ordinary_advance_fresh_genesis_anchor_required",
                )
                tc_id = verify_tc(
                    tc, previous_qc=previous["certifying_qc"],
                    previous_qc_id=qc_ids[index - 1],
                    previous_view=previous_header["view"], target_view=header["view"],
                    context=context, epoch=epoch,
                    runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                    validator_set_hash=validator_set_hash,
                    parameters_hash=parameters_hash,
                    genesis_derived_state_hash=fresh_genesis_derived_state_hash,
                    parameters=parameters, members=members, threshold=threshold,
                )
            else:
                tc_id = verify_checkpoint_anchored_ordinary_tc(
                    tc, previous_qc=previous["certifying_qc"],
                    previous_qc_id=qc_ids[index - 1],
                    previous_view=previous_header["view"], target_view=header["view"],
                    context=context, epoch=epoch,
                    runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                    validator_set_hash=validator_set_hash,
                    parameters_hash=parameters_hash,
                    latest_checkpoint_id=current["latest_checkpoint_id"],
                    parameters=parameters, members=members, threshold=threshold,
                )
            require(header["timeout_certificate_id"] == tc_id, "ordinary_advance_header_tc_id")
            tc_ids.append(tc_id)
    require(len(tc_ids) <= 1, "ordinary_advance_tc_count")
    require(
        chain[0]["header"]["view"] < chain[1]["header"]["view"] < chain[2]["header"]["view"],
        "ordinary_advance_finality_view_order",
    )

    target = chain[0]
    certified_head = chain[-1]
    expected_output = {
        "schema_version": 1,
        "context": copy.deepcopy(context),
        "epoch": epoch,
        "epoch_start_height": current["epoch_start_height"],
        "finalized_height": target["header"]["height"],
        "finalized_header": copy.deepcopy(target["header"]),
        "finalized_block_id": target["block_id"],
        "certified_head_header": copy.deepcopy(certified_head["header"]),
        "certified_head_block_id": certified_head["block_id"],
        "certified_head_qc_id": certified_head["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(current["epoch_descriptor"]),
        "validator_set": copy.deepcopy(current["validator_set"]),
        "consensus_parameters": copy.deepcopy(parameters),
        "latest_checkpoint_id": current["latest_checkpoint_id"],
        "latest_handoff_id": current["latest_handoff_id"],
        "state_id": b"\x00" * 32,
    }
    seal_trusted_order_state(expected_output)
    require(
        advance["output_state"]["finalized_height"] > current["finalized_height"],
        "ordinary_advance_output_height",
    )
    require(advance["output_state"] == expected_output, "ordinary_advance_output_state")
    validate_trusted_order_state(expected_output)
    advance_id = digest(
        ORDINARY_FINALITY_ADVANCE_DOMAIN, enc_ordinary_advance_body(advance),
    )
    require(advance["advance_id"] == advance_id, "ordinary_advance_id")
    return expected_output, {
        "advance_id": advance_id,
        "input_state_id": current["state_id"],
        "output_state_id": expected_output["state_id"],
        "epoch": epoch,
        "old_finalized_height": current["finalized_height"],
        "new_finalized_height": expected_output["finalized_height"],
        "certified_head_height": expected_output["certified_head_header"]["height"],
        "qc_ids": qc_ids,
        "tc_ids": tc_ids,
        "qc_signatures_checked": sum(
            len(item["certifying_qc"]["body"]["signatures"]) for item in chain
        ),
        "tc_signatures_checked": sum(
            len(item["timeout_certificate"]["body"]["entries"])
            for item in chain if item["timeout_certificate"] is not None
        ),
        "raw_sha256": hashlib.sha256(raw).digest(),
    }


def verify_order_trust_path(raw: bytes) -> dict[str, Any]:
    path = decode_exact(raw, "order_trust_path", dec_trust_path, enc_trust_path)
    require(path["schema_version"] == 1, "trust_path_schema")
    initial = path["initial_state"]
    validate_trusted_order_state(initial)
    parameters = initial["consensus_parameters"]
    require(len(raw) <= parameters["max_cev1_value_bytes"], "trust_path_cev1_value_bound")
    require(len(path["steps"]) <= MAX_TRUST_PATH_STEPS, "trust_path_steps_bound")
    require(initial["epoch"] == 0 and initial["epoch_start_height"] == 1, "trust_path_initial_epoch")
    require(
        initial["finalized_height"] == initial["certified_head_header"]["height"]
        and initial["finalized_header"] == initial["certified_head_header"]
        and initial["finalized_block_id"] == initial["certified_head_block_id"],
        "trust_path_initial_head",
    )
    require(initial["latest_checkpoint_id"] is None and initial["latest_handoff_id"] is None, "trust_path_initial_sidecars")
    genesis = initial["finalized_header"]
    require(genesis["parent"]["variant"] == "GenesisAnchor", "trust_path_initial_genesis_parent")
    validate_fresh_genesis(genesis, genesis["parent"]["value"]["genesis_derived_state_hash"])
    current = copy.deepcopy(initial)
    step_results: list[dict[str, Any]] = []
    for index, carrier in enumerate(path["steps"]):
        if index == 0:
            require(carrier["variant"] == "ExistingFreshGenesisTransition", "trust_path_step0_variant")
            output, result = verify_existing_fresh_genesis_path_step(carrier["raw_step_cev1"], current)
            transition = decode_exact(
                carrier["raw_step_cev1"], "trust_path_transition_metrics",
                dec_epoch_transition, enc_epoch_transition,
            )
            result = dict(result)
            result["step_id"] = hashlib.sha256(carrier["raw_step_cev1"]).digest()
            result["input_state_id"] = current["state_id"]
            result["output_state_id"] = output["state_id"]
            result["qc_signatures_checked"] = sum(
                len(item["certifying_qc"]["body"]["signatures"])
                for item in transition["checkpoint_finality_proof"]["certified_chain"]
                + transition["new_epoch_certified_chain"]
            )
            result["handoff_signatures_checked"] = (
                len(transition["handoff"]["old_set_signatures"])
                + len(transition["handoff"]["new_set_signatures"])
            )
            result["tc_signatures_checked"] = 0
        else:
            require(carrier["variant"] == "CheckpointAnchoredTransition", "trust_path_step_order")
            output, result = verify_checkpoint_anchored_transition_step(carrier["raw_step_cev1"], current)
        require(output["epoch"] == current["epoch"] + 1, "trust_path_epoch_monotonicity")
        require(output["finalized_height"] > current["finalized_height"], "trust_path_height_monotonicity")
        step_results.append(result)
        current = output
    path_id = digest(ORDER_TRUST_PATH_DOMAIN, enc_trust_path_body(path))
    require(path["path_id"] == path_id, "trust_path_id")
    return {
        "path_id": path_id, "hop_count": len(path["steps"]),
        "initial_state_id": initial["state_id"], "terminal_state_id": current["state_id"],
        "initial_epoch": initial["epoch"], "terminal_epoch": current["epoch"],
        "initial_finalized_height": initial["finalized_height"],
        "terminal_finalized_height": current["finalized_height"],
        "step_ids": [result["step_id"] for result in step_results],
        "qc_signatures_checked": sum(result["qc_signatures_checked"] for result in step_results),
        "tc_signatures_checked": sum(result["tc_signatures_checked"] for result in step_results),
        "handoff_signatures_checked": sum(result["handoff_signatures_checked"] for result in step_results),
        "raw_sha256": hashlib.sha256(raw).digest(),
    }


def seal_weak_subjectivity_anchor(anchor: dict[str, Any]) -> dict[str, Any]:
    anchor["anchor_id"] = digest(
        WEAK_SUBJECTIVITY_ANCHOR_DOMAIN,
        enc_weak_subjectivity_anchor_body(anchor),
    )
    return anchor


def validate_weak_subjectivity_anchor(anchor: dict[str, Any], *, prefix: str) -> bytes:
    require(anchor["schema_version"] == 1, f"{prefix}_schema")
    validate_context(anchor["context"])
    anchor_id = digest(
        WEAK_SUBJECTIVITY_ANCHOR_DOMAIN,
        enc_weak_subjectivity_anchor_body(anchor),
    )
    require(anchor["anchor_id"] == anchor_id, f"{prefix}_id")
    return anchor_id


def seal_weak_subjectivity_policy(policy: dict[str, Any]) -> dict[str, Any]:
    policy["policy_id"] = digest(
        WEAK_SUBJECTIVITY_POLICY_DOMAIN,
        enc_weak_subjectivity_policy_body(policy),
    )
    return policy


def weak_subjectivity_anchor_from_checkpoint(
    checkpoint: dict[str, Any],
) -> dict[str, Any]:
    """Derive the complete renewal anchor from one verified checkpoint.

    The helper intentionally copies no trusted-state summary.  Every field is
    committed by EpochCheckpointV1 itself, so a caller cannot substitute the
    current epoch's validator set, parameters or roots for the authority that
    actually certified the checkpoint.
    """
    body = checkpoint["body"]
    return seal_weak_subjectivity_anchor({
        "schema_version": 1,
        "context": copy.deepcopy(body["context"]),
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_epoch": body["epoch"],
        "checkpoint_height": body["checkpoint_height"],
        "checkpoint_block_id": body["checkpoint_block_id"],
        "validator_set_hash": body["validator_set_hash"],
        "consensus_parameters_hash": body["consensus_parameters_hash"],
        "application_state_root": body["application_state_root"],
        "state_schema_hash": body["state_schema_hash"],
        "anchor_id": b"\x00" * 32,
    })


def seal_weak_subjectivity_renewal(
    renewal: dict[str, Any],
) -> dict[str, Any]:
    renewal["renewal_id"] = digest(
        WEAK_SUBJECTIVITY_RENEWAL_DOMAIN,
        enc_weak_subjectivity_renewal_body(renewal),
    )
    return renewal


def verify_weak_subjectivity_checkpoint_renewal(
    trust_path_raw: bytes, renewal_raw: bytes,
) -> dict[str, Any]:
    """Verify one bounded checkpoint-anchor renewal over an exact TrustPath.

    This is deterministic checkpoint admissibility, not operator/key
    authentication.  The prior and renewed anchors must be derived from the
    first and last checkpoint objects already authenticated by the same raw
    three-hop TrustPath.  The terminal trusted state is used only as the
    observed finalized head for the age window.
    """
    path_result = verify_order_trust_path(trust_path_raw)
    path = decode_exact(
        trust_path_raw, "weak_subjectivity_path", dec_trust_path, enc_trust_path,
    )
    require(len(path["steps"]) == 3, "weak_subjectivity_path_hops")
    renewal = decode_exact(
        renewal_raw, "weak_subjectivity_renewal", dec_weak_subjectivity_renewal,
        enc_weak_subjectivity_renewal,
    )
    require(renewal["schema_version"] == 1, "weak_subjectivity_renewal_schema")
    prior = renewal["prior_anchor"]
    renewed = renewal["renewed_anchor"]
    validate_weak_subjectivity_anchor(prior, prefix="weak_subjectivity_prior_anchor")
    validate_weak_subjectivity_anchor(renewed, prefix="weak_subjectivity_renewed_anchor")

    policy = renewal["policy"]
    require(policy["schema_version"] == 1, "weak_subjectivity_policy_schema")
    policy_id = digest(
        WEAK_SUBJECTIVITY_POLICY_DOMAIN, enc_weak_subjectivity_policy_body(policy),
    )
    require(policy["policy_id"] == policy_id, "weak_subjectivity_policy_id")
    require(
        policy["max_checkpoint_age_epochs"] > 0
        and policy["max_checkpoint_age_blocks"] > 0
        and policy["min_finalized_height_advance"] > 0,
        "weak_subjectivity_policy_positive",
    )

    # A renewal cannot silently replace chain identity.  Stack profiles may
    # evolve at epoch handoff, but chain/genesis/protocol lineage is invariant.
    require(
        prior["context"]["chain_id"] == renewed["context"]["chain_id"]
        and prior["context"]["genesis_hash"] == renewed["context"]["genesis_hash"]
        and prior["context"]["protocol_version"]
        == renewed["context"]["protocol_version"] == 1,
        "weak_subjectivity_context_lineage",
    )
    require(
        renewed["checkpoint_epoch"] > prior["checkpoint_epoch"],
        "weak_subjectivity_epoch_monotonicity",
    )

    # Reject the safety-significant same-height conflict before the generic
    # strictly-monotonic check so the evidence corpus proves the exact rule.
    if renewed["checkpoint_height"] == prior["checkpoint_height"]:
        require(
            renewed["checkpoint_id"] == prior["checkpoint_id"]
            and renewed["checkpoint_block_id"] == prior["checkpoint_block_id"],
            "weak_subjectivity_same_height_conflict",
        )
        reject("weak_subjectivity_height_monotonicity")
    require(
        renewed["checkpoint_height"] > prior["checkpoint_height"],
        "weak_subjectivity_height_monotonicity",
    )
    require(
        renewed["checkpoint_height"] - prior["checkpoint_height"]
        >= policy["min_finalized_height_advance"],
        "weak_subjectivity_minimum_advance",
    )

    first_carrier = path["steps"][0]
    require(
        first_carrier["variant"] == "ExistingFreshGenesisTransition",
        "weak_subjectivity_first_step_variant",
    )
    first_transition = decode_exact(
        first_carrier["raw_step_cev1"], "weak_subjectivity_first_transition",
        dec_epoch_transition, enc_epoch_transition,
    )
    prior_checkpoint = first_transition["checkpoint"]
    expected_prior = weak_subjectivity_anchor_from_checkpoint(prior_checkpoint)
    require(prior["context"] == expected_prior["context"], "weak_subjectivity_prior_context")
    require(
        prior["checkpoint_id"] == expected_prior["checkpoint_id"]
        and prior["checkpoint_epoch"] == expected_prior["checkpoint_epoch"]
        and prior["checkpoint_height"] == expected_prior["checkpoint_height"]
        and prior["checkpoint_block_id"] == expected_prior["checkpoint_block_id"],
        "weak_subjectivity_prior_checkpoint",
    )
    require(
        prior["validator_set_hash"] == expected_prior["validator_set_hash"]
        and prior["consensus_parameters_hash"]
        == expected_prior["consensus_parameters_hash"],
        "weak_subjectivity_prior_authority",
    )
    require(
        prior["application_state_root"] == expected_prior["application_state_root"]
        and prior["state_schema_hash"] == expected_prior["state_schema_hash"],
        "weak_subjectivity_prior_roots",
    )

    last_carrier = path["steps"][-1]
    require(
        last_carrier["variant"] == "CheckpointAnchoredTransition",
        "weak_subjectivity_last_step_variant",
    )
    last_step = decode_exact(
        last_carrier["raw_step_cev1"], "weak_subjectivity_last_transition",
        dec_checkpoint_transition_step, enc_checkpoint_transition_step,
    )
    terminal = renewal["terminal_trusted_state"]
    require(
        terminal == last_step["output_state"]
        and terminal["state_id"] == path_result["terminal_state_id"],
        "weak_subjectivity_terminal_state",
    )
    validate_trusted_order_state(terminal)
    checkpoint = renewal["terminal_checkpoint"]
    require(
        checkpoint == last_step["checkpoint"],
        "weak_subjectivity_terminal_checkpoint",
    )
    checkpoint_body = checkpoint["body"]
    checkpoint_id = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
    require(checkpoint["checkpoint_id"] == checkpoint_id, "weak_subjectivity_checkpoint_id")
    require(
        terminal["latest_checkpoint_id"] == checkpoint_id,
        "weak_subjectivity_checkpoint_latest",
    )
    expected_renewed = weak_subjectivity_anchor_from_checkpoint(checkpoint)
    require(
        renewed["context"] == expected_renewed["context"],
        "weak_subjectivity_renewed_context",
    )
    require(
        renewed["checkpoint_id"] == expected_renewed["checkpoint_id"]
        and renewed["checkpoint_epoch"] == expected_renewed["checkpoint_epoch"]
        and renewed["checkpoint_height"] == expected_renewed["checkpoint_height"]
        and renewed["checkpoint_block_id"] == expected_renewed["checkpoint_block_id"],
        "weak_subjectivity_renewed_checkpoint",
    )
    require(
        renewed["validator_set_hash"] == expected_renewed["validator_set_hash"]
        and renewed["consensus_parameters_hash"]
        == expected_renewed["consensus_parameters_hash"],
        "weak_subjectivity_renewed_authority",
    )
    require(
        renewed["application_state_root"] == expected_renewed["application_state_root"]
        and renewed["state_schema_hash"] == expected_renewed["state_schema_hash"],
        "weak_subjectivity_renewed_roots",
    )
    require(
        checkpoint_body["epoch"] < terminal["epoch"]
        and checkpoint_body["checkpoint_height"] <= terminal["finalized_height"],
        "weak_subjectivity_checkpoint_before_observed_head",
    )

    observed_epoch = renewal["observed_finalized_epoch"]
    observed_height = renewal["observed_finalized_height"]
    require(
        observed_epoch == terminal["epoch"]
        and observed_height == terminal["finalized_height"],
        "weak_subjectivity_observed_head",
    )
    require(observed_epoch >= prior["checkpoint_epoch"], "weak_subjectivity_observed_epoch")
    require(observed_height >= prior["checkpoint_height"], "weak_subjectivity_observed_height")
    require(
        observed_epoch - prior["checkpoint_epoch"]
        <= policy["max_checkpoint_age_epochs"],
        "weak_subjectivity_prior_age_epoch",
    )
    require(
        observed_height - prior["checkpoint_height"]
        <= policy["max_checkpoint_age_blocks"],
        "weak_subjectivity_prior_age_block",
    )
    require(
        observed_epoch >= renewed["checkpoint_epoch"]
        and observed_epoch - renewed["checkpoint_epoch"]
        <= policy["max_checkpoint_age_epochs"],
        "weak_subjectivity_renewed_age_epoch",
    )
    require(
        observed_height >= renewed["checkpoint_height"]
        and observed_height - renewed["checkpoint_height"]
        <= policy["max_checkpoint_age_blocks"],
        "weak_subjectivity_renewed_age_block",
    )
    renewal_id = digest(
        WEAK_SUBJECTIVITY_RENEWAL_DOMAIN,
        enc_weak_subjectivity_renewal_body(renewal),
    )
    require(renewal["renewal_id"] == renewal_id, "weak_subjectivity_renewal_id")
    return {
        "renewal_id": renewal_id, "prior_anchor_id": prior["anchor_id"],
        "renewed_anchor_id": renewed["anchor_id"],
        "prior_height": prior["checkpoint_height"],
        "renewed_height": renewed["checkpoint_height"],
        "observed_epoch": observed_epoch, "observed_height": observed_height,
        "policy_id": policy_id,
    }


def base_parameters() -> dict[str, Any]:
    values = {
        "schema_version": 1, "quorum_numerator": 2, "quorum_denominator": 3,
        "finality_chain_length": 3, "execute_coordination_before_vote": True,
        "max_validators": 100, "max_consensus_string_bytes": 128, "max_cev1_nesting": 64,
        "max_cev1_value_bytes": 16 * 1024 * 1024, "max_signature_bytes": 64, "max_certificate_signers": 100,
        "max_epoch": U64_MAX - 1, "max_view": U64_MAX - 1, "max_height": U64_MAX - 1,
        "max_retained_views": 4096, "epoch_length_blocks": 1000, "checkpoint_offset_blocks": 997,
        "seal_1_offset_blocks": 998, "seal_2_offset_blocks": 999, "max_block_ordered_bytes": 4 * 1024 * 1024,
        "max_batch_refs_per_block": 4096, "max_protocol_objects_per_block": 4096,
        "max_transactions_per_batch": 10000, "max_transaction_bytes": 1024 * 1024,
        "max_block_execution_units": 10**18, "base_view_timeout_ms": 500, "maximum_view_timeout_ms": 30000,
        "timeout_multiplier_numerator": 3, "timeout_multiplier_denominator": 2,
        "max_evidence_items_per_block": 1024, "max_evidence_bytes_per_block": 4 * 1024 * 1024,
    }
    require(set(values) == {name for name, _ in PARAMETER_FIELDS}, "base_parameter_inventory")
    return values


def make_header(*, context: dict[str, Any], epoch: int, view: int, height: int, kind: str, parent: dict[str, Any], proposer_id: bytes, descriptor_id: bytes, justify: bytes | None, label: str) -> dict[str, Any]:
    roots = {name: label_hash(f"{label}:{name}") for name in HEADER_ROOT_FIELDS}
    return {
        "schema_version": 1, "context": copy.deepcopy(context), "epoch": epoch, "view": view, "height": height,
        "block_kind": kind, "parent": copy.deepcopy(parent), "proposer_id": proposer_id,
        "epoch_descriptor_id": descriptor_id, "justify_qc_id": justify, "timeout_certificate_id": None,
        **roots, "next_epoch_descriptor_id": None, "upgrade_plan_id": None, "epoch_handoff_id": None,
    }


def make_qc(header: dict[str, Any], block_id: bytes, *, runtime_profile_hash: bytes, validator_set_hash: bytes, parameters_hash: bytes, validators: list[dict[str, Any]], seed_indices: list[int] | None = None) -> dict[str, Any]:
    vote = {
        "schema_version": 1,
        "consensus_context": {
            "schema_version": 1, "context": copy.deepcopy(header["context"]), "runtime_profile_hash": runtime_profile_hash,
            "epoch": header["epoch"], "validator_set_hash": validator_set_hash,
            "consensus_parameters_hash": parameters_hash, "view": header["view"], "message_kind": 1,
        },
        "block_id": block_id, "height": header["height"], "epoch_descriptor_id": header["epoch_descriptor_id"],
        "post_state_root": header["post_state_root"], "batch_refs_root": header["batch_refs_root"],
        "transaction_execution_receipts_root": header["transaction_execution_receipts_root"],
    }
    root = digest(VOTE_DOMAIN, enc_vote(vote))
    indices = list(range(len(validators))) if seed_indices is None else seed_indices
    signatures = [{"voter_id": validators[index]["validator_id"], "signature_scheme": 0, "signature": ed25519_sign(fixture_seed(index), root)} for index in indices]
    body = {"schema_version": 1, "statement": vote, "signatures": signatures}
    return {"body": body, "quorum_certificate_id": digest(QC_DOMAIN, enc_qc_body(body))}


def make_tc(
    *, context: dict[str, Any], epoch: int, timed_out_view: int,
    runtime_profile_hash: bytes, validator_set_hash: bytes, parameters_hash: bytes,
    previous_qc: dict[str, Any], previous_view: int, genesis_derived_state_hash: bytes,
    validators: list[dict[str, Any]], seed_indices: list[int] | None = None,
) -> dict[str, Any]:
    previous_qc_id = previous_qc["quorum_certificate_id"]
    indices = list(range(len(validators))) if seed_indices is None else seed_indices
    entries = []
    for index in indices:
        statement = {
            "schema_version": 1,
            "consensus_context": {
                "schema_version": 1, "context": copy.deepcopy(context),
                "runtime_profile_hash": runtime_profile_hash, "epoch": epoch,
                "validator_set_hash": validator_set_hash,
                "consensus_parameters_hash": parameters_hash,
                "view": timed_out_view, "message_kind": 2,
            },
            "high_justification": {
                "variant": "QC", "value": {"qc_id": previous_qc_id, "qc_view": previous_view},
            },
            "locked_qc_id": previous_qc_id, "locked_qc_view": previous_view,
            "last_finalized_anchor": {
                "variant": "FreshGenesis",
                "value": {"genesis_derived_state_hash": genesis_derived_state_hash},
            },
            "pacemaker_generation": index + 1,
        }
        root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(statement))
        entries.append({
            "validator_id": validators[index]["validator_id"], "statement": statement,
            "signature_scheme": 0, "signature": ed25519_sign(fixture_seed(index), root),
        })
    body = {
        "schema_version": 1, "context": copy.deepcopy(context),
        "runtime_profile_hash": runtime_profile_hash, "epoch": epoch,
        "validator_set_hash": validator_set_hash,
        "consensus_parameters_hash": parameters_hash,
        "timed_out_view": timed_out_view, "target_view": timed_out_view + 1,
        "justifications": [{"variant": "QC", "value": copy.deepcopy(previous_qc)}],
        "entries": entries,
    }
    return {"body": body, "timeout_certificate_id": digest(TC_DOMAIN, enc_tc_body(body))}


def make_epoch_start_tc(
    *, context: dict[str, Any], epoch: int, runtime_profile_hash: bytes,
    validator_set_hash: bytes, parameters_hash: bytes,
    handoff: dict[str, Any], checkpoint_id: bytes,
    validators: list[dict[str, Any]], seed_indices: list[int] | None = None,
) -> dict[str, Any]:
    initial_view = handoff["body"]["initial_new_view"]
    require(initial_view > 0 and initial_view < U64_MAX, "epoch_start_tc_fixture_initial_view")
    high = {
        "variant": "EpochStart",
        "value": {
            "anchor_kind": 2, "anchor_id": handoff["handoff_id"],
            "anchor_view": initial_view - 1,
        },
    }
    finalized = {
        "variant": "EpochCheckpoint", "value": {"checkpoint_id": checkpoint_id},
    }
    indices = list(range(len(validators))) if seed_indices is None else seed_indices
    entries = []
    for index in indices:
        statement = {
            "schema_version": 1,
            "consensus_context": {
                "schema_version": 1, "context": copy.deepcopy(context),
                "runtime_profile_hash": runtime_profile_hash, "epoch": epoch,
                "validator_set_hash": validator_set_hash,
                "consensus_parameters_hash": parameters_hash,
                "view": initial_view, "message_kind": 2,
            },
            "high_justification": copy.deepcopy(high),
            "locked_qc_id": None, "locked_qc_view": 0,
            "last_finalized_anchor": copy.deepcopy(finalized),
            "pacemaker_generation": index + 1,
        }
        root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(statement))
        entries.append({
            "validator_id": validators[index]["validator_id"], "statement": statement,
            "signature_scheme": STRICT_ED25519,
            "signature": ed25519_sign(fixture_seed(index), root),
        })
    body = {
        "schema_version": 1, "context": copy.deepcopy(context),
        "runtime_profile_hash": runtime_profile_hash, "epoch": epoch,
        "validator_set_hash": validator_set_hash,
        "consensus_parameters_hash": parameters_hash,
        "timed_out_view": initial_view, "target_view": initial_view + 1,
        "justifications": [{
            "variant": "EpochStart",
            "value": {"variant": "EpochHandoff", "value": copy.deepcopy(handoff)},
        }],
        "entries": entries,
    }
    return {"body": body, "timeout_certificate_id": digest(TC_DOMAIN, enc_tc_body(body))}


def build_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    context = {"schema_version": 1, "genesis_hash": bytes.fromhex("11" * 32), "chain_id": "trnm-ai-light-client-1", "protocol_version": 1, "stack_profile_hash": bytes.fromhex("22" * 32)}
    validators = []
    for index, suffix in enumerate((b"a", b"b", b"c", b"d")):
        validators.append({
            "validator_id": b"validator-" + suffix, "consensus_key_scheme": 0,
            "consensus_public_key": ed25519_public_key(fixture_seed(index)), "voting_weight": 1,
            "network_identity_commitment": label_hash(f"validator-{index}:network"),
            "safety_signer_policy_hash": label_hash(f"validator-{index}:safety"),
            "poco_economic_record_hash": label_hash(f"validator-{index}:economic"),
        })
    definition = {"schema_version": 1, "members": validators, "total_weight": 4, "quorum_threshold": 3}
    definition_hash = digest(VALIDATOR_SET_DEFINITION_DOMAIN, enc_validator_definition(definition))
    validator_set = {"schema_version": 1, "context": copy.deepcopy(context), "epoch": 0, "definition": definition}
    validator_set_hash = digest(VALIDATOR_SET_DOMAIN, enc_validator_set(validator_set))
    parameters = base_parameters()
    parameters_hash = digest(CONSENSUS_PARAMETERS_DOMAIN, enc_parameters(parameters))
    epoch_body = {
        "schema_version": 1, "context": copy.deepcopy(context), "epoch": 0,
        "validator_set_hash": validator_set_hash, "consensus_parameters_hash": parameters_hash,
        "runtime_profile_hash": label_hash("runtime-profile"), "snapshot_policy_hash": label_hash("snapshot-policy"),
        "da_policy_hash": label_hash("da-policy"), "da_committee_set_root": label_hash("da-committee-set"),
        "verification_registry_hash": label_hash("verification-registry"), "fee_schedule_hash": label_hash("fee-schedule"),
        "state_schema_hash": label_hash("state-schema"), "leader_schedule_id": label_hash("leader-schedule"),
        "upgrade_authority_root": label_hash("upgrade-disabled"),
    }
    descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(epoch_body))
    descriptor = {"body": epoch_body, "epoch_descriptor_id": descriptor_id}
    derived = label_hash("fresh-genesis-derived-state")
    application_root = label_hash("fresh-genesis-application-root")
    genesis = make_header(context=context, epoch=0, view=1, height=1, kind="FreshGenesis", parent={"variant": "GenesisAnchor", "value": {"genesis_derived_state_hash": derived, "application_state_root": application_root}}, proposer_id=validators[0]["validator_id"], descriptor_id=descriptor_id, justify=None, label="genesis")
    genesis["post_state_root"] = application_root
    for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
        genesis[field] = empty_ordered_root(root_kind)
    genesis_id = digest(BLOCK_DOMAIN, enc_header(genesis))
    genesis_qc = make_qc(genesis, genesis_id, runtime_profile_hash=epoch_body["runtime_profile_hash"], validator_set_hash=validator_set_hash, parameters_hash=parameters_hash, validators=validators)
    certified: list[dict[str, Any]] = [{
        "header": copy.deepcopy(genesis), "block_id": genesis_id,
        "certifying_qc": genesis_qc, "timeout_certificate": None,
    }]
    parent_id = genesis_id
    prior_qc = genesis_qc["quorum_certificate_id"]
    for index in range(2):
        header = make_header(context=context, epoch=0, view=index + 2, height=index + 2, kind="Ordinary", parent={"variant": "V1Block", "value": {"block_id": parent_id}}, proposer_id=validators[(index + 1) % 4]["validator_id"], descriptor_id=descriptor_id, justify=prior_qc, label=f"block-{index}")
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(header, block_id, runtime_profile_hash=epoch_body["runtime_profile_hash"], validator_set_hash=validator_set_hash, parameters_hash=parameters_hash, validators=validators)
        certified.append({"header": header, "block_id": block_id, "certifying_qc": qc, "timeout_certificate": None})
        parent_id, prior_qc = block_id, qc["quorum_certificate_id"]
    proof = {
        "schema_version": 1, "context": copy.deepcopy(context),
        "trusted_anchor": {"variant": "FreshGenesis", "value": {"genesis_derived_state_hash": derived, "trusted_genesis_header": copy.deepcopy(genesis)}},
        "target_block_id": certified[0]["block_id"], "target_height": certified[0]["header"]["height"],
        "target_header": copy.deepcopy(certified[0]["header"]), "certified_chain": certified, "epoch_handoffs": [],
    }
    trust = {"schema_version": 1, "context": context, "genesis_derived_state_hash": derived, "genesis_validator_set_definition_hash": definition_hash, "trusted_genesis_header": genesis, "epoch_descriptor": descriptor, "validator_set": validator_set, "consensus_parameters": parameters}
    return trust, proof


def build_ordinary_tc_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    trust, proof = build_fixture()
    chain = proof["certified_chain"]
    body = trust["epoch_descriptor"]["body"]
    validators = trust["validator_set"]["definition"]["members"]

    skipped = chain[2]
    skipped["header"]["view"] = 4
    tc = make_tc(
        context=trust["context"], epoch=0, timed_out_view=3,
        runtime_profile_hash=body["runtime_profile_hash"],
        validator_set_hash=body["validator_set_hash"],
        parameters_hash=body["consensus_parameters_hash"],
        previous_qc=chain[1]["certifying_qc"], previous_view=chain[1]["header"]["view"],
        genesis_derived_state_hash=trust["genesis_derived_state_hash"], validators=validators,
    )
    skipped["timeout_certificate"] = tc
    skipped["header"]["timeout_certificate_id"] = tc["timeout_certificate_id"]
    resign_item(proof, 2, trust)

    last_header = make_header(
        context=trust["context"], epoch=0, view=5, height=4, kind="Ordinary",
        parent={"variant": "V1Block", "value": {"block_id": skipped["block_id"]}},
        proposer_id=validators[3]["validator_id"],
        descriptor_id=trust["epoch_descriptor"]["epoch_descriptor_id"],
        justify=skipped["certifying_qc"]["quorum_certificate_id"], label="ordinary-finality-b2",
    )
    last_id = digest(BLOCK_DOMAIN, enc_header(last_header))
    last_qc = make_qc(
        last_header, last_id, runtime_profile_hash=body["runtime_profile_hash"],
        validator_set_hash=body["validator_set_hash"], parameters_hash=body["consensus_parameters_hash"],
        validators=validators,
    )
    chain.append({
        "header": last_header, "block_id": last_id,
        "certifying_qc": last_qc, "timeout_certificate": None,
    })
    proof["target_block_id"] = chain[1]["block_id"]
    proof["target_height"] = chain[1]["header"]["height"]
    proof["target_header"] = copy.deepcopy(chain[1]["header"])
    return trust, proof


def build_direct_ordinary_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the smallest direct-view proof whose finalized target is Ordinary.

    The certified prefix itself is the ancestry witness: every header is
    independently certified, every parent names the exact prior block ID, and
    the target is selected by the committed three-chain finality rule.  No
    caller-supplied height/block map participates in this construction.
    """
    trust, proof = build_fixture()
    chain = proof["certified_chain"]
    body = trust["epoch_descriptor"]["body"]
    validators = trust["validator_set"]["definition"]["members"]
    previous = chain[-1]
    last_header = make_header(
        context=trust["context"], epoch=0,
        view=previous["header"]["view"] + 1,
        height=previous["header"]["height"] + 1,
        kind="Ordinary",
        parent={"variant": "V1Block", "value": {"block_id": previous["block_id"]}},
        proposer_id=validators[3]["validator_id"],
        descriptor_id=trust["epoch_descriptor"]["epoch_descriptor_id"],
        justify=previous["certifying_qc"]["quorum_certificate_id"],
        label="direct-ordinary-finality-b2",
    )
    last_id = digest(BLOCK_DOMAIN, enc_header(last_header))
    last_qc = make_qc(
        last_header, last_id,
        runtime_profile_hash=body["runtime_profile_hash"],
        validator_set_hash=body["validator_set_hash"],
        parameters_hash=body["consensus_parameters_hash"],
        validators=validators,
    )
    chain.append({
        "header": last_header,
        "block_id": last_id,
        "certifying_qc": last_qc,
        "timeout_certificate": None,
    })
    target = chain[1]
    proof["target_block_id"] = target["block_id"]
    proof["target_height"] = target["header"]["height"]
    proof["target_header"] = copy.deepcopy(target["header"])
    return trust, proof


def build_ordinary_advance_fixture(
    current: dict[str, Any], *, fresh_genesis_derived_state_hash: bytes,
    skipped_view: bool,
) -> dict[str, Any]:
    meta = validate_trusted_order_state(current)
    context = current["context"]
    epoch = current["epoch"]
    descriptor = current["epoch_descriptor"]
    descriptor_body = descriptor["body"]
    validators = current["validator_set"]["definition"]["members"]
    parent_id = current["certified_head_block_id"]
    prior_qc_id = current["certified_head_qc_id"]
    previous_view = current["certified_head_header"]["view"]
    previous_height = current["certified_head_header"]["height"]
    chain: list[dict[str, Any]] = []
    for index in range(3):
        view = previous_view + 1
        if skipped_view and index == 1:
            view += 1
        header = make_header(
            context=context, epoch=epoch, view=view,
            height=previous_height + 1, kind="Ordinary",
            parent={"variant": "V1Block", "value": {"block_id": parent_id}},
            proposer_id=validators[(index + 1) % len(validators)]["validator_id"],
            descriptor_id=meta["descriptor_id"], justify=prior_qc_id,
            label=(
                f"ordinary-advance-epoch-{epoch}-from-{current['certified_head_header']['height']}"
                f"-{index}-{'tc' if skipped_view else 'direct'}"
            ),
        )
        timeout_certificate = None
        if skipped_view and index == 1:
            previous = chain[-1]
            timeout_certificate = make_tc(
                context=context, epoch=epoch, timed_out_view=previous_view + 1,
                runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                validator_set_hash=meta["validator_set_hash"],
                parameters_hash=meta["parameters_hash"],
                previous_qc=previous["certifying_qc"], previous_view=previous_view,
                genesis_derived_state_hash=fresh_genesis_derived_state_hash,
                validators=validators,
            )
            header["timeout_certificate_id"] = timeout_certificate["timeout_certificate_id"]
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header, block_id,
            runtime_profile_hash=descriptor_body["runtime_profile_hash"],
            validator_set_hash=meta["validator_set_hash"],
            parameters_hash=meta["parameters_hash"], validators=validators,
        )
        chain.append({
            "header": header, "block_id": block_id,
            "certifying_qc": qc, "timeout_certificate": timeout_certificate,
        })
        parent_id = block_id
        prior_qc_id = qc["quorum_certificate_id"]
        previous_view = view
        previous_height = header["height"]
    target = chain[0]
    head = chain[-1]
    output = {
        "schema_version": 1, "context": copy.deepcopy(context), "epoch": epoch,
        "epoch_start_height": current["epoch_start_height"],
        "finalized_height": target["header"]["height"],
        "finalized_header": copy.deepcopy(target["header"]),
        "finalized_block_id": target["block_id"],
        "certified_head_header": copy.deepcopy(head["header"]),
        "certified_head_block_id": head["block_id"],
        "certified_head_qc_id": head["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(current["epoch_descriptor"]),
        "validator_set": copy.deepcopy(current["validator_set"]),
        "consensus_parameters": copy.deepcopy(current["consensus_parameters"]),
        "latest_checkpoint_id": current["latest_checkpoint_id"],
        "latest_handoff_id": current["latest_handoff_id"],
        "state_id": b"\x00" * 32,
    }
    seal_trusted_order_state(output)
    advance = {
        "schema_version": 1, "input_state": copy.deepcopy(current),
        "certified_chain": chain, "output_state": output,
        "advance_id": b"\x00" * 32,
    }
    advance["advance_id"] = digest(
        ORDINARY_FINALITY_ADVANCE_DOMAIN, enc_ordinary_advance_body(advance),
    )
    return advance


def build_ordinary_advance_fixtures(
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    trust, proof = build_ordinary_tc_fixture()
    trust_raw, proof_raw = enc_trust(trust), enc_proof(proof)
    verify_light_client(trust_raw, proof_raw)
    initial = trusted_state_from_direct_ordinary_proof(trust, proof)
    first = build_ordinary_advance_fixture(
        initial, fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
        skipped_view=True,
    )
    state_1, result_1 = verify_ordinary_finality_advance(
        enc_ordinary_advance(first), expected_input_state_id=initial["state_id"],
        fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
    )
    second = build_ordinary_advance_fixture(
        state_1, fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
        skipped_view=False,
    )
    _, result_2 = verify_ordinary_finality_advance(
        enc_ordinary_advance(second), expected_input_state_id=state_1["state_id"],
        fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
    )
    return trust, proof, [first, second], [result_1, result_2]


def make_handoff_entries(
    *, role: int, context: dict[str, Any], runtime_profile_hash: bytes, epoch: int,
    validator_set_hash: bytes, parameters_hash: bytes, view: int, handoff_id: bytes,
    validators: list[dict[str, Any]], seed_indices: list[int] | None = None,
) -> list[dict[str, Any]]:
    require(role in (0, 1), "handoff_fixture_role")
    indices = list(range(len(validators))) if seed_indices is None else seed_indices
    statement = {
        "schema_version": 1,
        "consensus_context": {
            "schema_version": 1, "context": copy.deepcopy(context),
            "runtime_profile_hash": runtime_profile_hash, "epoch": epoch,
            "validator_set_hash": validator_set_hash,
            "consensus_parameters_hash": parameters_hash, "view": view,
            "message_kind": 3 if role == 0 else 4,
        },
        "handoff_id": handoff_id,
    }
    domain = EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN if role == 0 else EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN
    root = digest(domain, enc_handoff_statement(statement))
    return [{
        "signer_id": validators[index]["validator_id"], "role": role,
        "statement": copy.deepcopy(statement), "signature_scheme": 0,
        "signature": ed25519_sign(fixture_seed(index), root),
    } for index in indices]


def build_epoch_transition_fixture(*, iterable_successor: bool = False) -> dict[str, Any]:
    trust, _ = build_fixture()
    old_context = trust["context"]
    old_parameters = trust["consensus_parameters"]
    old_parameters.update({
        "epoch_length_blocks": 4, "checkpoint_offset_blocks": 1,
        "seal_1_offset_blocks": 2, "seal_2_offset_blocks": 3,
    })
    old_parameters_hash = digest(CONSENSUS_PARAMETERS_DOMAIN, enc_parameters(old_parameters))
    old_validators = trust["validator_set"]["definition"]["members"]
    old_validator_set_hash = digest(VALIDATOR_SET_DOMAIN, enc_validator_set(trust["validator_set"]))

    new_context = copy.deepcopy(old_context)
    new_context["stack_profile_hash"] = label_hash("epoch-1-stack-profile")
    new_definition = copy.deepcopy(trust["validator_set"]["definition"])
    new_definition["members"][0]["voting_weight"] = 2
    new_definition["total_weight"] = 5
    new_definition["quorum_threshold"] = 4
    new_validator_set = {"schema_version": 1, "context": new_context, "epoch": 1, "definition": new_definition}
    new_validator_set_hash = digest(VALIDATOR_SET_DOMAIN, enc_validator_set(new_validator_set))
    new_parameters = copy.deepcopy(old_parameters)
    if iterable_successor:
        # The legacy transition itself keeps the frozen four-block epoch-0
        # schedule.  Only its committed successor parameters are lengthened so
        # the certified head at height 8 has an immediately following
        # checkpoint at height 9.  This changes bytes, not the old anchor tag.
        new_parameters.update({
            "epoch_length_blocks": 7, "checkpoint_offset_blocks": 4,
            "seal_1_offset_blocks": 5, "seal_2_offset_blocks": 6,
        })
    new_parameters_hash = digest(CONSENSUS_PARAMETERS_DOMAIN, enc_parameters(new_parameters))
    old_epoch_body = trust["epoch_descriptor"]["body"]
    old_epoch_body["consensus_parameters_hash"] = old_parameters_hash
    old_epoch_body["validator_set_hash"] = old_validator_set_hash
    old_descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(old_epoch_body))
    trust["epoch_descriptor"]["epoch_descriptor_id"] = old_descriptor_id

    new_epoch_body = copy.deepcopy(old_epoch_body)
    new_epoch_body.update({
        "context": new_context, "epoch": 1, "validator_set_hash": new_validator_set_hash,
        "consensus_parameters_hash": new_parameters_hash,
        "runtime_profile_hash": label_hash("epoch-1-runtime-profile"),
        "leader_schedule_id": label_hash("epoch-1-leader-schedule"),
    })
    new_descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(new_epoch_body))
    new_descriptor = {"body": new_epoch_body, "epoch_descriptor_id": new_descriptor_id}

    genesis = trust["trusted_genesis_header"]
    genesis["epoch_descriptor_id"] = old_descriptor_id
    genesis_id = digest(BLOCK_DOMAIN, enc_header(genesis))
    genesis_qc = make_qc(
        genesis, genesis_id, runtime_profile_hash=old_epoch_body["runtime_profile_hash"],
        validator_set_hash=old_validator_set_hash, parameters_hash=old_parameters_hash,
        validators=old_validators,
    )
    old_chain = [{
        "header": copy.deepcopy(genesis), "block_id": genesis_id,
        "certifying_qc": genesis_qc, "timeout_certificate": None,
    }]
    parent_id, prior_qc = genesis_id, genesis_qc["quorum_certificate_id"]
    checkpoint_state_root = label_hash("epoch-0-checkpoint-state")
    for index, (kind, height) in enumerate((("EpochCheckpoint", 2), ("EpochSeal1", 3), ("EpochSeal2", 4)), start=1):
        header = make_header(
            context=old_context, epoch=0, view=height, height=height, kind=kind,
            parent={"variant": "V1Block", "value": {"block_id": parent_id}},
            proposer_id=old_validators[index % 4]["validator_id"], descriptor_id=old_descriptor_id,
            justify=prior_qc, label=f"epoch-0-{kind}",
        )
        header["post_state_root"] = checkpoint_state_root
        header["next_epoch_descriptor_id"] = new_descriptor_id
        for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
            header[field] = empty_ordered_root(root_kind)
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header, block_id, runtime_profile_hash=old_epoch_body["runtime_profile_hash"],
            validator_set_hash=old_validator_set_hash, parameters_hash=old_parameters_hash,
            validators=old_validators,
        )
        old_chain.append({"header": header, "block_id": block_id, "certifying_qc": qc, "timeout_certificate": None})
        parent_id, prior_qc = block_id, qc["quorum_certificate_id"]
    checkpoint_proof = {
        "schema_version": 1, "context": copy.deepcopy(old_context),
        "trusted_anchor": {
            "variant": "FreshGenesis", "value": {
                "genesis_derived_state_hash": trust["genesis_derived_state_hash"],
                "trusted_genesis_header": copy.deepcopy(genesis),
            },
        },
        "target_block_id": old_chain[1]["block_id"], "target_height": 2,
        "target_header": copy.deepcopy(old_chain[1]["header"]),
        "certified_chain": old_chain, "epoch_handoffs": [],
    }
    checkpoint_body = {
        "schema_version": 1, "context": copy.deepcopy(old_context), "epoch": 0,
        "checkpoint_height": 2, "checkpoint_block_id": old_chain[1]["block_id"],
        "checkpoint_header": copy.deepcopy(old_chain[1]["header"]),
        "epoch_descriptor_id": old_descriptor_id,
        "validator_set_hash": old_validator_set_hash,
        "consensus_parameters_hash": old_parameters_hash,
        "application_state_root": checkpoint_state_root,
        "da_committee_set_root": old_epoch_body["da_committee_set_root"],
        "verification_registry_hash": old_epoch_body["verification_registry_hash"],
        "stack_profile_hash": old_context["stack_profile_hash"],
        "fee_schedule_hash": old_epoch_body["fee_schedule_hash"],
        "state_schema_hash": old_epoch_body["state_schema_hash"],
        "snapshot_policy_hash": old_epoch_body["snapshot_policy_hash"],
        "next_epoch_descriptor_id": new_descriptor_id, "upgrade_plan_id": None,
    }
    checkpoint_id = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
    checkpoint = {"body": checkpoint_body, "checkpoint_id": checkpoint_id}
    checkpoint_attachment = {"checkpoint_id": checkpoint_id, "order_finality_proof": copy.deepcopy(checkpoint_proof)}

    terminal = old_chain[-1]
    handoff_body = {
        "schema_version": 1, "source_context": copy.deepcopy(old_context),
        "target_context": copy.deepcopy(new_context), "old_epoch": 0, "new_epoch": 1,
        "old_epoch_checkpoint_id": checkpoint_id, "old_epoch_descriptor_id": old_descriptor_id,
        "new_epoch_descriptor_id": new_descriptor_id,
        "old_validator_set_hash": old_validator_set_hash, "new_validator_set_hash": new_validator_set_hash,
        "old_consensus_parameters_hash": old_parameters_hash,
        "new_consensus_parameters_hash": new_parameters_hash,
        "terminal_block_id": terminal["block_id"], "terminal_height": 4,
        "terminal_view": 4, "activation_height": 5, "initial_new_view": 1,
    }
    handoff_id = digest(EPOCH_HANDOFF_DOMAIN, enc_handoff_body(handoff_body))
    handoff = {
        "body": handoff_body, "handoff_id": handoff_id,
        "old_set_signatures": make_handoff_entries(
            role=0, context=old_context, runtime_profile_hash=old_epoch_body["runtime_profile_hash"],
            epoch=0, validator_set_hash=old_validator_set_hash, parameters_hash=old_parameters_hash,
            view=4, handoff_id=handoff_id, validators=old_validators,
        ),
        "new_set_signatures": make_handoff_entries(
            role=1, context=new_context, runtime_profile_hash=new_epoch_body["runtime_profile_hash"],
            epoch=1, validator_set_hash=new_validator_set_hash, parameters_hash=new_parameters_hash,
            view=1, handoff_id=handoff_id, validators=new_definition["members"],
        ),
    }

    new_chain = []
    parent_id, prior_qc = terminal["block_id"], None
    for index in range(4):
        kind = "V1HandoffFirst" if index == 0 else "Ordinary"
        header = make_header(
            context=new_context, epoch=1, view=index + 1, height=index + 5, kind=kind,
            parent={"variant": "V1Block", "value": {"block_id": parent_id}},
            proposer_id=new_definition["members"][index % 4]["validator_id"],
            descriptor_id=new_descriptor_id, justify=prior_qc,
            label=f"epoch-1-{kind}-{index}",
        )
        if index == 0:
            header["epoch_handoff_id"] = handoff_id
            header["post_state_root"] = terminal["header"]["post_state_root"]
            for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
                header[field] = empty_ordered_root(root_kind)
            header["protocol_objects_root"] = epoch_handoff_protocol_objects_root(handoff)
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header, block_id, runtime_profile_hash=new_epoch_body["runtime_profile_hash"],
            validator_set_hash=new_validator_set_hash, parameters_hash=new_parameters_hash,
            validators=new_definition["members"],
        )
        new_chain.append({"header": header, "block_id": block_id, "certifying_qc": qc, "timeout_certificate": None})
        parent_id, prior_qc = block_id, qc["quorum_certificate_id"]
    return {
        "schema_version": 1, "old_trust_bundle": trust,
        "checkpoint_finality_proof": checkpoint_proof, "checkpoint": checkpoint,
        "checkpoint_attachment": checkpoint_attachment, "new_epoch_descriptor": new_descriptor,
        "new_validator_set": new_validator_set, "new_consensus_parameters": new_parameters,
        "handoff": handoff, "new_epoch_certified_chain": new_chain,
    }


def build_checkpoint_anchored_step(
    current: dict[str, Any], *, epoch_start_skipped_view: bool = False,
) -> dict[str, Any]:
    """Build a deterministic next-epoch fixture from an exact trusted state."""
    current_meta = validate_trusted_order_state(current)
    old_context = current["context"]
    old_epoch = current["epoch"]
    old_parameters = current["consensus_parameters"]
    old_parameters_hash = current_meta["parameters_hash"]
    old_validator_set_hash = current_meta["validator_set_hash"]
    old_descriptor_id = current_meta["descriptor_id"]
    old_descriptor_body = current["epoch_descriptor"]["body"]
    old_validators = current["validator_set"]["definition"]["members"]

    new_epoch = old_epoch + 1
    new_context = copy.deepcopy(old_context)
    new_context["stack_profile_hash"] = label_hash(f"trust-path-epoch-{new_epoch}-stack-profile")
    new_definition = copy.deepcopy(current["validator_set"]["definition"])
    for index, member in enumerate(new_definition["members"]):
        member["voting_weight"] = 2 if index == new_epoch % len(new_definition["members"]) else 1
    new_definition["total_weight"] = sum(member["voting_weight"] for member in new_definition["members"])
    new_definition["quorum_threshold"] = (
        old_parameters["quorum_numerator"] * new_definition["total_weight"]
        // old_parameters["quorum_denominator"] + 1
    )
    new_validator_set = {
        "schema_version": 1, "context": copy.deepcopy(new_context),
        "epoch": new_epoch, "definition": new_definition,
    }
    new_validator_set_hash = digest(VALIDATOR_SET_DOMAIN, enc_validator_set(new_validator_set))
    new_parameters = copy.deepcopy(old_parameters)
    new_parameters_hash = digest(CONSENSUS_PARAMETERS_DOMAIN, enc_parameters(new_parameters))
    new_descriptor_body = copy.deepcopy(old_descriptor_body)
    new_descriptor_body.update({
        "context": copy.deepcopy(new_context), "epoch": new_epoch,
        "validator_set_hash": new_validator_set_hash,
        "consensus_parameters_hash": new_parameters_hash,
        "runtime_profile_hash": label_hash(f"trust-path-epoch-{new_epoch}-runtime-profile"),
        "leader_schedule_id": label_hash(f"trust-path-epoch-{new_epoch}-leader-schedule"),
    })
    new_descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(new_descriptor_body))
    new_descriptor = {"body": new_descriptor_body, "epoch_descriptor_id": new_descriptor_id}

    checkpoint_chain: list[dict[str, Any]] = []
    parent_id = current["certified_head_block_id"]
    prior_qc = current["certified_head_qc_id"]
    prior_view = current["certified_head_header"]["view"]
    checkpoint_state_root = current["certified_head_header"]["post_state_root"]
    for index, (kind, offset) in enumerate((
        ("EpochCheckpoint", old_parameters["checkpoint_offset_blocks"]),
        ("EpochSeal1", old_parameters["seal_1_offset_blocks"]),
        ("EpochSeal2", old_parameters["seal_2_offset_blocks"]),
    )):
        height = current["epoch_start_height"] + offset
        header = make_header(
            context=old_context, epoch=old_epoch, view=prior_view + 1,
            height=height, kind=kind,
            parent={"variant": "V1Block", "value": {"block_id": parent_id}},
            proposer_id=old_validators[(index + 1) % len(old_validators)]["validator_id"],
            descriptor_id=old_descriptor_id, justify=prior_qc,
            label=f"trust-path-epoch-{old_epoch}-{kind}",
        )
        header["post_state_root"] = checkpoint_state_root
        header["next_epoch_descriptor_id"] = new_descriptor_id
        for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
            header[field] = empty_ordered_root(root_kind)
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header, block_id,
            runtime_profile_hash=old_descriptor_body["runtime_profile_hash"],
            validator_set_hash=old_validator_set_hash,
            parameters_hash=old_parameters_hash, validators=old_validators,
        )
        checkpoint_chain.append({
            "header": header, "block_id": block_id,
            "certifying_qc": qc, "timeout_certificate": None,
        })
        parent_id, prior_qc, prior_view = block_id, qc["quorum_certificate_id"], header["view"]

    checkpoint_header = checkpoint_chain[0]["header"]
    checkpoint_body = {
        "schema_version": 1, "context": copy.deepcopy(old_context), "epoch": old_epoch,
        "checkpoint_height": checkpoint_header["height"],
        "checkpoint_block_id": checkpoint_chain[0]["block_id"],
        "checkpoint_header": copy.deepcopy(checkpoint_header),
        "epoch_descriptor_id": old_descriptor_id,
        "validator_set_hash": old_validator_set_hash,
        "consensus_parameters_hash": old_parameters_hash,
        "application_state_root": checkpoint_state_root,
        "da_committee_set_root": old_descriptor_body["da_committee_set_root"],
        "verification_registry_hash": old_descriptor_body["verification_registry_hash"],
        "stack_profile_hash": old_context["stack_profile_hash"],
        "fee_schedule_hash": old_descriptor_body["fee_schedule_hash"],
        "state_schema_hash": old_descriptor_body["state_schema_hash"],
        "snapshot_policy_hash": old_descriptor_body["snapshot_policy_hash"],
        "next_epoch_descriptor_id": new_descriptor_id, "upgrade_plan_id": None,
    }
    checkpoint_id = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
    checkpoint = {"body": checkpoint_body, "checkpoint_id": checkpoint_id}

    terminal = checkpoint_chain[-1]
    handoff_body = {
        "schema_version": 1, "source_context": copy.deepcopy(old_context),
        "target_context": copy.deepcopy(new_context), "old_epoch": old_epoch,
        "new_epoch": new_epoch, "old_epoch_checkpoint_id": checkpoint_id,
        "old_epoch_descriptor_id": old_descriptor_id,
        "new_epoch_descriptor_id": new_descriptor_id,
        "old_validator_set_hash": old_validator_set_hash,
        "new_validator_set_hash": new_validator_set_hash,
        "old_consensus_parameters_hash": old_parameters_hash,
        "new_consensus_parameters_hash": new_parameters_hash,
        "terminal_block_id": terminal["block_id"],
        "terminal_height": terminal["header"]["height"],
        "terminal_view": terminal["header"]["view"],
        "activation_height": terminal["header"]["height"] + 1,
        "initial_new_view": 1,
    }
    handoff_id = digest(EPOCH_HANDOFF_DOMAIN, enc_handoff_body(handoff_body))
    handoff = {
        "body": handoff_body, "handoff_id": handoff_id,
        "old_set_signatures": make_handoff_entries(
            role=0, context=old_context,
            runtime_profile_hash=old_descriptor_body["runtime_profile_hash"],
            epoch=old_epoch, validator_set_hash=old_validator_set_hash,
            parameters_hash=old_parameters_hash, view=terminal["header"]["view"],
            handoff_id=handoff_id, validators=old_validators,
        ),
        "new_set_signatures": make_handoff_entries(
            role=1, context=new_context,
            runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
            epoch=new_epoch, validator_set_hash=new_validator_set_hash,
            parameters_hash=new_parameters_hash, view=1, handoff_id=handoff_id,
            validators=new_definition["members"],
        ),
    }

    new_chain: list[dict[str, Any]] = []
    parent_id, prior_qc = terminal["block_id"], None
    for index in range(4):
        kind = "V1HandoffFirst" if index == 0 else "Ordinary"
        view = index + 1 + (1 if epoch_start_skipped_view else 0)
        header = make_header(
            context=new_context, epoch=new_epoch, view=view,
            height=handoff_body["activation_height"] + index, kind=kind,
            parent={"variant": "V1Block", "value": {"block_id": parent_id}},
            proposer_id=new_definition["members"][index % len(new_definition["members"])]["validator_id"],
            descriptor_id=new_descriptor_id, justify=prior_qc,
            label=f"trust-path-epoch-{new_epoch}-{kind}-{index}",
        )
        if index == 0:
            header["epoch_handoff_id"] = handoff_id
            header["post_state_root"] = terminal["header"]["post_state_root"]
            for field, root_kind in EMPTY_HEADER_ROOT_KINDS.items():
                header[field] = empty_ordered_root(root_kind)
            header["protocol_objects_root"] = epoch_handoff_protocol_objects_root(handoff)
        timeout_certificate = None
        if index == 0 and epoch_start_skipped_view:
            timeout_certificate = make_epoch_start_tc(
                context=new_context, epoch=new_epoch,
                runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
                validator_set_hash=new_validator_set_hash,
                parameters_hash=new_parameters_hash, handoff=handoff,
                checkpoint_id=checkpoint_id,
                validators=new_definition["members"],
            )
            header["timeout_certificate_id"] = timeout_certificate["timeout_certificate_id"]
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header, block_id,
            runtime_profile_hash=new_descriptor_body["runtime_profile_hash"],
            validator_set_hash=new_validator_set_hash,
            parameters_hash=new_parameters_hash, validators=new_definition["members"],
        )
        new_chain.append({
            "header": header, "block_id": block_id,
            "certifying_qc": qc, "timeout_certificate": timeout_certificate,
        })
        parent_id, prior_qc = block_id, qc["quorum_certificate_id"]

    output_state = {
        "schema_version": 1, "context": copy.deepcopy(new_context), "epoch": new_epoch,
        "epoch_start_height": new_chain[0]["header"]["height"],
        "finalized_height": new_chain[1]["header"]["height"],
        "finalized_header": copy.deepcopy(new_chain[1]["header"]),
        "finalized_block_id": new_chain[1]["block_id"],
        "certified_head_header": copy.deepcopy(new_chain[-1]["header"]),
        "certified_head_block_id": new_chain[-1]["block_id"],
        "certified_head_qc_id": new_chain[-1]["certifying_qc"]["quorum_certificate_id"],
        "epoch_descriptor": copy.deepcopy(new_descriptor),
        "validator_set": copy.deepcopy(new_validator_set),
        "consensus_parameters": copy.deepcopy(new_parameters),
        "latest_checkpoint_id": checkpoint_id, "latest_handoff_id": handoff_id,
        "state_id": b"\x00" * 32,
    }
    seal_trusted_order_state(output_state)
    step = {
        "schema_version": 1, "input_state_id": current["state_id"],
        "checkpoint_certified_chain": checkpoint_chain, "checkpoint": checkpoint,
        "new_epoch_descriptor": new_descriptor, "new_validator_set": new_validator_set,
        "new_consensus_parameters": new_parameters, "handoff": handoff,
        "new_epoch_certified_chain": new_chain, "output_state": output_state,
        "step_id": b"\x00" * 32,
    }
    step["step_id"] = digest(
        CHECKPOINT_TRANSITION_STEP_DOMAIN, enc_checkpoint_transition_step_body(step),
    )
    return step


def seal_order_trust_path(path: dict[str, Any]) -> dict[str, Any]:
    path["path_id"] = digest(ORDER_TRUST_PATH_DOMAIN, enc_trust_path_body(path))
    return path


def build_order_trust_path_fixtures() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    transition = build_epoch_transition_fixture(iterable_successor=True)
    transition_raw = enc_epoch_transition(transition)
    initial = initial_state_from_existing_transition(transition)
    state_1, _ = verify_existing_fresh_genesis_path_step(transition_raw, initial)
    checkpoint_step_1 = build_checkpoint_anchored_step(state_1)
    checkpoint_step_1_raw = enc_checkpoint_transition_step(checkpoint_step_1)
    state_2, _ = verify_checkpoint_anchored_transition_step(checkpoint_step_1_raw, state_1)
    checkpoint_step_2 = build_checkpoint_anchored_step(
        state_2, epoch_start_skipped_view=True,
    )
    checkpoint_step_2_raw = enc_checkpoint_transition_step(checkpoint_step_2)
    verify_checkpoint_anchored_transition_step(checkpoint_step_2_raw, state_2)
    carriers = [
        {"variant": "ExistingFreshGenesisTransition", "raw_step_cev1": transition_raw},
        {"variant": "CheckpointAnchoredTransition", "raw_step_cev1": checkpoint_step_1_raw},
        {"variant": "CheckpointAnchoredTransition", "raw_step_cev1": checkpoint_step_2_raw},
    ]
    fixtures: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for hop_count in range(4):
        path = {
            "schema_version": 1, "initial_state": copy.deepcopy(initial),
            "steps": copy.deepcopy(carriers[:hop_count]), "path_id": b"\x00" * 32,
        }
        seal_order_trust_path(path)
        result = verify_order_trust_path(enc_trust_path(path))
        fixtures.append((path, result))
    return fixtures


def build_weak_subjectivity_renewal_fixture(
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    path = copy.deepcopy(build_order_trust_path_fixtures()[-1][0])
    path_raw = enc_trust_path(path)
    first_transition = decode_exact(
        path["steps"][0]["raw_step_cev1"], "weak_subjectivity_fixture_first",
        dec_epoch_transition, enc_epoch_transition,
    )
    last_step = decode_exact(
        path["steps"][-1]["raw_step_cev1"], "weak_subjectivity_fixture_last",
        dec_checkpoint_transition_step, enc_checkpoint_transition_step,
    )
    prior_anchor = weak_subjectivity_anchor_from_checkpoint(
        first_transition["checkpoint"],
    )
    renewed_anchor = weak_subjectivity_anchor_from_checkpoint(last_step["checkpoint"])
    policy = seal_weak_subjectivity_policy({
        "schema_version": 1,
        "max_checkpoint_age_epochs": 4,
        "max_checkpoint_age_blocks": 24,
        "min_finalized_height_advance": 1,
        "policy_id": b"\x00" * 32,
    })
    terminal = copy.deepcopy(last_step["output_state"])
    renewal = {
        "schema_version": 1,
        "prior_anchor": prior_anchor,
        "terminal_trusted_state": terminal,
        "terminal_checkpoint": copy.deepcopy(last_step["checkpoint"]),
        "policy": policy,
        "observed_finalized_epoch": terminal["epoch"],
        "observed_finalized_height": terminal["finalized_height"],
        "renewed_anchor": renewed_anchor,
        "renewal_id": b"\x00" * 32,
    }
    seal_weak_subjectivity_renewal(renewal)
    result = verify_weak_subjectivity_checkpoint_renewal(
        path_raw, enc_weak_subjectivity_renewal(renewal),
    )
    return path, renewal, result


WEAK_SUBJECTIVITY_NEGATIVE_SPECS = (
    ("renewal_trailing_byte", "trailing_bytes"),
    ("renewal_truncated", "truncated"),
    ("renewal_schema_version", "weak_subjectivity_renewal_schema"),
    ("renewal_id_substitution", "weak_subjectivity_renewal_id"),
    ("prior_anchor_schema", "weak_subjectivity_prior_anchor_schema"),
    ("prior_anchor_id_substitution", "weak_subjectivity_prior_anchor_id"),
    ("renewed_anchor_schema", "weak_subjectivity_renewed_anchor_schema"),
    ("renewed_anchor_id_substitution", "weak_subjectivity_renewed_anchor_id"),
    ("policy_schema", "weak_subjectivity_policy_schema"),
    ("policy_id_substitution", "weak_subjectivity_policy_id"),
    ("policy_zero_epoch_age", "weak_subjectivity_policy_positive"),
    ("policy_zero_block_age", "weak_subjectivity_policy_positive"),
    ("policy_zero_minimum", "weak_subjectivity_policy_positive"),
    ("context_chain_mismatch", "weak_subjectivity_context_lineage"),
    ("context_genesis_mismatch", "weak_subjectivity_context_lineage"),
    ("context_protocol_mismatch", "context_protocol_version"),
    ("prior_context_substitution", "weak_subjectivity_prior_context"),
    ("prior_checkpoint_id_substitution", "weak_subjectivity_prior_checkpoint"),
    ("prior_checkpoint_epoch_substitution", "weak_subjectivity_prior_checkpoint"),
    ("prior_checkpoint_height_substitution", "weak_subjectivity_prior_checkpoint"),
    ("prior_checkpoint_block_substitution", "weak_subjectivity_prior_checkpoint"),
    ("prior_validator_set_substitution", "weak_subjectivity_prior_authority"),
    ("prior_parameters_substitution", "weak_subjectivity_prior_authority"),
    ("prior_application_root_substitution", "weak_subjectivity_prior_roots"),
    ("prior_state_schema_substitution", "weak_subjectivity_prior_roots"),
    ("terminal_state_substitution", "weak_subjectivity_terminal_state"),
    ("terminal_checkpoint_substitution", "weak_subjectivity_terminal_checkpoint"),
    ("renewed_context_substitution", "weak_subjectivity_renewed_context"),
    ("renewed_checkpoint_id_substitution", "weak_subjectivity_renewed_checkpoint"),
    ("renewed_checkpoint_epoch_substitution", "weak_subjectivity_renewed_checkpoint"),
    ("renewed_checkpoint_height_substitution", "weak_subjectivity_renewed_checkpoint"),
    ("renewed_checkpoint_block_substitution", "weak_subjectivity_renewed_checkpoint"),
    ("renewed_validator_set_substitution", "weak_subjectivity_renewed_authority"),
    ("renewed_parameters_substitution", "weak_subjectivity_renewed_authority"),
    ("renewed_application_root_substitution", "weak_subjectivity_renewed_roots"),
    ("renewed_state_schema_substitution", "weak_subjectivity_renewed_roots"),
    ("observed_epoch_substitution", "weak_subjectivity_observed_head"),
    ("observed_height_substitution", "weak_subjectivity_observed_head"),
    ("prior_age_epoch_exceeded", "weak_subjectivity_prior_age_epoch"),
    ("prior_age_block_exceeded", "weak_subjectivity_prior_age_block"),
    ("minimum_advance_exceeded", "weak_subjectivity_minimum_advance"),
    ("renewed_epoch_rollback", "weak_subjectivity_epoch_monotonicity"),
    ("renewed_height_rollback", "weak_subjectivity_height_monotonicity"),
    ("same_height_conflict", "weak_subjectivity_same_height_conflict"),
    ("same_height_replay", "weak_subjectivity_height_monotonicity"),
)
WEAK_SUBJECTIVITY_NEGATIVE_IDS = tuple(
    case_id for case_id, _ in WEAK_SUBJECTIVITY_NEGATIVE_SPECS
)
EXPECTED_WEAK_SUBJECTIVITY_NEGATIVE_CODES = dict(
    WEAK_SUBJECTIVITY_NEGATIVE_SPECS
)


BASE_NEGATIVE_SPECS = (
    ("proof_trailing_byte", "trailing_bytes"), ("proof_truncated", "truncated"),
    ("trust_trailing_byte", "trailing_bytes"), ("trust_truncated", "truncated"),
    ("unknown_anchor_variant", "anchor_variant"), ("proof_wrong_chain", "proof_context"),
    ("proof_wrong_genesis", "proof_context"), ("proof_wrong_stack_profile", "proof_context"),
    ("proof_protocol_downgrade", "proof_context"),
    ("trust_validator_set_hash_mismatch", "epoch_descriptor_validator_set_hash"),
    ("trust_parameters_hash_mismatch", "epoch_descriptor_parameters_hash"),
    ("genesis_validator_definition_hash_mismatch", "genesis_validator_set_definition_hash"),
    ("epoch_descriptor_id_mismatch", "epoch_descriptor_id"),
    ("anchor_derived_state_mismatch", "anchor_derived_state"),
    ("anchor_header_mismatch", "anchor_header"),
    ("certified_chain_too_short", "direct_three_chain_cardinality"),
    ("certified_chain_too_long", "direct_three_chain_cardinality"),
    ("nonempty_epoch_handoff", "epoch_handoffs_unsupported"),
    ("block_id_mismatch", "block_id"), ("qc_id_mismatch", "qc_id"),
    ("qc_statement_block_substitution", "vote_header_identity"),
    ("qc_statement_height_substitution", "vote_header_identity"),
    ("qc_statement_descriptor_substitution", "vote_header_identity"),
    ("qc_statement_state_root_substitution", "vote_header_roots"),
    ("qc_statement_batch_root_substitution", "vote_header_roots"),
    ("qc_statement_receipts_root_substitution", "vote_header_roots"),
    ("qc_context_view_substitution", "vote_view"),
    ("qc_context_chain_substitution", "vote_context"),
    ("qc_signature_bitflip", "qc_signature"), ("qc_signature_wrong_key", "qc_signature"),
    ("qc_signature_wrong_domain", "qc_signature"),
    ("qc_signature_unknown_scheme", "qc_signature_scheme"),
    ("qc_duplicate_signer", "qc_signer_order"), ("qc_unsorted_signers", "qc_signer_order"),
    ("qc_insufficient_weight", "qc_quorum"), ("qc_noncanonical_scalar", "qc_signature"),
    ("certified_genesis_parent_substitution", "certified_genesis"),
    ("b0_broken_parent", "chain_parent"), ("b1_broken_parent", "chain_parent"),
    ("height_gap", "chain_height"), ("duplicate_view", "chain_view_order"),
    ("skipped_view_without_tc", "missing_timeout_certificate"),
    ("b0_wrong_justify", "chain_justify"), ("b1_wrong_justify", "chain_justify"),
    ("cross_epoch_header", "header_epoch"),
    ("target_block_substitution", "proof_target"),
    ("target_height_substitution", "proof_target"),
    ("target_header_substitution", "proof_target"),
    ("unknown_proposer", "header_proposer"),
    ("timeout_certificate_present", "unexpected_timeout_certificate"),
    ("certified_genesis_justify_present", "certified_genesis"),
    ("nonordinary_certified_header", "certified_chain_kinds"),
    ("proof_chain_reordered", "certified_chain_kinds"),
    ("finalized_height_rollback", "finalized_monotonicity"),
    ("same_height_conflict", "finalized_monotonicity"),
)

PARAMETER_NEGATIVE_SPECS = (
    ("parameter_schema_version", "parameters_version"),
    ("parameter_quorum_constants", "parameters_quorum"),
    ("parameter_finality_chain_length", "parameters_finality_chain_length"),
    ("parameter_execute_before_vote_false", "parameters_execute_before_vote"),
    *((f"parameter_zero_{name}", f"parameter_positive_{name}") for name in POSITIVE_PARAMETER_FIELDS),
    ("parameter_unsupported_max_validators", "parameter_supported_max_validators"),
    ("parameter_unsupported_max_certificate_signers", "parameter_supported_max_certificate_signers"),
    ("parameter_unsupported_max_consensus_string_bytes", "parameter_supported_max_consensus_string_bytes"),
    ("parameter_unsupported_max_signature_bytes", "parameter_supported_max_signature_bytes"),
    ("parameter_certificate_capacity", "parameter_certificate_capacity"),
    ("parameter_tranche_nesting", "parameter_tranche_nesting"),
    ("parameter_schedule_seal1", "parameter_schedule_seal1"),
    ("parameter_schedule_seal2", "parameter_schedule_seal2"),
    ("parameter_schedule_epoch_length", "parameter_schedule_epoch_length"),
    ("parameter_timeout_order", "parameter_timeout_order"),
    ("parameter_timeout_multiplier", "parameter_timeout_multiplier"),
    ("parameter_chain_id_committed_bound", "chain_id_committed_bound"),
    ("parameter_trust_cev1_value_bound", "trust_cev1_value_bound"),
    ("parameter_proof_cev1_value_bound", "proof_cev1_value_bound"),
    ("parameter_signature_committed_bound", "qc_signature_committed_bound"),
    ("parameter_retained_view_bound", "certified_chain_retained_view_bound"),
    ("parameter_validator_count_bound", "validator_count"),
    ("parameter_header_epoch_bound", "header_epoch_bound"),
    ("parameter_header_view_bound", "header_view_bound"),
    ("parameter_header_height_bound", "header_height_bound"),
)

FRESH_GENESIS_NEGATIVE_SPECS = (
    ("fresh_genesis_wrong_epoch", "fresh_genesis_epoch"),
    ("fresh_genesis_wrong_initial_view", "fresh_genesis_initial_view"),
    ("fresh_genesis_wrong_kind", "fresh_genesis_kind"),
    ("fresh_genesis_wrong_parent_variant", "fresh_genesis_parent_variant"),
    ("fresh_genesis_wrong_derived_state", "fresh_genesis_derived_state"),
    ("fresh_genesis_wrong_application_state_root", "fresh_genesis_application_state_root"),
    ("fresh_genesis_justify_present", "fresh_genesis_justify_absent"),
    ("fresh_genesis_timeout_present", "fresh_genesis_timeout_absent"),
    ("fresh_genesis_next_epoch_present", "fresh_genesis_next_epoch_absent"),
    ("fresh_genesis_upgrade_present", "fresh_genesis_upgrade_absent"),
    ("fresh_genesis_handoff_present", "fresh_genesis_handoff_absent"),
    ("fresh_genesis_empty_batch_refs_root", "fresh_genesis_empty_batch_refs_root"),
    ("fresh_genesis_empty_protocol_objects_root", "fresh_genesis_empty_protocol_objects_root"),
    ("fresh_genesis_empty_transaction_execution_receipts_root", "fresh_genesis_empty_transaction_execution_receipts_root"),
    ("fresh_genesis_empty_evidence_root", "fresh_genesis_empty_evidence_root"),
    ("fresh_genesis_empty_consumption_rollups_root", "fresh_genesis_empty_consumption_rollups_root"),
    ("fresh_genesis_empty_settlement_root", "fresh_genesis_empty_settlement_root"),
    ("fresh_genesis_empty_resource_usage_root", "fresh_genesis_empty_resource_usage_root"),
)

NEGATIVE_SPECS = BASE_NEGATIVE_SPECS + PARAMETER_NEGATIVE_SPECS + FRESH_GENESIS_NEGATIVE_SPECS
NEGATIVE_IDS = tuple(case_id for case_id, _ in NEGATIVE_SPECS)
EXPECTED_NEGATIVE_CODES = dict(NEGATIVE_SPECS)

TC_NEGATIVE_SPECS = (
    ("tc_id_mismatch", "tc_id"),
    ("tc_header_id_mismatch", "header_tc_id"),
    ("tc_missing_carrier", "missing_timeout_certificate"),
    ("tc_on_consecutive_view", "unexpected_timeout_certificate"),
    ("tc_wrong_target_view", "tc_target_view"),
    ("tc_non_immediate_target", "tc_immediate_target"),
    ("tc_wrong_context", "tc_context"),
    ("tc_wrong_authority", "tc_authority"),
    ("tc_wrong_justification", "tc_justification_inventory"),
    ("tc_duplicate_signer", "tc_signer_order"),
    ("tc_unsorted_signers", "tc_signer_order"),
    ("tc_insufficient_weight", "tc_quorum"),
    ("tc_signature_bitflip", "tc_signature"),
    ("tc_signature_wrong_domain", "tc_signature"),
    ("tc_signature_unknown_scheme", "tc_signature_scheme"),
    ("tc_timeout_wrong_kind", "timeout_version_kind"),
    ("tc_timeout_wrong_view", "timeout_view"),
    ("tc_timeout_wrong_high_qc", "timeout_high_justification"),
    ("tc_timeout_wrong_locked_qc", "timeout_locked_qc"),
    ("tc_timeout_wrong_finalized_anchor", "timeout_finalized_anchor"),
    ("tc_timeout_zero_generation", "timeout_pacemaker_generation"),
)
TC_NEGATIVE_IDS = tuple(case_id for case_id, _ in TC_NEGATIVE_SPECS)
EXPECTED_TC_NEGATIVE_CODES = dict(TC_NEGATIVE_SPECS)

TRANSITION_NEGATIVE_SPECS = (
    ("transition_trailing_byte", "trailing_bytes"),
    ("transition_truncated", "truncated"),
    ("transition_schema_version", "transition_schema_version"),
    ("checkpoint_proof_anchor_substitution", "anchor_derived_state"),
    ("checkpoint_context_substitution", "checkpoint_context"),
    ("checkpoint_epoch_substitution", "checkpoint_epoch"),
    ("checkpoint_block_substitution", "checkpoint_target"),
    ("checkpoint_height_substitution", "checkpoint_target"),
    ("checkpoint_header_substitution", "checkpoint_target"),
    ("checkpoint_descriptor_substitution", "checkpoint_descriptor"),
    ("checkpoint_validator_set_substitution", "checkpoint_authority"),
    ("checkpoint_parameters_substitution", "checkpoint_authority"),
    ("checkpoint_state_substitution", "checkpoint_state"),
    ("checkpoint_policy_substitution", "checkpoint_policy"),
    ("checkpoint_next_descriptor_substitution", "checkpoint_next_descriptor"),
    ("checkpoint_upgrade_present", "checkpoint_upgrade"),
    ("checkpoint_id_substitution", "checkpoint_id"),
    ("attachment_checkpoint_substitution", "attachment_checkpoint_id"),
    ("attachment_proof_substitution", "attachment_proof"),
    ("new_context_lineage_substitution", "handoff_context_lineage"),
    ("new_validator_set_epoch_substitution", "validator_set_epoch"),
    ("new_descriptor_set_substitution", "new_epoch_descriptor_validator_set_hash"),
    ("new_descriptor_parameters_substitution", "new_epoch_descriptor_parameters_hash"),
    ("new_descriptor_id_substitution", "new_epoch_descriptor_id"),
    ("handoff_source_context_substitution", "handoff_context"),
    ("handoff_target_context_substitution", "handoff_context"),
    ("handoff_epoch_substitution", "handoff_epoch"),
    ("handoff_checkpoint_substitution", "handoff_checkpoint"),
    ("handoff_old_descriptor_substitution", "handoff_descriptor"),
    ("handoff_new_descriptor_substitution", "handoff_descriptor"),
    ("handoff_old_set_substitution", "handoff_authority"),
    ("handoff_new_set_substitution", "handoff_authority"),
    ("handoff_old_parameters_substitution", "handoff_authority"),
    ("handoff_new_parameters_substitution", "handoff_authority"),
    ("handoff_terminal_block_substitution", "handoff_terminal"),
    ("handoff_terminal_height_substitution", "handoff_terminal"),
    ("handoff_terminal_view_substitution", "handoff_terminal"),
    ("handoff_activation_height_substitution", "handoff_activation"),
    ("handoff_initial_view_substitution", "handoff_initial_view"),
    ("handoff_id_substitution", "handoff_id"),
    ("old_role_tag_substitution", "old_handoff_role"),
    ("new_role_tag_substitution", "new_handoff_role"),
    ("old_role_context_substitution", "old_handoff_context"),
    ("new_role_context_substitution", "new_handoff_context"),
    ("old_role_authority_substitution", "old_handoff_authority"),
    ("new_role_authority_substitution", "new_handoff_authority"),
    ("old_role_duplicate_signer", "old_handoff_signer_order"),
    ("new_role_duplicate_signer", "new_handoff_signer_order"),
    ("old_role_under_quorum", "old_handoff_quorum"),
    ("new_role_under_quorum", "new_handoff_quorum"),
    ("old_role_signature_bitflip", "old_handoff_signature"),
    ("new_role_signature_bitflip", "new_handoff_signature"),
    ("handoff_first_kind_substitution", "new_epoch_chain_kinds"),
    ("handoff_first_parent_substitution", "new_epoch_first_parent"),
    ("handoff_first_height_substitution", "new_epoch_first_height"),
    ("handoff_first_view_substitution", "new_epoch_first_view"),
    ("handoff_first_justify_present", "new_epoch_first_justify"),
    ("handoff_first_epoch_substitution", "new_epoch_header_epoch"),
    ("handoff_first_handoff_substitution", "new_epoch_first_handoff"),
    ("handoff_first_state_substitution", "new_epoch_first_state"),
    ("handoff_first_payload_substitution", "new_epoch_first_empty_payload"),
    ("ordinary_parent_substitution", "new_epoch_chain_parent"),
    ("ordinary_height_substitution", "new_epoch_chain_height"),
    ("ordinary_view_substitution", "new_epoch_chain_view"),
    ("ordinary_justify_substitution", "new_epoch_chain_justify"),
    ("ordinary_epoch_substitution", "new_epoch_header_epoch"),
    ("ordinary_handoff_present", "new_epoch_ordinary_handoff"),
    ("new_epoch_qc_signature_bitflip", "qc_signature"),
)
TRANSITION_NEGATIVE_IDS = tuple(case_id for case_id, _ in TRANSITION_NEGATIVE_SPECS)
EXPECTED_TRANSITION_NEGATIVE_CODES = dict(TRANSITION_NEGATIVE_SPECS)


def resign_item(proof: dict[str, Any], index: int, trust: dict[str, Any], *, update_target: bool = False) -> None:
    item = proof["certified_chain"][index]
    item["block_id"] = digest(BLOCK_DOMAIN, enc_header(item["header"]))
    body = trust["epoch_descriptor"]["body"]
    set_hash = body["validator_set_hash"]
    params_hash = body["consensus_parameters_hash"]
    item["certifying_qc"] = make_qc(item["header"], item["block_id"], runtime_profile_hash=body["runtime_profile_hash"], validator_set_hash=set_hash, parameters_hash=params_hash, validators=trust["validator_set"]["definition"]["members"])
    if index == 0 and update_target:
        proof["target_block_id"] = item["block_id"]
        proof["target_height"] = item["header"]["height"]
        proof["target_header"] = copy.deepcopy(item["header"])


def rebind_all_authority(trust: dict[str, Any], proof: dict[str, Any]) -> None:
    """Repair every non-target commitment after an authority/header mutation."""
    context = trust["context"]
    descriptor_body = trust["epoch_descriptor"]["body"]
    epoch = descriptor_body["epoch"]
    validator_set = trust["validator_set"]
    validator_set["context"] = copy.deepcopy(context)
    validator_set["epoch"] = epoch
    definition = validator_set["definition"]
    trust["genesis_validator_set_definition_hash"] = digest(
        VALIDATOR_SET_DEFINITION_DOMAIN,
        enc_validator_definition(definition),
    )
    descriptor_body["context"] = copy.deepcopy(context)
    descriptor_body["validator_set_hash"] = digest(
        VALIDATOR_SET_DOMAIN,
        enc_validator_set(validator_set),
    )
    descriptor_body["consensus_parameters_hash"] = digest(
        CONSENSUS_PARAMETERS_DOMAIN,
        enc_parameters(trust["consensus_parameters"]),
    )
    descriptor_id = digest(EPOCH_DESCRIPTOR_DOMAIN, enc_epoch_body(descriptor_body))
    trust["epoch_descriptor"]["epoch_descriptor_id"] = descriptor_id

    genesis = trust["trusted_genesis_header"]
    genesis["context"] = copy.deepcopy(context)
    genesis["epoch"] = epoch
    genesis["epoch_descriptor_id"] = descriptor_id
    proof["context"] = copy.deepcopy(context)
    proof["trusted_anchor"] = {
        "variant": "FreshGenesis",
        "value": {
            "genesis_derived_state_hash": trust["genesis_derived_state_hash"],
            "trusted_genesis_header": copy.deepcopy(genesis),
        },
    }

    headers = [copy.deepcopy(genesis)] + [
        copy.deepcopy(item["header"])
        for item in proof["certified_chain"][1:3]
    ]
    previous_block_id: bytes | None = None
    previous_qc_id: bytes | None = None
    members = validator_set["definition"]["members"]
    rebuilt = []
    for index, header in enumerate(headers):
        header["context"] = copy.deepcopy(context)
        header["epoch"] = epoch
        header["epoch_descriptor_id"] = descriptor_id
        if index > 0:
            header["parent"] = {
                "variant": "V1Block",
                "value": {"block_id": previous_block_id},
            }
            header["justify_qc_id"] = previous_qc_id
        block_id = digest(BLOCK_DOMAIN, enc_header(header))
        qc = make_qc(
            header,
            block_id,
            runtime_profile_hash=descriptor_body["runtime_profile_hash"],
            validator_set_hash=descriptor_body["validator_set_hash"],
            parameters_hash=descriptor_body["consensus_parameters_hash"],
            validators=members,
        )
        rebuilt.append({"header": header, "block_id": block_id, "certifying_qc": qc, "timeout_certificate": None})
        previous_block_id = block_id
        previous_qc_id = qc["quorum_certificate_id"]
    proof["certified_chain"] = rebuilt
    proof["target_block_id"] = rebuilt[0]["block_id"]
    proof["target_height"] = rebuilt[0]["header"]["height"]
    proof["target_header"] = copy.deepcopy(rebuilt[0]["header"])


def refresh_qc_id(proof: dict[str, Any], index: int = 0) -> None:
    qc = proof["certified_chain"][index]["certifying_qc"]
    qc["quorum_certificate_id"] = digest(QC_DOMAIN, enc_qc_body(qc["body"]))


def mutation_case(case_id: str, trust_raw: bytes, proof_raw: bytes) -> tuple[bytes, bytes, tuple[int, bytes] | None]:
    trust = decode_exact(trust_raw, "base_trust", dec_trust, enc_trust)
    proof = decode_exact(proof_raw, "base_proof", dec_proof, enc_proof)
    prior: tuple[int, bytes] | None = None
    if case_id == "proof_trailing_byte": return trust_raw, proof_raw + b"\x00", None
    if case_id == "proof_truncated": return trust_raw, proof_raw[:-1], None
    if case_id == "trust_trailing_byte": return trust_raw + b"\x00", proof_raw, None
    if case_id == "trust_truncated": return trust_raw[:-1], proof_raw, None
    if case_id == "unknown_anchor_variant":
        offset = 2 + len(enc_protocol_context(proof["context"]))
        changed = bytearray(proof_raw); changed[offset] = 9
        return trust_raw, bytes(changed), None
    if case_id == "nonempty_epoch_handoff": return trust_raw, proof_raw[:-4] + struct.pack("<I", 1), None
    if case_id.startswith("parameter_zero_"):
        name = case_id.removeprefix("parameter_zero_")
        require(name in POSITIVE_PARAMETER_FIELDS, "unknown_parameter_negative", name)
        trust["consensus_parameters"][name] = 0
        rebind_all_authority(trust, proof)
    elif case_id == "parameter_schema_version": trust["consensus_parameters"]["schema_version"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_quorum_constants": trust["consensus_parameters"]["quorum_numerator"] = 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_finality_chain_length": trust["consensus_parameters"]["finality_chain_length"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_execute_before_vote_false": trust["consensus_parameters"]["execute_coordination_before_vote"] = False; rebind_all_authority(trust, proof)
    elif case_id == "parameter_unsupported_max_validators": trust["consensus_parameters"]["max_validators"] = MAX_PARSER_VALIDATORS + 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_unsupported_max_certificate_signers": trust["consensus_parameters"]["max_certificate_signers"] = MAX_PARSER_CERTIFICATE_SIGNERS + 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_unsupported_max_consensus_string_bytes": trust["consensus_parameters"]["max_consensus_string_bytes"] = MAX_PARSER_CONSENSUS_STRING_BYTES + 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_unsupported_max_signature_bytes": trust["consensus_parameters"]["max_signature_bytes"] = MAX_PARSER_SIGNATURE_BYTES + 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_certificate_capacity": trust["consensus_parameters"]["max_certificate_signers"] = trust["consensus_parameters"]["max_validators"] - 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_tranche_nesting": trust["consensus_parameters"]["max_cev1_nesting"] = REQUIRED_TRANCHE_CEV1_NESTING - 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_schedule_seal1": trust["consensus_parameters"]["seal_1_offset_blocks"] = trust["consensus_parameters"]["checkpoint_offset_blocks"] + 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_schedule_seal2": trust["consensus_parameters"]["seal_2_offset_blocks"] = trust["consensus_parameters"]["seal_1_offset_blocks"] + 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_schedule_epoch_length": trust["consensus_parameters"]["epoch_length_blocks"] = trust["consensus_parameters"]["seal_2_offset_blocks"] + 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_timeout_order": trust["consensus_parameters"]["base_view_timeout_ms"] = trust["consensus_parameters"]["maximum_view_timeout_ms"] + 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_timeout_multiplier": trust["consensus_parameters"]["timeout_multiplier_numerator"] = trust["consensus_parameters"]["timeout_multiplier_denominator"] - 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_chain_id_committed_bound": trust["consensus_parameters"]["max_consensus_string_bytes"] = 4; rebind_all_authority(trust, proof)
    elif case_id == "parameter_trust_cev1_value_bound": trust["consensus_parameters"]["max_cev1_value_bytes"] = len(trust_raw) - 1; rebind_all_authority(trust, proof)
    elif case_id == "parameter_proof_cev1_value_bound": trust["consensus_parameters"]["max_cev1_value_bytes"] = (len(trust_raw) + len(proof_raw)) // 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_signature_committed_bound": trust["consensus_parameters"]["max_signature_bytes"] = 63; rebind_all_authority(trust, proof)
    elif case_id == "parameter_retained_view_bound": trust["consensus_parameters"]["max_retained_views"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_validator_count_bound": trust["consensus_parameters"]["max_validators"] = 3; rebind_all_authority(trust, proof)
    elif case_id == "parameter_header_epoch_bound":
        trust["consensus_parameters"]["max_epoch"] = 1; rebind_all_authority(trust, proof)
        proof["certified_chain"][2]["header"]["epoch"] = 2; resign_item(proof, 2, trust)
    elif case_id == "parameter_header_view_bound": trust["consensus_parameters"]["max_view"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "parameter_header_height_bound": trust["consensus_parameters"]["max_height"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_epoch": trust["epoch_descriptor"]["body"]["epoch"] = 1; rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_initial_view": trust["trusted_genesis_header"]["view"] = 2; rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_kind": trust["trusted_genesis_header"]["block_kind"] = "Ordinary"; rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_parent_variant": trust["trusted_genesis_header"]["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash("wrong-genesis-parent")}}; rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_derived_state": trust["trusted_genesis_header"]["parent"]["value"]["genesis_derived_state_hash"] = label_hash("wrong-genesis-derived"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_wrong_application_state_root": trust["trusted_genesis_header"]["post_state_root"] = label_hash("wrong-genesis-state"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_justify_present": trust["trusted_genesis_header"]["justify_qc_id"] = label_hash("unexpected-genesis-qc"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_timeout_present": trust["trusted_genesis_header"]["timeout_certificate_id"] = label_hash("unexpected-genesis-tc"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_next_epoch_present": trust["trusted_genesis_header"]["next_epoch_descriptor_id"] = label_hash("unexpected-next-epoch"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_upgrade_present": trust["trusted_genesis_header"]["upgrade_plan_id"] = label_hash("unexpected-upgrade"); rebind_all_authority(trust, proof)
    elif case_id == "fresh_genesis_handoff_present": trust["trusted_genesis_header"]["epoch_handoff_id"] = label_hash("unexpected-handoff"); rebind_all_authority(trust, proof)
    elif case_id.startswith("fresh_genesis_empty_"):
        field = case_id.removeprefix("fresh_genesis_empty_")
        require(field in EMPTY_HEADER_ROOT_KINDS, "unknown_genesis_root_negative", field)
        trust["trusted_genesis_header"][field] = label_hash(f"nonempty-{field}")
        rebind_all_authority(trust, proof)
    elif case_id == "proof_wrong_chain": proof["context"]["chain_id"] = "wrong-chain"
    elif case_id == "proof_wrong_genesis": proof["context"]["genesis_hash"] = label_hash("wrong-genesis")
    elif case_id == "proof_wrong_stack_profile": proof["context"]["stack_profile_hash"] = label_hash("wrong-stack")
    elif case_id == "proof_protocol_downgrade": proof["context"]["protocol_version"] = 0
    elif case_id == "trust_validator_set_hash_mismatch": trust["epoch_descriptor"]["body"]["validator_set_hash"] = label_hash("wrong-set")
    elif case_id == "trust_parameters_hash_mismatch": trust["epoch_descriptor"]["body"]["consensus_parameters_hash"] = label_hash("wrong-params")
    elif case_id == "genesis_validator_definition_hash_mismatch": trust["genesis_validator_set_definition_hash"] = label_hash("wrong-definition")
    elif case_id == "epoch_descriptor_id_mismatch": trust["epoch_descriptor"]["epoch_descriptor_id"] = label_hash("wrong-descriptor")
    elif case_id == "anchor_derived_state_mismatch": proof["trusted_anchor"]["value"]["genesis_derived_state_hash"] = label_hash("wrong-derived")
    elif case_id == "anchor_header_mismatch": proof["trusted_anchor"]["value"]["trusted_genesis_header"]["post_state_root"] = label_hash("wrong-genesis-header")
    elif case_id == "certified_chain_too_short": proof["certified_chain"] = proof["certified_chain"][:2]
    elif case_id == "certified_chain_too_long":
        proof["certified_chain"].append(copy.deepcopy(proof["certified_chain"][-1]))
        proof["certified_chain"].append(copy.deepcopy(proof["certified_chain"][-1]))
    elif case_id == "block_id_mismatch": proof["certified_chain"][0]["block_id"] = label_hash("wrong-block-id")
    elif case_id == "qc_id_mismatch": proof["certified_chain"][0]["certifying_qc"]["quorum_certificate_id"] = label_hash("wrong-qc-id")
    elif case_id == "qc_statement_block_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["block_id"] = label_hash("wrong-vote-block"); refresh_qc_id(proof)
    elif case_id == "qc_statement_height_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["height"] += 1; refresh_qc_id(proof)
    elif case_id == "qc_statement_descriptor_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["epoch_descriptor_id"] = label_hash("wrong-vote-descriptor"); refresh_qc_id(proof)
    elif case_id == "qc_statement_state_root_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["post_state_root"] = label_hash("wrong-vote-state"); refresh_qc_id(proof)
    elif case_id == "qc_statement_batch_root_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["batch_refs_root"] = label_hash("wrong-vote-batches"); refresh_qc_id(proof)
    elif case_id == "qc_statement_receipts_root_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["transaction_execution_receipts_root"] = label_hash("wrong-vote-receipts"); refresh_qc_id(proof)
    elif case_id == "qc_context_view_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["consensus_context"]["view"] += 1; refresh_qc_id(proof)
    elif case_id == "qc_context_chain_substitution": proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]["consensus_context"]["context"]["chain_id"] = "wrong-chain"; refresh_qc_id(proof)
    elif case_id == "qc_signature_bitflip":
        sig = bytearray(proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]["signature"]); sig[7] ^= 1
        proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]["signature"] = bytes(sig)
        refresh_qc_id(proof)
    elif case_id == "qc_signature_wrong_key":
        vote = proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]
        proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]["signature"] = ed25519_sign(fixture_seed(1), digest(VOTE_DOMAIN, enc_vote(vote)))
        refresh_qc_id(proof)
    elif case_id == "qc_signature_wrong_domain":
        vote = proof["certified_chain"][0]["certifying_qc"]["body"]["statement"]
        proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]["signature"] = ed25519_sign(fixture_seed(0), digest(QC_DOMAIN, enc_vote(vote)))
        refresh_qc_id(proof)
    elif case_id == "qc_signature_unknown_scheme": proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]["signature_scheme"] = 1; refresh_qc_id(proof)
    elif case_id == "qc_duplicate_signer": proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][1] = copy.deepcopy(proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]); refresh_qc_id(proof)
    elif case_id == "qc_unsorted_signers":
        sigs = proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"]; sigs[0], sigs[1] = sigs[1], sigs[0]; refresh_qc_id(proof)
    elif case_id == "qc_insufficient_weight": proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"] = proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][:2]; refresh_qc_id(proof)
    elif case_id == "qc_noncanonical_scalar":
        entry = proof["certified_chain"][0]["certifying_qc"]["body"]["signatures"][0]
        entry["signature"] = entry["signature"][:32] + GROUP_ORDER.to_bytes(32, "little")
        refresh_qc_id(proof)
    elif case_id in {"certified_genesis_parent_substitution", "b0_broken_parent", "b1_broken_parent"}:
        index = {"certified_genesis_parent_substitution": 0, "b0_broken_parent": 1, "b1_broken_parent": 2}[case_id]
        proof["certified_chain"][index]["header"]["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash(case_id)}}
        resign_item(proof, index, trust, update_target=index == 0)
    elif case_id in {"height_gap", "duplicate_view", "skipped_view_without_tc"}:
        if case_id == "height_gap":
            proof["certified_chain"][1]["header"]["height"] += 1
        elif case_id == "duplicate_view":
            proof["certified_chain"][1]["header"]["view"] = proof["certified_chain"][0]["header"]["view"]
        else:
            proof["certified_chain"][1]["header"]["view"] += 1
        resign_item(proof, 1, trust)
        proof["certified_chain"][2]["header"]["parent"] = {
            "variant": "V1Block",
            "value": {"block_id": proof["certified_chain"][1]["block_id"]},
        }
        proof["certified_chain"][2]["header"]["justify_qc_id"] = proof["certified_chain"][1]["certifying_qc"]["quorum_certificate_id"]
        resign_item(proof, 2, trust)
    elif case_id == "b0_wrong_justify": proof["certified_chain"][1]["header"]["justify_qc_id"] = label_hash("wrong-justify-0"); resign_item(proof, 1, trust)
    elif case_id == "b1_wrong_justify": proof["certified_chain"][2]["header"]["justify_qc_id"] = label_hash("wrong-justify-1"); resign_item(proof, 2, trust)
    elif case_id == "cross_epoch_header": proof["certified_chain"][2]["header"]["epoch"] = 1; resign_item(proof, 2, trust)
    elif case_id == "target_block_substitution": proof["target_block_id"] = label_hash("wrong-target")
    elif case_id == "target_height_substitution": proof["target_height"] += 1
    elif case_id == "target_header_substitution": proof["target_header"]["post_state_root"] = label_hash("wrong-target-header")
    elif case_id == "unknown_proposer": proof["certified_chain"][1]["header"]["proposer_id"] = b"unknown"; resign_item(proof, 1, trust)
    elif case_id == "timeout_certificate_present": proof["certified_chain"][1]["header"]["timeout_certificate_id"] = label_hash("unexpected-tc"); resign_item(proof, 1, trust)
    elif case_id == "certified_genesis_justify_present": proof["certified_chain"][0]["header"]["justify_qc_id"] = label_hash("unexpected-qc"); resign_item(proof, 0, trust, update_target=True)
    elif case_id == "nonordinary_certified_header": proof["certified_chain"][1]["header"]["block_kind"] = "FreshGenesis"; resign_item(proof, 1, trust)
    elif case_id == "proof_chain_reordered": proof["certified_chain"][0], proof["certified_chain"][1] = proof["certified_chain"][1], proof["certified_chain"][0]
    elif case_id == "finalized_height_rollback": prior = (proof["target_height"] + 1, label_hash("later-finalized"))
    elif case_id == "same_height_conflict": prior = (proof["target_height"], label_hash("conflicting-finalized"))
    else: reject("unknown_negative", case_id)
    return enc_trust(trust), enc_proof(proof), prior


def relink_from(proof: dict[str, Any], trust: dict[str, Any], start_index: int) -> None:
    for index in range(start_index, len(proof["certified_chain"])):
        if index > 0:
            previous = proof["certified_chain"][index - 1]
            header = proof["certified_chain"][index]["header"]
            header["parent"] = {"variant": "V1Block", "value": {"block_id": previous["block_id"]}}
            header["justify_qc_id"] = previous["certifying_qc"]["quorum_certificate_id"]
        resign_item(proof, index, trust)


def refresh_tc_and_chain(proof: dict[str, Any], trust: dict[str, Any], index: int = 2) -> None:
    tc = proof["certified_chain"][index]["timeout_certificate"]
    require(tc is not None, "tc_fixture_missing")
    tc["timeout_certificate_id"] = digest(TC_DOMAIN, enc_tc_body(tc["body"]))
    proof["certified_chain"][index]["header"]["timeout_certificate_id"] = tc["timeout_certificate_id"]
    relink_from(proof, trust, index)


def mutation_tc_case(case_id: str, trust_raw: bytes, proof_raw: bytes) -> tuple[bytes, bytes]:
    trust = decode_exact(trust_raw, "ordinary_trust", dec_trust, enc_trust)
    proof = decode_exact(proof_raw, "ordinary_proof", dec_proof, enc_proof)
    item = proof["certified_chain"][2]
    tc = item["timeout_certificate"]
    require(tc is not None, "tc_fixture_missing")
    body = tc["body"]
    entries = body["entries"]

    if case_id == "tc_id_mismatch":
        tc["timeout_certificate_id"] = label_hash("wrong-tc-id")
    elif case_id == "tc_header_id_mismatch":
        item["header"]["timeout_certificate_id"] = label_hash("wrong-header-tc-id")
        relink_from(proof, trust, 2)
    elif case_id == "tc_missing_carrier":
        item["timeout_certificate"] = None
    elif case_id == "tc_on_consecutive_view":
        item["header"]["view"] = proof["certified_chain"][1]["header"]["view"] + 1
        relink_from(proof, trust, 2)
    elif case_id == "tc_wrong_target_view":
        body["target_view"] += 1
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_non_immediate_target":
        body["timed_out_view"] -= 1
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_wrong_context":
        body["context"]["chain_id"] = "wrong-tc-chain"
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_wrong_authority":
        body["runtime_profile_hash"] = label_hash("wrong-tc-runtime")
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_wrong_justification":
        body["justifications"][0]["value"] = copy.deepcopy(proof["certified_chain"][0]["certifying_qc"])
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_duplicate_signer":
        entries[1] = copy.deepcopy(entries[0])
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_unsorted_signers":
        entries[0], entries[1] = entries[1], entries[0]
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_insufficient_weight":
        body["entries"] = entries[:2]
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_signature_bitflip":
        signature = bytearray(entries[0]["signature"])
        signature[9] ^= 1
        entries[0]["signature"] = bytes(signature)
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_signature_wrong_domain":
        entries[0]["signature"] = ed25519_sign(
            fixture_seed(0), digest(QC_DOMAIN, enc_timeout_statement(entries[0]["statement"])),
        )
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_signature_unknown_scheme":
        entries[0]["signature_scheme"] = 1
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_wrong_kind":
        entries[0]["statement"]["consensus_context"]["message_kind"] = 1
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_wrong_view":
        entries[0]["statement"]["consensus_context"]["view"] -= 1
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_wrong_high_qc":
        entries[0]["statement"]["high_justification"]["value"]["qc_id"] = label_hash("wrong-timeout-high-qc")
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_wrong_locked_qc":
        entries[0]["statement"]["locked_qc_id"] = label_hash("wrong-timeout-lock")
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_wrong_finalized_anchor":
        entries[0]["statement"]["last_finalized_anchor"]["value"]["genesis_derived_state_hash"] = label_hash("wrong-finalized-anchor")
        refresh_tc_and_chain(proof, trust)
    elif case_id == "tc_timeout_zero_generation":
        entries[0]["statement"]["pacemaker_generation"] = 0
        refresh_tc_and_chain(proof, trust)
    else:
        reject("unknown_tc_negative", case_id)
    return enc_trust(trust), enc_proof(proof)


def resign_transition_new_item(transition: dict[str, Any], index: int) -> None:
    item = transition["new_epoch_certified_chain"][index]
    descriptor_body = transition["new_epoch_descriptor"]["body"]
    item["block_id"] = digest(BLOCK_DOMAIN, enc_header(item["header"]))
    item["certifying_qc"] = make_qc(
        item["header"], item["block_id"],
        runtime_profile_hash=descriptor_body["runtime_profile_hash"],
        validator_set_hash=descriptor_body["validator_set_hash"],
        parameters_hash=descriptor_body["consensus_parameters_hash"],
        validators=transition["new_validator_set"]["definition"]["members"],
    )


def mutation_transition_case(case_id: str, transition_raw: bytes) -> bytes:
    if case_id == "transition_trailing_byte":
        return transition_raw + b"\x00"
    if case_id == "transition_truncated":
        return transition_raw[:-1]

    transition = decode_exact(
        transition_raw, "epoch_transition_mutation", dec_epoch_transition, enc_epoch_transition,
    )
    checkpoint = transition["checkpoint"]
    checkpoint_body = checkpoint["body"]
    handoff = transition["handoff"]
    handoff_body = handoff["body"]
    new_descriptor = transition["new_epoch_descriptor"]
    new_chain = transition["new_epoch_certified_chain"]

    if case_id == "transition_schema_version":
        transition["schema_version"] = 2
    elif case_id == "checkpoint_proof_anchor_substitution":
        transition["checkpoint_finality_proof"]["trusted_anchor"]["value"]["genesis_derived_state_hash"] = label_hash(case_id)
    elif case_id == "checkpoint_context_substitution":
        checkpoint_body["context"]["chain_id"] = "wrong-checkpoint-chain"
    elif case_id == "checkpoint_epoch_substitution":
        checkpoint_body["epoch"] += 1
    elif case_id == "checkpoint_block_substitution":
        checkpoint_body["checkpoint_block_id"] = label_hash(case_id)
    elif case_id == "checkpoint_height_substitution":
        checkpoint_body["checkpoint_height"] += 1
    elif case_id == "checkpoint_header_substitution":
        checkpoint_body["checkpoint_header"]["post_state_root"] = label_hash(case_id)
    elif case_id == "checkpoint_descriptor_substitution":
        checkpoint_body["epoch_descriptor_id"] = label_hash(case_id)
    elif case_id == "checkpoint_validator_set_substitution":
        checkpoint_body["validator_set_hash"] = label_hash(case_id)
    elif case_id == "checkpoint_parameters_substitution":
        checkpoint_body["consensus_parameters_hash"] = label_hash(case_id)
    elif case_id == "checkpoint_state_substitution":
        checkpoint_body["application_state_root"] = label_hash(case_id)
    elif case_id == "checkpoint_policy_substitution":
        checkpoint_body["snapshot_policy_hash"] = label_hash(case_id)
    elif case_id == "checkpoint_next_descriptor_substitution":
        checkpoint_body["next_epoch_descriptor_id"] = label_hash(case_id)
        checkpoint["checkpoint_id"] = digest(EPOCH_CHECKPOINT_DOMAIN, enc_checkpoint_body(checkpoint_body))
        transition["checkpoint_attachment"]["checkpoint_id"] = checkpoint["checkpoint_id"]
    elif case_id == "checkpoint_upgrade_present":
        checkpoint_body["upgrade_plan_id"] = label_hash(case_id)
    elif case_id == "checkpoint_id_substitution":
        checkpoint["checkpoint_id"] = label_hash(case_id)
    elif case_id == "attachment_checkpoint_substitution":
        transition["checkpoint_attachment"]["checkpoint_id"] = label_hash(case_id)
    elif case_id == "attachment_proof_substitution":
        transition["checkpoint_attachment"]["order_finality_proof"]["target_height"] += 1
    elif case_id == "new_context_lineage_substitution":
        new_descriptor["body"]["context"]["chain_id"] = "wrong-successor-chain"
    elif case_id == "new_validator_set_epoch_substitution":
        transition["new_validator_set"]["epoch"] += 1
    elif case_id == "new_descriptor_set_substitution":
        new_descriptor["body"]["validator_set_hash"] = label_hash(case_id)
    elif case_id == "new_descriptor_parameters_substitution":
        new_descriptor["body"]["consensus_parameters_hash"] = label_hash(case_id)
    elif case_id == "new_descriptor_id_substitution":
        new_descriptor["epoch_descriptor_id"] = label_hash(case_id)
    elif case_id == "handoff_source_context_substitution":
        handoff_body["source_context"]["stack_profile_hash"] = label_hash(case_id)
    elif case_id == "handoff_target_context_substitution":
        handoff_body["target_context"]["stack_profile_hash"] = label_hash(case_id)
    elif case_id == "handoff_epoch_substitution":
        handoff_body["new_epoch"] += 1
    elif case_id == "handoff_checkpoint_substitution":
        handoff_body["old_epoch_checkpoint_id"] = label_hash(case_id)
    elif case_id == "handoff_old_descriptor_substitution":
        handoff_body["old_epoch_descriptor_id"] = label_hash(case_id)
    elif case_id == "handoff_new_descriptor_substitution":
        handoff_body["new_epoch_descriptor_id"] = label_hash(case_id)
    elif case_id == "handoff_old_set_substitution":
        handoff_body["old_validator_set_hash"] = label_hash(case_id)
    elif case_id == "handoff_new_set_substitution":
        handoff_body["new_validator_set_hash"] = label_hash(case_id)
    elif case_id == "handoff_old_parameters_substitution":
        handoff_body["old_consensus_parameters_hash"] = label_hash(case_id)
    elif case_id == "handoff_new_parameters_substitution":
        handoff_body["new_consensus_parameters_hash"] = label_hash(case_id)
    elif case_id == "handoff_terminal_block_substitution":
        handoff_body["terminal_block_id"] = label_hash(case_id)
    elif case_id == "handoff_terminal_height_substitution":
        handoff_body["terminal_height"] += 1
    elif case_id == "handoff_terminal_view_substitution":
        handoff_body["terminal_view"] += 1
    elif case_id == "handoff_activation_height_substitution":
        handoff_body["activation_height"] += 1
    elif case_id == "handoff_initial_view_substitution":
        handoff_body["initial_new_view"] += 1
    elif case_id == "handoff_id_substitution":
        handoff["handoff_id"] = label_hash(case_id)
    elif case_id == "old_role_tag_substitution":
        handoff["old_set_signatures"][0]["role"] = 1
    elif case_id == "new_role_tag_substitution":
        handoff["new_set_signatures"][0]["role"] = 0
    elif case_id == "old_role_context_substitution":
        handoff["old_set_signatures"][0]["statement"]["consensus_context"]["context"]["chain_id"] = "wrong-old-role-chain"
    elif case_id == "new_role_context_substitution":
        handoff["new_set_signatures"][0]["statement"]["consensus_context"]["context"]["chain_id"] = "wrong-new-role-chain"
    elif case_id == "old_role_authority_substitution":
        handoff["old_set_signatures"][0]["statement"]["consensus_context"]["runtime_profile_hash"] = label_hash(case_id)
    elif case_id == "new_role_authority_substitution":
        handoff["new_set_signatures"][0]["statement"]["consensus_context"]["runtime_profile_hash"] = label_hash(case_id)
    elif case_id == "old_role_duplicate_signer":
        handoff["old_set_signatures"][1] = copy.deepcopy(handoff["old_set_signatures"][0])
    elif case_id == "new_role_duplicate_signer":
        handoff["new_set_signatures"][1] = copy.deepcopy(handoff["new_set_signatures"][0])
    elif case_id == "old_role_under_quorum":
        handoff["old_set_signatures"] = handoff["old_set_signatures"][:2]
    elif case_id == "new_role_under_quorum":
        handoff["new_set_signatures"] = handoff["new_set_signatures"][:2]
    elif case_id == "old_role_signature_bitflip":
        signature = bytearray(handoff["old_set_signatures"][0]["signature"])
        signature[7] ^= 1
        handoff["old_set_signatures"][0]["signature"] = bytes(signature)
    elif case_id == "new_role_signature_bitflip":
        signature = bytearray(handoff["new_set_signatures"][0]["signature"])
        signature[7] ^= 1
        handoff["new_set_signatures"][0]["signature"] = bytes(signature)
    elif case_id == "handoff_first_kind_substitution":
        new_chain[0]["header"]["block_kind"] = "Ordinary"
    elif case_id == "handoff_first_parent_substitution":
        new_chain[0]["header"]["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash(case_id)}}
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_height_substitution":
        new_chain[0]["header"]["height"] += 1
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_view_substitution":
        new_chain[0]["header"]["view"] += 1
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_justify_present":
        new_chain[0]["header"]["justify_qc_id"] = label_hash(case_id)
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_epoch_substitution":
        new_chain[0]["header"]["epoch"] += 1
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_handoff_substitution":
        new_chain[0]["header"]["epoch_handoff_id"] = label_hash(case_id)
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_state_substitution":
        new_chain[0]["header"]["post_state_root"] = label_hash(case_id)
        resign_transition_new_item(transition, 0)
    elif case_id == "handoff_first_payload_substitution":
        new_chain[0]["header"]["batch_refs_root"] = label_hash(case_id)
        resign_transition_new_item(transition, 0)
    elif case_id == "ordinary_parent_substitution":
        new_chain[1]["header"]["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash(case_id)}}
        resign_transition_new_item(transition, 1)
    elif case_id == "ordinary_height_substitution":
        new_chain[1]["header"]["height"] += 1
        resign_transition_new_item(transition, 1)
    elif case_id == "ordinary_view_substitution":
        new_chain[1]["header"]["view"] += 1
        resign_transition_new_item(transition, 1)
    elif case_id == "ordinary_justify_substitution":
        new_chain[1]["header"]["justify_qc_id"] = label_hash(case_id)
        resign_transition_new_item(transition, 1)
    elif case_id == "ordinary_epoch_substitution":
        new_chain[1]["header"]["epoch"] += 1
        resign_transition_new_item(transition, 1)
    elif case_id == "ordinary_handoff_present":
        new_chain[1]["header"]["epoch_handoff_id"] = label_hash(case_id)
        resign_transition_new_item(transition, 1)
    elif case_id == "new_epoch_qc_signature_bitflip":
        qc = new_chain[1]["certifying_qc"]
        signature = bytearray(qc["body"]["signatures"][0]["signature"])
        signature[7] ^= 1
        qc["body"]["signatures"][0]["signature"] = bytes(signature)
        qc["quorum_certificate_id"] = digest(QC_DOMAIN, enc_qc_body(qc["body"]))
    else:
        reject("unknown_transition_negative", case_id)
    return enc_epoch_transition(transition)


ORDINARY_ADVANCE_NEGATIVE_SPECS = (
    ("advance_trailing_byte", "trailing_bytes"),
    ("advance_truncated", "truncated"),
    ("advance_schema_version", "ordinary_advance_schema"),
    ("advance_id_substitution", "ordinary_advance_id"),
    ("input_state_id_substitution", "trusted_state_id"),
    ("input_state_binding_substitution", "ordinary_advance_input_state"),
    ("chain_too_short", "ordinary_advance_chain_cardinality"),
    ("chain_kind_substitution", "ordinary_advance_chain_kinds"),
    ("header_context_substitution", "ordinary_advance_header_context"),
    ("header_epoch_substitution", "ordinary_advance_header_epoch"),
    ("header_descriptor_substitution", "ordinary_advance_header_descriptor"),
    ("header_proposer_substitution", "ordinary_advance_header_proposer"),
    ("header_sidecar_substitution", "ordinary_advance_header_sidecars"),
    ("block_id_substitution", "block_id"),
    ("qc_id_substitution", "qc_id"),
    ("vote_context_substitution", "vote_context"),
    ("vote_authority_substitution", "vote_authority"),
    ("vote_view_substitution", "vote_view"),
    ("vote_header_identity_substitution", "vote_header_identity"),
    ("vote_root_substitution", "vote_header_roots"),
    ("qc_signer_order", "qc_signer_order"),
    ("qc_duplicate_signer", "qc_signer_order"),
    ("qc_unknown_signer", "qc_unknown_signer"),
    ("qc_wrong_scheme", "qc_signature_scheme"),
    ("qc_signature_bitflip", "qc_signature"),
    ("qc_under_quorum", "qc_quorum"),
    ("first_parent_substitution", "ordinary_advance_first_parent"),
    ("first_height_substitution", "ordinary_advance_first_height"),
    ("first_view_substitution", "ordinary_advance_first_view"),
    ("first_justify_substitution", "ordinary_advance_first_justify"),
    ("first_tc_present", "ordinary_advance_first_tc_absent"),
    ("chain_parent_substitution", "ordinary_advance_chain_parent"),
    ("chain_height_substitution", "ordinary_advance_chain_height"),
    ("chain_justify_substitution", "ordinary_advance_chain_justify"),
    ("view_gap_too_large", "ordinary_advance_single_skipped_view"),
    ("skipped_view_missing_tc", "ordinary_advance_missing_tc"),
    ("consecutive_view_unexpected_tc", "ordinary_advance_unexpected_tc"),
    ("header_tc_id_substitution", "ordinary_advance_header_tc_id"),
    ("tc_id_substitution", "tc_id"),
    ("tc_context_substitution", "tc_context"),
    ("tc_authority_substitution", "tc_authority"),
    ("tc_target_substitution", "tc_target_view"),
    ("tc_justification_substitution", "tc_justification_inventory"),
    ("tc_signer_order", "tc_signer_order"),
    ("timeout_high_substitution", "timeout_high_justification"),
    ("timeout_lock_substitution", "timeout_locked_qc"),
    ("timeout_anchor_substitution", "timeout_finalized_anchor"),
    ("tc_signature_bitflip", "tc_signature"),
    ("tc_under_quorum", "tc_quorum"),
    ("second_tc_present", "ordinary_advance_tc_count"),
    ("output_finalized_height_rollback", "ordinary_advance_output_height"),
    ("output_state_substitution", "ordinary_advance_output_state"),
)
ORDINARY_ADVANCE_NEGATIVE_IDS = tuple(
    case_id for case_id, _ in ORDINARY_ADVANCE_NEGATIVE_SPECS
)
EXPECTED_ORDINARY_ADVANCE_NEGATIVE_CODES = dict(ORDINARY_ADVANCE_NEGATIVE_SPECS)


def resign_ordinary_advance_item(advance: dict[str, Any], index: int) -> None:
    item = advance["certified_chain"][index]
    current = advance["input_state"]
    meta = validate_trusted_order_state(current)
    body = current["epoch_descriptor"]["body"]
    item["block_id"] = digest(BLOCK_DOMAIN, enc_header(item["header"]))
    item["certifying_qc"] = make_qc(
        item["header"], item["block_id"],
        runtime_profile_hash=body["runtime_profile_hash"],
        validator_set_hash=meta["validator_set_hash"],
        parameters_hash=meta["parameters_hash"],
        validators=current["validator_set"]["definition"]["members"],
    )


def refresh_ordinary_advance_tc(advance: dict[str, Any], index: int) -> None:
    item = advance["certified_chain"][index]
    tc = item["timeout_certificate"]
    require(tc is not None, "ordinary_advance_mutation_tc_fixture")
    tc["timeout_certificate_id"] = digest(TC_DOMAIN, enc_tc_body(tc["body"]))
    item["header"]["timeout_certificate_id"] = tc["timeout_certificate_id"]
    resign_ordinary_advance_item(advance, index)


def mutation_ordinary_advance_case(
    case_id: str, advance_raw: bytes, *, replacement_state: dict[str, Any],
    fresh_genesis_derived_state_hash: bytes,
) -> bytes:
    if case_id == "advance_trailing_byte":
        return advance_raw + b"\x00"
    if case_id == "advance_truncated":
        return advance_raw[:-1]
    advance = decode_exact(
        advance_raw, "ordinary_advance_mutation", dec_ordinary_advance,
        enc_ordinary_advance,
    )
    chain = advance["certified_chain"]
    reseal_id = True
    if case_id == "advance_schema_version":
        advance["schema_version"] = 2
    elif case_id == "advance_id_substitution":
        advance["advance_id"] = label_hash(case_id)
        reseal_id = False
    elif case_id == "input_state_id_substitution":
        advance["input_state"]["state_id"] = label_hash(case_id)
    elif case_id == "input_state_binding_substitution":
        advance["input_state"] = copy.deepcopy(replacement_state)
    elif case_id == "chain_too_short":
        advance["certified_chain"] = chain[:2]
    elif case_id == "chain_kind_substitution":
        chain[0]["header"]["block_kind"] = "EpochCheckpoint"
    elif case_id == "header_context_substitution":
        chain[0]["header"]["context"]["chain_id"] = "wrong-ordinary-advance-chain"
    elif case_id == "header_epoch_substitution":
        chain[0]["header"]["epoch"] += 1
    elif case_id == "header_descriptor_substitution":
        chain[0]["header"]["epoch_descriptor_id"] = label_hash(case_id)
    elif case_id == "header_proposer_substitution":
        chain[0]["header"]["proposer_id"] = b"unknown-ordinary-proposer"
    elif case_id == "header_sidecar_substitution":
        chain[0]["header"]["upgrade_plan_id"] = label_hash(case_id)
    elif case_id == "block_id_substitution":
        chain[0]["block_id"] = label_hash(case_id)
    elif case_id == "qc_id_substitution":
        chain[0]["certifying_qc"]["quorum_certificate_id"] = label_hash(case_id)
    elif case_id in {
        "vote_context_substitution", "vote_authority_substitution",
        "vote_view_substitution", "vote_header_identity_substitution",
        "vote_root_substitution", "qc_signer_order", "qc_duplicate_signer",
        "qc_unknown_signer", "qc_wrong_scheme", "qc_signature_bitflip",
        "qc_under_quorum",
    }:
        qc = chain[0]["certifying_qc"]
        body = qc["body"]
        vote = body["statement"]
        signatures = body["signatures"]
        if case_id == "vote_context_substitution":
            vote["consensus_context"]["context"]["chain_id"] = "wrong-vote-chain"
        elif case_id == "vote_authority_substitution":
            vote["consensus_context"]["runtime_profile_hash"] = label_hash(case_id)
        elif case_id == "vote_view_substitution":
            vote["consensus_context"]["view"] += 1
        elif case_id == "vote_header_identity_substitution":
            vote["height"] += 1
        elif case_id == "vote_root_substitution":
            vote["post_state_root"] = label_hash(case_id)
        elif case_id == "qc_signer_order":
            signatures[0], signatures[1] = signatures[1], signatures[0]
        elif case_id == "qc_duplicate_signer":
            signatures[1]["voter_id"] = signatures[0]["voter_id"]
        elif case_id == "qc_unknown_signer":
            signatures[-1]["voter_id"] = b"zz-unknown-validator"
        elif case_id == "qc_wrong_scheme":
            signatures[0]["signature_scheme"] = 1
        elif case_id == "qc_signature_bitflip":
            changed = bytearray(signatures[0]["signature"])
            changed[7] ^= 1
            signatures[0]["signature"] = bytes(changed)
        else:
            body["signatures"] = signatures[:2]
        qc["quorum_certificate_id"] = digest(QC_DOMAIN, enc_qc_body(body))
    elif case_id in {
        "first_parent_substitution", "first_height_substitution",
        "first_view_substitution", "first_justify_substitution", "first_tc_present",
    }:
        first = chain[0]
        header = first["header"]
        if case_id == "first_parent_substitution":
            header["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash(case_id)}}
        elif case_id == "first_height_substitution":
            header["height"] += 1
        elif case_id == "first_view_substitution":
            header["view"] += 1
        elif case_id == "first_justify_substitution":
            header["justify_qc_id"] = label_hash(case_id)
        else:
            first["timeout_certificate"] = copy.deepcopy(chain[1]["timeout_certificate"])
            header["timeout_certificate_id"] = first["timeout_certificate"]["timeout_certificate_id"]
        resign_ordinary_advance_item(advance, 0)
    elif case_id in {
        "chain_parent_substitution", "chain_height_substitution",
        "chain_justify_substitution", "view_gap_too_large",
        "skipped_view_missing_tc", "consecutive_view_unexpected_tc",
        "header_tc_id_substitution",
    }:
        item = chain[1]
        header = item["header"]
        if case_id == "chain_parent_substitution":
            header["parent"] = {"variant": "V1Block", "value": {"block_id": label_hash(case_id)}}
        elif case_id == "chain_height_substitution":
            header["height"] += 1
        elif case_id == "chain_justify_substitution":
            header["justify_qc_id"] = label_hash(case_id)
        elif case_id == "view_gap_too_large":
            header["view"] = chain[0]["header"]["view"] + 3
        elif case_id == "skipped_view_missing_tc":
            item["timeout_certificate"] = None
            header["timeout_certificate_id"] = None
        elif case_id == "consecutive_view_unexpected_tc":
            header["view"] = chain[0]["header"]["view"] + 1
        else:
            header["timeout_certificate_id"] = label_hash(case_id)
        resign_ordinary_advance_item(advance, 1)
    elif case_id in {
        "tc_id_substitution", "tc_context_substitution", "tc_authority_substitution",
        "tc_target_substitution", "tc_justification_substitution", "tc_signer_order",
        "timeout_high_substitution", "timeout_lock_substitution",
        "timeout_anchor_substitution", "tc_signature_bitflip", "tc_under_quorum",
    }:
        tc = chain[1]["timeout_certificate"]
        require(tc is not None, "ordinary_advance_mutation_tc_fixture")
        body = tc["body"]
        entries = body["entries"]
        if case_id == "tc_id_substitution":
            tc["timeout_certificate_id"] = label_hash(case_id)
            chain[1]["header"]["timeout_certificate_id"] = tc["timeout_certificate_id"]
            resign_ordinary_advance_item(advance, 1)
        else:
            if case_id == "tc_context_substitution":
                body["context"]["chain_id"] = "wrong-tc-chain"
            elif case_id == "tc_authority_substitution":
                body["runtime_profile_hash"] = label_hash(case_id)
            elif case_id == "tc_target_substitution":
                body["target_view"] += 1
            elif case_id == "tc_justification_substitution":
                body["justifications"][0]["value"]["quorum_certificate_id"] = label_hash(case_id)
            elif case_id == "tc_signer_order":
                entries[0], entries[1] = entries[1], entries[0]
            elif case_id == "timeout_high_substitution":
                entries[0]["statement"]["high_justification"]["value"]["qc_id"] = label_hash(case_id)
            elif case_id == "timeout_lock_substitution":
                entries[0]["statement"]["locked_qc_id"] = label_hash(case_id)
            elif case_id == "timeout_anchor_substitution":
                entries[0]["statement"]["last_finalized_anchor"]["value"]["genesis_derived_state_hash"] = label_hash(case_id)
            elif case_id == "tc_signature_bitflip":
                changed = bytearray(entries[0]["signature"])
                changed[7] ^= 1
                entries[0]["signature"] = bytes(changed)
            else:
                body["entries"] = entries[:2]
            refresh_ordinary_advance_tc(advance, 1)
    elif case_id == "second_tc_present":
        item = chain[2]
        previous = chain[1]
        previous_view = previous["header"]["view"]
        item["header"]["view"] = previous_view + 2
        meta = validate_trusted_order_state(advance["input_state"])
        descriptor_body = advance["input_state"]["epoch_descriptor"]["body"]
        item["timeout_certificate"] = make_tc(
            context=advance["input_state"]["context"],
            epoch=advance["input_state"]["epoch"], timed_out_view=previous_view + 1,
            runtime_profile_hash=descriptor_body["runtime_profile_hash"],
            validator_set_hash=meta["validator_set_hash"],
            parameters_hash=meta["parameters_hash"],
            previous_qc=previous["certifying_qc"], previous_view=previous_view,
            genesis_derived_state_hash=fresh_genesis_derived_state_hash,
            validators=advance["input_state"]["validator_set"]["definition"]["members"],
        )
        item["header"]["timeout_certificate_id"] = item["timeout_certificate"]["timeout_certificate_id"]
        resign_ordinary_advance_item(advance, 2)
    elif case_id == "output_finalized_height_rollback":
        advance["output_state"]["finalized_height"] = advance["input_state"]["finalized_height"]
        seal_trusted_order_state(advance["output_state"])
    elif case_id == "output_state_substitution":
        advance["output_state"]["latest_handoff_id"] = label_hash(case_id)
        seal_trusted_order_state(advance["output_state"])
    else:
        reject("unknown_ordinary_advance_negative", case_id)
    if reseal_id:
        advance["advance_id"] = digest(
            ORDINARY_FINALITY_ADVANCE_DOMAIN, enc_ordinary_advance_body(advance),
        )
    return enc_ordinary_advance(advance)


TRUST_PATH_NEGATIVE_SPECS = (
    ("path_trailing_byte", "trailing_bytes"),
    ("path_truncated", "truncated"),
    ("path_schema_version", "trust_path_schema"),
    ("path_id_substitution", "trust_path_id"),
    ("path_step_count_bound", "trust_path_steps_bound"),
    ("path_unknown_step_variant", "trust_path_step_variant"),
    ("path_step0_checkpoint_variant", "trust_path_step0_variant"),
    ("path_repeated_fresh_genesis_step", "trust_path_step_order"),
    ("path_step0_trailing", "trailing_bytes"),
    ("path_step0_truncated", "truncated"),
    ("initial_state_id_substitution", "trusted_state_id"),
    ("initial_context_substitution", "trusted_state_descriptor_context"),
    ("initial_epoch_substitution", "trusted_state_descriptor_context"),
    ("initial_head_block_substitution", "trusted_state_certified_head_block_id"),
    ("initial_head_qc_substitution", "trust_path_initial_state_binding"),
    ("initial_checkpoint_present", "trust_path_initial_sidecars"),
    ("checkpoint_step_trailing", "trailing_bytes"),
    ("checkpoint_step_truncated", "truncated"),
    ("checkpoint_step_schema_version", "checkpoint_step_schema"),
    ("checkpoint_step_input_state_substitution", "checkpoint_step_input_state"),
    ("checkpoint_chain_too_short", "checkpoint_step_chain_cardinality"),
    ("checkpoint_chain_kind_substitution", "checkpoint_step_chain_kinds"),
    ("checkpoint_chain_parent_substitution", "checkpoint_step_chain_parent"),
    ("checkpoint_chain_height_substitution", "checkpoint_step_chain_height"),
    ("checkpoint_chain_view_substitution", "checkpoint_step_chain_view"),
    ("checkpoint_chain_justify_substitution", "checkpoint_step_chain_justify"),
    ("checkpoint_header_context_substitution", "checkpoint_step_header_context"),
    ("checkpoint_header_epoch_substitution", "checkpoint_step_header_epoch"),
    ("checkpoint_header_descriptor_substitution", "checkpoint_step_header_descriptor"),
    ("checkpoint_header_state_substitution", "checkpoint_step_state"),
    ("checkpoint_header_sidecar_substitution", "checkpoint_step_header_sidecars"),
    ("checkpoint_qc_authority_substitution", "vote_authority"),
    ("checkpoint_qc_signature_bitflip", "qc_signature"),
    ("checkpoint_object_target_substitution", "checkpoint_step_checkpoint_target"),
    ("checkpoint_object_id_substitution", "checkpoint_step_checkpoint_id"),
    ("checkpoint_object_next_descriptor_substitution", "checkpoint_step_checkpoint_next_descriptor"),
    ("successor_context_lineage_substitution", "checkpoint_step_context_lineage"),
    ("successor_epoch_substitution", "checkpoint_step_epoch_progression"),
    ("successor_descriptor_set_substitution", "checkpoint_step_descriptor_set"),
    ("handoff_terminal_substitution", "checkpoint_step_handoff_terminal"),
    ("handoff_activation_substitution", "checkpoint_step_handoff_activation"),
    ("old_handoff_signature_bitflip", "old_handoff_signature"),
    ("new_handoff_under_quorum", "new_handoff_quorum"),
    ("new_first_handoff_sidecar_root_empty", "checkpoint_step_new_first_handoff_sidecar_root"),
    ("new_first_handoff_sidecar_root_wrong", "checkpoint_step_new_first_handoff_sidecar_root"),
    ("new_first_handoff_sidecar_root_different_wrapper", "checkpoint_step_new_first_handoff_sidecar_root"),
    ("epoch_start_skipped_view_without_tc", "checkpoint_step_epoch_start_tc_missing"),
    ("epoch_start_tc_header_id_substitution", "checkpoint_step_epoch_start_tc_header_id"),
    ("epoch_start_tc_wrong_target", "epoch_start_tc_immediate_target"),
    ("epoch_start_tc_qc_safe_parent", "epoch_start_tc_justification_inventory"),
    ("epoch_start_tc_wrong_handoff_id", "epoch_start_timeout_high_justification"),
    ("epoch_start_tc_locked_qc_present", "epoch_start_timeout_lock_absent"),
    ("epoch_start_tc_wrong_finalized_checkpoint", "epoch_start_timeout_finalized_anchor"),
    ("epoch_start_tc_signature_bitflip", "epoch_start_tc_signature"),
    ("epoch_start_tc_under_quorum", "epoch_start_tc_quorum"),
    ("epoch_start_tc_on_initial_view", "checkpoint_step_epoch_start_initial_tc_absent"),
    ("epoch_start_view_gap_too_large", "checkpoint_step_epoch_start_single_skipped_view"),
    ("new_first_parent_substitution", "checkpoint_step_new_first_parent"),
    ("output_state_substitution", "checkpoint_step_output_state"),
    ("output_finalized_height_rollback", "checkpoint_step_output_height"),
    ("checkpoint_step_id_substitution", "checkpoint_step_id"),
    ("intermediate_step_reordered", "checkpoint_step_input_state"),
    ("intermediate_step_duplicated", "checkpoint_step_input_state"),
)
TRUST_PATH_NEGATIVE_IDS = tuple(case_id for case_id, _ in TRUST_PATH_NEGATIVE_SPECS)
EXPECTED_TRUST_PATH_NEGATIVE_CODES = dict(TRUST_PATH_NEGATIVE_SPECS)


def mutation_trust_path_case(case_id: str, path_raw: bytes) -> bytes:
    if case_id == "path_trailing_byte":
        return path_raw + b"\x00"
    if case_id == "path_truncated":
        return path_raw[:-1]
    path = decode_exact(path_raw, "trust_path_mutation", dec_trust_path, enc_trust_path)
    if case_id == "path_unknown_step_variant":
        tag_offset = 2 + len(enc_trusted_order_state(path["initial_state"])) + 4
        changed = bytearray(path_raw)
        changed[tag_offset] = 9
        return bytes(changed)
    if case_id == "path_schema_version":
        path["schema_version"] = 2
    elif case_id == "path_id_substitution":
        path["path_id"] = label_hash(case_id)
        return enc_trust_path(path)
    elif case_id == "path_step_count_bound":
        path["steps"].append(copy.deepcopy(path["steps"][-1]))
    elif case_id == "path_step0_checkpoint_variant":
        path["steps"][0]["variant"] = "CheckpointAnchoredTransition"
    elif case_id == "path_repeated_fresh_genesis_step":
        path["steps"][1] = copy.deepcopy(path["steps"][0])
    elif case_id == "path_step0_trailing":
        path["steps"][0]["raw_step_cev1"] += b"\x00"
    elif case_id == "path_step0_truncated":
        path["steps"][0]["raw_step_cev1"] = path["steps"][0]["raw_step_cev1"][:-1]
    elif case_id == "initial_state_id_substitution":
        path["initial_state"]["state_id"] = label_hash(case_id)
    elif case_id == "initial_context_substitution":
        path["initial_state"]["context"]["chain_id"] = "wrong-initial-chain"
        seal_trusted_order_state(path["initial_state"])
    elif case_id == "initial_epoch_substitution":
        path["initial_state"]["epoch"] += 1
        seal_trusted_order_state(path["initial_state"])
    elif case_id == "initial_head_block_substitution":
        path["initial_state"]["certified_head_block_id"] = label_hash(case_id)
        seal_trusted_order_state(path["initial_state"])
    elif case_id == "initial_head_qc_substitution":
        path["initial_state"]["certified_head_qc_id"] = label_hash(case_id)
        seal_trusted_order_state(path["initial_state"])
    elif case_id == "initial_checkpoint_present":
        path["initial_state"]["latest_checkpoint_id"] = label_hash(case_id)
        seal_trusted_order_state(path["initial_state"])
    elif case_id == "intermediate_step_reordered":
        path["steps"][1], path["steps"][2] = path["steps"][2], path["steps"][1]
    elif case_id == "intermediate_step_duplicated":
        path["steps"][2] = copy.deepcopy(path["steps"][1])
    else:
        epoch_start_tc_cases = {
            "epoch_start_skipped_view_without_tc",
            "epoch_start_tc_header_id_substitution",
            "epoch_start_tc_wrong_target",
            "epoch_start_tc_qc_safe_parent",
            "epoch_start_tc_wrong_handoff_id",
            "epoch_start_tc_locked_qc_present",
            "epoch_start_tc_wrong_finalized_checkpoint",
            "epoch_start_tc_signature_bitflip",
            "epoch_start_tc_under_quorum",
            "epoch_start_tc_on_initial_view",
            "epoch_start_view_gap_too_large",
        }
        carrier = path["steps"][2 if case_id in epoch_start_tc_cases else 1]
        raw_step = carrier["raw_step_cev1"]
        if case_id == "checkpoint_step_trailing":
            carrier["raw_step_cev1"] = raw_step + b"\x00"
            seal_order_trust_path(path)
            return enc_trust_path(path)
        if case_id == "checkpoint_step_truncated":
            carrier["raw_step_cev1"] = raw_step[:-1]
            seal_order_trust_path(path)
            return enc_trust_path(path)
        step = decode_exact(
            raw_step, "checkpoint_step_mutation", dec_checkpoint_transition_step,
            enc_checkpoint_transition_step,
        )
        checkpoint_chain = step["checkpoint_certified_chain"]
        checkpoint_body = step["checkpoint"]["body"]
        handoff = step["handoff"]
        handoff_body = handoff["body"]
        new_chain = step["new_epoch_certified_chain"]
        if case_id == "checkpoint_step_schema_version":
            step["schema_version"] = 2
        elif case_id == "checkpoint_step_input_state_substitution":
            step["input_state_id"] = label_hash(case_id)
        elif case_id == "checkpoint_chain_too_short":
            step["checkpoint_certified_chain"] = checkpoint_chain[:2]
        elif case_id == "checkpoint_chain_kind_substitution":
            checkpoint_chain[0]["header"]["block_kind"] = "Ordinary"
        elif case_id == "checkpoint_chain_parent_substitution":
            checkpoint_chain[0]["header"]["parent"] = {
                "variant": "V1Block", "value": {"block_id": label_hash(case_id)},
            }
        elif case_id == "checkpoint_chain_height_substitution":
            checkpoint_chain[0]["header"]["height"] += 1
        elif case_id == "checkpoint_chain_view_substitution":
            checkpoint_chain[0]["header"]["view"] += 1
        elif case_id == "checkpoint_chain_justify_substitution":
            checkpoint_chain[0]["header"]["justify_qc_id"] = label_hash(case_id)
        elif case_id == "checkpoint_header_context_substitution":
            checkpoint_chain[0]["header"]["context"]["chain_id"] = "wrong-checkpoint-chain"
        elif case_id == "checkpoint_header_epoch_substitution":
            checkpoint_chain[0]["header"]["epoch"] += 1
        elif case_id == "checkpoint_header_descriptor_substitution":
            checkpoint_chain[0]["header"]["epoch_descriptor_id"] = label_hash(case_id)
        elif case_id == "checkpoint_header_state_substitution":
            checkpoint_chain[0]["header"]["post_state_root"] = label_hash(case_id)
        elif case_id == "checkpoint_header_sidecar_substitution":
            checkpoint_chain[0]["header"]["next_epoch_descriptor_id"] = label_hash(case_id)
        elif case_id == "checkpoint_qc_authority_substitution":
            qc = checkpoint_chain[0]["certifying_qc"]
            qc["body"]["statement"]["consensus_context"]["runtime_profile_hash"] = label_hash(case_id)
            qc["quorum_certificate_id"] = digest(QC_DOMAIN, enc_qc_body(qc["body"]))
        elif case_id == "checkpoint_qc_signature_bitflip":
            qc = checkpoint_chain[0]["certifying_qc"]
            signature = bytearray(qc["body"]["signatures"][0]["signature"])
            signature[7] ^= 1
            qc["body"]["signatures"][0]["signature"] = bytes(signature)
            qc["quorum_certificate_id"] = digest(QC_DOMAIN, enc_qc_body(qc["body"]))
        elif case_id == "checkpoint_object_target_substitution":
            checkpoint_body["checkpoint_block_id"] = label_hash(case_id)
        elif case_id == "checkpoint_object_id_substitution":
            step["checkpoint"]["checkpoint_id"] = label_hash(case_id)
        elif case_id == "checkpoint_object_next_descriptor_substitution":
            checkpoint_body["next_epoch_descriptor_id"] = label_hash(case_id)
        elif case_id == "successor_context_lineage_substitution":
            step["new_epoch_descriptor"]["body"]["context"]["chain_id"] = "wrong-successor-chain"
        elif case_id == "successor_epoch_substitution":
            step["new_epoch_descriptor"]["body"]["epoch"] += 1
        elif case_id == "successor_descriptor_set_substitution":
            step["new_epoch_descriptor"]["body"]["validator_set_hash"] = label_hash(case_id)
        elif case_id == "handoff_terminal_substitution":
            handoff_body["terminal_block_id"] = label_hash(case_id)
        elif case_id == "handoff_activation_substitution":
            handoff_body["activation_height"] += 1
        elif case_id == "old_handoff_signature_bitflip":
            signature = bytearray(handoff["old_set_signatures"][0]["signature"])
            signature[7] ^= 1
            handoff["old_set_signatures"][0]["signature"] = bytes(signature)
        elif case_id == "new_handoff_under_quorum":
            handoff["new_set_signatures"] = handoff["new_set_signatures"][:1]
        elif case_id in {
            "new_first_handoff_sidecar_root_empty",
            "new_first_handoff_sidecar_root_wrong",
            "new_first_handoff_sidecar_root_different_wrapper",
        }:
            if case_id == "new_first_handoff_sidecar_root_empty":
                root = empty_ordered_root(PROTOCOL_OBJECTS_ROOT_KIND)
            elif case_id == "new_first_handoff_sidecar_root_wrong":
                root = label_hash(case_id)
            else:
                different_wrapper = copy.deepcopy(handoff)
                different_wrapper["old_set_signatures"] = different_wrapper["old_set_signatures"][:3]
                root = epoch_handoff_protocol_objects_root(different_wrapper)
            new_chain[0]["header"]["protocol_objects_root"] = root
            descriptor_body = step["new_epoch_descriptor"]["body"]
            new_chain[0]["block_id"] = digest(BLOCK_DOMAIN, enc_header(new_chain[0]["header"]))
            new_chain[0]["certifying_qc"] = make_qc(
                new_chain[0]["header"], new_chain[0]["block_id"],
                runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                validator_set_hash=descriptor_body["validator_set_hash"],
                parameters_hash=descriptor_body["consensus_parameters_hash"],
                validators=step["new_validator_set"]["definition"]["members"],
            )
        elif case_id in epoch_start_tc_cases:
            first = new_chain[0]
            header = first["header"]
            tc = first["timeout_certificate"]
            require(tc is not None, "epoch_start_tc_mutation_fixture")
            body = tc["body"]
            entries = body["entries"]
            if case_id == "epoch_start_skipped_view_without_tc":
                first["timeout_certificate"] = None
                header["timeout_certificate_id"] = None
            elif case_id == "epoch_start_tc_header_id_substitution":
                header["timeout_certificate_id"] = label_hash(case_id)
            elif case_id == "epoch_start_tc_wrong_target":
                body["target_view"] += 1
            elif case_id == "epoch_start_tc_qc_safe_parent":
                body["justifications"] = [{
                    "variant": "QC",
                    "value": copy.deepcopy(first["certifying_qc"]),
                }]
            elif case_id == "epoch_start_tc_wrong_handoff_id":
                entries[0]["statement"]["high_justification"]["value"]["anchor_id"] = label_hash(case_id)
            elif case_id == "epoch_start_tc_locked_qc_present":
                entries[0]["statement"]["locked_qc_id"] = label_hash(case_id)
                entries[0]["statement"]["locked_qc_view"] = 1
            elif case_id == "epoch_start_tc_wrong_finalized_checkpoint":
                entries[0]["statement"]["last_finalized_anchor"]["value"]["checkpoint_id"] = label_hash(case_id)
            elif case_id == "epoch_start_tc_signature_bitflip":
                signature = bytearray(entries[0]["signature"])
                signature[7] ^= 1
                entries[0]["signature"] = bytes(signature)
            elif case_id == "epoch_start_tc_under_quorum":
                body["entries"] = entries[:1]
            elif case_id == "epoch_start_tc_on_initial_view":
                header["view"] = step["handoff"]["body"]["initial_new_view"]
            elif case_id == "epoch_start_view_gap_too_large":
                header["view"] += 1
            tc["timeout_certificate_id"] = digest(TC_DOMAIN, enc_tc_body(body))
            if case_id not in {
                "epoch_start_skipped_view_without_tc",
                "epoch_start_tc_header_id_substitution",
                "epoch_start_tc_on_initial_view",
                "epoch_start_view_gap_too_large",
            }:
                header["timeout_certificate_id"] = tc["timeout_certificate_id"]
            descriptor_body = step["new_epoch_descriptor"]["body"]
            first["block_id"] = digest(BLOCK_DOMAIN, enc_header(header))
            first["certifying_qc"] = make_qc(
                header, first["block_id"],
                runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                validator_set_hash=descriptor_body["validator_set_hash"],
                parameters_hash=descriptor_body["consensus_parameters_hash"],
                validators=step["new_validator_set"]["definition"]["members"],
            )
        elif case_id == "new_first_parent_substitution":
            new_chain[0]["header"]["parent"] = {
                "variant": "V1Block", "value": {"block_id": label_hash(case_id)},
            }
            descriptor_body = step["new_epoch_descriptor"]["body"]
            new_chain[0]["block_id"] = digest(BLOCK_DOMAIN, enc_header(new_chain[0]["header"]))
            new_chain[0]["certifying_qc"] = make_qc(
                new_chain[0]["header"], new_chain[0]["block_id"],
                runtime_profile_hash=descriptor_body["runtime_profile_hash"],
                validator_set_hash=descriptor_body["validator_set_hash"],
                parameters_hash=descriptor_body["consensus_parameters_hash"],
                validators=step["new_validator_set"]["definition"]["members"],
            )
        elif case_id == "output_state_substitution":
            step["output_state"]["latest_checkpoint_id"] = label_hash(case_id)
            seal_trusted_order_state(step["output_state"])
        elif case_id == "output_finalized_height_rollback":
            step["output_state"]["finalized_height"] = path["initial_state"]["finalized_height"]
            seal_trusted_order_state(step["output_state"])
        elif case_id == "checkpoint_step_id_substitution":
            step["step_id"] = label_hash(case_id)
        else:
            reject("unknown_trust_path_negative", case_id)
        carrier["raw_step_cev1"] = enc_checkpoint_transition_step(step)
    seal_order_trust_path(path)
    return enc_trust_path(path)


def trust_path_result_json(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "path_id": result["path_id"].hex(), "hop_count": result["hop_count"],
        "initial_state_id": result["initial_state_id"].hex(),
        "terminal_state_id": result["terminal_state_id"].hex(),
        "initial_epoch": result["initial_epoch"], "terminal_epoch": result["terminal_epoch"],
        "initial_finalized_height": result["initial_finalized_height"],
        "terminal_finalized_height": result["terminal_finalized_height"],
        "step_ids": [value.hex() for value in result["step_ids"]],
        "qc_signatures_checked": result["qc_signatures_checked"],
        "tc_signatures_checked": result["tc_signatures_checked"],
        "handoff_signatures_checked": result["handoff_signatures_checked"],
        "raw_sha256": result["raw_sha256"].hex(),
    }


def mutation_weak_subjectivity_case(
    case_id: str, trust_path_raw: bytes, renewal_raw: bytes,
) -> tuple[bytes, bytes]:
    if case_id == "renewal_trailing_byte":
        return trust_path_raw, renewal_raw + b"\x00"
    if case_id == "renewal_truncated":
        return trust_path_raw, renewal_raw[:-1]

    renewal = decode_exact(
        renewal_raw, "weak_subjectivity_mutation", dec_weak_subjectivity_renewal,
        enc_weak_subjectivity_renewal,
    )
    path = decode_exact(
        trust_path_raw, "weak_subjectivity_mutation_path", dec_trust_path,
        enc_trust_path,
    )
    prior = renewal["prior_anchor"]
    renewed = renewal["renewed_anchor"]
    policy = renewal["policy"]

    reseal_prior = False
    reseal_renewed = False
    reseal_policy = False
    reseal_renewal = True

    if case_id == "renewal_schema_version":
        renewal["schema_version"] = 2
    elif case_id == "renewal_id_substitution":
        renewal["renewal_id"] = label_hash(case_id)
        reseal_renewal = False
    elif case_id == "prior_anchor_schema":
        prior["schema_version"] = 2
        reseal_prior = True
    elif case_id == "prior_anchor_id_substitution":
        prior["anchor_id"] = label_hash(case_id)
        reseal_renewal = False
    elif case_id == "renewed_anchor_schema":
        renewed["schema_version"] = 2
        reseal_renewed = True
    elif case_id == "renewed_anchor_id_substitution":
        renewed["anchor_id"] = label_hash(case_id)
        reseal_renewal = False
    elif case_id == "policy_schema":
        policy["schema_version"] = 2
        reseal_policy = True
    elif case_id == "policy_id_substitution":
        policy["policy_id"] = label_hash(case_id)
        reseal_renewal = False
    elif case_id == "policy_zero_epoch_age":
        policy["max_checkpoint_age_epochs"] = 0
        reseal_policy = True
    elif case_id == "policy_zero_block_age":
        policy["max_checkpoint_age_blocks"] = 0
        reseal_policy = True
    elif case_id == "policy_zero_minimum":
        policy["min_finalized_height_advance"] = 0
        reseal_policy = True
    elif case_id == "context_chain_mismatch":
        renewed["context"]["chain_id"] = "trnm-poco-ai-renewal-other-chain"
        reseal_renewed = True
    elif case_id == "context_genesis_mismatch":
        renewed["context"]["genesis_hash"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "context_protocol_mismatch":
        renewed["context"]["protocol_version"] = 0
        reseal_renewed = True
    elif case_id == "prior_context_substitution":
        prior["context"]["stack_profile_hash"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_checkpoint_id_substitution":
        prior["checkpoint_id"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_checkpoint_epoch_substitution":
        prior["checkpoint_epoch"] += 1
        reseal_prior = True
    elif case_id == "prior_checkpoint_height_substitution":
        prior["checkpoint_height"] += 1
        reseal_prior = True
    elif case_id == "prior_checkpoint_block_substitution":
        prior["checkpoint_block_id"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_validator_set_substitution":
        prior["validator_set_hash"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_parameters_substitution":
        prior["consensus_parameters_hash"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_application_root_substitution":
        prior["application_state_root"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "prior_state_schema_substitution":
        prior["state_schema_hash"] = label_hash(case_id)
        reseal_prior = True
    elif case_id == "terminal_state_substitution":
        earlier = decode_exact(
            path["steps"][-2]["raw_step_cev1"],
            "weak_subjectivity_mutation_earlier_step",
            dec_checkpoint_transition_step, enc_checkpoint_transition_step,
        )
        renewal["terminal_trusted_state"] = copy.deepcopy(earlier["output_state"])
    elif case_id == "terminal_checkpoint_substitution":
        earlier = decode_exact(
            path["steps"][-2]["raw_step_cev1"],
            "weak_subjectivity_mutation_earlier_checkpoint",
            dec_checkpoint_transition_step, enc_checkpoint_transition_step,
        )
        renewal["terminal_checkpoint"] = copy.deepcopy(earlier["checkpoint"])
    elif case_id == "renewed_context_substitution":
        renewed["context"]["stack_profile_hash"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_checkpoint_id_substitution":
        renewed["checkpoint_id"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_checkpoint_epoch_substitution":
        renewed["checkpoint_epoch"] += 1
        reseal_renewed = True
    elif case_id == "renewed_checkpoint_height_substitution":
        renewed["checkpoint_height"] += 1
        reseal_renewed = True
    elif case_id == "renewed_checkpoint_block_substitution":
        renewed["checkpoint_block_id"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_validator_set_substitution":
        renewed["validator_set_hash"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_parameters_substitution":
        renewed["consensus_parameters_hash"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_application_root_substitution":
        renewed["application_state_root"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "renewed_state_schema_substitution":
        renewed["state_schema_hash"] = label_hash(case_id)
        reseal_renewed = True
    elif case_id == "observed_epoch_substitution":
        renewal["observed_finalized_epoch"] -= 1
    elif case_id == "observed_height_substitution":
        renewal["observed_finalized_height"] -= 1
    elif case_id == "prior_age_epoch_exceeded":
        policy["max_checkpoint_age_epochs"] = 2
        reseal_policy = True
    elif case_id == "prior_age_block_exceeded":
        policy["max_checkpoint_age_blocks"] = 17
        reseal_policy = True
    elif case_id == "minimum_advance_exceeded":
        policy["min_finalized_height_advance"] = 15
        reseal_policy = True
    elif case_id == "renewed_epoch_rollback":
        renewed["checkpoint_epoch"] = prior["checkpoint_epoch"]
        reseal_renewed = True
    elif case_id == "renewed_height_rollback":
        renewed["checkpoint_height"] = prior["checkpoint_height"] - 1
        reseal_renewed = True
    elif case_id == "same_height_conflict":
        renewed["checkpoint_height"] = prior["checkpoint_height"]
        reseal_renewed = True
    elif case_id == "same_height_replay":
        renewed_epoch = renewed["checkpoint_epoch"]
        renewal["renewed_anchor"] = copy.deepcopy(prior)
        renewed = renewal["renewed_anchor"]
        renewed["checkpoint_epoch"] = renewed_epoch
        reseal_renewed = True
    else:
        reject("unknown_weak_subjectivity_negative", case_id)

    if reseal_prior:
        seal_weak_subjectivity_anchor(prior)
    if reseal_renewed:
        seal_weak_subjectivity_anchor(renewed)
    if reseal_policy:
        seal_weak_subjectivity_policy(policy)
    if reseal_renewal:
        seal_weak_subjectivity_renewal(renewal)
    return trust_path_raw, enc_weak_subjectivity_renewal(renewal)


def weak_subjectivity_result_json(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "renewal_id": result["renewal_id"].hex(),
        "prior_anchor_id": result["prior_anchor_id"].hex(),
        "renewed_anchor_id": result["renewed_anchor_id"].hex(),
        "prior_height": result["prior_height"],
        "renewed_height": result["renewed_height"],
        "observed_epoch": result["observed_epoch"],
        "observed_height": result["observed_height"],
        "policy_id": result["policy_id"].hex(),
    }


def ordinary_advance_result_json(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "advance_id": result["advance_id"].hex(),
        "input_state_id": result["input_state_id"].hex(),
        "output_state_id": result["output_state_id"].hex(),
        "epoch": result["epoch"],
        "old_finalized_height": result["old_finalized_height"],
        "new_finalized_height": result["new_finalized_height"],
        "certified_head_height": result["certified_head_height"],
        "qc_ids": [value.hex() for value in result["qc_ids"]],
        "tc_ids": [value.hex() for value in result["tc_ids"]],
        "qc_signatures_checked": result["qc_signatures_checked"],
        "tc_signatures_checked": result["tc_signatures_checked"],
        "raw_sha256": result["raw_sha256"].hex(),
    }


def build_trust_path_corpus() -> dict[str, Any]:
    fixtures = build_order_trust_path_fixtures()
    case_ids = (
        "zero_hop_trusted_fresh_genesis",
        "one_hop_existing_fresh_genesis_transition",
        "two_hop_checkpoint_anchored_transition",
        "three_hop_checkpoint_anchored_transition",
    )
    positive_cases = []
    for case_id, (path, result) in zip(case_ids, fixtures, strict=True):
        positive_cases.append({
            "case_id": case_id, "path_cev1_hex": enc_trust_path(path).hex(),
            "expected": trust_path_result_json(result),
        })
    two_hop_path = copy.deepcopy(fixtures[2][0])
    three_hop_path = fixtures[3][0]
    two_hop_path["steps"].append(copy.deepcopy(three_hop_path["steps"][-1]))
    seal_order_trust_path(two_hop_path)
    appended_raw = enc_trust_path(two_hop_path)
    three_hop_raw = enc_trust_path(three_hop_path)
    require(appended_raw == three_hop_raw, "trust_path_fixture_append_determinism")
    source_inventory = {}
    for name, path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("trust_path_schema", TRUST_PATH_SCHEMA_PATH),
    ):
        source_inventory[name] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return {
        "artifact": "poco-ai-native-v1-order-trust-path-iterator-corpus",
        "artifact_version": 1, "status": "candidate-non-normative",
        "scope": "bounded-zero-to-three-hop-fresh-genesis-then-checkpoint-anchored-order-trust-progression",
        "source_inventory": source_inventory,
        "decoder_independence": {
            "implementation": "Python standard library only",
            "forbidden_imports": [
                "PoCO checker modules", "TRNM Rust crates", "generated schema bindings",
            ],
            "raw_rule": "Every path and embedded step is strict-decoded and byte-for-byte re-encoded before semantic verification."
        },
        "positive_cases": positive_cases,
        "determinism_controls": {
            "exact_replay": {
                "case_id": case_ids[-1],
                "expected_path_id": fixtures[-1][1]["path_id"].hex(),
                "expected_raw_sha256": hashlib.sha256(three_hop_raw).hexdigest(),
            },
            "prefix_append": {
                "prefix_case_id": case_ids[-2], "appended_step_index": 2,
                "expected_path_id": fixtures[-1][1]["path_id"].hex(),
                "expected_raw_sha256": hashlib.sha256(appended_raw).hexdigest(),
            },
        },
        "negative_cases": [
            {
                "case_id": case_id, "mutation": case_id, "expected": "must_reject",
                "expected_error_code": expected_code,
            }
            for case_id, expected_code in TRUST_PATH_NEGATIVE_SPECS
        ],
        "openssl_cross_check": {
            "three_hop_valid_signatures": 116,
            "breakdown": {
                "qc_signatures": fixtures[-1][1]["qc_signatures_checked"],
                "tc_signatures": fixtures[-1][1]["tc_signatures_checked"],
                "handoff_signatures": fixtures[-1][1]["handoff_signatures_checked"],
            },
            "mutated_signature_control": "must reject",
        },
        "explicit_exclusions": [
            "No v0 activation authority or migration verification.",
            "No weak subjectivity checkpoint selection or trust expiry.",
            "No arbitrary-length or unbounded trust path.",
            "No state sync or non-Order proof classes.",
            "No complete wire or crypto corpus.",
            "No second implementation or interoperability evidence.",
            "No global light client completeness, normative freeze, implementation or production activation.",
        ],
    }


def build_ordinary_advance_corpus() -> dict[str, Any]:
    trust, proof, advances, results = build_ordinary_advance_fixtures()
    trust_raw = enc_trust(trust)
    proof_raw = enc_proof(proof)
    advance_raws = [enc_ordinary_advance(value) for value in advances]
    source_result = verify_light_client(trust_raw, proof_raw)
    initial_state = trusted_state_from_direct_ordinary_proof(trust, proof)
    source_inventory = {}
    for name, source_path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("ordinary_advance_schema", ORDINARY_ADVANCE_SCHEMA_PATH),
    ):
        source_inventory[name] = {
            "path": str(source_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }
    return {
        "artifact": "poco-ai-native-v1-order-ordinary-finality-advance-corpus",
        "artifact_version": 1,
        "status": "candidate-non-normative",
        "scope": "fresh-genesis-ordinary-target-then-two-bounded-same-epoch-ordinary-finality-advances",
        "source_inventory": source_inventory,
        "decoder_independence": {
            "implementation": "Python standard library only",
            "raw_rule": "The trust bundle, source proof and each advance are strict-decoded and byte-for-byte re-encoded before semantic verification.",
        },
        "source_trust_bundle_cev1_hex": trust_raw.hex(),
        "source_order_finality_proof_cev1_hex": proof_raw.hex(),
        "source_expected": {
            "proof_id": source_result["proof_id"].hex(),
            "ordinary_finalized_block_id": source_result["finalized_block_id"].hex(),
            "ordinary_finalized_height": source_result["finalized_height"],
            "target_kind": source_result["target_kind"],
            "initial_state_id": initial_state["state_id"].hex(),
            "qc_signatures_checked": sum(
                len(item["certifying_qc"]["body"]["signatures"])
                for item in proof["certified_chain"]
            ),
            "tc_signatures_checked": sum(
                len(item["timeout_certificate"]["body"]["entries"])
                for item in proof["certified_chain"]
                if item["timeout_certificate"] is not None
            ),
        },
        "advance_cases": [
            {
                "case_id": "same_epoch_one_skipped_view_tc",
                "advance_cev1_hex": advance_raws[0].hex(),
                "expected": ordinary_advance_result_json(results[0]),
            },
            {
                "case_id": "same_epoch_consecutive_views",
                "advance_cev1_hex": advance_raws[1].hex(),
                "expected": ordinary_advance_result_json(results[1]),
            },
        ],
        "positive_cases": [
            "fresh_genesis_ordinary_target_source_with_one_skipped_view_tc",
            "same_epoch_ordinary_advance_with_one_skipped_view_tc",
            "second_same_epoch_consecutive_ordinary_advance",
            "exact_raw_reencode_replay_and_sequential_composition",
        ],
        "determinism_controls": {
            "source_trust_sha256": hashlib.sha256(trust_raw).hexdigest(),
            "source_proof_sha256": hashlib.sha256(proof_raw).hexdigest(),
            "first_advance_sha256": hashlib.sha256(advance_raws[0]).hexdigest(),
            "second_advance_sha256": hashlib.sha256(advance_raws[1]).hexdigest(),
            "initial_state_id": initial_state["state_id"].hex(),
            "terminal_state_id": results[-1]["output_state_id"].hex(),
        },
        "negative_cases": [
            {
                "case_id": case_id, "mutation": case_id,
                "expected": "must_reject", "expected_error_code": expected_code,
            }
            for case_id, expected_code in ORDINARY_ADVANCE_NEGATIVE_SPECS
        ],
        "openssl_cross_check": {
            "valid_signatures": 48,
            "breakdown": {"qc_signatures": 40, "tc_signatures": 8},
            "mutated_signature_control": "must reject",
        },
        "explicit_exclusions": [
            "No payload bytes, transaction execution, application-state derivation or payload-dependent limits.",
            "No proposer signature; this bounded light client relies on the exact weighted QC over each header and block id.",
            "No checkpoint transition, epoch handoff, v0 activation authority, migration or arbitrary trust-anchor selection.",
            "No more than one skipped view per advance, more than two composed advances, arbitrary-length history or unbounded iteration.",
            "No state sync, non-Order proof class, complete wire or crypto corpus, second implementation or interoperability evidence.",
            "No global light-client completeness, normative freeze, node implementation, production activation or release readiness.",
        ],
    }


def build_weak_subjectivity_corpus() -> dict[str, Any]:
    path, renewal, result = build_weak_subjectivity_renewal_fixture()
    path_raw = enc_trust_path(path)
    renewal_raw = enc_weak_subjectivity_renewal(renewal)
    source_inventory = {}
    for name, source_path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("trust_path_schema", TRUST_PATH_SCHEMA_PATH),
        ("weak_subjectivity_schema", WEAK_SUBJECTIVITY_SCHEMA_PATH),
    ):
        source_inventory[name] = {
            "path": str(source_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }
    return {
        "artifact": "poco-ai-native-v1-weak-subjectivity-checkpoint-renewal-corpus",
        "artifact_version": 1,
        "status": "candidate-non-normative",
        "scope": "exact-three-hop-first-to-latest-checkpoint-anchor-renewal",
        "source_inventory": source_inventory,
        "decoder_independence": {
            "implementation": "Python standard library only",
            "raw_rule": "TrustPath and renewal bytes are independently strict-decoded and byte-for-byte re-encoded before semantic verification.",
        },
        "trust_path_cev1_hex": path_raw.hex(),
        "renewal_cev1_hex": renewal_raw.hex(),
        "expected": weak_subjectivity_result_json(result),
        "positive_cases": [
            {
                "case_id": "three_hop_first_to_latest_checkpoint_renewal",
                "operation": "derive both anchors from exact authenticated checkpoint objects",
            },
            {
                "case_id": "exact_raw_reencode_and_replay",
                "operation": "verify identical bytes twice with identical result",
            },
        ],
        "determinism_controls": {
            "trust_path_sha256": hashlib.sha256(path_raw).hexdigest(),
            "renewal_sha256": hashlib.sha256(renewal_raw).hexdigest(),
            "renewal_id": result["renewal_id"].hex(),
        },
        "negative_cases": [
            {
                "case_id": case_id,
                "mutation": case_id,
                "expected": "must_reject",
                "expected_error_code": expected_code,
            }
            for case_id, expected_code in WEAK_SUBJECTIVITY_NEGATIVE_SPECS
        ],
        "explicit_exclusions": [
            "No wall-clock oracle, operator key, governance authorization or external bootstrap-package authentication.",
            "No arbitrary checkpoint selection outside the exact bounded TrustPath.",
            "No arbitrary-length or unbounded weak-subjectivity history.",
            "No v0 activation authority, migration verification, state sync or non-Order proof class.",
            "No complete wire or crypto corpus, second implementation or interoperability evidence.",
            "No global light client, normative freeze, node implementation, production activation or release readiness.",
        ],
    }


def validate_ordinary_advance_schema_contract() -> None:
    schema = load_json_document(ORDINARY_ADVANCE_SCHEMA_PATH, "ordinary_advance_schema")
    require(
        schema.get("schema")
        == "trnm-poco-ai-native-v1-order-ordinary-finality-advance-candidate"
        and schema.get("schema_version") == 1
        and schema.get("status") == "candidate-non-normative"
        and schema.get("canonical_encoding") == "CEV1",
        "ordinary_advance_schema_identity",
    )
    require(
        schema.get("classification")
        == "bounded-independent-same-epoch-ordinary-finality-advance-evidence",
        "ordinary_advance_schema_classification",
    )
    require(
        schema.get("digest_construction")
        == "SHA256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))",
        "ordinary_advance_schema_digest",
    )
    require(schema.get("domains") == {
        "ordinary_finality_advance": ORDINARY_FINALITY_ADVANCE_DOMAIN,
    }, "ordinary_advance_schema_domains")
    imports = schema.get("imports", {})
    require(
        imports.get("foundation_schema") == FOUNDATION_SCHEMA_PATH.name
        and imports.get("one_step_schema") == SCHEMA_PATH.name
        and "ordinary-target" in imports.get("source_authority", "").lower(),
        "ordinary_advance_schema_imports",
    )
    types = schema.get("added_cev1_types")
    require(isinstance(types, dict) and tuple(types) == (
        "OrdinaryFinalityAdvanceBodyV1", "OrdinaryFinalityAdvanceV1",
    ), "ordinary_advance_schema_type_inventory")
    relations = " ".join(schema.get("verified_relations", [])).lower()
    for marker in (
        "source freshgenesis", "input state id", "exactly three ordinary",
        "immediate height and view", "weighted quorum", "skip exactly one view",
        "at most one skipped-view", "three-chain finalizes",
        "output finalized height", "sequentially composed",
    ):
        require(marker in relations, "ordinary_advance_schema_relation", marker)
    require(
        schema.get("negative_inventory_count") == len(ORDINARY_ADVANCE_NEGATIVE_IDS),
        "ordinary_advance_schema_negative_count",
    )
    exclusions = " ".join(schema.get("explicit_exclusions", [])).lower()
    for marker in (
        "payload bytes", "proposer signature", "checkpoint scheduling",
        "v0 activation", "more than one skipped view", "arbitrary-length",
        "state sync", "complete wire", "second implementation",
        "global light-client", "normative freeze", "production activation",
    ):
        require(marker in exclusions, "ordinary_advance_schema_exclusion", marker)


def validate_ordinary_advance_corpus(
    corpus: dict[str, Any], self_test_mutants: bool,
) -> tuple[bytes, bytes, list[bytes], list[dict[str, Any]]]:
    require(
        corpus.get("artifact")
        == "poco-ai-native-v1-order-ordinary-finality-advance-corpus"
        and corpus.get("artifact_version") == 1
        and corpus.get("status") == "candidate-non-normative",
        "ordinary_advance_corpus_identity",
    )
    require(
        corpus.get("scope")
        == "fresh-genesis-ordinary-target-then-two-bounded-same-epoch-ordinary-finality-advances",
        "ordinary_advance_corpus_scope",
    )
    inventory = exact_keys(
        corpus.get("source_inventory"),
        {"foundation_schema", "one_step_schema", "ordinary_advance_schema"},
        "ordinary_advance_source_inventory",
    )
    for name, path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("ordinary_advance_schema", ORDINARY_ADVANCE_SCHEMA_PATH),
    ):
        entry = exact_keys(inventory[name], {"path", "sha256"}, "ordinary_advance_source_entry")
        require(
            entry["path"] == str(path.relative_to(ROOT))
            and entry["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest(),
            "ordinary_advance_source_hash", name,
        )
    negative_cases = corpus.get("negative_cases")
    require(
        isinstance(negative_cases, list)
        and len(negative_cases) == len(ORDINARY_ADVANCE_NEGATIVE_IDS)
        and tuple(item.get("case_id") for item in negative_cases)
        == ORDINARY_ADVANCE_NEGATIVE_IDS,
        "ordinary_advance_negative_inventory",
    )
    require(
        all(
            item.get("mutation") == item.get("case_id")
            and item.get("expected") == "must_reject"
            and item.get("expected_error_code")
            == EXPECTED_ORDINARY_ADVANCE_NEGATIVE_CODES[item["case_id"]]
            for item in negative_cases
        ),
        "ordinary_advance_negative_shape",
    )
    trust_raw = parse_hex(corpus.get("source_trust_bundle_cev1_hex"), "ordinary_source_trust")
    proof_raw = parse_hex(corpus.get("source_order_finality_proof_cev1_hex"), "ordinary_source_proof")
    source_result = verify_light_client(trust_raw, proof_raw)
    trust = decode_exact(trust_raw, "ordinary_source_trust_decode", dec_trust, enc_trust)
    proof = decode_exact(proof_raw, "ordinary_source_proof_decode", dec_proof, enc_proof)
    require(source_result["target_kind"] == "Ordinary", "ordinary_advance_source_target")
    require(len(source_result["tc_ids"]) == 1, "ordinary_advance_source_tc")
    initial = trusted_state_from_direct_ordinary_proof(trust, proof)
    source_expected = exact_keys(corpus.get("source_expected"), {
        "proof_id", "ordinary_finalized_block_id", "ordinary_finalized_height",
        "target_kind", "initial_state_id", "qc_signatures_checked",
        "tc_signatures_checked",
    }, "ordinary_advance_source_expected_fields")
    require(
        source_result["proof_id"] == parse_hex(source_expected["proof_id"], "ordinary_source_proof_id")
        and source_result["finalized_block_id"]
        == parse_hex(source_expected["ordinary_finalized_block_id"], "ordinary_source_block")
        and source_result["finalized_height"] == source_expected["ordinary_finalized_height"]
        and source_expected["target_kind"] == "Ordinary"
        and initial["state_id"] == parse_hex(source_expected["initial_state_id"], "ordinary_source_state"),
        "ordinary_advance_source_expected",
    )
    require(
        source_expected["qc_signatures_checked"] == 16
        and source_expected["tc_signatures_checked"] == 4,
        "ordinary_advance_source_signature_counts",
    )
    cases = corpus.get("advance_cases")
    require(
        isinstance(cases, list) and len(cases) == 2
        and [item.get("case_id") for item in cases]
        == ["same_epoch_one_skipped_view_tc", "same_epoch_consecutive_views"],
        "ordinary_advance_positive_inventory",
    )
    current = initial
    raws: list[bytes] = []
    results: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        raw = parse_hex(case.get("advance_cev1_hex"), f"ordinary_advance_{index}")
        output, result = verify_ordinary_finality_advance(
            raw, expected_input_state_id=current["state_id"],
            fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
        )
        expected = exact_keys(case.get("expected"), {
            "advance_id", "input_state_id", "output_state_id", "epoch",
            "old_finalized_height", "new_finalized_height", "certified_head_height",
            "qc_ids", "tc_ids", "qc_signatures_checked", "tc_signatures_checked",
            "raw_sha256",
        }, "ordinary_advance_expected_fields")
        require(ordinary_advance_result_json(result) == expected, "ordinary_advance_expected", str(index))
        require(result["input_state_id"] == current["state_id"], "ordinary_advance_sequence_input")
        require(result["new_finalized_height"] > result["old_finalized_height"], "ordinary_advance_sequence_height")
        raws.append(raw)
        results.append(result)
        current = output
    require(len(results[0]["tc_ids"]) == 1 and len(results[1]["tc_ids"]) == 0, "ordinary_advance_tc_inventory")
    replay_output, replay_result = verify_ordinary_finality_advance(
        raws[0], expected_input_state_id=initial["state_id"],
        fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
    )
    require(replay_result == results[0] and replay_output["state_id"] == results[0]["output_state_id"], "ordinary_advance_exact_replay")
    controls = exact_keys(corpus.get("determinism_controls"), {
        "source_trust_sha256", "source_proof_sha256", "first_advance_sha256",
        "second_advance_sha256", "initial_state_id", "terminal_state_id",
    }, "ordinary_advance_determinism_fields")
    require(
        controls["source_trust_sha256"] == hashlib.sha256(trust_raw).hexdigest()
        and controls["source_proof_sha256"] == hashlib.sha256(proof_raw).hexdigest()
        and controls["first_advance_sha256"] == hashlib.sha256(raws[0]).hexdigest()
        and controls["second_advance_sha256"] == hashlib.sha256(raws[1]).hexdigest()
        and controls["initial_state_id"] == initial["state_id"].hex()
        and controls["terminal_state_id"] == results[-1]["output_state_id"].hex(),
        "ordinary_advance_determinism",
    )
    openssl = exact_keys(corpus.get("openssl_cross_check"), {
        "valid_signatures", "breakdown", "mutated_signature_control",
    }, "ordinary_advance_openssl_fields")
    require(
        openssl["valid_signatures"] == 48
        and openssl["breakdown"] == {"qc_signatures": 40, "tc_signatures": 8}
        and openssl["mutated_signature_control"] == "must reject",
        "ordinary_advance_openssl_counts",
    )
    exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
    for marker in (
        "payload bytes", "proposer signature", "checkpoint transition",
        "v0 activation", "more than one skipped view", "arbitrary-length",
        "state sync", "complete wire", "second implementation",
        "global light-client", "normative freeze", "production activation",
    ):
        require(marker in exclusions, "ordinary_advance_corpus_exclusion", marker)
    if self_test_mutants:
        replacement = decode_exact(
            raws[1], "ordinary_advance_replacement", dec_ordinary_advance,
            enc_ordinary_advance,
        )["input_state"]
        for case_id in ORDINARY_ADVANCE_NEGATIVE_IDS:
            mutated = mutation_ordinary_advance_case(
                case_id, raws[0], replacement_state=replacement,
                fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
            )
            try:
                verify_ordinary_finality_advance(
                    mutated, expected_input_state_id=initial["state_id"],
                    fresh_genesis_derived_state_hash=trust["genesis_derived_state_hash"],
                )
            except EvidenceError as exc:
                actual = str(exc).split(":", 1)[0]
                require(
                    actual == EXPECTED_ORDINARY_ADVANCE_NEGATIVE_CODES[case_id],
                    "ordinary_advance_negative_error_code",
                    f"{case_id}: expected {EXPECTED_ORDINARY_ADVANCE_NEGATIVE_CODES[case_id]}, got {actual}",
                )
                continue
            reject("ordinary_advance_negative_accepted", case_id)
    return trust_raw, proof_raw, raws, results


def ordinary_advance_openssl_records(
    trust_raw: bytes, proof_raw: bytes, advance_raws: list[bytes],
) -> list[tuple[str, str, str]]:
    records = openssl_records(trust_raw, proof_raw)
    for raw in advance_raws:
        advance = decode_exact(
            raw, "ordinary_advance_openssl", dec_ordinary_advance,
            enc_ordinary_advance,
        )
        members = {
            member["validator_id"]: member
            for member in advance["input_state"]["validator_set"]["definition"]["members"]
        }
        for item in advance["certified_chain"]:
            qc_body = item["certifying_qc"]["body"]
            root = digest(VOTE_DOMAIN, enc_vote(qc_body["statement"]))
            for entry in qc_body["signatures"]:
                records.append((
                    members[entry["voter_id"]]["consensus_public_key"].hex(),
                    entry["signature"].hex(), root.hex(),
                ))
            tc = item["timeout_certificate"]
            if tc is not None:
                for entry in tc["body"]["entries"]:
                    timeout_root = digest(
                        TIMEOUT_SIGNATURE_DOMAIN,
                        enc_timeout_statement(entry["statement"]),
                    )
                    records.append((
                        members[entry["validator_id"]]["consensus_public_key"].hex(),
                        entry["signature"].hex(), timeout_root.hex(),
                    ))
    return records


def validate_weak_subjectivity_schema_contract() -> None:
    schema = load_json_document(
        WEAK_SUBJECTIVITY_SCHEMA_PATH, "weak_subjectivity_schema",
    )
    require(
        schema.get("schema")
        == "trnm-poco-ai-native-v1-weak-subjectivity-checkpoint-renewal-candidate"
        and schema.get("schema_version") == 1
        and schema.get("status") == "candidate-non-normative"
        and schema.get("canonical_encoding") == "CEV1",
        "weak_subjectivity_schema_identity",
    )
    require(
        schema.get("classification")
        == "bounded-independent-checkpoint-anchor-renewal-evidence",
        "weak_subjectivity_schema_classification",
    )
    require(
        schema.get("digest_construction")
        == "SHA256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))",
        "weak_subjectivity_schema_digest",
    )
    require(schema.get("domains") == {
        "weak_subjectivity_anchor": WEAK_SUBJECTIVITY_ANCHOR_DOMAIN,
        "weak_subjectivity_renewal_policy": WEAK_SUBJECTIVITY_POLICY_DOMAIN,
        "weak_subjectivity_renewal": WEAK_SUBJECTIVITY_RENEWAL_DOMAIN,
    }, "weak_subjectivity_schema_domains")
    imports = schema.get("imports", {})
    require(
        imports.get("foundation_schema") == FOUNDATION_SCHEMA_PATH.name
        and imports.get("one_step_schema") == SCHEMA_PATH.name
        and imports.get("trust_path_schema") == TRUST_PATH_SCHEMA_PATH.name
        and "exactly three" in imports.get("trust_path_requirement", ""),
        "weak_subjectivity_schema_imports",
    )
    types = schema.get("added_cev1_types")
    require(isinstance(types, dict) and tuple(types) == (
        "WeakSubjectivityCheckpointAnchorBodyV1",
        "WeakSubjectivityCheckpointAnchorV1",
        "WeakSubjectivityRenewalPolicyBodyV1",
        "WeakSubjectivityRenewalPolicyV1",
        "WeakSubjectivityCheckpointRenewalBodyV1",
        "WeakSubjectivityCheckpointRenewalV1",
    ), "weak_subjectivity_schema_type_inventory")
    relations = " ".join(schema.get("verified_relations", [])).lower()
    for marker in (
        "first and last checkpoint", "validator set", "parameters", "chain id",
        "observed finalized", "epoch-age", "strictly later", "same height",
        "length-prefixed",
    ):
        require(marker in relations, "weak_subjectivity_schema_relation", marker)
    require(
        schema.get("negative_inventory_count")
        == len(WEAK_SUBJECTIVITY_NEGATIVE_IDS),
        "weak_subjectivity_schema_negative_count",
    )
    exclusions = " ".join(schema.get("explicit_exclusions", [])).lower()
    for marker in (
        "wall-clock", "operator key", "arbitrary checkpoint", "arbitrary-length",
        "v0 activation", "state sync", "complete wire", "second implementation",
        "global light-client", "normative freeze", "production activation",
    ):
        require(marker in exclusions, "weak_subjectivity_schema_exclusion", marker)


def validate_weak_subjectivity_corpus(
    corpus: dict[str, Any], self_test_mutants: bool,
) -> tuple[bytes, bytes, dict[str, Any]]:
    require(
        corpus.get("artifact")
        == "poco-ai-native-v1-weak-subjectivity-checkpoint-renewal-corpus"
        and corpus.get("artifact_version") == 1
        and corpus.get("status") == "candidate-non-normative",
        "weak_subjectivity_corpus_identity",
    )
    require(
        corpus.get("scope")
        == "exact-three-hop-first-to-latest-checkpoint-anchor-renewal",
        "weak_subjectivity_corpus_scope",
    )
    expected_sources = {}
    for name, source_path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("trust_path_schema", TRUST_PATH_SCHEMA_PATH),
        ("weak_subjectivity_schema", WEAK_SUBJECTIVITY_SCHEMA_PATH),
    ):
        expected_sources[name] = {
            "path": str(source_path.relative_to(ROOT)),
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }
    require(
        corpus.get("source_inventory") == expected_sources,
        "weak_subjectivity_source_inventory",
    )
    independence = corpus.get("decoder_independence", {})
    require(
        independence.get("implementation") == "Python standard library only"
        and "strict-decoded" in independence.get("raw_rule", ""),
        "weak_subjectivity_decoder_independence",
    )
    positives = corpus.get("positive_cases")
    require(
        isinstance(positives, list)
        and [case.get("case_id") for case in positives] == [
            "three_hop_first_to_latest_checkpoint_renewal",
            "exact_raw_reencode_and_replay",
        ],
        "weak_subjectivity_positive_inventory",
    )
    path_raw = parse_hex(corpus.get("trust_path_cev1_hex"), "weak_subjectivity_path")
    renewal_raw = parse_hex(corpus.get("renewal_cev1_hex"), "weak_subjectivity_renewal")
    result = verify_weak_subjectivity_checkpoint_renewal(path_raw, renewal_raw)
    require(
        corpus.get("expected") == weak_subjectivity_result_json(result),
        "weak_subjectivity_expected_result",
    )
    require(
        verify_weak_subjectivity_checkpoint_renewal(path_raw, renewal_raw) == result,
        "weak_subjectivity_exact_replay",
    )
    require(corpus.get("determinism_controls") == {
        "trust_path_sha256": hashlib.sha256(path_raw).hexdigest(),
        "renewal_sha256": hashlib.sha256(renewal_raw).hexdigest(),
        "renewal_id": result["renewal_id"].hex(),
    }, "weak_subjectivity_determinism_controls")
    negatives = corpus.get("negative_cases")
    require(
        isinstance(negatives, list)
        and tuple(case.get("case_id") for case in negatives)
        == WEAK_SUBJECTIVITY_NEGATIVE_IDS,
        "weak_subjectivity_negative_inventory",
    )
    require(all(
        case.get("mutation") == case.get("case_id")
        and case.get("expected") == "must_reject"
        and case.get("expected_error_code")
        == EXPECTED_WEAK_SUBJECTIVITY_NEGATIVE_CODES[case["case_id"]]
        for case in negatives
    ), "weak_subjectivity_negative_shape")
    exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
    for marker in (
        "wall-clock", "operator key", "arbitrary checkpoint", "arbitrary-length",
        "v0 activation", "state sync", "complete wire", "second implementation",
        "global light client", "normative freeze", "production activation",
    ):
        require(marker in exclusions, "weak_subjectivity_corpus_exclusion", marker)
    if self_test_mutants:
        for case_id in WEAK_SUBJECTIVITY_NEGATIVE_IDS:
            mutated_path, mutated_renewal = mutation_weak_subjectivity_case(
                case_id, path_raw, renewal_raw,
            )
            try:
                verify_weak_subjectivity_checkpoint_renewal(
                    mutated_path, mutated_renewal,
                )
            except EvidenceError as exc:
                actual = str(exc).split(":", 1)[0]
                require(
                    actual == EXPECTED_WEAK_SUBJECTIVITY_NEGATIVE_CODES[case_id],
                    "weak_subjectivity_negative_error_code",
                    f"{case_id}: expected "
                    f"{EXPECTED_WEAK_SUBJECTIVITY_NEGATIVE_CODES[case_id]}, got {actual}",
                )
                continue
            reject("weak_subjectivity_negative_accepted", case_id)
    return path_raw, renewal_raw, result


def validate_trust_path_schema_contract() -> None:
    schema = load_json_document(TRUST_PATH_SCHEMA_PATH, "trust_path_schema")
    require(
        schema.get("schema") == "trnm-poco-ai-native-v1-order-trust-path-iterator-candidate"
        and schema.get("schema_version") == 1
        and schema.get("status") == "candidate-non-normative"
        and schema.get("canonical_encoding") == "CEV1",
        "trust_path_schema_identity",
    )
    require(
        schema.get("digest_construction")
        == "SHA256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))",
        "trust_path_schema_digest_construction",
    )
    require(schema.get("domains") == {
        "trusted_order_state": TRUSTED_ORDER_STATE_DOMAIN,
        "checkpoint_anchored_transition_step": CHECKPOINT_TRANSITION_STEP_DOMAIN,
        "order_trust_path": ORDER_TRUST_PATH_DOMAIN,
        "protocol_sidecar_content": PROTOCOL_SIDECAR_CONTENT_DOMAIN,
        "merkle_leaf": MERKLE_LEAF_DOMAIN,
        "merkle_node": MERKLE_NODE_DOMAIN,
        "merkle_list_root": MERKLE_LIST_ROOT_DOMAIN,
    }, "trust_path_schema_domains")
    require(schema.get("handoff_sidecar_root_contract") == {
        "protocol_sidecar_discriminant_width": "u8",
        "epoch_handoff_variant": EPOCH_HANDOFF_SIDECAR_TAG,
        "protocol_objects_root_kind": PROTOCOL_OBJECTS_ROOT_KIND,
        "epoch_handoff_object_kind": EPOCH_HANDOFF_OBJECT_KIND,
        "item_id": "EpochHandoffV1.handoff_id",
        "item_commitment": "DigestV1(\"trnm.poco-ai.protocol-sidecar-content.v1\", ProtocolObjectSidecarV1::EpochHandoff(EpochHandoffV1))",
        "cardinality": 1,
        "root_rule": "exact single-item typed ordered root; the complete wrapper and both signature lists are committed",
    }, "trust_path_schema_handoff_sidecar_root")
    require(schema.get("bounded_accepted_enums") == {
        "TrustPathStepV1": {"0": "ExistingFreshGenesisTransition", "1": "CheckpointAnchoredTransition"},
    }, "trust_path_schema_variants")
    added = schema.get("added_cev1_types")
    require(isinstance(added, dict) and tuple(added) == (
        "TrustedOrderStateBodyV1", "TrustedOrderStateV1",
        "CheckpointAnchoredTransitionStepBodyV1", "CheckpointAnchoredTransitionStepV1",
        "TrustPathStepV1", "OrderTrustPathBodyV1", "OrderTrustPathV1",
    ), "trust_path_schema_type_inventory")
    require(schema.get("resource_bounds", {}).get("max_steps") == MAX_TRUST_PATH_STEPS, "trust_path_schema_step_bound")
    require(schema.get("negative_inventory_count") == len(TRUST_PATH_NEGATIVE_IDS), "trust_path_schema_negative_count")
    imports = schema.get("imports", {})
    require(
        imports.get("foundation_schema") == FOUNDATION_SCHEMA_PATH.name
        and imports.get("one_step_schema") == SCHEMA_PATH.name
        and imports.get("existing_first_step_type") == "BoundedEpochTransitionEvidenceV1",
        "trust_path_schema_imports",
    )
    relations = " ".join(schema.get("verified_relations", [])).lower()
    for marker in (
        "position zero", "input_state_id", "certified_head_qc_id", "dual weighted quorum",
        "protocol_objects_root", "signature lists", "timeoutcertificatev1",
        "identical epochhandoffv1", "no locked qc", "epochcheckpointv1",
        "strictly", "at most three",
    ):
        require(marker in relations, "trust_path_schema_relation", marker)
    exclusions = " ".join(schema.get("explicit_exclusions", [])).lower()
    for marker in (
        "v0 activation", "weak-subjectivity", "arbitrary-length", "state-sync",
        "more than one skipped", "multiple tcs", "general pacemaker-history",
        "complete wire", "second implementation", "global light-client", "normative freeze",
        "production activation",
    ):
        require(marker in exclusions, "trust_path_schema_exclusion", marker)


def validate_trust_path_corpus(corpus: dict[str, Any], self_test_mutants: bool) -> tuple[bytes, dict[str, Any]]:
    require(
        corpus.get("artifact") == "poco-ai-native-v1-order-trust-path-iterator-corpus"
        and corpus.get("artifact_version") == 1
        and corpus.get("status") == "candidate-non-normative",
        "trust_path_corpus_identity",
    )
    require(
        corpus.get("scope") == "bounded-zero-to-three-hop-fresh-genesis-then-checkpoint-anchored-order-trust-progression",
        "trust_path_corpus_scope",
    )
    expected_sources = {}
    for name, path in (
        ("foundation_schema", FOUNDATION_SCHEMA_PATH),
        ("one_step_schema", SCHEMA_PATH),
        ("trust_path_schema", TRUST_PATH_SCHEMA_PATH),
    ):
        expected_sources[name] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    require(corpus.get("source_inventory") == expected_sources, "trust_path_source_inventory")
    independence = corpus.get("decoder_independence", {})
    require(
        independence.get("implementation") == "Python standard library only"
        and "strict-decoded" in independence.get("raw_rule", ""),
        "trust_path_decoder_independence",
    )
    positives = corpus.get("positive_cases")
    expected_case_ids = [
        "zero_hop_trusted_fresh_genesis", "one_hop_existing_fresh_genesis_transition",
        "two_hop_checkpoint_anchored_transition", "three_hop_checkpoint_anchored_transition",
    ]
    require(
        isinstance(positives, list)
        and [case.get("case_id") for case in positives] == expected_case_ids,
        "trust_path_positive_inventory",
    )
    raws: list[bytes] = []
    results: list[dict[str, Any]] = []
    for hop_count, case in enumerate(positives):
        exact_keys(case, {"case_id", "path_cev1_hex", "expected"}, "trust_path_positive_shape")
        raw = parse_hex(case["path_cev1_hex"], f"trust_path_positive_{hop_count}")
        result = verify_order_trust_path(raw)
        require(result["hop_count"] == hop_count, "trust_path_expected_hop_count")
        require(case["expected"] == trust_path_result_json(result), "trust_path_expected_result")
        require(verify_order_trust_path(raw) == result, "trust_path_exact_replay")
        raws.append(raw)
        results.append(result)
    determinism = corpus.get("determinism_controls", {})
    require(
        determinism.get("exact_replay") == {
            "case_id": expected_case_ids[-1], "expected_path_id": results[-1]["path_id"].hex(),
            "expected_raw_sha256": hashlib.sha256(raws[-1]).hexdigest(),
        },
        "trust_path_replay_control",
    )
    prefix = decode_exact(raws[-2], "trust_path_prefix", dec_trust_path, enc_trust_path)
    full = decode_exact(raws[-1], "trust_path_full", dec_trust_path, enc_trust_path)
    prefix["steps"].append(copy.deepcopy(full["steps"][-1]))
    seal_order_trust_path(prefix)
    appended_raw = enc_trust_path(prefix)
    require(appended_raw == raws[-1], "trust_path_append_bytes")
    require(
        determinism.get("prefix_append") == {
            "prefix_case_id": expected_case_ids[-2], "appended_step_index": 2,
            "expected_path_id": results[-1]["path_id"].hex(),
            "expected_raw_sha256": hashlib.sha256(appended_raw).hexdigest(),
        },
        "trust_path_append_control",
    )
    negatives = corpus.get("negative_cases")
    require(
        isinstance(negatives, list)
        and tuple(case.get("case_id") for case in negatives) == TRUST_PATH_NEGATIVE_IDS,
        "trust_path_negative_inventory",
    )
    require(all(
        case.get("mutation") == case.get("case_id")
        and case.get("expected") == "must_reject"
        and case.get("expected_error_code") == EXPECTED_TRUST_PATH_NEGATIVE_CODES[case["case_id"]]
        for case in negatives
    ), "trust_path_negative_shape")
    openssl = corpus.get("openssl_cross_check", {})
    require(
        openssl.get("three_hop_valid_signatures") == 116
        and openssl.get("breakdown") == {
            "qc_signatures": results[-1]["qc_signatures_checked"],
            "tc_signatures": results[-1]["tc_signatures_checked"],
            "handoff_signatures": results[-1]["handoff_signatures_checked"],
        }
        and openssl.get("mutated_signature_control") == "must reject",
        "trust_path_openssl_contract",
    )
    exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
    for marker in (
        "v0 activation", "weak subjectivity", "arbitrary-length", "state sync",
        "complete wire", "second implementation", "global light client", "normative freeze",
        "production activation",
    ):
        require(marker in exclusions, "trust_path_corpus_exclusion", marker)
    if self_test_mutants:
        for case_id in TRUST_PATH_NEGATIVE_IDS:
            mutated = mutation_trust_path_case(case_id, raws[-1])
            try:
                verify_order_trust_path(mutated)
            except EvidenceError as exc:
                actual = str(exc).split(":", 1)[0]
                require(
                    actual == EXPECTED_TRUST_PATH_NEGATIVE_CODES[case_id],
                    "trust_path_negative_error_code",
                    f"{case_id}: expected {EXPECTED_TRUST_PATH_NEGATIVE_CODES[case_id]}, got {actual}",
                )
                continue
            reject("trust_path_negative_accepted", case_id)
    return raws[-1], results[-1]


def trust_path_openssl_records(path_raw: bytes) -> list[tuple[str, str, str]]:
    verify_order_trust_path(path_raw)
    path = decode_exact(path_raw, "trust_path_openssl", dec_trust_path, enc_trust_path)
    current = path["initial_state"]
    records: list[tuple[str, str, str]] = []
    for index, carrier in enumerate(path["steps"]):
        if index == 0:
            transition = decode_exact(
                carrier["raw_step_cev1"], "trust_path_openssl_transition",
                dec_epoch_transition, enc_epoch_transition,
            )
            records.extend(transition_openssl_records(carrier["raw_step_cev1"]))
            current = output_state_from_existing_transition(transition)
            continue
        step = decode_exact(
            carrier["raw_step_cev1"], "trust_path_openssl_checkpoint_step",
            dec_checkpoint_transition_step, enc_checkpoint_transition_step,
        )
        old_members = {
            member["validator_id"]: member
            for member in current["validator_set"]["definition"]["members"]
        }
        new_members = {
            member["validator_id"]: member
            for member in step["new_validator_set"]["definition"]["members"]
        }
        for item, members in (
            *((item, old_members) for item in step["checkpoint_certified_chain"]),
            *((item, new_members) for item in step["new_epoch_certified_chain"]),
        ):
            body = item["certifying_qc"]["body"]
            root = digest(VOTE_DOMAIN, enc_vote(body["statement"]))
            for entry in body["signatures"]:
                records.append((
                    members[entry["voter_id"]]["consensus_public_key"].hex(),
                    entry["signature"].hex(), root.hex(),
                ))
            tc = item["timeout_certificate"]
            if tc is not None:
                for entry in tc["body"]["entries"]:
                    root = digest(
                        TIMEOUT_SIGNATURE_DOMAIN,
                        enc_timeout_statement(entry["statement"]),
                    )
                    records.append((
                        members[entry["validator_id"]]["consensus_public_key"].hex(),
                        entry["signature"].hex(), root.hex(),
                    ))
        handoff = step["handoff"]
        for entries, members, domain in (
            (handoff["old_set_signatures"], old_members, EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN),
            (handoff["new_set_signatures"], new_members, EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN),
        ):
            for entry in entries:
                root = digest(domain, enc_handoff_statement(entry["statement"]))
                records.append((
                    members[entry["signer_id"]]["consensus_public_key"].hex(),
                    entry["signature"].hex(), root.hex(),
                ))
        current = step["output_state"]
    return records


def build_corpus() -> dict[str, Any]:
    trust, proof = build_fixture()
    trust_raw, proof_raw = enc_trust(trust), enc_proof(proof)
    result = verify_light_client(trust_raw, proof_raw)
    signatures = sum(len(item["certifying_qc"]["body"]["signatures"]) for item in proof["certified_chain"])
    ordinary_trust, ordinary_proof = build_ordinary_tc_fixture()
    ordinary_trust_raw, ordinary_proof_raw = enc_trust(ordinary_trust), enc_proof(ordinary_proof)
    ordinary_result = verify_light_client(
        ordinary_trust_raw, ordinary_proof_raw,
        (result["finalized_height"], result["finalized_block_id"]),
    )
    ordinary_qc_signatures = sum(
        len(item["certifying_qc"]["body"]["signatures"])
        for item in ordinary_proof["certified_chain"]
    )
    ordinary_tc_signatures = sum(
        len(item["timeout_certificate"]["body"]["entries"])
        for item in ordinary_proof["certified_chain"]
        if item["timeout_certificate"] is not None
    )
    direct_ordinary_trust, direct_ordinary_proof = build_direct_ordinary_fixture()
    direct_ordinary_trust_raw = enc_trust(direct_ordinary_trust)
    direct_ordinary_proof_raw = enc_proof(direct_ordinary_proof)
    direct_ordinary_result = verify_light_client(
        direct_ordinary_trust_raw, direct_ordinary_proof_raw,
        (result["finalized_height"], result["finalized_block_id"]),
    )
    direct_ordinary_qc_signatures = sum(
        len(item["certifying_qc"]["body"]["signatures"])
        for item in direct_ordinary_proof["certified_chain"]
    )
    transition = build_epoch_transition_fixture()
    transition_raw = enc_epoch_transition(transition)
    transition_result = verify_epoch_transition(transition_raw)
    transition_old_qc_signatures = sum(
        len(item["certifying_qc"]["body"]["signatures"])
        for item in transition["checkpoint_finality_proof"]["certified_chain"]
    )
    transition_new_qc_signatures = sum(
        len(item["certifying_qc"]["body"]["signatures"])
        for item in transition["new_epoch_certified_chain"]
    )
    return {
        "artifact": "poco-ai-native-v1-order-finality-light-client-corpus",
        "artifact_version": 1,
        "status": "candidate-non-normative",
        "scope": "fresh-genesis-ordinary-checkpoint-and-one-epoch-handoff-bounded-trust-progression",
        "schema_path": "docs/protocol/poco-ai-native-v1/schema/cev1-order-finality-light-client-kernel-v1.json",
        "trust_bundle_cev1_hex": trust_raw.hex(),
        "order_finality_proof_cev1_hex": proof_raw.hex(),
        "expected": {
            "order_finality_proof_id": result["proof_id"].hex(), "trusted_genesis_block_id": result["genesis_block_id"].hex(),
            "finalized_block_id": result["finalized_block_id"].hex(), "finalized_height": result["finalized_height"],
            "validator_set_definition_hash": result["validator_set_definition_hash"].hex(),
            "validator_set_hash": result["validator_set_hash"].hex(),
            "consensus_parameters_hash": result["consensus_parameters_hash"].hex(),
            "epoch_descriptor_id": result["epoch_descriptor_id"].hex(),
            "qc_ids": [value.hex() for value in result["qc_ids"]], "valid_qc_signatures_checked": signatures,
        },
        "ordinary_target_case": {
            "trust_bundle_cev1_hex": ordinary_trust_raw.hex(),
            "order_finality_proof_cev1_hex": ordinary_proof_raw.hex(),
            "expected": {
                "order_finality_proof_id": ordinary_result["proof_id"].hex(),
                "finalized_block_id": ordinary_result["finalized_block_id"].hex(),
                "finalized_height": ordinary_result["finalized_height"],
                "target_kind": ordinary_result["target_kind"],
                "qc_ids": [value.hex() for value in ordinary_result["qc_ids"]],
                "tc_ids": [value.hex() for value in ordinary_result["tc_ids"]],
                "valid_qc_signatures_checked": ordinary_qc_signatures,
                "valid_tc_signatures_checked": ordinary_tc_signatures,
            },
        },
        "direct_ordinary_target_case": {
            "trust_bundle_cev1_hex": direct_ordinary_trust_raw.hex(),
            "order_finality_proof_cev1_hex": direct_ordinary_proof_raw.hex(),
            "expected": {
                "order_finality_proof_id": direct_ordinary_result["proof_id"].hex(),
                "finalized_block_id": direct_ordinary_result["finalized_block_id"].hex(),
                "finalized_height": direct_ordinary_result["finalized_height"],
                "target_kind": direct_ordinary_result["target_kind"],
                "qc_ids": [value.hex() for value in direct_ordinary_result["qc_ids"]],
                "tc_ids": [value.hex() for value in direct_ordinary_result["tc_ids"]],
                "valid_qc_signatures_checked": direct_ordinary_qc_signatures,
            },
        },
        "epoch_transition_case": {
            "epoch_transition_cev1_hex": transition_raw.hex(),
            "expected": {
                "transition_sha256": transition_result["transition_sha256"].hex(),
                "checkpoint_proof_id": transition_result["checkpoint_proof_id"].hex(),
                "checkpoint_id": transition_result["checkpoint_id"].hex(),
                "handoff_id": transition_result["handoff_id"].hex(),
                "old_terminal_block_id": transition_result["old_terminal_block_id"].hex(),
                "old_terminal_height": transition_result["old_terminal_height"],
                "new_epoch": transition_result["new_epoch"],
                "new_epoch_descriptor_id": transition_result["new_epoch_descriptor_id"].hex(),
                "new_validator_set_hash": transition_result["new_validator_set_hash"].hex(),
                "new_consensus_parameters_hash": transition_result["new_consensus_parameters_hash"].hex(),
                "handoff_anchor_finalized_block_id": transition_result["handoff_anchor_finalized_block_id"].hex(),
                "handoff_anchor_finalized_height": transition_result["handoff_anchor_finalized_height"],
                "finalized_block_id": transition_result["finalized_block_id"].hex(),
                "finalized_height": transition_result["finalized_height"],
                "finalized_kind": transition_result["finalized_kind"],
                "new_qc_ids": [value.hex() for value in transition_result["new_qc_ids"]],
                "old_handoff_weight": transition_result["old_handoff_weight"],
                "new_handoff_weight": transition_result["new_handoff_weight"],
                "old_handoff_signatures": transition_result["old_handoff_signatures"],
                "new_handoff_signatures": transition_result["new_handoff_signatures"],
                "old_qc_signatures_checked": transition_old_qc_signatures,
                "new_qc_signatures_checked": transition_new_qc_signatures,
            },
        },
        "positive_cases": [
            {"case_id": "fresh_genesis_certified_direct_three_chain", "operation": "verify_first_finality_from_trusted_genesis"},
            {"case_id": "exact_raw_reencode_and_replay", "operation": "verify_twice_identically"},
            {"case_id": "same_height_same_id_monotonic_replay", "operation": "verify_idempotent_finalized_tip"},
            {"case_id": "ordinary_target_with_one_skipped_view_tc", "operation": "verify_ordinary_finality_and_complete_timeout_certificate"},
            {"case_id": "ordinary_target_monotonic_advance", "operation": "advance_finalized_tip_from_genesis_to_ordinary"},
            {"case_id": "checkpoint_attachment_finalizes_exact_epoch_checkpoint", "operation": "verify_checkpoint_finality_and_attachment_identity"},
            {"case_id": "epoch_handoff_dual_weighted_quorum", "operation": "verify_old_and_new_role_isolated_signatures_and_quorums"},
            {"case_id": "v1_handoff_first_three_chain", "operation": "finalize_handoff_first_anchor_under_new_epoch_authority"},
            {"case_id": "ordinary_consumes_handoff_trusted_state", "operation": "advance_one_ordinary_finality_from_handoff_anchor"},
        ],
        "negative_cases": [
            {
                "case_id": case_id,
                "mutation": case_id,
                "expected": "must_reject",
                "expected_error_code": EXPECTED_NEGATIVE_CODES[case_id],
            }
            for case_id in NEGATIVE_IDS
        ],
        "tc_negative_cases": [
            {
                "case_id": case_id,
                "mutation": case_id,
                "expected": "must_reject",
                "expected_error_code": EXPECTED_TC_NEGATIVE_CODES[case_id],
            }
            for case_id in TC_NEGATIVE_IDS
        ],
        "transition_negative_cases": [
            {
                "case_id": case_id,
                "mutation": case_id,
                "expected": "must_reject",
                "expected_error_code": EXPECTED_TRANSITION_NEGATIVE_CODES[case_id],
            }
            for case_id in TRANSITION_NEGATIVE_IDS
        ],
        "explicit_exclusions": [
            "V0 activation, more than one epoch handoff, arbitrary-length trust-path iteration, and weak-subjectivity checkpoint selection",
            "more than one skipped view between certified parents, multiple TCs in one proof, EpochStart TC safe parents, or non-FreshGenesis finalized anchors",
            "OrderProposal and proposer-signature verification, full-node admission, payload retrieval, DA, and execution",
            "Ordinary-block payload-dependent byte/count/execution/evidence limits because only committed roots are present",
            "chain-descriptor/bootstrap-file authentication or trust-bundle materialization from a canonical genesis package",
            "application, artifact, result/settlement, state-sync, migration, and complete v0 authority proofs",
            "global wire-schema or crypto interoperability, second implementation, implementation, activation, production, release readiness, or normative freeze",
        ],
    }


def parse_hex(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value == value.lower() and len(value) % 2 == 0, "corpus_hex", label)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EvidenceError(f"corpus_hex: {label}") from exc


def validate_schema_contract() -> None:
    schema = load_json_document(SCHEMA_PATH, "light_client_schema")
    foundation = load_json_document(FOUNDATION_SCHEMA_PATH, "foundation_schema")
    require(schema.get("status") == "candidate-non-normative", "schema_status")
    require(
        schema.get("classification")
        == "bounded-fresh-genesis-ordinary-checkpoint-and-one-handoff-light-client-kernel",
        "schema_classification",
    )
    require(
        foundation.get("artifact") == "trnm.poco-ai.cev1-foundation-order-kernel.v1"
        and foundation.get("artifact_version") == 1
        and foundation.get("protocol_version") == 1
        and foundation.get("canonical_encoding") == "CEV1",
        "foundation_identity",
    )
    require(schema.get("domains") == {
        "validator_set_definition": VALIDATOR_SET_DEFINITION_DOMAIN, "validator_set": VALIDATOR_SET_DOMAIN,
        "consensus_parameters": CONSENSUS_PARAMETERS_DOMAIN, "epoch_descriptor": EPOCH_DESCRIPTOR_DOMAIN,
        "block_id": BLOCK_DOMAIN, "vote_signature": VOTE_DOMAIN, "quorum_certificate": QC_DOMAIN,
        "timeout_signature": TIMEOUT_SIGNATURE_DOMAIN, "timeout_certificate": TC_DOMAIN,
        "epoch_checkpoint": EPOCH_CHECKPOINT_DOMAIN, "epoch_handoff": EPOCH_HANDOFF_DOMAIN,
        "epoch_handoff_old_signature": EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN,
        "epoch_handoff_new_signature": EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN,
        "order_finality_proof": PROOF_DOMAIN,
    }, "schema_domains")
    imports = exact_keys(schema.get("imports"), {"artifact", "types", "rule", "structural_snapshot_sha256"}, "foundation_import_shape")
    require(imports["artifact"] == foundation["artifact"], "foundation_import")
    require(imports["types"] == list(FOUNDATION_TYPE_SNAPSHOT_SHA256), "foundation_import_type_inventory")
    declared_snapshot = exact_keys(
        imports["structural_snapshot_sha256"],
        {"types", "domains", "registries", "constraints"},
        "foundation_declared_snapshot_shape",
    )
    require(declared_snapshot["types"] == FOUNDATION_TYPE_SNAPSHOT_SHA256, "foundation_declared_type_snapshot")
    require(declared_snapshot["domains"] == FOUNDATION_DOMAINS_SNAPSHOT_SHA256, "foundation_declared_domains_snapshot")
    require(declared_snapshot["registries"] == FOUNDATION_REGISTRIES_SNAPSHOT_SHA256, "foundation_declared_registries_snapshot")
    require(declared_snapshot["constraints"] == FOUNDATION_CONSTRAINTS_SNAPSHOT_SHA256, "foundation_declared_constraints_snapshot")
    foundation_types = foundation.get("types")
    require(isinstance(foundation_types, dict), "foundation_types_shape")
    for name, expected_hash in FOUNDATION_TYPE_SNAPSHOT_SHA256.items():
        require(name in foundation_types, "foundation_type", name)
        require(structural_sha256(foundation_types[name]) == expected_hash, "foundation_type_structural_snapshot", name)
    require(structural_sha256(foundation.get("domains")) == FOUNDATION_DOMAINS_SNAPSHOT_SHA256, "foundation_domains_structural_snapshot")
    require(structural_sha256(foundation.get("registries")) == FOUNDATION_REGISTRIES_SNAPSHOT_SHA256, "foundation_registries_structural_snapshot")
    require(structural_sha256(foundation.get("constraints")) == FOUNDATION_CONSTRAINTS_SNAPSHOT_SHA256, "foundation_constraints_structural_snapshot")
    require("proposer signature" in schema.get("full_node_vs_light_client_signature_boundary", ""), "signature_boundary")


def validate_corpus(
    corpus: dict[str, Any], self_test_mutants: bool,
) -> tuple[bytes, bytes, bytes, bytes, bytes, dict[str, Any], dict[str, Any], dict[str, Any]]:
    require(corpus.get("artifact") == "poco-ai-native-v1-order-finality-light-client-corpus" and corpus.get("artifact_version") == 1, "corpus_identity")
    require(corpus.get("status") == "candidate-non-normative", "corpus_status")
    require(corpus.get("scope") == "fresh-genesis-ordinary-checkpoint-and-one-epoch-handoff-bounded-trust-progression", "corpus_scope")
    positives = corpus.get("positive_cases")
    negatives = corpus.get("negative_cases")
    tc_negatives = corpus.get("tc_negative_cases")
    transition_negatives = corpus.get("transition_negative_cases")
    require(isinstance(positives, list) and [item.get("case_id") for item in positives] == [
        "fresh_genesis_certified_direct_three_chain", "exact_raw_reencode_and_replay",
        "same_height_same_id_monotonic_replay", "ordinary_target_with_one_skipped_view_tc",
        "ordinary_target_monotonic_advance",
        "checkpoint_attachment_finalizes_exact_epoch_checkpoint",
        "epoch_handoff_dual_weighted_quorum", "v1_handoff_first_three_chain",
        "ordinary_consumes_handoff_trusted_state",
    ], "positive_inventory")
    require(isinstance(negatives, list) and len(negatives) == len(NEGATIVE_IDS) and tuple(item.get("case_id") for item in negatives) == NEGATIVE_IDS, "negative_inventory")
    require(
        all(
            item.get("mutation") == item.get("case_id")
            and item.get("expected") == "must_reject"
            and item.get("expected_error_code") == EXPECTED_NEGATIVE_CODES[item["case_id"]]
            for item in negatives
        ),
        "negative_shape",
    )
    require(isinstance(tc_negatives, list) and len(tc_negatives) == len(TC_NEGATIVE_IDS) and tuple(item.get("case_id") for item in tc_negatives) == TC_NEGATIVE_IDS, "tc_negative_inventory")
    require(
        all(
            item.get("mutation") == item.get("case_id")
            and item.get("expected") == "must_reject"
            and item.get("expected_error_code") == EXPECTED_TC_NEGATIVE_CODES[item["case_id"]]
            for item in tc_negatives
        ),
        "tc_negative_shape",
    )
    require(
        isinstance(transition_negatives, list)
        and len(transition_negatives) == len(TRANSITION_NEGATIVE_IDS)
        and tuple(item.get("case_id") for item in transition_negatives) == TRANSITION_NEGATIVE_IDS,
        "transition_negative_inventory",
    )
    require(
        all(
            item.get("mutation") == item.get("case_id")
            and item.get("expected") == "must_reject"
            and item.get("expected_error_code")
            == EXPECTED_TRANSITION_NEGATIVE_CODES[item["case_id"]]
            for item in transition_negatives
        ),
        "transition_negative_shape",
    )
    trust_raw = parse_hex(corpus.get("trust_bundle_cev1_hex"), "trust")
    proof_raw = parse_hex(corpus.get("order_finality_proof_cev1_hex"), "proof")
    result = verify_light_client(trust_raw, proof_raw)
    expected = exact_keys(corpus.get("expected"), {
        "order_finality_proof_id", "trusted_genesis_block_id", "finalized_block_id", "finalized_height",
        "validator_set_definition_hash", "validator_set_hash", "consensus_parameters_hash",
        "epoch_descriptor_id", "qc_ids", "valid_qc_signatures_checked",
    }, "expected_fields")
    require(result["proof_id"] == parse_hex(expected["order_finality_proof_id"], "proof_id") and result["genesis_block_id"] == parse_hex(expected["trusted_genesis_block_id"], "genesis_id"), "expected_ids")
    require(result["finalized_block_id"] == parse_hex(expected["finalized_block_id"], "finalized_id") and result["finalized_height"] == expected["finalized_height"], "expected_finalized")
    require(result["validator_set_definition_hash"] == parse_hex(expected["validator_set_definition_hash"], "validator_set_definition_hash"), "expected_validator_set_definition_hash")
    require(result["validator_set_hash"] == parse_hex(expected["validator_set_hash"], "validator_set_hash"), "expected_validator_set_hash")
    require(result["consensus_parameters_hash"] == parse_hex(expected["consensus_parameters_hash"], "consensus_parameters_hash"), "expected_consensus_parameters_hash")
    require(result["epoch_descriptor_id"] == parse_hex(expected["epoch_descriptor_id"], "epoch_descriptor_id"), "expected_epoch_descriptor_id")
    require([value.hex() for value in result["qc_ids"]] == expected["qc_ids"] and expected["valid_qc_signatures_checked"] == 12, "expected_qcs")
    replay = verify_light_client(trust_raw, proof_raw)
    require(replay == result, "exact_replay")
    monotonic_replay = verify_light_client(trust_raw, proof_raw, (result["finalized_height"], result["finalized_block_id"]))
    require(monotonic_replay == result, "monotonic_replay")
    ordinary_case = exact_keys(
        corpus.get("ordinary_target_case"),
        {"trust_bundle_cev1_hex", "order_finality_proof_cev1_hex", "expected"},
        "ordinary_case_fields",
    )
    ordinary_trust_raw = parse_hex(ordinary_case["trust_bundle_cev1_hex"], "ordinary_trust")
    ordinary_proof_raw = parse_hex(ordinary_case["order_finality_proof_cev1_hex"], "ordinary_proof")
    ordinary_result = verify_light_client(
        ordinary_trust_raw, ordinary_proof_raw,
        (result["finalized_height"], result["finalized_block_id"]),
    )
    ordinary_expected = exact_keys(ordinary_case["expected"], {
        "order_finality_proof_id", "finalized_block_id", "finalized_height", "target_kind",
        "qc_ids", "tc_ids", "valid_qc_signatures_checked", "valid_tc_signatures_checked",
    }, "ordinary_expected_fields")
    require(ordinary_result["proof_id"] == parse_hex(ordinary_expected["order_finality_proof_id"], "ordinary_proof_id"), "ordinary_expected_proof_id")
    require(
        ordinary_result["finalized_block_id"] == parse_hex(ordinary_expected["finalized_block_id"], "ordinary_finalized_id")
        and ordinary_result["finalized_height"] == ordinary_expected["finalized_height"]
        and ordinary_result["target_kind"] == ordinary_expected["target_kind"] == "Ordinary",
        "ordinary_expected_target",
    )
    require([value.hex() for value in ordinary_result["qc_ids"]] == ordinary_expected["qc_ids"], "ordinary_expected_qcs")
    require([value.hex() for value in ordinary_result["tc_ids"]] == ordinary_expected["tc_ids"], "ordinary_expected_tcs")
    require(ordinary_expected["valid_qc_signatures_checked"] == 16 and ordinary_expected["valid_tc_signatures_checked"] == 4, "ordinary_expected_signatures")
    require(ordinary_result["finalized_height"] > result["finalized_height"], "ordinary_monotonic_advance")

    direct_case = exact_keys(
        corpus.get("direct_ordinary_target_case"),
        {"trust_bundle_cev1_hex", "order_finality_proof_cev1_hex", "expected"},
        "direct_ordinary_case_fields",
    )
    direct_trust_raw = parse_hex(
        direct_case["trust_bundle_cev1_hex"], "direct_ordinary_trust",
    )
    direct_proof_raw = parse_hex(
        direct_case["order_finality_proof_cev1_hex"], "direct_ordinary_proof",
    )
    require(direct_trust_raw == trust_raw, "direct_ordinary_trust_identity")
    direct_result = verify_light_client(
        direct_trust_raw, direct_proof_raw,
        (result["finalized_height"], result["finalized_block_id"]),
    )
    direct_expected = exact_keys(direct_case["expected"], {
        "order_finality_proof_id", "finalized_block_id", "finalized_height",
        "target_kind", "qc_ids", "tc_ids", "valid_qc_signatures_checked",
    }, "direct_ordinary_expected_fields")
    require(
        direct_result["proof_id"]
        == parse_hex(direct_expected["order_finality_proof_id"], "direct_ordinary_proof_id")
        and direct_result["finalized_block_id"]
        == parse_hex(direct_expected["finalized_block_id"], "direct_ordinary_finalized_id")
        and direct_result["finalized_height"] == direct_expected["finalized_height"] == 2
        and direct_result["target_kind"] == direct_expected["target_kind"] == "Ordinary",
        "direct_ordinary_expected_target",
    )
    require(
        [value.hex() for value in direct_result["qc_ids"]] == direct_expected["qc_ids"]
        and direct_result["tc_ids"] == []
        and direct_expected["tc_ids"] == []
        and direct_expected["valid_qc_signatures_checked"] == 16,
        "direct_ordinary_expected_certificates",
    )

    transition_case = exact_keys(
        corpus.get("epoch_transition_case"),
        {"epoch_transition_cev1_hex", "expected"},
        "transition_case_fields",
    )
    transition_raw = parse_hex(
        transition_case["epoch_transition_cev1_hex"], "epoch_transition",
    )
    transition_result = verify_epoch_transition(transition_raw)
    transition_expected = exact_keys(transition_case["expected"], {
        "transition_sha256", "checkpoint_proof_id", "checkpoint_id", "handoff_id",
        "old_terminal_block_id", "old_terminal_height", "new_epoch",
        "new_epoch_descriptor_id", "new_validator_set_hash",
        "new_consensus_parameters_hash", "handoff_anchor_finalized_block_id",
        "handoff_anchor_finalized_height", "finalized_block_id", "finalized_height",
        "finalized_kind", "new_qc_ids", "old_handoff_weight", "new_handoff_weight",
        "old_handoff_signatures", "new_handoff_signatures",
        "old_qc_signatures_checked", "new_qc_signatures_checked",
    }, "transition_expected_fields")
    for key in (
        "transition_sha256", "checkpoint_proof_id", "checkpoint_id", "handoff_id",
        "old_terminal_block_id", "new_epoch_descriptor_id", "new_validator_set_hash",
        "new_consensus_parameters_hash", "handoff_anchor_finalized_block_id",
        "finalized_block_id",
    ):
        require(
            transition_result[key] == parse_hex(transition_expected[key], key),
            "transition_expected_id",
            key,
        )
    for key in (
        "old_terminal_height", "new_epoch", "handoff_anchor_finalized_height",
        "finalized_height", "old_handoff_weight", "new_handoff_weight",
        "old_handoff_signatures", "new_handoff_signatures",
    ):
        require(transition_result[key] == transition_expected[key], "transition_expected_scalar", key)
    require(
        transition_result["finalized_kind"] == transition_expected["finalized_kind"] == "Ordinary",
        "transition_expected_kind",
    )
    require(
        [value.hex() for value in transition_result["new_qc_ids"]]
        == transition_expected["new_qc_ids"],
        "transition_expected_qcs",
    )
    require(
        transition_expected["old_qc_signatures_checked"] == 16
        and transition_expected["new_qc_signatures_checked"] == 16
        and transition_result["old_handoff_signatures"] == 4
        and transition_result["new_handoff_signatures"] == 4,
        "transition_expected_signatures",
    )
    require(
        transition_result["old_terminal_height"]
        < transition_result["handoff_anchor_finalized_height"]
        < transition_result["finalized_height"],
        "transition_expected_progression",
    )
    require(verify_epoch_transition(transition_raw) == transition_result, "transition_exact_replay")
    exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
    for marker in (
        "more than one epoch handoff", "arbitrary-length", "proposer-signature",
        "state-sync", "second implementation", "activation", "normative freeze",
    ):
        require(marker in exclusions, "corpus_exclusion", marker)
    if self_test_mutants:
        for case_id in NEGATIVE_IDS:
            mutated_trust, mutated_proof, prior = mutation_case(case_id, trust_raw, proof_raw)
            try:
                verify_light_client(mutated_trust, mutated_proof, prior)
            except EvidenceError as exc:
                actual_code = str(exc).split(":", 1)[0]
                require(
                    actual_code == EXPECTED_NEGATIVE_CODES[case_id],
                    "negative_error_code",
                    f"{case_id}: expected {EXPECTED_NEGATIVE_CODES[case_id]}, got {actual_code}",
                )
                continue
            reject("negative_accepted", case_id)
        for case_id in TC_NEGATIVE_IDS:
            mutated_trust, mutated_proof = mutation_tc_case(case_id, ordinary_trust_raw, ordinary_proof_raw)
            try:
                verify_light_client(mutated_trust, mutated_proof)
            except EvidenceError as exc:
                actual_code = str(exc).split(":", 1)[0]
                require(
                    actual_code == EXPECTED_TC_NEGATIVE_CODES[case_id],
                    "tc_negative_error_code",
                    f"{case_id}: expected {EXPECTED_TC_NEGATIVE_CODES[case_id]}, got {actual_code}",
                )
                continue
            reject("tc_negative_accepted", case_id)
        for case_id in TRANSITION_NEGATIVE_IDS:
            mutated_transition = mutation_transition_case(case_id, transition_raw)
            try:
                verify_epoch_transition(mutated_transition)
            except EvidenceError as exc:
                actual_code = str(exc).split(":", 1)[0]
                require(
                    actual_code == EXPECTED_TRANSITION_NEGATIVE_CODES[case_id],
                    "transition_negative_error_code",
                    f"{case_id}: expected {EXPECTED_TRANSITION_NEGATIVE_CODES[case_id]}, got {actual_code}",
                )
                continue
            reject("transition_negative_accepted", case_id)
    return (
        trust_raw, proof_raw, ordinary_trust_raw, ordinary_proof_raw,
        transition_raw, result, ordinary_result, transition_result,
    )


def openssl_records(trust_raw: bytes, *proofs_raw: bytes) -> list[tuple[str, str, str]]:
    trust = decode_exact(trust_raw, "trust", dec_trust, enc_trust)
    members = {member["validator_id"]: member for member in trust["validator_set"]["definition"]["members"]}
    records = []
    for proof_index, proof_raw in enumerate(proofs_raw):
        proof = decode_exact(proof_raw, f"proof-{proof_index}", dec_proof, enc_proof)
        for certified in proof["certified_chain"]:
            body = certified["certifying_qc"]["body"]
            root = digest(VOTE_DOMAIN, enc_vote(body["statement"]))
            for entry in body["signatures"]:
                records.append((members[entry["voter_id"]]["consensus_public_key"].hex(), entry["signature"].hex(), root.hex()))
            tc = certified["timeout_certificate"]
            if tc is not None:
                for entry in tc["body"]["entries"]:
                    root = digest(TIMEOUT_SIGNATURE_DOMAIN, enc_timeout_statement(entry["statement"]))
                    records.append((members[entry["validator_id"]]["consensus_public_key"].hex(), entry["signature"].hex(), root.hex()))
    return records


def transition_openssl_records(transition_raw: bytes) -> list[tuple[str, str, str]]:
    transition = decode_exact(
        transition_raw, "epoch_transition_openssl", dec_epoch_transition, enc_epoch_transition,
    )
    old_members = {
        member["validator_id"]: member
        for member in transition["old_trust_bundle"]["validator_set"]["definition"]["members"]
    }
    new_members = {
        member["validator_id"]: member
        for member in transition["new_validator_set"]["definition"]["members"]
    }
    records: list[tuple[str, str, str]] = []
    for item, members in (
        *((item, old_members) for item in transition["checkpoint_finality_proof"]["certified_chain"]),
        *((item, new_members) for item in transition["new_epoch_certified_chain"]),
    ):
        body = item["certifying_qc"]["body"]
        root = digest(VOTE_DOMAIN, enc_vote(body["statement"]))
        for entry in body["signatures"]:
            records.append((
                members[entry["voter_id"]]["consensus_public_key"].hex(),
                entry["signature"].hex(), root.hex(),
            ))
    handoff = transition["handoff"]
    for entries, members, domain in (
        (handoff["old_set_signatures"], old_members, EPOCH_HANDOFF_OLD_SIGNATURE_DOMAIN),
        (handoff["new_set_signatures"], new_members, EPOCH_HANDOFF_NEW_SIGNATURE_DOMAIN),
    ):
        for entry in entries:
            root = digest(domain, enc_handoff_statement(entry["statement"]))
            records.append((
                members[entry["signer_id"]]["consensus_public_key"].hex(),
                entry["signature"].hex(), root.hex(),
            ))
    return records


def main() -> None:
    assert_strict_json_loader()
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test-mutants", action="store_true")
    parser.add_argument("--emit-corpus", action="store_true")
    parser.add_argument("--write-corpus", action="store_true")
    parser.add_argument("--emit-openssl-records", action="store_true")
    parser.add_argument("--check-trust-path", action="store_true")
    parser.add_argument("--self-test-trust-path-mutants", action="store_true")
    parser.add_argument("--emit-trust-path-corpus", action="store_true")
    parser.add_argument("--write-trust-path-corpus", action="store_true")
    parser.add_argument("--emit-trust-path-openssl-records", action="store_true")
    parser.add_argument("--check-weak-subjectivity-renewal", action="store_true")
    parser.add_argument("--self-test-weak-subjectivity-mutants", action="store_true")
    parser.add_argument("--emit-weak-subjectivity-corpus", action="store_true")
    parser.add_argument("--write-weak-subjectivity-corpus", action="store_true")
    parser.add_argument("--check-ordinary-advance", action="store_true")
    parser.add_argument("--self-test-ordinary-advance-mutants", action="store_true")
    parser.add_argument("--emit-ordinary-advance-corpus", action="store_true")
    parser.add_argument("--write-ordinary-advance-corpus", action="store_true")
    parser.add_argument("--emit-ordinary-advance-openssl-records", action="store_true")
    args = parser.parse_args()
    old_modes = (args.check, args.emit_corpus, args.write_corpus, args.emit_openssl_records)
    trust_path_modes = (
        args.check_trust_path, args.emit_trust_path_corpus,
        args.write_trust_path_corpus, args.emit_trust_path_openssl_records,
    )
    weak_subjectivity_modes = (
        args.check_weak_subjectivity_renewal,
        args.emit_weak_subjectivity_corpus,
        args.write_weak_subjectivity_corpus,
    )
    ordinary_advance_modes = (
        args.check_ordinary_advance,
        args.emit_ordinary_advance_corpus,
        args.write_ordinary_advance_corpus,
        args.emit_ordinary_advance_openssl_records,
    )
    require(
        sum(old_modes + trust_path_modes + weak_subjectivity_modes + ordinary_advance_modes) == 1,
        "mode",
    )
    if any(ordinary_advance_modes):
        validate_ordinary_advance_schema_contract()
        if args.emit_ordinary_advance_corpus or args.write_ordinary_advance_corpus:
            rendered = json.dumps(
                build_ordinary_advance_corpus(), indent=2, sort_keys=False,
            ) + "\n"
            if args.write_ordinary_advance_corpus:
                ORDINARY_ADVANCE_CORPUS_PATH.write_text(rendered, encoding="utf-8")
                print(f"WROTE: {ORDINARY_ADVANCE_CORPUS_PATH.relative_to(ROOT)}")
            else:
                print(rendered, end="")
            return
        corpus = load_json_document(
            ORDINARY_ADVANCE_CORPUS_PATH, "ordinary_advance_corpus",
        )
        trust_raw, proof_raw, advance_raws, results = validate_ordinary_advance_corpus(
            corpus, args.self_test_ordinary_advance_mutants,
        )
        if args.emit_ordinary_advance_openssl_records:
            records = ordinary_advance_openssl_records(trust_raw, proof_raw, advance_raws)
            require(len(records) == 48, "ordinary_advance_openssl_record_count")
            for public_key, signature, message in records:
                print(f"{public_key}\t{signature}\t{message}")
            return
        print(
            "PASS: bounded PoCO AI-native v1 Ordinary finality advance "
            f"(positive_controls=4 sequential_advances=2 exact_error_negatives="
            f"{len(ORDINARY_ADVANCE_NEGATIVE_IDS)} source_finalized_height="
            f"{results[0]['old_finalized_height']} terminal_finalized_height="
            f"{results[-1]['new_finalized_height']} QC_signatures=40 "
            f"TC_signatures=8 OpenSSL_signatures=48 terminal_state_id="
            f"{results[-1]['output_state_id'].hex()}); candidate-only, same-epoch, "
            "one-skipped-view-per-advance; payload-execution/arbitrary-history/"
            "global-light-client/freeze/implementation/activation remain false"
        )
        return
    if any(weak_subjectivity_modes):
        validate_weak_subjectivity_schema_contract()
        if args.emit_weak_subjectivity_corpus or args.write_weak_subjectivity_corpus:
            rendered = json.dumps(
                build_weak_subjectivity_corpus(), indent=2, sort_keys=False,
            ) + "\n"
            if args.write_weak_subjectivity_corpus:
                WEAK_SUBJECTIVITY_CORPUS_PATH.write_text(rendered, encoding="utf-8")
                print(f"WROTE: {WEAK_SUBJECTIVITY_CORPUS_PATH.relative_to(ROOT)}")
            else:
                print(rendered, end="")
            return
        corpus = load_json_document(
            WEAK_SUBJECTIVITY_CORPUS_PATH, "weak_subjectivity_corpus",
        )
        _, _, result = validate_weak_subjectivity_corpus(
            corpus, args.self_test_weak_subjectivity_mutants,
        )
        print(
            "PASS: bounded PoCO AI-native v1 weak-subjectivity checkpoint renewal "
            f"(positive_controls=2 exact_error_negatives="
            f"{len(WEAK_SUBJECTIVITY_NEGATIVE_IDS)} prior_height={result['prior_height']} "
            f"renewed_height={result['renewed_height']} "
            f"observed_epoch={result['observed_epoch']} "
            f"observed_height={result['observed_height']} "
            f"renewal_id={result['renewal_id'].hex()}); candidate-only, exact-three-hop; "
            "wall-clock/operator-auth/arbitrary-history/global-light-client/"
            "freeze/implementation/activation remain false"
        )
        return
    if any(trust_path_modes):
        validate_trust_path_schema_contract()
        if args.emit_trust_path_corpus or args.write_trust_path_corpus:
            rendered = json.dumps(build_trust_path_corpus(), indent=2, sort_keys=False) + "\n"
            if args.write_trust_path_corpus:
                TRUST_PATH_CORPUS_PATH.write_text(rendered, encoding="utf-8")
                print(f"WROTE: {TRUST_PATH_CORPUS_PATH.relative_to(ROOT)}")
            else:
                print(rendered, end="")
            return
        trust_path_corpus = load_json_document(
            TRUST_PATH_CORPUS_PATH, "trust_path_corpus",
        )
        trust_path_raw, trust_path_result = validate_trust_path_corpus(
            trust_path_corpus, args.self_test_trust_path_mutants,
        )
        if args.emit_trust_path_openssl_records:
            records = trust_path_openssl_records(trust_path_raw)
            require(len(records) == 116, "trust_path_openssl_record_count")
            for public_key, signature, message in records:
                print(f"{public_key}\t{signature}\t{message}")
            return
        print(
            "PASS: bounded PoCO AI-native v1 Order trust-path iterator "
            f"(positive_hops=0/1/2/3 replay_controls=2 negatives={len(TRUST_PATH_NEGATIVE_IDS)} "
            f"QC_signatures={trust_path_result['qc_signatures_checked']} "
            f"TC_signatures={trust_path_result['tc_signatures_checked']} "
            f"handoff_signatures={trust_path_result['handoff_signatures_checked']} "
            f"OpenSSL_signatures=116 terminal_epoch={trust_path_result['terminal_epoch']} "
            f"terminal_height={trust_path_result['terminal_finalized_height']} "
            f"path_id={trust_path_result['path_id'].hex()}); candidate-only, max_hops=3; "
            "v0 activation/weak-subjectivity/global-light-client/complete-wire/freeze/implementation/activation remain false"
        )
        return
    validate_schema_contract()
    if args.emit_corpus or args.write_corpus:
        rendered = json.dumps(build_corpus(), indent=2, sort_keys=False) + "\n"
        if args.write_corpus:
            CORPUS_PATH.write_text(rendered, encoding="utf-8")
            print(f"WROTE: {CORPUS_PATH.relative_to(ROOT)}")
        else:
            print(rendered, end="")
        return
    corpus = load_json_document(CORPUS_PATH, "light_client_corpus")
    (
        trust_raw, proof_raw, ordinary_trust_raw, ordinary_proof_raw,
        transition_raw, result, ordinary_result, transition_result,
    ) = validate_corpus(corpus, args.self_test_mutants)
    if args.emit_openssl_records:
        require(trust_raw == ordinary_trust_raw, "openssl_trust_bundle_identity")
        for public_key, signature, message in openssl_records(trust_raw, proof_raw, ordinary_proof_raw):
            print(f"{public_key}\t{signature}\t{message}")
        for public_key, signature, message in transition_openssl_records(transition_raw):
            print(f"{public_key}\t{signature}\t{message}")
        return
    print(
        "PASS: bounded PoCO AI-native v1 independent OrderFinalityProof light client "
        f"(raw_CEV1_objects=5+2_rust_direct positive_controls=9 "
        f"QC_signatures=60 direct_ordinary_QC_signatures=16 TC_signatures=4 "
        f"handoff_signatures=8 negatives={len(NEGATIVE_IDS) + len(TC_NEGATIVE_IDS) + len(TRANSITION_NEGATIVE_IDS)} "
        f"fresh_height={result['finalized_height']} ordinary_height={ordinary_result['finalized_height']} "
        f"handoff_height={transition_result['handoff_anchor_finalized_height']} "
        f"post_handoff_ordinary_height={transition_result['finalized_height']} "
        f"transition_sha256={transition_result['transition_sha256'].hex()}); "
        "candidate-only, FreshGenesis/Ordinary/checkpoint/one-handoff trust progression; "
        "no arbitrary-length handoff path/global-light-client/freeze/activation claim"
    )


if __name__ == "__main__":
    try:
        main()
    except (EvidenceError, json.JSONDecodeError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
