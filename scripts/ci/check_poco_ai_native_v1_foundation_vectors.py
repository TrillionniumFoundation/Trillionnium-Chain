#!/usr/bin/env python3
"""Author and verify the candidate CEV1 foundation/order-kernel artifact.

This checker is deliberately self-contained (Python standard library only).
It closes only the logical types listed in the generated schema.  It does not
change, or provide evidence for changing, any repository-wide v1 draft/freeze,
implementation, activation, release, or semantic-consistency truth bit.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json"
VECTORS_PATH = REPO_ROOT / "docs/protocol/poco-ai-native-v1/vectors/cev1-foundation-order-kernel-v1.json"

U8_MAX = (1 << 8) - 1
U16_MAX = (1 << 16) - 1
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1


class CandidateError(ValueError):
    """A stable conformance rejection used by negative vectors."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _field(name: str, type_expr: Any) -> dict[str, Any]:
    return {"name": name, "type": type_expr}


def _record(*fields: tuple[str, Any]) -> dict[str, Any]:
    return {"kind": "record", "fields": [_field(name, typ) for name, typ in fields]}


def _alias(target: str) -> dict[str, str]:
    return {"kind": "alias", "target": target}


def _option(target: Any) -> dict[str, Any]:
    return {"option": target}


def _list(target: Any) -> dict[str, Any]:
    return {"list": target}


def _enum(repr_type: str, variants: list[tuple[int, str, Any | None]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for tag, name, body in variants:
        item: dict[str, Any] = {"tag": tag, "name": name}
        if body is not None:
            item["body"] = body
        items.append(item)
    return {"kind": "enum", "repr": repr_type, "variants": items}


def build_schema() -> dict[str, Any]:
    root_kinds = [
        (0, "block_batch_refs"),
        (1, "block_protocol_objects"),
        (2, "block_transaction_execution_receipts"),
        (3, "block_or_evaluation_evidence"),
        (4, "block_consumption_rollups"),
        (5, "block_settlement"),
        (6, "block_resource_usage"),
        (7, "transaction_batch_content"),
        (8, "artifact_evidence_content"),
        (9, "da_chunks"),
        (10, "retrieval_returned_chunks"),
        (11, "transaction_events"),
        (12, "transaction_read_set"),
        (13, "transaction_write_set"),
        (14, "transaction_state_delta"),
        (15, "transaction_created_objects"),
        (16, "rollup_receipts"),
        (17, "result_task_result"),
        (18, "settlement_input_value"),
        (19, "settlement_planned_deltas"),
        (20, "settlement_conservation"),
    ]

    object_kind_names = [
        "AgentIdV1",
        "AgentKeyIdV1",
        "CapabilityIdV1",
        "SessionKeyGrantIdV1",
        "TaskIdV1",
        "BidIdV1",
        "LeaseIdV1",
        "EscrowIdV1",
        "CheckpointIdV1",
        "ResultIdV1",
        "ExecutionReceiptIdV1",
        "TransactionExecutionReceiptIdV1",
        "VerificationClaimIdV1",
        "VerificationDecisionIdV1",
        "ChallengeIdV1",
        "BatchIdV1",
        "ArtifactIdV1",
        "AvailabilityCertificateIdV1",
        "ConsumptionRollupIdV1",
        "ConsumptionReceiptIdV1",
        "SettlementIdV1",
        "AgentTransactionIdV1",
        "BlockIdV1",
        "OrderProposalIdV1",
        "VoteIdV1",
        "TimeoutIdV1",
        "QuorumCertificateIdV1",
        "TimeoutCertificateIdV1",
        "EpochDescriptorIdV1",
        "EpochCheckpointIdV1",
        "EpochHandoffIdV1",
        "DaCommitteeIdV1",
        "DaAttestationIdV1",
        "RetrievalReceiptIdV1",
        "StateSyncManifestIdV1",
        "UpgradePlanIdV1",
        "MigrationReceiptIdV1",
        "V0ToV1ActivationStatementIdV1",
        "ActivationAnchorIdV1",
        "OrderFinalityProofIdV1",
        "ApplicationStateProofIdV1",
        "ArtifactAvailabilityProofIdV1",
        "ResultSettlementFinalityProofIdV1",
        "GenesisAnchorIdV1",
        "NonceLaneIdV1",
        "AccountIdV1",
        "ValuePoolIdV1",
        "BondIdV1",
        "ConsumptionReceiptCoordinateIdV1",
        "DaObligationIdV1",
        "GlobalExecutionBindingIdV1",
    ]
    object_domains = [
        "trnm.poco-ai.agent.v1",
        "trnm.poco-ai.agent-key.v1",
        "trnm.poco-ai.capability.v1",
        "trnm.poco-ai.session-key-grant.v1",
        "trnm.poco-ai.task.v1",
        "trnm.poco-ai.bid.v1",
        "trnm.poco-ai.lease.v1",
        "trnm.poco-ai.escrow.v1",
        "trnm.poco-ai.compute-checkpoint.v1",
        "trnm.poco-ai.result.v1",
        "trnm.poco-ai.execution-receipt.v1",
        "trnm.poco-ai.transaction-execution-receipt.v1",
        "trnm.poco-ai.verification-claim.v1",
        "trnm.poco-ai.verification-decision.v1",
        "trnm.poco-ai.challenge.v1",
        "trnm.poco-ai.da-batch.v1",
        "trnm.poco-ai.artifact.v1",
        "trnm.poco-ai.availability-certificate.v1",
        "trnm.poco-ai.consumption-rollup.v1",
        "trnm.poco-ai.consumption-receipt.v1",
        "trnm.poco-ai.settlement.v1",
        "trnm.poco-ai.agent-transaction.v1",
        "trnm.poco-ai.order-block.v1",
        "trnm.poco-ai.order-proposal.v1",
        "trnm.poco-ai.order-vote.v1",
        "trnm.poco-ai.order-timeout.v1",
        "trnm.poco-ai.order-qc.v1",
        "trnm.poco-ai.order-tc.v1",
        "trnm.poco-ai.epoch-descriptor.v1",
        "trnm.poco-ai.epoch-checkpoint.v1",
        "trnm.poco-ai.epoch-handoff.v1",
        "trnm.poco-ai.da-committee.v1",
        "trnm.poco-ai.da-attestation.v1",
        "trnm.poco-ai.retrieval-receipt.v1",
        "trnm.poco-ai.state-sync-manifest.v1",
        "trnm.poco-ai.upgrade-plan.v1",
        "trnm.poco-ai.migration-receipt.v1",
        "trnm.poco-ai.v0-to-v1-activation-statement.v1",
        "trnm.poco-ai.activation-anchor.v1",
        "trnm.poco-ai.order-finality-proof.v1",
        "trnm.poco-ai.application-state-proof.v1",
        "trnm.poco-ai.artifact-availability-proof.v1",
        "trnm.poco-ai.result-settlement-finality-proof.v1",
        "trnm.poco-ai.genesis-anchor.v1",
        "trnm.poco-ai.nonce-lane.v1",
        "trnm.poco-ai.account.v1",
        "trnm.poco-ai.value-pool.v1",
        "trnm.poco-ai.bond.v1",
        "trnm.poco-ai.consumption-receipt-coordinate.v1",
        "trnm.poco-ai.da-obligation.v1",
        "trnm.poco-ai.global-execution-binding.v1",
    ]
    object_kinds = [
        {"tag": tag, "type": name, "domain": object_domains[tag]}
        for tag, name in enumerate(object_kind_names)
    ]

    types: dict[str, Any] = {}
    for name in object_kind_names:
        types[name] = _alias("Hash32")

    types.update(
        {
            "ProtocolContextV1": _record(
                ("schema_version", "u16"),
                ("genesis_hash", "Hash32"),
                ("chain_id", "ConsensusString"),
                ("protocol_version", "u32"),
                ("stack_profile_hash", "Hash32"),
            ),
            "ValidatorMemberV1": _record(
                ("validator_id", "Bytes"),
                ("consensus_key_scheme", "u16"),
                ("consensus_public_key", "Bytes"),
                ("voting_weight", "u128"),
                ("network_identity_commitment", "Hash32"),
                ("safety_signer_policy_hash", "Hash32"),
                ("poco_economic_record_hash", "Hash32"),
            ),
            "ValidatorSetDefinitionV1": _record(
                ("schema_version", "u16"),
                ("members", _list("ValidatorMemberV1")),
                ("total_weight", "u128"),
                ("quorum_threshold", "u128"),
            ),
            "ValidatorSetDescriptorV1": _record(
                ("schema_version", "u16"),
                ("context", "ProtocolContextV1"),
                ("epoch", "u64"),
                ("definition", "ValidatorSetDefinitionV1"),
            ),
            "ConsensusParametersV1": _record(
                ("schema_version", "u16"),
                ("quorum_numerator", "u16"),
                ("quorum_denominator", "u16"),
                ("finality_chain_length", "u8"),
                ("execute_coordination_before_vote", "bool"),
                ("max_validators", "u32"),
                ("max_consensus_string_bytes", "u32"),
                ("max_cev1_nesting", "u16"),
                ("max_cev1_value_bytes", "u64"),
                ("max_signature_bytes", "u32"),
                ("max_certificate_signers", "u32"),
                ("max_epoch", "u64"),
                ("max_view", "u64"),
                ("max_height", "u64"),
                ("max_retained_views", "u32"),
                ("epoch_length_blocks", "u64"),
                ("checkpoint_offset_blocks", "u64"),
                ("seal_1_offset_blocks", "u64"),
                ("seal_2_offset_blocks", "u64"),
                ("max_block_ordered_bytes", "u64"),
                ("max_batch_refs_per_block", "u32"),
                ("max_protocol_objects_per_block", "u32"),
                ("max_transactions_per_batch", "u32"),
                ("max_transaction_bytes", "u64"),
                ("max_block_execution_units", "u128"),
                ("base_view_timeout_ms", "u64"),
                ("maximum_view_timeout_ms", "u64"),
                ("timeout_multiplier_numerator", "u32"),
                ("timeout_multiplier_denominator", "u32"),
                ("max_evidence_items_per_block", "u32"),
                ("max_evidence_bytes_per_block", "u64"),
            ),
            "TypedObjectIdV1": _record(("object_kind", "u16"), ("object_id", "Hash32")),
            "MerkleLeafBodyV1": _record(
                ("root_kind", "u16"),
                ("index", "u32"),
                ("item_kind", "u16"),
                ("item_id", "Hash32"),
                ("item_commitment", "Hash32"),
            ),
            "MerkleNodeBodyV1": _record(
                ("root_kind", "u16"),
                ("level", "u32"),
                ("left", "Hash32"),
                ("right", "Hash32"),
            ),
            "MerkleListRootBodyV1": _record(
                ("root_kind", "u16"),
                ("item_count", "u32"),
                ("tree_root", _option("Hash32")),
            ),
            "ConsensusContextV1": _record(
                ("schema_version", "u16"),
                ("context", "ProtocolContextV1"),
                ("runtime_profile_hash", "Hash32"),
                ("epoch", "u64"),
                ("validator_set_hash", "Hash32"),
                ("consensus_parameters_hash", "Hash32"),
                ("view", "u64"),
                ("message_kind", "u8"),
            ),
            "BatchRefV1": _record(
                ("schema_version", "u16"),
                ("context", "ProtocolContextV1"),
                ("epoch", "u64"),
                ("author_id", "Bytes"),
                ("author_sequence", "u64"),
                ("batch_id", "BatchIdV1"),
                ("content_root", "Hash32"),
                ("item_count", "u32"),
                ("uncompressed_bytes", "u64"),
                ("availability_certificate_id", "AvailabilityCertificateIdV1"),
                ("retention_end_epoch", "u64"),
            ),
            "GenesisParentBodyV1": _record(
                ("genesis_derived_state_hash", "Hash32"),
                ("application_state_root", "Hash32"),
            ),
            "V1BlockParentBodyV1": _record(("block_id", "BlockIdV1")),
            "V0TerminalBlockParentBodyV1": _record(
                ("block_id_bytes", "Hash32"),
                ("handoff_certificate_digest", "Hash32"),
                ("activation_statement_id", "V0ToV1ActivationStatementIdV1"),
            ),
            "ParentBlockRefV1": _enum(
                "u8",
                [
                    (0, "GenesisAnchor", "GenesisParentBodyV1"),
                    (1, "V1Block", "V1BlockParentBodyV1"),
                    (2, "V0TerminalBlock", "V0TerminalBlockParentBodyV1"),
                ],
            ),
            "BlockKindV1": _enum(
                "u8",
                [
                    (0, "FreshGenesis", None),
                    (1, "Ordinary", None),
                    (2, "EpochCheckpoint", None),
                    (3, "EpochSeal1", None),
                    (4, "EpochSeal2", None),
                    (5, "V0ActivationFirst", None),
                    (6, "V1HandoffFirst", None),
                ],
            ),
            "BlockHeaderV1": _record(
                ("schema_version", "u16"),
                ("context", "ProtocolContextV1"),
                ("epoch", "u64"),
                ("view", "u64"),
                ("height", "u64"),
                ("block_kind", "BlockKindV1"),
                ("parent", "ParentBlockRefV1"),
                ("proposer_id", "Bytes"),
                ("epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("justify_qc_id", _option("QuorumCertificateIdV1")),
                ("timeout_certificate_id", _option("TimeoutCertificateIdV1")),
                ("batch_refs_root", "Hash32"),
                ("protocol_objects_root", "Hash32"),
                ("post_state_root", "Hash32"),
                ("transaction_execution_receipts_root", "Hash32"),
                ("evidence_root", "Hash32"),
                ("consumption_rollups_root", "Hash32"),
                ("settlement_root", "Hash32"),
                ("resource_usage_root", "Hash32"),
                ("next_epoch_descriptor_id", _option("EpochDescriptorIdV1")),
                ("upgrade_plan_id", _option("UpgradePlanIdV1")),
                ("epoch_handoff_id", _option("EpochHandoffIdV1")),
            ),
            "VoteStatementBodyV1": _record(
                ("schema_version", "u16"),
                ("consensus_context", "ConsensusContextV1"),
                ("block_id", "BlockIdV1"),
                ("height", "u64"),
                ("epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("post_state_root", "Hash32"),
                ("batch_refs_root", "Hash32"),
                ("transaction_execution_receipts_root", "Hash32"),
            ),
            "VoteSignatureEntryV1": _record(
                ("voter_id", "Bytes"),
                ("signature_scheme", "u16"),
                ("signature", "Bytes"),
            ),
            "VoteIdentityBodyV1": _record(
                ("statement", "VoteStatementBodyV1"), ("voter_id", "Bytes")
            ),
            "QuorumCertificateBodyV1": _record(
                ("schema_version", "u16"),
                ("statement", "VoteStatementBodyV1"),
                ("signatures", _list("VoteSignatureEntryV1")),
            ),
            "QuorumCertificateV1": _record(
                ("body", "QuorumCertificateBodyV1"),
                ("quorum_certificate_id", "QuorumCertificateIdV1"),
            ),
            "QcJustificationRefBodyV1": _record(
                ("qc_id", "QuorumCertificateIdV1"), ("qc_view", "u64")
            ),
            "EpochStartJustificationRefBodyV1": _record(
                ("anchor_kind", "u8"), ("anchor_id", "Hash32"), ("anchor_view", "u64")
            ),
            "HighJustificationRefV1": _enum(
                "u8",
                [
                    (0, "QC", "QcJustificationRefBodyV1"),
                    (1, "EpochStart", "EpochStartJustificationRefBodyV1"),
                ],
            ),
            "FreshGenesisFinalizedAnchorBodyV1": _record(
                ("genesis_derived_state_hash", "Hash32"),
            ),
            "V0ActivationFinalizedAnchorBodyV1": _record(
                ("activation_statement_id", "V0ToV1ActivationStatementIdV1"),
            ),
            "EpochCheckpointFinalizedAnchorBodyV1": _record(
                ("checkpoint_id", "EpochCheckpointIdV1"),
            ),
            "FinalizedAnchorRefV1": _enum(
                "u8",
                [
                    (0, "FreshGenesis", "FreshGenesisFinalizedAnchorBodyV1"),
                    (1, "V0Activation", "V0ActivationFinalizedAnchorBodyV1"),
                    (2, "EpochCheckpoint", "EpochCheckpointFinalizedAnchorBodyV1"),
                ],
            ),
            "TimeoutStatementBodyV1": _record(
                ("schema_version", "u16"),
                ("consensus_context", "ConsensusContextV1"),
                ("high_justification", "HighJustificationRefV1"),
                ("locked_qc_id", _option("QuorumCertificateIdV1")),
                ("locked_qc_view", "u64"),
                ("last_finalized_anchor", "FinalizedAnchorRefV1"),
                ("pacemaker_generation", "u64"),
            ),
            "TimeoutSignatureEntryV1": _record(
                ("validator_id", "Bytes"),
                ("statement", "TimeoutStatementBodyV1"),
                ("signature_scheme", "u16"),
                ("signature", "Bytes"),
            ),
            "TimeoutIdentityBodyV1": _record(
                ("statement", "TimeoutStatementBodyV1"), ("validator_id", "Bytes")
            ),
            "GenesisAnchorBodyV1": _record(
                ("schema_version", "u16"),
                ("target_context", "ProtocolContextV1"),
                ("genesis_derived_state_hash", "Hash32"),
                ("application_state_root", "Hash32"),
                ("target_epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("initial_height", "u64"),
                ("initial_view", "u64"),
            ),
            "GenesisAnchorV1": _record(
                ("body", "GenesisAnchorBodyV1"), ("genesis_anchor_id", "GenesisAnchorIdV1")
            ),
            "ActivationAnchorBodyV1": _record(
                ("schema_version", "u16"),
                ("target_context", "ProtocolContextV1"),
                ("activation_statement_id", "V0ToV1ActivationStatementIdV1"),
                ("handoff_certificate_digest_v0", "Hash32"),
                ("terminal_qc_digest_v0", "Hash32"),
                ("source_terminal_block_id", "Hash32"),
                ("target_epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("activation_height", "u64"),
                ("initial_view", "u64"),
            ),
            "ActivationAnchorV1": _record(
                ("body", "ActivationAnchorBodyV1"),
                ("activation_anchor_id", "ActivationAnchorIdV1"),
            ),
            "EpochHandoffBodyV1": _record(
                ("schema_version", "u16"),
                ("source_context", "ProtocolContextV1"),
                ("target_context", "ProtocolContextV1"),
                ("old_epoch", "u64"),
                ("new_epoch", "u64"),
                ("old_epoch_checkpoint_id", "EpochCheckpointIdV1"),
                ("old_epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("new_epoch_descriptor_id", "EpochDescriptorIdV1"),
                ("old_validator_set_hash", "Hash32"),
                ("new_validator_set_hash", "Hash32"),
                ("old_consensus_parameters_hash", "Hash32"),
                ("new_consensus_parameters_hash", "Hash32"),
                ("terminal_block_id", "BlockIdV1"),
                ("terminal_height", "u64"),
                ("terminal_view", "u64"),
                ("activation_height", "u64"),
                ("initial_new_view", "u64"),
            ),
            "EpochHandoffSignStatementV1": _record(
                ("schema_version", "u16"),
                ("consensus_context", "ConsensusContextV1"),
                ("handoff_id", "EpochHandoffIdV1"),
            ),
            "EpochHandoffSignatureEntryV1": _record(
                ("signer_id", "Bytes"),
                ("role", "u8"),
                ("statement", "EpochHandoffSignStatementV1"),
                ("signature_scheme", "u16"),
                ("signature", "Bytes"),
            ),
            "EpochHandoffV1": _record(
                ("body", "EpochHandoffBodyV1"),
                ("handoff_id", "EpochHandoffIdV1"),
                ("old_set_signatures", _list("EpochHandoffSignatureEntryV1")),
                ("new_set_signatures", _list("EpochHandoffSignatureEntryV1")),
            ),
            "EpochStartJustificationV1": _enum(
                "u8",
                [
                    (0, "GenesisAnchor", "GenesisAnchorV1"),
                    (1, "ActivationAnchor", "ActivationAnchorV1"),
                    (2, "EpochHandoff", "EpochHandoffV1"),
                ],
            ),
            "HighJustificationObjectV1": _enum(
                "u8",
                [
                    (0, "QC", "QuorumCertificateV1"),
                    (1, "EpochStart", "EpochStartJustificationV1"),
                ],
            ),
            "TimeoutCertificateBodyV1": _record(
                ("schema_version", "u16"),
                ("context", "ProtocolContextV1"),
                ("runtime_profile_hash", "Hash32"),
                ("epoch", "u64"),
                ("validator_set_hash", "Hash32"),
                ("consensus_parameters_hash", "Hash32"),
                ("timed_out_view", "u64"),
                ("target_view", "u64"),
                ("justifications", _list("HighJustificationObjectV1")),
                ("entries", _list("TimeoutSignatureEntryV1")),
            ),
        }
    )

    covered_types = [
        "ProtocolContextV1",
        "ValidatorMemberV1",
        "ValidatorSetDefinitionV1",
        "ValidatorSetDescriptorV1",
        "ConsensusParametersV1",
        "TypedObjectIdV1",
        "MerkleLeafBodyV1",
        "MerkleNodeBodyV1",
        "MerkleListRootBodyV1",
        "ConsensusContextV1",
        "BatchRefV1",
        "ParentBlockRefV1",
        "BlockKindV1",
        "BlockHeaderV1",
        "VoteStatementBodyV1",
        "VoteSignatureEntryV1",
        "VoteIdentityBodyV1",
        "QuorumCertificateBodyV1",
        "QuorumCertificateV1",
        "HighJustificationRefV1",
        "FinalizedAnchorRefV1",
        "TimeoutStatementBodyV1",
        "TimeoutSignatureEntryV1",
        "TimeoutIdentityBodyV1",
        "GenesisAnchorBodyV1",
        "GenesisAnchorV1",
        "ActivationAnchorBodyV1",
        "ActivationAnchorV1",
        "EpochHandoffBodyV1",
        "EpochHandoffSignStatementV1",
        "EpochHandoffSignatureEntryV1",
        "EpochHandoffV1",
        "EpochStartJustificationV1",
        "HighJustificationObjectV1",
        "TimeoutCertificateBodyV1",
    ]
    structural_helper_types = [
        type_name
        for type_name in types
        if type_name not in covered_types and type_name not in object_kind_names
    ]

    return {
        "artifact": "trnm.poco-ai.cev1-foundation-order-kernel.v1",
        "artifact_version": 1,
        "protocol_version": 1,
        "canonical_encoding": "CEV1",
        "status": {
            "classification": "candidate_non_normative",
            "closed_for_listed_types_only": True,
            "normative_freeze": False,
            "global_wire_schema_complete": False,
            "semantic_consistency_proven": False,
            "implementation_or_activation_evidence": False,
            "cryptographic_interoperability_evidence": False,
        },
        "scope": {
            "covered_types": covered_types,
            "typed_id_wrappers": object_kind_names,
            "structural_helper_types": structural_helper_types,
            "excluded": [
                "OrderProposalBodyV1 and transport protobuf",
                "DA, Agent, Market, Compute, execution, settlement, state-sync, and light-client schemas",
                "strict Ed25519 verification and independent parser interoperability",
                "repository-wide schema completeness, normative freeze, implementation, activation, or release claims",
            ],
        },
        "source_contracts": [
            "docs/protocol/poco-ai-native-v1/02-versioning-chain-profile-wire-and-crypto.md",
            "docs/protocol/poco-ai-native-v1/07-order-consensus-epochs-and-finality.md",
            "docs/protocol/poco-ai-native-v1/10-invariants-formal-obligations-and-conformance.md",
        ],
        "encoding": {
            "integers": "fixed_width_little_endian",
            "bool": {"width_bytes": 1, "accepted": [0, 1]},
            "Hash32": {"width_bytes": 32},
            "Bytes": "u32_le_length_then_exact_bytes",
            "ConsensusString": "u32_le_utf8_byte_length_then_exact_utf8",
            "Option": "u8_tag_0_absent_1_present_then_value",
            "List": "u32_le_count_then_items_in_declared_order",
            "record": "fields_in_declared_order_without_tags",
            "enum": "declared_integer_discriminant_then_selected_body_only",
            "strict_decode": [
                "no trailing bytes",
                "no unknown discriminants",
                "no alternate integer widths",
                "no ignored or omitted record fields",
                "bounds before allocation",
                "canonical input order is verified, never repaired",
            ],
        },
        "machine_json_representation": {
            "unsigned_integer": "unquoted base-10 integer parsed losslessly through u128; floats, exponents, signs, leading zeros, and overflow are invalid",
            "Hash32_and_Bytes": "lowercase even-length hexadecimal without 0x prefix; Hash32 is exactly 64 hex digits",
            "enum": "object with variant and, only for a body-carrying variant, value",
            "option": "null for absent or the represented inner value for present",
            "note": "This JSON representation authors CEV1 values; JSON bytes are never CEV1 signing or hashing preimages.",
        },
        "digest": {
            "algorithm": "SHA-256",
            "formula": "SHA256(u32_le(len(UTF8(domain))) || UTF8(domain) || CEV1(value))",
            "domain_policy": "nonempty ASCII candidate domains",
        },
        "ordered_root_algorithm": {
            "leaf": "DigestV1(merkle_leaf, (root_kind,index,item_kind,item_id,item_commitment)) in canonical input order",
            "parent": "DigestV1(merkle_node, (root_kind,level,left,right)); level 0 is the parent of leaves",
            "odd_width": "duplicate the final unpaired hash as both left and right",
            "final": "DigestV1(merkle_list_root, (root_kind,item_count,tree_root:Option<Hash32>))",
            "empty": "item_count=0 and tree_root=None",
        },
        "domains": {
            "validator_set_definition": "trnm.poco-ai.validator-set-definition.v1",
            "validator_set": "trnm.poco-ai.validator-set.v1",
            "consensus_parameters": "trnm.poco-ai.consensus-parameters.v1",
            "merkle_leaf": "trnm.poco-ai.merkle-leaf.v1",
            "merkle_node": "trnm.poco-ai.merkle-node.v1",
            "merkle_list_root": "trnm.poco-ai.merkle-list-root.v1",
            "block_id": "trnm.poco-ai.order-block.v1",
            "vote_id": "trnm.poco-ai.order-vote.v1",
            "vote_signature": "trnm.poco-ai.order-vote-signature.v1",
            "quorum_certificate": "trnm.poco-ai.order-qc.v1",
            "timeout_id": "trnm.poco-ai.order-timeout.v1",
            "timeout_signature": "trnm.poco-ai.order-timeout-signature.v1",
            "timeout_certificate": "trnm.poco-ai.order-tc.v1",
            "genesis_anchor": "trnm.poco-ai.genesis-anchor.v1",
            "activation_anchor": "trnm.poco-ai.activation-anchor.v1",
            "epoch_handoff": "trnm.poco-ai.epoch-handoff.v1",
            "epoch_handoff_old_signature": "trnm.poco-ai.epoch-handoff-old-signature.v1",
            "epoch_handoff_new_signature": "trnm.poco-ai.epoch-handoff-new-signature.v1",
        },
        "registries": {
            "RootKindV1": [{"tag": tag, "purpose": purpose} for tag, purpose in root_kinds],
            "ObjectKindV1": object_kinds,
            "ConsensusMessageKindV1": [
                {"tag": 0, "name": "OrderProposal"},
                {"tag": 1, "name": "Vote"},
                {"tag": 2, "name": "Timeout"},
                {"tag": 3, "name": "EpochHandoffOldSet"},
                {"tag": 4, "name": "EpochHandoffNewSet"},
            ],
        },
        "constraints": [
            {"id": "schema-v1", "rule": "Every covered version field named schema_version equals 1."},
            {"id": "protocol-v1", "rule": "ProtocolContextV1.protocol_version equals 1."},
            {"id": "validator-order", "rule": "Validator IDs are nonempty, unique, and strictly increasing by raw bytes; consensus public keys are unique."},
            {"id": "validator-quorum", "rule": "Positive u128 weights checked-sum to total_weight; threshold=floor(2W/3)+1 with checked arithmetic."},
            {"id": "root-registry", "rule": "RootKindV1 is closed to tags 0..20 and the requested destination kind is bound."},
            {"id": "vote-context", "rule": "VoteStatementBodyV1 carries ConsensusMessageKindV1 Vote."},
            {"id": "timeout-context", "rule": "TimeoutStatementBodyV1 carries ConsensusMessageKindV1 Timeout."},
            {"id": "certificate-order", "rule": "QC and TC signer entries are strictly increasing by raw signer ID and duplicate-free before checked weight accumulation."},
            {"id": "certificate-quorum", "rule": "QC and TC checked signer weight reaches the committed validator-set threshold."},
            {"id": "tc-view", "rule": "TimeoutCertificateBodyV1.target_view=timed_out_view+1 with checked u64 arithmetic."},
            {"id": "handoff-monotonic", "rule": "new_epoch=old_epoch+1, activation_height=terminal_height+1, and initial_new_view=1 with checked arithmetic."},
            {"id": "signature-carrier", "rule": "Candidate vectors bind exact signature roots and opaque canonical signature bytes but do not claim Ed25519 verification."},
        ],
        "types": types,
    }


def _parse_hex(value: Any, *, expected_len: int | None = None, code: str = "invalid_hex") -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise CandidateError(code)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise CandidateError(code) from exc
    if value != value.lower():
        raise CandidateError(code, "hex must be lowercase")
    if expected_len is not None and len(raw) != expected_len:
        raise CandidateError(code, f"expected {expected_len} bytes")
    return raw


def _unsigned(value: Any, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CandidateError("invalid_integer_type")
    maximum = (1 << bits) - 1
    if value < 0 or value > maximum:
        raise CandidateError("integer_out_of_range")
    return value


def _resolve_type(type_expr: Any, schema: dict[str, Any]) -> Any:
    seen: set[str] = set()
    while isinstance(type_expr, str) and type_expr in schema["types"]:
        if type_expr in seen:
            raise CandidateError("schema_alias_cycle")
        seen.add(type_expr)
        definition = schema["types"][type_expr]
        if definition["kind"] != "alias":
            return definition
        type_expr = definition["target"]
    return type_expr


def _validate_schema_structure(schema: dict[str, Any]) -> None:
    primitives = {"u8", "u16", "u32", "u64", "u128", "bool", "Hash32", "Bytes", "ConsensusString"}
    definitions = schema.get("types")
    if not isinstance(definitions, dict) or not definitions:
        raise CandidateError("schema_types_missing")

    def visit(expr: Any, path: str, aliases: tuple[str, ...] = ()) -> None:
        if isinstance(expr, str):
            if expr in primitives:
                return
            if expr not in definitions:
                raise CandidateError("schema_unresolved_type", f"{path}: {expr}")
            definition = definitions[expr]
            if definition.get("kind") == "alias":
                if expr in aliases:
                    raise CandidateError("schema_alias_cycle", f"{path}: {expr}")
                visit(definition.get("target"), path, aliases + (expr,))
            else:
                visit(definition, f"types.{expr}")
            return
        if not isinstance(expr, dict):
            raise CandidateError("schema_invalid_type_expression", path)
        if set(expr) == {"option"}:
            visit(expr["option"], f"{path}.option")
            return
        if set(expr) == {"list"}:
            visit(expr["list"], f"{path}.list")
            return
        kind = expr.get("kind")
        if kind == "alias":
            if set(expr) != {"kind", "target"}:
                raise CandidateError("schema_invalid_alias", path)
            visit(expr["target"], f"{path}.target", aliases)
            return
        if kind == "record":
            if set(expr) != {"kind", "fields"} or not isinstance(expr["fields"], list):
                raise CandidateError("schema_invalid_record", path)
            names = [field.get("name") for field in expr["fields"]]
            if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
                raise CandidateError("schema_duplicate_or_invalid_field", path)
            for field in expr["fields"]:
                if set(field) != {"name", "type"}:
                    raise CandidateError("schema_invalid_field", f"{path}.{field.get('name')}")
                visit(field["type"], f"{path}.{field['name']}")
            return
        if kind == "enum":
            if set(expr) != {"kind", "repr", "variants"} or expr["repr"] not in ("u8", "u16"):
                raise CandidateError("schema_invalid_enum", path)
            maximum = U8_MAX if expr["repr"] == "u8" else U16_MAX
            tags = [variant.get("tag") for variant in expr["variants"]]
            names = [variant.get("name") for variant in expr["variants"]]
            if (
                not expr["variants"]
                or len(set(tags)) != len(tags)
                or len(set(names)) != len(names)
                or any(isinstance(tag, bool) or not isinstance(tag, int) or tag < 0 or tag > maximum for tag in tags)
                or any(not isinstance(name, str) or not name for name in names)
            ):
                raise CandidateError("schema_duplicate_or_invalid_variant", path)
            for variant in expr["variants"]:
                if set(variant) not in ({"tag", "name"}, {"tag", "name", "body"}):
                    raise CandidateError("schema_invalid_variant", f"{path}.{variant.get('name')}")
                if "body" in variant:
                    visit(variant["body"], f"{path}.{variant['name']}")
            return
        raise CandidateError("schema_unknown_type_kind", path)

    for type_name in definitions:
        visit(type_name, f"types.{type_name}")
    scoped_types = (
        schema["scope"]["covered_types"]
        + schema["scope"]["typed_id_wrappers"]
        + schema["scope"]["structural_helper_types"]
    )
    if len(set(scoped_types)) != len(scoped_types) or set(scoped_types) != set(definitions):
        raise CandidateError("schema_scope_partition_mismatch")
    for type_name in scoped_types:
        if type_name not in definitions:
            raise CandidateError("schema_scope_type_missing", type_name)


def encode_value(type_expr: Any, value: Any, schema: dict[str, Any], limits: dict[str, int]) -> bytes:
    resolved = _resolve_type(type_expr, schema)
    if isinstance(resolved, str):
        widths = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16}
        if resolved in widths:
            number = _unsigned(value, widths[resolved] * 8)
            return number.to_bytes(widths[resolved], "little")
        if resolved == "bool":
            if type(value) is not bool:
                raise CandidateError("invalid_bool")
            return b"\x01" if value else b"\x00"
        if resolved == "Hash32":
            return _parse_hex(value, expected_len=32, code="invalid_hash32")
        if resolved == "Bytes":
            raw = _parse_hex(value, code="invalid_bytes_hex")
            if len(raw) > limits["max_bytes_bytes"]:
                raise CandidateError("bound_bytes")
            return struct.pack("<I", len(raw)) + raw
        if resolved == "ConsensusString":
            if not isinstance(value, str):
                raise CandidateError("invalid_consensus_string")
            try:
                raw = value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise CandidateError("invalid_utf8") from exc
            if len(raw) > limits["max_consensus_string_bytes"]:
                raise CandidateError("bound_consensus_string")
            return struct.pack("<I", len(raw)) + raw
        raise CandidateError("unknown_type", str(resolved))
    if isinstance(resolved, dict) and "option" in resolved:
        if value is None:
            return b"\x00"
        return b"\x01" + encode_value(resolved["option"], value, schema, limits)
    if isinstance(resolved, dict) and "list" in resolved:
        if not isinstance(value, list):
            raise CandidateError("invalid_list")
        if len(value) > limits["max_list_items"]:
            raise CandidateError("bound_list")
        return struct.pack("<I", len(value)) + b"".join(
            encode_value(resolved["list"], item, schema, limits) for item in value
        )
    if not isinstance(resolved, dict):
        raise CandidateError("unknown_type_expression")
    if resolved["kind"] == "record":
        if not isinstance(value, dict):
            raise CandidateError("invalid_record")
        names = [field["name"] for field in resolved["fields"]]
        if set(value) != set(names) or len(value) != len(names):
            raise CandidateError("record_field_mismatch")
        return b"".join(
            encode_value(field["type"], value[field["name"]], schema, limits)
            for field in resolved["fields"]
        )
    if resolved["kind"] == "enum":
        if not isinstance(value, dict) or "variant" not in value:
            raise CandidateError("invalid_enum")
        matches = [item for item in resolved["variants"] if item["name"] == value["variant"]]
        if len(matches) != 1:
            raise CandidateError("unknown_enum_variant")
        selected = matches[0]
        allowed = {"variant", "value"} if "body" in selected else {"variant"}
        if set(value) != allowed:
            raise CandidateError("enum_field_mismatch")
        encoded = encode_value(resolved["repr"], selected["tag"], schema, limits)
        if "body" in selected:
            encoded += encode_value(selected["body"], value["value"], schema, limits)
        return encoded
    raise CandidateError("unknown_type_kind")


def decode_value(
    type_expr: Any,
    data: bytes,
    offset: int,
    schema: dict[str, Any],
    limits: dict[str, int],
    depth: int = 0,
) -> tuple[Any, int]:
    if depth > limits["max_nesting"]:
        raise CandidateError("bound_nesting")
    resolved = _resolve_type(type_expr, schema)

    def take(count: int) -> bytes:
        if count < 0 or offset + count > len(data):
            raise CandidateError("truncated")
        return data[offset : offset + count]

    if isinstance(resolved, str):
        widths = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16}
        if resolved in widths:
            width = widths[resolved]
            return int.from_bytes(take(width), "little"), offset + width
        if resolved == "bool":
            raw = take(1)[0]
            if raw not in (0, 1):
                raise CandidateError("invalid_bool")
            return bool(raw), offset + 1
        if resolved == "Hash32":
            return take(32).hex(), offset + 32
        if resolved in ("Bytes", "ConsensusString"):
            length_raw = take(4)
            length = int.from_bytes(length_raw, "little")
            bound_name = "max_bytes_bytes" if resolved == "Bytes" else "max_consensus_string_bytes"
            if length > limits[bound_name]:
                raise CandidateError("bound_bytes" if resolved == "Bytes" else "bound_consensus_string")
            start = offset + 4
            if start + length > len(data):
                raise CandidateError("truncated")
            raw = data[start : start + length]
            if resolved == "Bytes":
                return raw.hex(), start + length
            try:
                return raw.decode("utf-8", "strict"), start + length
            except UnicodeDecodeError as exc:
                raise CandidateError("invalid_utf8") from exc
        raise CandidateError("unknown_type")
    if isinstance(resolved, dict) and "option" in resolved:
        if offset >= len(data):
            raise CandidateError("truncated")
        tag = data[offset]
        if tag == 0:
            return None, offset + 1
        if tag != 1:
            raise CandidateError("invalid_option_tag")
        return decode_value(resolved["option"], data, offset + 1, schema, limits, depth + 1)
    if isinstance(resolved, dict) and "list" in resolved:
        if offset + 4 > len(data):
            raise CandidateError("truncated")
        count = int.from_bytes(data[offset : offset + 4], "little")
        if count > limits["max_list_items"]:
            raise CandidateError("bound_list")
        cursor = offset + 4
        values = []
        for _ in range(count):
            item, cursor = decode_value(resolved["list"], data, cursor, schema, limits, depth + 1)
            values.append(item)
        return values, cursor
    if not isinstance(resolved, dict):
        raise CandidateError("unknown_type_expression")
    if resolved["kind"] == "record":
        cursor = offset
        result = {}
        for field in resolved["fields"]:
            result[field["name"]], cursor = decode_value(
                field["type"], data, cursor, schema, limits, depth + 1
            )
        return result, cursor
    if resolved["kind"] == "enum":
        tag, cursor = decode_value(resolved["repr"], data, offset, schema, limits, depth + 1)
        matches = [item for item in resolved["variants"] if item["tag"] == tag]
        if len(matches) != 1:
            raise CandidateError("unknown_enum_discriminant")
        selected = matches[0]
        result: dict[str, Any] = {"variant": selected["name"]}
        if "body" in selected:
            result["value"], cursor = decode_value(
                selected["body"], data, cursor, schema, limits, depth + 1
            )
        return result, cursor
    raise CandidateError("unknown_type_kind")


def decode_full(type_expr: Any, encoded: bytes, schema: dict[str, Any], limits: dict[str, int]) -> Any:
    value, cursor = decode_value(type_expr, encoded, 0, schema, limits)
    if cursor != len(encoded):
        raise CandidateError("trailing_bytes")
    return value


def digest_v1(domain: str, type_expr: Any, value: Any, schema: dict[str, Any], limits: dict[str, int]) -> str:
    try:
        domain_bytes = domain.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise CandidateError("invalid_domain") from exc
    if not domain_bytes:
        raise CandidateError("invalid_domain")
    encoded = encode_value(type_expr, value, schema, limits)
    return hashlib.sha256(struct.pack("<I", len(domain_bytes)) + domain_bytes + encoded).hexdigest()


def derive_ordered_root(
    root_kind: int,
    items: list[dict[str, Any]],
    schema: dict[str, Any],
    limits: dict[str, int],
) -> dict[str, Any]:
    if root_kind not in range(21):
        raise CandidateError("unknown_root_kind")
    if len(items) > U32_MAX:
        raise CandidateError("bound_list")
    leaf_entries = []
    hashes: list[str] = []
    for index, item in enumerate(items):
        if set(item) != {"item_kind", "item_id", "item_commitment"}:
            raise CandidateError("ordered_root_item_shape")
        body = {"root_kind": root_kind, "index": index, **item}
        digest = digest_v1(
            schema["domains"]["merkle_leaf"], "MerkleLeafBodyV1", body, schema, limits
        )
        leaf_entries.append({"body": body, "digest_hex": digest})
        hashes.append(digest)
    levels = []
    level = 0
    while len(hashes) > 1:
        nodes = []
        next_hashes = []
        for index in range(0, len(hashes), 2):
            left = hashes[index]
            right = hashes[index + 1] if index + 1 < len(hashes) else left
            body = {"root_kind": root_kind, "level": level, "left": left, "right": right}
            digest = digest_v1(
                schema["domains"]["merkle_node"], "MerkleNodeBodyV1", body, schema, limits
            )
            nodes.append({"body": body, "digest_hex": digest})
            next_hashes.append(digest)
        levels.append({"level": level, "nodes": nodes})
        hashes = next_hashes
        level = _checked_add(level, 1, U32_MAX)
    root_body = {
        "root_kind": root_kind,
        "item_count": len(items),
        "tree_root": hashes[0] if hashes else None,
    }
    return {
        "root_kind": root_kind,
        "items": items,
        "leaves": leaf_entries,
        "levels": levels,
        "root_body": root_body,
        "root_digest_hex": digest_v1(
            schema["domains"]["merkle_list_root"],
            "MerkleListRootBodyV1",
            root_body,
            schema,
            limits,
        ),
    }


def _checked_add(left: int, right: int, maximum: int, code: str = "checked_overflow") -> int:
    if left < 0 or right < 0 or left > maximum - right:
        raise CandidateError(code)
    return left + right


def _schema_version_one(type_name: str, value: Any) -> None:
    if isinstance(value, dict) and "schema_version" in value and value["schema_version"] != 1:
        raise CandidateError("invalid_schema_version", type_name)


def _validate_protocol_context(value: dict[str, Any]) -> None:
    _schema_version_one("ProtocolContextV1", value)
    if value["protocol_version"] != 1:
        raise CandidateError("invalid_protocol_version")


def _validate_validator_definition(value: dict[str, Any]) -> None:
    _schema_version_one("ValidatorSetDefinitionV1", value)
    members = value["members"]
    if not members:
        raise CandidateError("empty_validator_set")
    ids = [_parse_hex(member["validator_id"], code="invalid_validator_id") for member in members]
    keys = [_parse_hex(member["consensus_public_key"], code="invalid_public_key") for member in members]
    if any(not validator_id for validator_id in ids):
        raise CandidateError("empty_validator_id")
    if any(ids[index] >= ids[index + 1] for index in range(len(ids) - 1)):
        raise CandidateError("validator_order")
    if len(set(ids)) != len(ids):
        raise CandidateError("duplicate_validator")
    if len(set(keys)) != len(keys):
        raise CandidateError("duplicate_consensus_key")
    total = 0
    for member in members:
        if member["consensus_key_scheme"] != 0:
            raise CandidateError("unsupported_signature_scheme")
        weight = _unsigned(member["voting_weight"], 128)
        if weight == 0:
            raise CandidateError("zero_weight")
        total = _checked_add(total, weight, U128_MAX)
    if total != value["total_weight"]:
        raise CandidateError("total_weight_mismatch")
    doubled = _checked_add(total, total, U128_MAX)
    threshold = _checked_add(doubled // 3, 1, U128_MAX)
    if threshold != value["quorum_threshold"]:
        raise CandidateError("quorum_threshold_mismatch")


def _validate_consensus_parameters(value: dict[str, Any]) -> None:
    _schema_version_one("ConsensusParametersV1", value)
    if value["quorum_numerator"] != 2 or value["quorum_denominator"] != 3:
        raise CandidateError("invalid_quorum_constants")
    if value["finality_chain_length"] != 3 or value["execute_coordination_before_vote"] is not True:
        raise CandidateError("invalid_consensus_constants")
    positive = [
        key
        for key in value
        if key.startswith("max_")
        or key.endswith("_blocks")
        or key.endswith("_ms")
        or key.startswith("timeout_multiplier_")
    ]
    if any(value[key] <= 0 for key in positive):
        raise CandidateError("nonpositive_consensus_parameter")
    checkpoint = value["checkpoint_offset_blocks"]
    seal1 = value["seal_1_offset_blocks"]
    seal2 = value["seal_2_offset_blocks"]
    epoch_len = value["epoch_length_blocks"]
    if not checkpoint < seal1 < seal2 < epoch_len:
        raise CandidateError("invalid_epoch_schedule")
    if _checked_add(checkpoint, 1, U64_MAX) != seal1:
        raise CandidateError("invalid_epoch_schedule")
    if _checked_add(seal1, 1, U64_MAX) != seal2:
        raise CandidateError("invalid_epoch_schedule")
    if _checked_add(seal2, 1, U64_MAX) != epoch_len:
        raise CandidateError("invalid_epoch_schedule")
    if value["base_view_timeout_ms"] > value["maximum_view_timeout_ms"]:
        raise CandidateError("invalid_timeout_bounds")
    if value["timeout_multiplier_numerator"] < value["timeout_multiplier_denominator"]:
        raise CandidateError("invalid_timeout_multiplier")


def _validator_weight_map(definition: dict[str, Any]) -> tuple[dict[bytes, int], int]:
    _validate_validator_definition(definition)
    return (
        {
            _parse_hex(member["validator_id"], code="invalid_validator_id"): member["voting_weight"]
            for member in definition["members"]
        },
        definition["quorum_threshold"],
    )


def _validate_signature_entries(
    entries: list[dict[str, Any]],
    signer_field: str,
    definition: dict[str, Any],
    limits: dict[str, int],
) -> None:
    weights, threshold = _validator_weight_map(definition)
    if len(entries) > limits["max_certificate_signers"]:
        raise CandidateError("bound_certificate_signers")
    signer_ids = [_parse_hex(entry[signer_field], code="invalid_validator_id") for entry in entries]
    if any(signer_ids[index] >= signer_ids[index + 1] for index in range(len(signer_ids) - 1)):
        if len(set(signer_ids)) != len(signer_ids):
            raise CandidateError("duplicate_signer")
        raise CandidateError("signer_order")
    if len(set(signer_ids)) != len(signer_ids):
        raise CandidateError("duplicate_signer")
    total = 0
    for signer_id, entry in zip(signer_ids, entries):
        if signer_id not in weights:
            raise CandidateError("unknown_signer")
        if entry["signature_scheme"] != 0:
            raise CandidateError("unsupported_signature_scheme")
        signature = _parse_hex(entry["signature"], code="invalid_signature")
        if len(signature) > limits["max_signature_bytes"]:
            raise CandidateError("bound_signature")
        total = _checked_add(total, weights[signer_id], U128_MAX)
    if total < threshold:
        raise CandidateError("insufficient_quorum")


def _validate_consensus_context(value: dict[str, Any], expected_kind: int | None = None) -> None:
    _schema_version_one("ConsensusContextV1", value)
    _validate_protocol_context(value["context"])
    if value["message_kind"] not in range(5):
        raise CandidateError("unknown_message_kind")
    if expected_kind is not None and value["message_kind"] != expected_kind:
        raise CandidateError("wrong_message_kind")


def _validate_context_authority(
    value: dict[str, Any], fixtures: dict[str, Any], role: str = "source"
) -> None:
    descriptor = fixtures[f"{role}_validator_set_descriptor"]
    if (
        value["context"] != descriptor["context"]
        or value["epoch"] != descriptor["epoch"]
        or value["validator_set_hash"] != fixtures[f"{role}_validator_set_hash"]
        or value["consensus_parameters_hash"] != fixtures["consensus_parameters_hash"]
        or value["runtime_profile_hash"] != fixtures[f"{role}_runtime_profile_hash"]
    ):
        raise CandidateError("consensus_context_authority_mismatch")


def _validate_vote_statement(value: dict[str, Any]) -> None:
    _schema_version_one("VoteStatementBodyV1", value)
    _validate_consensus_context(value["consensus_context"], 1)


def _validate_qc(value: dict[str, Any], fixtures: dict[str, Any], limits: dict[str, int]) -> None:
    _schema_version_one("QuorumCertificateBodyV1", value)
    _validate_vote_statement(value["statement"])
    _validate_context_authority(value["statement"]["consensus_context"], fixtures)
    _validate_signature_entries(value["signatures"], "voter_id", fixtures["validator_set_definition"], limits)


def _validate_high_ref(value: dict[str, Any]) -> None:
    if value["variant"] == "EpochStart":
        body = value["value"]
        if body["anchor_kind"] not in (0, 1, 2):
            raise CandidateError("unknown_anchor_kind")


def _validate_timeout_statement(value: dict[str, Any]) -> None:
    _schema_version_one("TimeoutStatementBodyV1", value)
    _validate_consensus_context(value["consensus_context"], 2)
    _validate_high_ref(value["high_justification"])
    if value["locked_qc_id"] is None and value["locked_qc_view"] != 0:
        raise CandidateError("locked_qc_view_mismatch")


def _validate_handoff_body(value: dict[str, Any]) -> None:
    _schema_version_one("EpochHandoffBodyV1", value)
    _validate_protocol_context(value["source_context"])
    _validate_protocol_context(value["target_context"])
    if _checked_add(value["old_epoch"], 1, U64_MAX) != value["new_epoch"]:
        raise CandidateError("handoff_epoch_mismatch")
    if _checked_add(value["terminal_height"], 1, U64_MAX) != value["activation_height"]:
        raise CandidateError("handoff_height_mismatch")
    if value["initial_new_view"] != 1:
        raise CandidateError("handoff_initial_view")
    source = value["source_context"]
    target = value["target_context"]
    for key in ("genesis_hash", "chain_id", "protocol_version"):
        if source[key] != target[key]:
            raise CandidateError("handoff_context_mismatch")


def _validate_handoff_body_authority(body: dict[str, Any], fixtures: dict[str, Any]) -> None:
    if (
        body["source_context"] != fixtures["source_validator_set_descriptor"]["context"]
        or body["target_context"] != fixtures["target_validator_set_descriptor"]["context"]
        or body["old_epoch"] != fixtures["source_validator_set_descriptor"]["epoch"]
        or body["new_epoch"] != fixtures["target_validator_set_descriptor"]["epoch"]
        or body["old_validator_set_hash"] != fixtures["source_validator_set_hash"]
        or body["new_validator_set_hash"] != fixtures["target_validator_set_hash"]
        or body["old_consensus_parameters_hash"] != fixtures["consensus_parameters_hash"]
        or body["new_consensus_parameters_hash"] != fixtures["consensus_parameters_hash"]
    ):
        raise CandidateError("handoff_authority_mismatch")


def _validate_handoff_object(
    value: dict[str, Any], schema: dict[str, Any], fixtures: dict[str, Any], limits: dict[str, int]
) -> None:
    body = value["body"]
    _validate_handoff_body(body)
    expected_id = digest_v1(
        schema["domains"]["epoch_handoff"], "EpochHandoffBodyV1", body, schema, limits
    )
    if value["handoff_id"] != expected_id:
        raise CandidateError("handoff_id_mismatch")
    _validate_handoff_body_authority(body, fixtures)

    roles = (
        ("old_set_signatures", 0, 3, "source", body["terminal_view"]),
        ("new_set_signatures", 1, 4, "target", body["initial_new_view"]),
    )
    for field_name, role, message_kind, authority_role, expected_view in roles:
        entries = value[field_name]
        for entry in entries:
            if entry["role"] != role:
                raise CandidateError("wrong_handoff_role")
            statement = entry["statement"]
            _schema_version_one("EpochHandoffSignStatementV1", statement)
            _validate_consensus_context(statement["consensus_context"], message_kind)
            _validate_context_authority(statement["consensus_context"], fixtures, authority_role)
            if statement["handoff_id"] != expected_id:
                raise CandidateError("handoff_statement_id_mismatch")
            if statement["consensus_context"]["view"] != expected_view:
                raise CandidateError("handoff_statement_view_mismatch")
        definition = fixtures[f"{authority_role}_validator_set_descriptor"]["definition"]
        _validate_signature_entries(entries, "signer_id", definition, limits)


def _validate_justification_object(
    item: dict[str, Any],
    schema: dict[str, Any],
    fixtures: dict[str, Any],
    limits: dict[str, int],
    *,
    expected_context: dict[str, Any],
    expected_epoch: int,
) -> None:
    if item["variant"] == "QC":
        qc = item["value"]
        _validate_qc_object(qc, schema, fixtures, limits)
        return
    epoch_start = item["value"]
    anchor_variant = epoch_start["variant"]
    anchor = epoch_start["value"]
    if anchor_variant == "GenesisAnchor":
        body = anchor["body"]
        _schema_version_one("GenesisAnchorBodyV1", body)
        _validate_protocol_context(body["target_context"])
        if body["initial_view"] == 0:
            raise CandidateError("anchor_initial_view")
        if body["target_context"] != expected_context:
            raise CandidateError("epoch_start_context_mismatch")
        expected = digest_v1(
            schema["domains"]["genesis_anchor"], "GenesisAnchorBodyV1", body, schema, limits
        )
        if anchor["genesis_anchor_id"] != expected:
            raise CandidateError("genesis_anchor_id_mismatch")
        return
    if anchor_variant == "ActivationAnchor":
        body = anchor["body"]
        _schema_version_one("ActivationAnchorBodyV1", body)
        _validate_protocol_context(body["target_context"])
        if body["initial_view"] == 0:
            raise CandidateError("anchor_initial_view")
        if body["target_context"] != expected_context:
            raise CandidateError("epoch_start_context_mismatch")
        expected = digest_v1(
            schema["domains"]["activation_anchor"], "ActivationAnchorBodyV1", body, schema, limits
        )
        if anchor["activation_anchor_id"] != expected:
            raise CandidateError("activation_anchor_id_mismatch")
        return
    if anchor_variant == "EpochHandoff":
        _validate_handoff_object(anchor, schema, fixtures, limits)
        if anchor["body"]["target_context"] != expected_context or anchor["body"]["new_epoch"] != expected_epoch:
            raise CandidateError("epoch_start_context_mismatch")
        return
    raise CandidateError("unknown_epoch_start_variant")


def _validate_qc_object(
    value: dict[str, Any], schema: dict[str, Any], fixtures: dict[str, Any], limits: dict[str, int]
) -> None:
    _validate_qc(value["body"], fixtures, limits)
    expected = digest_v1(
        schema["domains"]["quorum_certificate"],
        "QuorumCertificateBodyV1",
        value["body"],
        schema,
        limits,
    )
    if value["quorum_certificate_id"] != expected:
        raise CandidateError("qc_id_mismatch")


def _justification_identity(item: dict[str, Any], schema: dict[str, Any], limits: dict[str, int]) -> tuple:
    if item["variant"] == "QC":
        qc = item["value"]
        return (
            qc["body"]["statement"]["consensus_context"]["view"],
            0,
            -1,
            bytes.fromhex(qc["quorum_certificate_id"]),
        )
    epoch_start = item["value"]
    anchor_variant = epoch_start["variant"]
    tag = {"GenesisAnchor": 0, "ActivationAnchor": 1, "EpochHandoff": 2}[anchor_variant]
    anchor = epoch_start["value"]
    if anchor_variant == "GenesisAnchor":
        return (anchor["body"]["initial_view"] - 1, 1, tag, bytes.fromhex(anchor["genesis_anchor_id"]))
    if anchor_variant == "ActivationAnchor":
        return (anchor["body"]["initial_view"] - 1, 1, tag, bytes.fromhex(anchor["activation_anchor_id"]))
    return (anchor["body"]["initial_new_view"] - 1, 1, tag, bytes.fromhex(anchor["handoff_id"]))


def _high_ref_identity(ref: dict[str, Any]) -> tuple[int, int, int, bytes]:
    body = ref["value"]
    if ref["variant"] == "QC":
        return (body["qc_view"], 0, -1, bytes.fromhex(body["qc_id"]))
    return (body["anchor_view"], 1, body["anchor_kind"], bytes.fromhex(body["anchor_id"]))


def _validate_tc(
    value: dict[str, Any], schema: dict[str, Any], fixtures: dict[str, Any], limits: dict[str, int]
) -> None:
    _schema_version_one("TimeoutCertificateBodyV1", value)
    _validate_protocol_context(value["context"])
    source_descriptor = fixtures["source_validator_set_descriptor"]
    if (
        value["context"] != source_descriptor["context"]
        or value["epoch"] != source_descriptor["epoch"]
        or value["validator_set_hash"] != fixtures["source_validator_set_hash"]
        or value["consensus_parameters_hash"] != fixtures["consensus_parameters_hash"]
        or value["runtime_profile_hash"] != fixtures["source_runtime_profile_hash"]
    ):
        raise CandidateError("tc_authority_mismatch")
    if _checked_add(value["timed_out_view"], 1, U64_MAX) != value["target_view"]:
        raise CandidateError("tc_target_view")
    for item in value["justifications"]:
        _validate_justification_object(
            item,
            schema,
            fixtures,
            limits,
            expected_context=value["context"],
            expected_epoch=value["epoch"],
        )
    identities = [_justification_identity(item, schema, limits) for item in value["justifications"]]
    if any(identities[index] >= identities[index + 1] for index in range(len(identities) - 1)):
        raise CandidateError("justification_order_or_duplicate")
    included = set(identities)
    referenced: set[tuple[int, int, int, bytes]] = set()
    for entry in value["entries"]:
        _validate_timeout_statement(entry["statement"])
        context = entry["statement"]["consensus_context"]
        if (
            context["context"] != value["context"]
            or context["runtime_profile_hash"] != value["runtime_profile_hash"]
            or context["epoch"] != value["epoch"]
            or context["validator_set_hash"] != value["validator_set_hash"]
            or context["consensus_parameters_hash"] != value["consensus_parameters_hash"]
            or context["view"] != value["timed_out_view"]
        ):
            raise CandidateError("tc_entry_context_mismatch")
        identity = _high_ref_identity(entry["statement"]["high_justification"])
        if identity not in included:
            raise CandidateError("unresolved_justification")
        referenced.add(identity)
    if referenced != included:
        raise CandidateError("unreferenced_justification")
    _validate_signature_entries(value["entries"], "validator_id", fixtures["validator_set_definition"], limits)


def validate_value(
    type_name: str,
    value: Any,
    schema: dict[str, Any],
    fixtures: dict[str, Any],
    limits: dict[str, int],
) -> None:
    encode_value(type_name, value, schema, limits)
    if type_name == "ProtocolContextV1":
        _validate_protocol_context(value)
    elif type_name == "ValidatorSetDefinitionV1":
        _validate_validator_definition(value)
    elif type_name == "ValidatorSetDescriptorV1":
        _schema_version_one(type_name, value)
        _validate_protocol_context(value["context"])
        _validate_validator_definition(value["definition"])
    elif type_name == "ConsensusParametersV1":
        _validate_consensus_parameters(value)
    elif type_name == "TypedObjectIdV1":
        if value["object_kind"] not in range(51):
            raise CandidateError("unknown_object_kind")
    elif type_name == "MerkleLeafBodyV1":
        if value["root_kind"] not in range(21):
            raise CandidateError("unknown_root_kind")
        if value["item_kind"] not in range(51):
            raise CandidateError("unknown_object_kind")
    elif type_name == "MerkleNodeBodyV1":
        if value["root_kind"] not in range(21):
            raise CandidateError("unknown_root_kind")
    elif type_name == "ConsensusContextV1":
        _validate_consensus_context(value)
    elif type_name == "VoteStatementBodyV1":
        _validate_vote_statement(value)
        _validate_context_authority(value["consensus_context"], fixtures)
    elif type_name == "QuorumCertificateBodyV1":
        _validate_qc(value, fixtures, limits)
    elif type_name == "QuorumCertificateV1":
        _validate_qc_object(value, schema, fixtures, limits)
    elif type_name == "TimeoutStatementBodyV1":
        _validate_timeout_statement(value)
        _validate_context_authority(value["consensus_context"], fixtures)
    elif type_name == "TimeoutCertificateBodyV1":
        _validate_tc(value, schema, fixtures, limits)
    elif type_name == "EpochHandoffBodyV1":
        _validate_handoff_body(value)
        _validate_handoff_body_authority(value, fixtures)
    elif type_name == "EpochHandoffSignStatementV1":
        context = value["consensus_context"]
        if context["message_kind"] == 3:
            _validate_consensus_context(context, 3)
            _validate_context_authority(context, fixtures, "source")
        elif context["message_kind"] == 4:
            _validate_consensus_context(context, 4)
            _validate_context_authority(context, fixtures, "target")
        else:
            raise CandidateError("wrong_message_kind")
    elif type_name == "EpochHandoffSignatureEntryV1":
        role = value["role"]
        if role not in (0, 1):
            raise CandidateError("wrong_handoff_role")
        expected_kind = 3 if role == 0 else 4
        authority_role = "source" if role == 0 else "target"
        context = value["statement"]["consensus_context"]
        _validate_consensus_context(context, expected_kind)
        _validate_context_authority(context, fixtures, authority_role)
        if value["signature_scheme"] != 0:
            raise CandidateError("unsupported_signature_scheme")
        if len(_parse_hex(value["signature"], code="invalid_signature")) > limits["max_signature_bytes"]:
            raise CandidateError("bound_signature")
        weights, _ = _validator_weight_map(
            fixtures[f"{authority_role}_validator_set_descriptor"]["definition"]
        )
        if _parse_hex(value["signer_id"], code="invalid_validator_id") not in weights:
            raise CandidateError("unknown_signer")
    elif type_name == "EpochHandoffV1":
        _validate_handoff_object(value, schema, fixtures, limits)
    elif type_name == "GenesisAnchorV1":
        _validate_justification_object(
            {"variant": "EpochStart", "value": {"variant": "GenesisAnchor", "value": value}},
            schema,
            fixtures,
            limits,
            expected_context=fixtures["source_validator_set_descriptor"]["context"],
            expected_epoch=fixtures["source_validator_set_descriptor"]["epoch"],
        )
    elif type_name == "ActivationAnchorV1":
        _validate_justification_object(
            {"variant": "EpochStart", "value": {"variant": "ActivationAnchor", "value": value}},
            schema,
            fixtures,
            limits,
            expected_context=fixtures["source_validator_set_descriptor"]["context"],
            expected_epoch=fixtures["source_validator_set_descriptor"]["epoch"],
        )
    elif type_name == "EpochStartJustificationV1":
        _validate_justification_object(
            {"variant": "EpochStart", "value": value},
            schema,
            fixtures,
            limits,
            expected_context=fixtures["source_validator_set_descriptor"]["context"],
            expected_epoch=fixtures["source_validator_set_descriptor"]["epoch"],
        )
    elif type_name == "HighJustificationObjectV1":
        _validate_justification_object(
            value,
            schema,
            fixtures,
            limits,
            expected_context=fixtures["source_validator_set_descriptor"]["context"],
            expected_epoch=fixtures["source_validator_set_descriptor"]["epoch"],
        )
    elif type_name == "MerkleListRootBodyV1":
        if value["root_kind"] not in range(21):
            raise CandidateError("unknown_root_kind")
        if (value["item_count"] == 0) != (value["tree_root"] is None):
            raise CandidateError("root_presence_mismatch")


def _hex_ascii(text: str) -> str:
    return text.encode("ascii").hex()


def _hash_byte(byte: int) -> str:
    return (bytes([byte]) * 32).hex()


def _sig(byte: int) -> str:
    return (bytes([byte]) * 64).hex()


def _validator(index: int, weight: int = 1) -> dict[str, Any]:
    letter = chr(ord("a") + index)
    return {
        "validator_id": _hex_ascii(f"validator-{letter}"),
        "consensus_key_scheme": 0,
        "consensus_public_key": (bytes([0x10 + index]) * 32).hex(),
        "voting_weight": weight,
        "network_identity_commitment": _hash_byte(0x20 + index),
        "safety_signer_policy_hash": _hash_byte(0x30 + index),
        "poco_economic_record_hash": _hash_byte(0x40 + index),
    }


def _context(stack_byte: int = 0x22) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "genesis_hash": _hash_byte(0x11),
        "chain_id": "trnm-ai-test-1",
        "protocol_version": 1,
        "stack_profile_hash": _hash_byte(stack_byte),
    }


def _consensus_context(
    kind: int,
    view: int,
    *,
    context: dict[str, Any],
    epoch: int,
    validator_set_hash: str,
    consensus_parameters_hash: str,
    runtime_profile_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "context": context,
        "runtime_profile_hash": runtime_profile_hash,
        "epoch": epoch,
        "validator_set_hash": validator_set_hash,
        "consensus_parameters_hash": consensus_parameters_hash,
        "view": view,
        "message_kind": kind,
    }


def _consensus_parameters() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "quorum_numerator": 2,
        "quorum_denominator": 3,
        "finality_chain_length": 3,
        "execute_coordination_before_vote": True,
        "max_validators": 100,
        "max_consensus_string_bytes": 64,
        "max_cev1_nesting": 64,
        "max_cev1_value_bytes": 1_048_576,
        "max_signature_bytes": 64,
        "max_certificate_signers": 100,
        "max_epoch": U64_MAX,
        "max_view": U64_MAX - 1,
        "max_height": U64_MAX - 1,
        "max_retained_views": 1024,
        "epoch_length_blocks": 4,
        "checkpoint_offset_blocks": 1,
        "seal_1_offset_blocks": 2,
        "seal_2_offset_blocks": 3,
        "max_block_ordered_bytes": 1_048_576,
        "max_batch_refs_per_block": 128,
        "max_protocol_objects_per_block": 128,
        "max_transactions_per_batch": 4096,
        "max_transaction_bytes": 65_536,
        "max_block_execution_units": 1_000_000,
        "base_view_timeout_ms": 500,
        "maximum_view_timeout_ms": 30_000,
        "timeout_multiplier_numerator": 3,
        "timeout_multiplier_denominator": 2,
        "max_evidence_items_per_block": 64,
        "max_evidence_bytes_per_block": 262_144,
    }


def _case(
    case_id: str,
    type_name: str,
    value: Any,
    schema: dict[str, Any],
    limits: dict[str, int],
    digests: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "case_id": case_id,
        "type": type_name,
        "value": value,
        "cev1_hex": encode_value(type_name, value, schema, limits).hex(),
    }
    if digests:
        item["digests"] = [
            {
                "label": label,
                "domain": domain,
                "digest_hex": digest_v1(domain, type_name, value, schema, limits),
            }
            for label, domain in digests
        ]
    return item


def build_vectors(schema: dict[str, Any]) -> dict[str, Any]:
    parameters = _consensus_parameters()
    limits = {
        "max_consensus_string_bytes": parameters["max_consensus_string_bytes"],
        "max_bytes_bytes": parameters["max_cev1_value_bytes"],
        "max_list_items": parameters["max_validators"],
        "max_nesting": parameters["max_cev1_nesting"],
        "max_signature_bytes": parameters["max_signature_bytes"],
        "max_certificate_signers": parameters["max_certificate_signers"],
    }
    source_context = _context()
    target_context = _context(0x23)
    source_runtime_profile_hash = _hash_byte(0x33)
    target_runtime_profile_hash = _hash_byte(0x34)
    source_definition = {
        "schema_version": 1,
        "members": [_validator(index) for index in range(4)],
        "total_weight": 4,
        "quorum_threshold": 3,
    }
    target_definition = copy.deepcopy(source_definition)
    source_validator_descriptor = {
        "schema_version": 1,
        "context": source_context,
        "epoch": 7,
        "definition": source_definition,
    }
    target_validator_descriptor = {
        "schema_version": 1,
        "context": target_context,
        "epoch": 8,
        "definition": target_definition,
    }
    source_validator_set_hash = digest_v1(
        schema["domains"]["validator_set"],
        "ValidatorSetDescriptorV1",
        source_validator_descriptor,
        schema,
        limits,
    )
    target_validator_set_hash = digest_v1(
        schema["domains"]["validator_set"],
        "ValidatorSetDescriptorV1",
        target_validator_descriptor,
        schema,
        limits,
    )
    consensus_parameters_hash = digest_v1(
        schema["domains"]["consensus_parameters"],
        "ConsensusParametersV1",
        parameters,
        schema,
        limits,
    )
    fixtures: dict[str, Any] = {
        "limits": limits,
        "limits_authority": "Order-relevant limits are derived from the vectorized ConsensusParametersV1; max_bytes_bytes uses max_cev1_value_bytes as this closed candidate's outer allocation ceiling.",
        "expected_context": source_context,
        "source_runtime_profile_hash": source_runtime_profile_hash,
        "target_runtime_profile_hash": target_runtime_profile_hash,
        "source_validator_set_descriptor": source_validator_descriptor,
        "source_validator_set_hash": source_validator_set_hash,
        "target_validator_set_descriptor": target_validator_descriptor,
        "target_validator_set_hash": target_validator_set_hash,
        "validator_set_definition": source_definition,
        "consensus_parameters": parameters,
        "consensus_parameters_hash": consensus_parameters_hash,
        "signature_note": "64-byte deterministic placeholders exercise canonical carriers and signing roots only; no Ed25519 verification is claimed.",
    }

    leaf0 = {
        "root_kind": 0,
        "index": 0,
        "item_kind": 15,
        "item_id": _hash_byte(0x61),
        "item_commitment": _hash_byte(0x71),
    }
    leaf1 = {
        "root_kind": 0,
        "index": 1,
        "item_kind": 15,
        "item_id": _hash_byte(0x62),
        "item_commitment": _hash_byte(0x72),
    }
    leaf0_hash = digest_v1(schema["domains"]["merkle_leaf"], "MerkleLeafBodyV1", leaf0, schema, limits)
    leaf1_hash = digest_v1(schema["domains"]["merkle_leaf"], "MerkleLeafBodyV1", leaf1, schema, limits)
    node = {"root_kind": 0, "level": 0, "left": leaf0_hash, "right": leaf1_hash}
    node_hash = digest_v1(schema["domains"]["merkle_node"], "MerkleNodeBodyV1", node, schema, limits)
    list_root = {"root_kind": 0, "item_count": 2, "tree_root": node_hash}
    empty_root = {"root_kind": 0, "item_count": 0, "tree_root": None}
    odd_ordered_root = derive_ordered_root(
        0,
        [
            {"item_kind": 15, "item_id": _hash_byte(0x61), "item_commitment": _hash_byte(0x71)},
            {"item_kind": 15, "item_id": _hash_byte(0x62), "item_commitment": _hash_byte(0x72)},
            {"item_kind": 15, "item_id": _hash_byte(0x63), "item_commitment": _hash_byte(0x73)},
        ],
        schema,
        limits,
    )
    odd_ordered_root["case_id"] = "ordered_root_three_items_odd_duplication"

    block_header = {
        "schema_version": 1,
        "context": _context(),
        "epoch": 7,
        "view": 8,
        "height": 42,
        "block_kind": {"variant": "Ordinary"},
        "parent": {"variant": "V1Block", "value": {"block_id": _hash_byte(0x81)}},
        "proposer_id": _validator(0)["validator_id"],
        "epoch_descriptor_id": _hash_byte(0x82),
        "justify_qc_id": _hash_byte(0x83),
        "timeout_certificate_id": None,
        "batch_refs_root": digest_v1(
            schema["domains"]["merkle_list_root"], "MerkleListRootBodyV1", list_root, schema, limits
        ),
        "protocol_objects_root": _hash_byte(0x84),
        "post_state_root": _hash_byte(0x85),
        "transaction_execution_receipts_root": _hash_byte(0x86),
        "evidence_root": _hash_byte(0x87),
        "consumption_rollups_root": _hash_byte(0x88),
        "settlement_root": _hash_byte(0x89),
        "resource_usage_root": _hash_byte(0x8A),
        "next_epoch_descriptor_id": None,
        "upgrade_plan_id": None,
        "epoch_handoff_id": None,
    }
    block_id = digest_v1(schema["domains"]["block_id"], "BlockHeaderV1", block_header, schema, limits)
    vote_statement = {
        "schema_version": 1,
        "consensus_context": _consensus_context(
            1,
            8,
            context=source_context,
            epoch=7,
            validator_set_hash=source_validator_set_hash,
            consensus_parameters_hash=consensus_parameters_hash,
            runtime_profile_hash=source_runtime_profile_hash,
        ),
        "block_id": block_id,
        "height": 42,
        "epoch_descriptor_id": _hash_byte(0x82),
        "post_state_root": _hash_byte(0x85),
        "batch_refs_root": block_header["batch_refs_root"],
        "transaction_execution_receipts_root": _hash_byte(0x86),
    }
    vote_entries = [
        {
            "voter_id": _validator(index)["validator_id"],
            "signature_scheme": 0,
            "signature": _sig(0xA0 + index),
        }
        for index in range(3)
    ]
    qc_body = {"schema_version": 1, "statement": vote_statement, "signatures": vote_entries}
    qc_id = digest_v1(schema["domains"]["quorum_certificate"], "QuorumCertificateBodyV1", qc_body, schema, limits)

    genesis_anchor_body = {
        "schema_version": 1,
        "target_context": _context(),
        "genesis_derived_state_hash": _hash_byte(0x91),
        "application_state_root": _hash_byte(0x92),
        "target_epoch_descriptor_id": _hash_byte(0x82),
        "initial_height": 1,
        "initial_view": 1,
    }
    genesis_anchor_id = digest_v1(
        schema["domains"]["genesis_anchor"], "GenesisAnchorBodyV1", genesis_anchor_body, schema, limits
    )
    genesis_anchor = {"body": genesis_anchor_body, "genesis_anchor_id": genesis_anchor_id}
    high_ref = {
        "variant": "EpochStart",
        "value": {"anchor_kind": 0, "anchor_id": genesis_anchor_id, "anchor_view": 0},
    }
    finalized_ref = {
        "variant": "FreshGenesis",
        "value": {"genesis_derived_state_hash": _hash_byte(0x91)},
    }
    timeout_entries = []
    timeout_statements = []
    for index in range(3):
        statement = {
            "schema_version": 1,
            "consensus_context": _consensus_context(
                2,
                9,
                context=source_context,
                epoch=7,
                validator_set_hash=source_validator_set_hash,
                consensus_parameters_hash=consensus_parameters_hash,
                runtime_profile_hash=source_runtime_profile_hash,
            ),
            "high_justification": high_ref,
            "locked_qc_id": None,
            "locked_qc_view": 0,
            "last_finalized_anchor": finalized_ref,
            "pacemaker_generation": 3,
        }
        timeout_statements.append(statement)
        timeout_entries.append(
            {
                "validator_id": _validator(index)["validator_id"],
                "statement": statement,
                "signature_scheme": 0,
                "signature": _sig(0xB0 + index),
            }
        )
    tc_body = {
        "schema_version": 1,
        "context": source_context,
        "runtime_profile_hash": source_runtime_profile_hash,
        "epoch": 7,
        "validator_set_hash": source_validator_set_hash,
        "consensus_parameters_hash": consensus_parameters_hash,
        "timed_out_view": 9,
        "target_view": 10,
        "justifications": [
            {
                "variant": "EpochStart",
                "value": {"variant": "GenesisAnchor", "value": genesis_anchor},
            }
        ],
        "entries": timeout_entries,
    }

    handoff_body = {
        "schema_version": 1,
        "source_context": source_context,
        "target_context": target_context,
        "old_epoch": 7,
        "new_epoch": 8,
        "old_epoch_checkpoint_id": _hash_byte(0xC1),
        "old_epoch_descriptor_id": _hash_byte(0xC2),
        "new_epoch_descriptor_id": _hash_byte(0xC3),
        "old_validator_set_hash": source_validator_set_hash,
        "new_validator_set_hash": target_validator_set_hash,
        "old_consensus_parameters_hash": consensus_parameters_hash,
        "new_consensus_parameters_hash": consensus_parameters_hash,
        "terminal_block_id": _hash_byte(0xC4),
        "terminal_height": 99,
        "terminal_view": 12,
        "activation_height": 100,
        "initial_new_view": 1,
    }
    handoff_id = digest_v1(
        schema["domains"]["epoch_handoff"], "EpochHandoffBodyV1", handoff_body, schema, limits
    )
    old_handoff_statement = {
        "schema_version": 1,
        "consensus_context": _consensus_context(
            3,
            12,
            context=source_context,
            epoch=7,
            validator_set_hash=source_validator_set_hash,
            consensus_parameters_hash=consensus_parameters_hash,
            runtime_profile_hash=source_runtime_profile_hash,
        ),
        "handoff_id": handoff_id,
    }
    new_handoff_statement = {
        "schema_version": 1,
        "consensus_context": _consensus_context(
            4,
            1,
            context=target_context,
            epoch=8,
            validator_set_hash=target_validator_set_hash,
            consensus_parameters_hash=consensus_parameters_hash,
            runtime_profile_hash=target_runtime_profile_hash,
        ),
        "handoff_id": handoff_id,
    }
    handoff = {
        "body": handoff_body,
        "handoff_id": handoff_id,
        "old_set_signatures": [
            {
                "signer_id": _validator(index)["validator_id"],
                "role": 0,
                "statement": old_handoff_statement,
                "signature_scheme": 0,
                "signature": _sig(0xC0 + index),
            }
            for index in range(3)
        ],
        "new_set_signatures": [
            {
                "signer_id": _validator(index)["validator_id"],
                "role": 1,
                "statement": new_handoff_statement,
                "signature_scheme": 0,
                "signature": _sig(0xD0 + index),
            }
            for index in range(3)
        ],
    }

    domains = schema["domains"]
    positive = [
        _case("u16_little_endian_0102", "u16", 0x0102, schema, limits),
        _case("u128_max", "u128", U128_MAX, schema, limits),
        _case("bytes_000102", "Bytes", "000102", schema, limits),
        _case("consensus_string", "ConsensusString", "trnm-ai-test-1", schema, limits),
        _case("protocol_context", "ProtocolContextV1", source_context, schema, limits),
        _case(
            "validator_set_definition",
            "ValidatorSetDefinitionV1",
            source_definition,
            schema,
            limits,
            [("validator_set_definition_hash", domains["validator_set_definition"])],
        ),
        _case(
            "validator_set_descriptor",
            "ValidatorSetDescriptorV1",
            source_validator_descriptor,
            schema,
            limits,
            [("validator_set_hash", domains["validator_set"])],
        ),
        _case(
            "consensus_parameters",
            "ConsensusParametersV1",
            parameters,
            schema,
            limits,
            [("consensus_parameters_hash", domains["consensus_parameters"])],
        ),
        _case("merkle_leaf_0", "MerkleLeafBodyV1", leaf0, schema, limits, [("leaf_hash", domains["merkle_leaf"])]),
        _case("merkle_leaf_1", "MerkleLeafBodyV1", leaf1, schema, limits, [("leaf_hash", domains["merkle_leaf"])]),
        _case("merkle_node_level_0", "MerkleNodeBodyV1", node, schema, limits, [("node_hash", domains["merkle_node"])]),
        _case("merkle_root_two_items", "MerkleListRootBodyV1", list_root, schema, limits, [("list_root", domains["merkle_list_root"])]),
        _case("merkle_root_empty", "MerkleListRootBodyV1", empty_root, schema, limits, [("list_root", domains["merkle_list_root"])]),
        _case("ordinary_parent", "ParentBlockRefV1", block_header["parent"], schema, limits),
        _case("ordinary_block_header", "BlockHeaderV1", block_header, schema, limits, [("block_id", domains["block_id"])]),
        _case(
            "vote_statement",
            "VoteStatementBodyV1",
            vote_statement,
            schema,
            limits,
            [("vote_signature_root", domains["vote_signature"])],
        ),
        _case(
            "vote_identity_validator_a",
            "VoteIdentityBodyV1",
            {"statement": vote_statement, "voter_id": _validator(0)["validator_id"]},
            schema,
            limits,
            [("vote_id", domains["vote_id"])],
        ),
        _case("quorum_certificate", "QuorumCertificateBodyV1", qc_body, schema, limits, [("qc_id", domains["quorum_certificate"])]),
        _case(
            "quorum_certificate_object",
            "QuorumCertificateV1",
            {"body": qc_body, "quorum_certificate_id": qc_id},
            schema,
            limits,
        ),
        _case("genesis_anchor", "GenesisAnchorBodyV1", genesis_anchor_body, schema, limits, [("genesis_anchor_id", domains["genesis_anchor"])]),
        _case(
            "timeout_statement_validator_a",
            "TimeoutStatementBodyV1",
            timeout_statements[0],
            schema,
            limits,
            [("timeout_signature_root", domains["timeout_signature"])],
        ),
        _case(
            "timeout_identity_validator_a",
            "TimeoutIdentityBodyV1",
            {"statement": timeout_statements[0], "validator_id": _validator(0)["validator_id"]},
            schema,
            limits,
            [("timeout_id", domains["timeout_id"])],
        ),
        _case("timeout_certificate", "TimeoutCertificateBodyV1", tc_body, schema, limits, [("tc_id", domains["timeout_certificate"])]),
        _case("epoch_handoff_body", "EpochHandoffBodyV1", handoff_body, schema, limits, [("handoff_id", domains["epoch_handoff"])]),
        _case(
            "epoch_handoff_old_statement",
            "EpochHandoffSignStatementV1",
            old_handoff_statement,
            schema,
            limits,
            [("old_set_signature_root", domains["epoch_handoff_old_signature"])],
        ),
        _case(
            "epoch_handoff_new_statement",
            "EpochHandoffSignStatementV1",
            new_handoff_statement,
            schema,
            limits,
            [("new_set_signature_root", domains["epoch_handoff_new_signature"])],
        ),
        _case("epoch_handoff_object", "EpochHandoffV1", handoff, schema, limits),
    ]

    by_id = {item["case_id"]: item for item in positive}
    bad_big_endian = "0102"
    bad_trailing = by_id["protocol_context"]["cev1_hex"] + "00"
    bad_truncated = by_id["protocol_context"]["cev1_hex"][:-2]
    bad_unknown_enum = "ff"
    bad_option = bytearray.fromhex(by_id["merkle_root_empty"]["cev1_hex"])
    bad_option[6] = 2
    bad_bool = bytearray.fromhex(by_id["consensus_parameters"]["cev1_hex"])
    bad_bool[7] = 2
    bad_bytes_length = "04000000000102"
    v0_context = (
        "0000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "000b74726e6d2d746573742d30000000000000000000000007"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "000000000000002a01"
    )
    duplicate_qc = copy.deepcopy(qc_body)
    duplicate_qc["signatures"][1] = copy.deepcopy(duplicate_qc["signatures"][0])
    reordered_qc = copy.deepcopy(qc_body)
    reordered_qc["signatures"][0], reordered_qc["signatures"][1] = (
        reordered_qc["signatures"][1],
        reordered_qc["signatures"][0],
    )
    single_quorum_handoff = copy.deepcopy(handoff)
    single_quorum_handoff["new_set_signatures"] = single_quorum_handoff["new_set_signatures"][:2]
    wrong_role_handoff = copy.deepcopy(handoff)
    wrong_role_handoff["new_set_signatures"][0]["role"] = 0
    overflow_definition = {
        "schema_version": 1,
        "members": [_validator(0, U128_MAX), _validator(1, 1)],
        "total_weight": U128_MAX,
        "quorum_threshold": U128_MAX,
    }
    wrong_chain = copy.deepcopy(_context())
    wrong_chain["chain_id"] = "other-chain"
    wrong_profile = copy.deepcopy(_context())
    wrong_profile["stack_profile_hash"] = _hash_byte(0x99)
    wrong_root = copy.deepcopy(list_root)
    wrong_root["root_kind"] = 1
    unknown_typed_id = {"object_kind": 51, "object_id": _hash_byte(0x61)}
    unknown_leaf_root = copy.deepcopy(leaf0)
    unknown_leaf_root["root_kind"] = 21
    unknown_leaf_item = copy.deepcopy(leaf0)
    unknown_leaf_item["item_kind"] = 51
    unknown_node_root = copy.deepcopy(node)
    unknown_node_root["root_kind"] = 21
    cross_chain_anchor_tc = copy.deepcopy(tc_body)
    cross_chain_anchor_body = cross_chain_anchor_tc["justifications"][0]["value"]["value"]["body"]
    cross_chain_anchor_body["target_context"]["chain_id"] = "other-chain"
    cross_chain_anchor_id = digest_v1(
        domains["genesis_anchor"],
        "GenesisAnchorBodyV1",
        cross_chain_anchor_body,
        schema,
        limits,
    )
    cross_chain_anchor_tc["justifications"][0]["value"]["value"]["genesis_anchor_id"] = cross_chain_anchor_id
    for entry in cross_chain_anchor_tc["entries"]:
        entry["statement"]["high_justification"]["value"]["anchor_id"] = cross_chain_anchor_id
    wrong_anchor_kind_tc = copy.deepcopy(tc_body)
    for entry in wrong_anchor_kind_tc["entries"]:
        entry["statement"]["high_justification"]["value"]["anchor_kind"] = 1

    negative = [
        {
            "case_id": "reject_big_endian_u16",
            "mode": "decode_equals",
            "type": "u16",
            "encoded_hex": bad_big_endian,
            "expected_value": 0x0102,
            "expected_error": "decoded_value_mismatch",
        },
        {"case_id": "reject_trailing_bytes", "mode": "decode", "type": "ProtocolContextV1", "encoded_hex": bad_trailing, "expected_error": "trailing_bytes"},
        {"case_id": "reject_truncation", "mode": "decode", "type": "ProtocolContextV1", "encoded_hex": bad_truncated, "expected_error": "truncated"},
        {"case_id": "reject_unknown_enum", "mode": "decode", "type": "ParentBlockRefV1", "encoded_hex": bad_unknown_enum, "expected_error": "unknown_enum_discriminant"},
        {"case_id": "reject_invalid_option_tag", "mode": "decode", "type": "MerkleListRootBodyV1", "encoded_hex": bytes(bad_option).hex(), "expected_error": "invalid_option_tag"},
        {"case_id": "reject_invalid_bool", "mode": "decode", "type": "ConsensusParametersV1", "encoded_hex": bytes(bad_bool).hex(), "expected_error": "invalid_bool"},
        {"case_id": "reject_bytes_length_mismatch", "mode": "decode", "type": "Bytes", "encoded_hex": bad_bytes_length, "expected_error": "truncated"},
        {
            "case_id": "reject_consensus_string_max_plus_one",
            "mode": "value",
            "type": "ConsensusString",
            "value": "x" * (parameters["max_consensus_string_bytes"] + 1),
            "expected_error": "bound_consensus_string",
        },
        {"case_id": "reject_checked_weight_overflow", "mode": "value", "type": "ValidatorSetDefinitionV1", "value": overflow_definition, "expected_error": "checked_overflow"},
        {"case_id": "reject_duplicate_qc_signer", "mode": "value", "type": "QuorumCertificateBodyV1", "value": duplicate_qc, "expected_error": "duplicate_signer"},
        {"case_id": "reject_reordered_qc_signer", "mode": "value", "type": "QuorumCertificateBodyV1", "value": reordered_qc, "expected_error": "signer_order"},
        {
            "case_id": "reject_single_quorum_handoff",
            "mode": "value",
            "type": "EpochHandoffV1",
            "value": single_quorum_handoff,
            "expected_error": "insufficient_quorum",
        },
        {
            "case_id": "reject_wrong_handoff_role",
            "mode": "value",
            "type": "EpochHandoffV1",
            "value": wrong_role_handoff,
            "expected_error": "wrong_handoff_role",
        },
        {
            "case_id": "reject_tc_cross_chain_epoch_start_anchor",
            "mode": "value",
            "type": "TimeoutCertificateBodyV1",
            "value": cross_chain_anchor_tc,
            "expected_error": "epoch_start_context_mismatch",
        },
        {
            "case_id": "reject_tc_anchor_kind_mismatch",
            "mode": "value",
            "type": "TimeoutCertificateBodyV1",
            "value": wrong_anchor_kind_tc,
            "expected_error": "unresolved_justification",
        },
        {
            "case_id": "reject_wrong_chain_binding",
            "mode": "context_binding",
            "type": "ProtocolContextV1",
            "value": wrong_chain,
            "expected_context": _context(),
            "expected_error": "context_binding_mismatch",
        },
        {
            "case_id": "reject_wrong_profile_binding",
            "mode": "context_binding",
            "type": "ProtocolContextV1",
            "value": wrong_profile,
            "expected_context": _context(),
            "expected_error": "context_binding_mismatch",
        },
        {
            "case_id": "reject_wrong_digest_domain",
            "mode": "digest",
            "type": "VoteStatementBodyV1",
            "value": vote_statement,
            "domain": domains["timeout_signature"],
            "declared_digest_hex": digest_v1(domains["vote_signature"], "VoteStatementBodyV1", vote_statement, schema, limits),
            "expected_error": "digest_mismatch",
        },
        {
            "case_id": "reject_wrong_destination_root_kind",
            "mode": "root_binding",
            "type": "MerkleListRootBodyV1",
            "value": wrong_root,
            "expected_root_kind": 0,
            "expected_error": "root_kind_mismatch",
        },
        {
            "case_id": "reject_unknown_typed_object_kind",
            "mode": "value",
            "type": "TypedObjectIdV1",
            "value": unknown_typed_id,
            "expected_error": "unknown_object_kind",
        },
        {
            "case_id": "reject_unknown_leaf_root_kind",
            "mode": "value",
            "type": "MerkleLeafBodyV1",
            "value": unknown_leaf_root,
            "expected_error": "unknown_root_kind",
        },
        {
            "case_id": "reject_unknown_leaf_item_kind",
            "mode": "value",
            "type": "MerkleLeafBodyV1",
            "value": unknown_leaf_item,
            "expected_error": "unknown_object_kind",
        },
        {
            "case_id": "reject_unknown_node_root_kind",
            "mode": "value",
            "type": "MerkleNodeBodyV1",
            "value": unknown_node_root,
            "expected_error": "unknown_root_kind",
        },
        {
            "case_id": "reject_v0_bytes_as_v1",
            "mode": "decode",
            "type": "ProtocolContextV1",
            "encoded_hex": v0_context,
            "source": "exact CEV0 common_vote_context from poco-bft-v0 wire-foundation vectors",
            "expected_error": "bound_consensus_string",
        },
    ]

    return {
        "artifact": "trnm.poco-ai.cev1-foundation-order-kernel.v1.vectors",
        "artifact_version": 1,
        "schema_artifact": schema["artifact"],
        "status": copy.deepcopy(schema["status"]),
        "fixtures": fixtures,
        "positive_cases": positive,
        "derived_cases": [odd_ordered_root],
        "negative_cases": negative,
        "coverage": {
            "positive": [
                "fixed-width little-endian primitives and length framing",
                "ProtocolContext and validator-set/parameter commitments",
                "typed ordered leaf/node/empty/nonempty roots",
                "three-item ordered-root odd-width duplication at level zero",
                "ordinary BlockHeader and BlockId",
                "Vote statement, VoteId preimage, signature root, weighted QC",
                "Timeout statement, TimeoutId preimage, signature root, weighted TC with complete epoch-start anchor",
                "epoch handoff body and role-specific signature roots",
            ],
            "negative": [
                "big-endian substitution",
                "trailing and truncated bytes",
                "unknown enum and invalid bool/option tags",
                "length and fixture-bound violations",
                "checked arithmetic overflow",
                "duplicate/reordered certificate signers",
                "single-quorum or role-confused epoch handoff",
                "wrong chain/profile/domain/root-kind binding",
                "cross-chain or anchor-kind-confused TC epoch-start justification",
                "unknown typed-object, leaf-item, leaf-root, and node-root registry tags",
                "v0 CEV0 bytes presented as v1 CEV1",
            ],
        },
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CandidateError("missing_artifact", str(path.relative_to(REPO_ROOT))) from exc
    except json.JSONDecodeError as exc:
        raise CandidateError("invalid_json", str(path.relative_to(REPO_ROOT))) from exc


def _run_negative(case: dict[str, Any], schema: dict[str, Any], fixtures: dict[str, Any]) -> None:
    limits = fixtures["limits"]
    mode = case["mode"]
    if mode == "decode":
        value = decode_full(case["type"], _parse_hex(case["encoded_hex"]), schema, limits)
        validate_value(case["type"], value, schema, fixtures, limits)
        return
    if mode == "decode_equals":
        value = decode_full(case["type"], _parse_hex(case["encoded_hex"]), schema, limits)
        if value != case["expected_value"]:
            raise CandidateError("decoded_value_mismatch")
        return
    if mode == "value":
        validate_value(case["type"], case["value"], schema, fixtures, limits)
        return
    if mode == "context_binding":
        validate_value(case["type"], case["value"], schema, fixtures, limits)
        if case["value"] != case["expected_context"]:
            raise CandidateError("context_binding_mismatch")
        return
    if mode == "digest":
        actual = digest_v1(case["domain"], case["type"], case["value"], schema, limits)
        if actual != case["declared_digest_hex"]:
            raise CandidateError("digest_mismatch")
        return
    if mode == "root_binding":
        validate_value(case["type"], case["value"], schema, fixtures, limits)
        if case["value"]["root_kind"] != case["expected_root_kind"]:
            raise CandidateError("root_kind_mismatch")
        return
    raise CandidateError("unknown_negative_mode", mode)


def _validate_fixture_authority(
    schema: dict[str, Any], fixtures: dict[str, Any], limits: dict[str, int]
) -> None:
    parameters = fixtures["consensus_parameters"]
    _validate_consensus_parameters(parameters)
    expected_limits = {
        "max_consensus_string_bytes": parameters["max_consensus_string_bytes"],
        "max_bytes_bytes": parameters["max_cev1_value_bytes"],
        "max_list_items": parameters["max_validators"],
        "max_nesting": parameters["max_cev1_nesting"],
        "max_signature_bytes": parameters["max_signature_bytes"],
        "max_certificate_signers": parameters["max_certificate_signers"],
    }
    if limits != expected_limits:
        raise CandidateError("fixture_limit_authority_mismatch")
    expected_parameter_hash = digest_v1(
        schema["domains"]["consensus_parameters"],
        "ConsensusParametersV1",
        parameters,
        schema,
        limits,
    )
    if fixtures["consensus_parameters_hash"] != expected_parameter_hash:
        raise CandidateError("consensus_parameters_hash_mismatch")
    for role in ("source", "target"):
        descriptor = fixtures[f"{role}_validator_set_descriptor"]
        _schema_version_one("ValidatorSetDescriptorV1", descriptor)
        _validate_protocol_context(descriptor["context"])
        _validate_validator_definition(descriptor["definition"])
        expected_set_hash = digest_v1(
            schema["domains"]["validator_set"],
            "ValidatorSetDescriptorV1",
            descriptor,
            schema,
            limits,
        )
        if fixtures[f"{role}_validator_set_hash"] != expected_set_hash:
            raise CandidateError("validator_set_hash_mismatch", role)
    if fixtures["expected_context"] != fixtures["source_validator_set_descriptor"]["context"]:
        raise CandidateError("expected_context_authority_mismatch")
    if fixtures["validator_set_definition"] != fixtures["source_validator_set_descriptor"]["definition"]:
        raise CandidateError("validator_definition_authority_mismatch")


def verify(schema: dict[str, Any], vectors: dict[str, Any]) -> None:
    expected_schema = build_schema()
    if schema != expected_schema:
        raise CandidateError("schema_fixture_mismatch", "run with --write")
    _validate_schema_structure(schema)
    expected_vectors = build_vectors(schema)
    if vectors != expected_vectors:
        raise CandidateError("vector_fixture_mismatch", "run with --write")
    if schema["status"] != vectors["status"]:
        raise CandidateError("candidate_status_mismatch")
    if any(
        schema["status"][key]
        for key in (
            "normative_freeze",
            "global_wire_schema_complete",
            "semantic_consistency_proven",
            "implementation_or_activation_evidence",
            "cryptographic_interoperability_evidence",
        )
    ):
        raise CandidateError("candidate_scope_overclaim")
    if not schema["status"]["closed_for_listed_types_only"]:
        raise CandidateError("candidate_scope_not_closed")

    fixtures = vectors["fixtures"]
    limits = fixtures["limits"]
    _validate_fixture_authority(schema, fixtures, limits)
    for case in vectors["positive_cases"]:
        validate_value(case["type"], case["value"], schema, fixtures, limits)
        encoded = encode_value(case["type"], case["value"], schema, limits)
        if encoded.hex() != case["cev1_hex"]:
            raise CandidateError("positive_encoding_mismatch", case["case_id"])
        decoded = decode_full(case["type"], encoded, schema, limits)
        if decoded != case["value"]:
            raise CandidateError("positive_roundtrip_mismatch", case["case_id"])
        for digest in case.get("digests", []):
            actual = digest_v1(digest["domain"], case["type"], case["value"], schema, limits)
            if actual != digest["digest_hex"]:
                raise CandidateError("positive_digest_mismatch", case["case_id"])

    for case in vectors["derived_cases"]:
        actual = derive_ordered_root(case["root_kind"], case["items"], schema, limits)
        actual["case_id"] = case["case_id"]
        if actual != case:
            raise CandidateError("derived_ordered_root_mismatch", case["case_id"])

    for case in vectors["negative_cases"]:
        try:
            _run_negative(case, schema, fixtures)
        except CandidateError as exc:
            if exc.code != case["expected_error"]:
                raise CandidateError(
                    "negative_error_mismatch",
                    f"{case['case_id']}: expected {case['expected_error']}, got {exc.code}",
                ) from exc
        else:
            raise CandidateError("negative_case_accepted", case["case_id"])


def self_test_mutants(schema: dict[str, Any], vectors: dict[str, Any]) -> None:
    """Prove the checker itself rejects a deliberately corrupted vector file."""

    mutant = copy.deepcopy(vectors)
    mutant["positive_cases"][0]["cev1_hex"] = "0102"  # CEV0/big-endian bytes for u16 0x0102.
    try:
        verify(schema, mutant)
    except CandidateError as exc:
        if exc.code != "vector_fixture_mismatch":
            raise CandidateError("mutant_wrong_rejection", exc.code) from exc
    else:
        raise CandidateError("mutant_accepted")

    fixtures = vectors["fixtures"]
    limits = fixtures["limits"]
    big_endian = bytes.fromhex("0102")
    decoded = decode_full("u16", big_endian, schema, limits)
    if decoded == 0x0102:
        raise CandidateError("mutant_big_endian_accepted")

    qc_case = next(case for case in vectors["positive_cases"] if case["case_id"] == "quorum_certificate")
    duplicate = copy.deepcopy(qc_case["value"])
    duplicate["signatures"][1] = copy.deepcopy(duplicate["signatures"][0])
    try:
        validate_value("QuorumCertificateBodyV1", duplicate, schema, fixtures, limits)
    except CandidateError as exc:
        if exc.code != "duplicate_signer":
            raise CandidateError("mutant_wrong_rejection", exc.code) from exc
    else:
        raise CandidateError("mutant_duplicate_signer_accepted")


def write_artifacts() -> None:
    schema = build_schema()
    vectors = build_vectors(schema)
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(_canonical_json(schema), encoding="utf-8")
    VECTORS_PATH.write_text(_canonical_json(vectors), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="verify checked-in schema/vectors (default)")
    group.add_argument("--write", action="store_true", help="author deterministic schema/vectors")
    parser.add_argument(
        "--self-test-mutants",
        action="store_true",
        help="also prove a deliberately bad vector file is rejected",
    )
    args = parser.parse_args()

    try:
        if args.write:
            write_artifacts()
        schema = _load_json(SCHEMA_PATH)
        vectors = _load_json(VECTORS_PATH)
        verify(schema, vectors)
        if args.self_test_mutants:
            self_test_mutants(schema, vectors)
    except CandidateError as exc:
        print(f"poco-ai-native-v1 foundation vectors: FAIL: {exc}", file=sys.stderr)
        return 1

    action = "authored and verified" if args.write else "verified"
    suffix = " with mutant self-test" if args.self_test_mutants else ""
    print(f"poco-ai-native-v1 foundation vectors: {action}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
