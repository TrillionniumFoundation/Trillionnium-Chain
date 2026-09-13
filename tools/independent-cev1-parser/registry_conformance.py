#!/usr/bin/env python3
"""Independent, fail-closed conformance checker for the CEV1 registries.

This module uses only Python's standard library and intentionally does not
import an A08 checker, Rust crate, or canonical serializer.  The A08 checker
is invoked separately as an optional cross-check and its result is recorded in
the evidence envelope.  A pending A08 semantic-correction pin is reported as
``BLOCKED_UPSTREAM``; local strict parsing and all retained mutants still run.
The retained corpus has a 54-case minimum, including dedicated corrected-A08
operation body-type, kind-27 disabled-row, and kind-29 mapping mutants.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Iterable, NoReturn


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REL = Path("docs/protocol/poco-ai-native-v1/registry")
CATALOG_REL = Path("docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml")
REGISTRY_FILES = (
    "operation-registry-v1.json",
    "object-registry-v1.json",
    "domain-registry-v1.json",
    "error-registry-v1.json",
    "limit-registry-v1.json",
    "verification-profile-registry-v1.json",
)
OPERATION_MAP_REL = Path("conformance/cev1/registry-v1/operation-mapping-v1.json")
NEGATIVE_CORPUS_REL = Path("conformance/cev1/registry-v1/negative-cases.json")
A08_CHECKER_REL = Path("scripts/ci/check_cev1_registry_spec_v1.py")
PLAN_REL = Path("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md")
PENDING_PIN = "<pending-a08-correction>"
REGISTRY_STATUS = "candidate-non-normative"
CATALOG_STATUS = "draft-design-only"

PLANES = {
    "agent",
    "market-task",
    "compute-verify",
    "data-availability",
    "order-coordination-settlement",
}
OPERATION_PLANES = {
    "agent",
    "market-task",
    "compute-verify",
    "data-availability",
    "execution",
    "settlement",
    "order-coordination-settlement",
    "order",
    "upgrade",
    "sync",
    "light-client",
    "governance",
    "reserved",
}
ERROR_CLASSES = {
    "malformed",
    "resource",
    "invalid",
    "conflict",
    "disabled",
    "unavailable",
    "stop-condition",
    "replay",
    "backend-error",
    "internal",
}
WIRE_STATES = {"candidate", "unassigned"}
OBJECT_ID_RE = re.compile(r"[A-Z][A-Za-z0-9]*V1\Z")
BODY_TYPE_RE = re.compile(r"[A-Z][A-Za-z0-9]*V1\Z")
SLUG_RE = re.compile(r"[a-z][a-z0-9-]*\Z")
CODE_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
LIMIT_NAME_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]*\Z")
HEX40_RE = re.compile(r"[0-9a-f]{40}\Z")
JSON_WS = " \t\r\n"
EVIDENCE_ID_PREFIX = "g15-a09-"
EVIDENCE_ID_HEX_LENGTH = 32
EVIDENCE_ID_ALGORITHM = "sha256-canonical-json-stable-projection-v1"

# The retained corpus is part of the independent conformance contract, not a
# best-effort smoke test.  Keep the historical 51 cases and require the three
# corrected-A08 semantic sentinels below so a future fixture refresh cannot
# silently drop coverage for body types, disabled kind 27, or kind 29.
MIN_NEGATIVE_CASE_COUNT = 54
REQUIRED_NEGATIVE_CASES = {
    "operation-body-type-drift": ("operation-registry-v1.json", "operation_body_type_drift"),
    "operation-kind27-disabled-drift": ("operation-registry-v1.json", "operation_kind27_disabled_drift"),
    "operation-kind29-mapping-drift": ("operation-registry-v1.json", "operation_kind29_mapping_drift"),
}


# A09-owned semantic assignment map.  It is intentionally independent of the
# A08 checker.  This table is the exact 0..29 projection published by the
# corrected A08 candidate (6c42673…); keeping the body type in the tuple makes
# a slot reassignment or schema substitution fail closed.
EXPECTED_OPERATION_ROWS: tuple[tuple[Any, ...], ...] = (
    (0, "AgentIdentityCreation", "AgentIdentityCreationOperationBodyV1", "agent", "candidate-assigned", False, "existing-or-self-origin", "self-origin", None),
    (1, "AgentKey", "AgentKeyBodyV1", "agent", "candidate-assigned", False, "existing-agent", "controller", None),
    (2, "CapabilityGrant", "CapabilityGrantBodyV1", "agent", "candidate-assigned", False, "existing-agent", "controller", None),
    (3, "SessionKeyGrant", "SessionKeyGrantBodyV1", "agent", "candidate-assigned", False, "existing-agent", "controller", None),
    (4, "TaskCreation", "TaskCreationOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "requester", None),
    (5, "Bid", "BidBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "provider", None),
    (6, "TaskLease", "TaskLeaseBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "requester", None),
    (7, "LeaseProviderAcceptance", "LeaseProviderAcceptanceBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "provider", None),
    (8, "ComputeCheckpoint", "ComputeCheckpointBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "provider", None),
    (9, "ArtifactCommitment", "ArtifactCommitmentBodyV1", "data-availability", "candidate-assigned", False, "existing-agent", "creator", None),
    (10, "ExecutionReceipt", "ExecutionReceiptBodyV1", "compute-verify", "candidate-assigned", False, "existing-agent", "provider", None),
    (11, "Challenge", "ChallengeBodyV1", "compute-verify", "candidate-assigned", False, "existing-agent", "challenger", None),
    (12, "CapabilityRevocation", "CapabilityRevocationOperationV1", "agent", "candidate-assigned", False, "existing-agent", "controller", None),
    (13, "AgentAdministration", "AgentAdministrationOperationV1", "agent", "candidate-assigned", False, "existing-agent", "controller", None),
    (14, "TaskStart", "TaskStartOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "provider", None),
    (15, "TaskPause", "TaskPauseOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "task-party", None),
    (16, "TaskResume", "TaskResumeOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "provider", None),
    (17, "TaskCancel", "TaskCancelOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "task-party", None),
    (18, "TaskTimeout", "TaskTimeoutOperationBodyV1", "market-task", "candidate-assigned", False, "permissionless-trigger", "outer-sender", None),
    (19, "TaskMigration", "TaskMigrationOperationBodyV1", "market-task", "candidate-assigned", False, "existing-agent", "task-party", None),
    (20, "TaskRevision", "TaskRevisionOperationBodyV1", "market-task", "disabled", False, "existing-agent", "task-party", "ERR_OPERATION_DISABLED"),
    (21, "VerificationClaim", "VerificationClaimV1", "compute-verify", "candidate-assigned", False, "externally-signed-object-submitted-by-agent", "submitter", None),
    (22, "EvaluationResult", "EvaluationResultV1", "compute-verify", "candidate-assigned", False, "existing-agent", "submitter", None),
    (23, "ChallengeUpdate", "ChallengeUpdateOperationBodyV1", "compute-verify", "candidate-assigned", False, "action-dependent", "outer-sender", None),
    (24, "ConsumptionReceipt", "ConsumptionReceiptV1", "settlement", "candidate-assigned", False, "externally-signed-object-submitted-by-agent", "submitter", None),
    (25, "ConsumptionRollup", "ConsumptionRollupV1", "settlement", "candidate-assigned", False, "externally-signed-object-submitted-by-agent", "submitter", None),
    (26, "Settlement", "SettlementOperationBodyV1", "settlement", "candidate-assigned", False, "permissionless-trigger", "outer-sender", None),
    (27, "OrderedEvidence", "OrderedEvidenceV1", "order-coordination-settlement", "disabled", False, "externally-signed-object-submitted-by-agent", "submitter", "ERR_OPERATION_DISABLED"),
    (28, "DaObligation", "DaObligationOperationBodyV1", "data-availability", "candidate-assigned", False, "action-dependent", "outer-sender", None),
    (29, "EconomicObject", "EconomicObjectOperationBodyV1", "order-coordination-settlement", "candidate-assigned", False, "existing-agent", "outer-sender", None),
)


EXPECTED_OBJECTS: tuple[tuple[str, str], ...] = (
    ("AgentIdentityV1", "agent"),
    ("AgentKeyV1", "agent"),
    ("CapabilityGrantV1", "agent"),
    ("CapabilityRevocationOperationV1", "agent"),
    ("SessionKeyGrantV1", "agent"),
    ("NonceLaneStateV1", "agent"),
    ("AgentTransactionV1", "agent"),
    ("TaskOfferV1", "market-task"),
    ("BidV1", "market-task"),
    ("TaskLeaseV1", "market-task"),
    ("EscrowV1", "market-task"),
    ("ComputeCheckpointV1", "market-task"),
    ("ExecutionReceiptV1", "compute-verify"),
    ("ResultV1", "compute-verify"),
    ("VerificationProfileV1", "compute-verify"),
    ("VerificationClaimV1", "compute-verify"),
    ("ChallengeV1", "compute-verify"),
    ("EvaluationResultV1", "compute-verify"),
    ("ArtifactCommitmentV1", "data-availability"),
    ("DaCommitteeDescriptorV1", "data-availability"),
    ("DaBatchEnvelopeV1", "data-availability"),
    ("DaAttestationV1", "data-availability"),
    ("AvailabilityCertificateV1", "data-availability"),
    ("WithholdingEvidenceV1", "data-availability"),
    ("RetrievalReceiptV1", "data-availability"),
    ("BatchRefV1", "order-coordination-settlement"),
    ("ChainDescriptorV1", "order-coordination-settlement"),
    ("StackProfileV1", "order-coordination-settlement"),
    ("BlockHeaderV1", "order-coordination-settlement"),
    ("OrderProposalV1", "order-coordination-settlement"),
    ("VoteV1", "order-coordination-settlement"),
    ("QuorumCertificateV1", "order-coordination-settlement"),
    ("TimeoutV1", "order-coordination-settlement"),
    ("TimeoutCertificateV1", "order-coordination-settlement"),
    ("EpochDescriptorV1", "order-coordination-settlement"),
    ("EpochHandoffV1", "order-coordination-settlement"),
    ("EpochCheckpointV1", "order-coordination-settlement"),
    ("TransactionExecutionReceiptV1", "order-coordination-settlement"),
    ("ConsumptionReceiptV1", "order-coordination-settlement"),
    ("ConsumptionRollupV1", "order-coordination-settlement"),
    ("FeeScheduleV1", "order-coordination-settlement"),
    ("SettlementIntentV1", "order-coordination-settlement"),
    ("SettlementReceiptV1", "order-coordination-settlement"),
    ("StateSyncManifestV1", "order-coordination-settlement"),
    ("UpgradePlanV1", "order-coordination-settlement"),
    ("MigrationReceiptV1", "order-coordination-settlement"),
    ("V0ToV1ActivationStatementV1", "order-coordination-settlement"),
    ("V0ToV1ActivationCertificateV1", "order-coordination-settlement"),
    ("OrderFinalityProofV1", "order-coordination-settlement"),
    ("ApplicationStateProofV1", "order-coordination-settlement"),
    ("ArtifactAvailabilityProofV1", "order-coordination-settlement"),
    ("ResultSettlementFinalityProofV1", "order-coordination-settlement"),
    ("GlobalExecutionBindingV1", "order-coordination-settlement"),
)

OBJECT_AUTHORITIES = {
    "state-object",
    "operation",
    "transaction-envelope",
    "economic-state",
    "execution-evidence",
    "result-state",
    "profile",
    "signed-claim",
    "challenge-state",
    "result-decision",
    "artifact-commitment",
    "committee-descriptor",
    "batch-envelope",
    "attestation",
    "availability-claim",
    "negative-evidence",
    "retrieval-evidence",
    "ordered-da-reference",
    "chain-identity",
    "ordered-header",
    "proposal",
    "signature",
    "certificate",
    "epoch-state",
    "dual-quorum",
    "epoch-checkpoint",
    "receipt",
    "bilateral-receipt",
    "rollup",
    "parameter-root",
    "immutable-intent",
    "economic-transition",
    "sync-manifest",
    "governance-plan",
    "migration-receipt",
    "activation-statement",
    "proof",
    "candidate-binding",
}

EXPECTED_DOMAIN_VALUES = {
    "protocol-context": "trnm.poco-ai.protocol-context.v1",
    "chain-descriptor": "trnm.poco-ai.chain-descriptor.v1",
    "stack-profile": "trnm.poco-ai.stack-profile.v1",
    "validator-set-definition": "trnm.poco-ai.validator-set-definition.v1",
    "validator-set": "trnm.poco-ai.validator-set.v1",
    "consensus-parameters": "trnm.poco-ai.consensus-parameters.v1",
    "agent-transaction": "trnm.poco-ai.agent-transaction.v1",
    "capability": "trnm.poco-ai.capability.v1",
    "session-key-grant": "trnm.poco-ai.session-key-grant.v1",
    "nonce-lane": "trnm.poco-ai.nonce-lane.v1",
    "task-offer": "trnm.poco-ai.task-offer.v1",
    "bid": "trnm.poco-ai.bid.v1",
    "lease": "trnm.poco-ai.lease.v1",
    "escrow": "trnm.poco-ai.escrow.v1",
    "transaction-batch": "trnm.poco-ai.transaction-batch.v1",
    "artifact-evidence": "trnm.poco-ai.artifact-evidence.v1",
    "availability-certificate": "trnm.poco-ai.availability-certificate.v1",
    "batch-ref": "trnm.poco-ai.batch-ref.v1",
    "execution-receipt": "trnm.poco-ai.execution-receipt.v1",
    "verification-claim": "trnm.poco-ai.verification-claim.v1",
    "challenge": "trnm.poco-ai.challenge.v1",
    "result-decision": "trnm.poco-ai.result-decision.v1",
    "settlement-intent": "trnm.poco-ai.settlement-intent.v1",
    "settlement-receipt": "trnm.poco-ai.settlement-receipt.v1",
    "vote-signature": "trnm.poco-ai.vote-signature.v1",
    "timeout-signature": "trnm.poco-ai.timeout-signature.v1",
    "order-finality-proof": "trnm.poco-ai.order-finality-proof.v1",
    "application-state-proof": "trnm.poco-ai.application-state-proof.v1",
    "artifact-availability-proof": "trnm.poco-ai.artifact-availability-proof.v1",
    "result-settlement-proof": "trnm.poco-ai.result-settlement-finality-proof.v1",
    "upgrade-plan": "trnm.poco-ai.upgrade-plan.v1",
    "v0-v1-activation": "trnm.poco-ai.v0-v1-activation.v1",
}
EXPECTED_DOMAIN_ORDER = tuple(EXPECTED_DOMAIN_VALUES)

EXPECTED_ERROR_CODES = {
    "ERR_MALFORMED_ENCODING": ("malformed", False),
    "ERR_UNKNOWN_SCHEMA_VERSION": ("malformed", False),
    "ERR_CROSS_VERSION_DOMAIN": ("malformed", False),
    "ERR_TRAILING_BYTES": ("malformed", False),
    "ERR_DUPLICATE_FIELD_OR_SIGNER": ("malformed", False),
    "ERR_LIMIT_EXCEEDED": ("resource", False),
    "ERR_SIGNATURE_INVALID": ("invalid", False),
    "ERR_AUTHORITY_INVALID": ("invalid", False),
    "ERR_CAPABILITY_SCOPE": ("invalid", False),
    "ERR_CAPABILITY_EXPIRED_OR_REVOKED": ("invalid", False),
    "ERR_NONCE_REPLAY_OR_GAP": ("invalid", False),
    "ERR_STALE_VERSION": ("conflict", True),
    "ERR_OPERATION_DISABLED": ("disabled", False),
    "ERR_PROFILE_DISABLED": ("disabled", False),
    "ERR_PROFILE_EXPIRED": ("invalid", False),
    "ERR_PROFILE_EVIDENCE_MISSING": ("unavailable", True),
    "ERR_DA_UNAVAILABLE": ("unavailable", True),
    "ERR_DA_WITHHELD": ("invalid", False),
    "ERR_ORDER_PROOF_INVALID": ("invalid", False),
    "ERR_EXECUTION_NONDETERMINISTIC": ("stop-condition", False),
    "ERR_RESULT_NOT_MATURE": ("conflict", True),
    "ERR_CHALLENGE_CONFLICT": ("conflict", False),
    "ERR_SETTLEMENT_ALREADY_APPLIED": ("replay", False),
    "ERR_SETTLEMENT_INSOLVENT": ("invalid", False),
    "ERR_ASSET_CONSERVATION": ("stop-condition", False),
    "ERR_CHECKPOINT_ROLLBACK": ("stop-condition", False),
    "ERR_STATE_ROOT_DIVERGENCE": ("stop-condition", False),
    "ERR_BACKEND_UNAVAILABLE": ("unavailable", True),
    "ERR_BACKEND_PROTOCOL": ("backend-error", False),
    "ERR_INTERNAL": ("internal", False),
}
EXPECTED_ERROR_ORDER = tuple(EXPECTED_ERROR_CODES)

EXPECTED_LIMIT_NAMES = {
    "max_cev1_nesting",
    "max_cev1_value_bytes",
    "max_transaction_bytes",
    "max_transactions_per_batch",
    "max_batch_refs_per_block",
    "max_protocol_objects_per_block",
    "max_signatures_per_object",
    "max_signature_work_per_transaction",
    "max_evidence_entries_per_challenge",
    "max_artifact_descriptor_bytes",
    "max_artifact_fullrep_bytes",
    "max_capability_depth",
    "max_operation_scopes",
    "max_resource_scopes",
    "max_nonce_lanes_per_agent",
    "max_read_set",
    "max_write_set",
    "max_execution_units_per_transaction",
    "max_light_client_hops_per_bundle",
    "max_state_sync_chunk_bytes",
}
EXPECTED_PROFILE_IDS = {
    "deterministic-reexecution-v1",
    "reproducible-ml-v1",
    "zk-v1",
    "tee-v1",
    "stake-quorum-v1",
    "optimistic-v1",
    "subjective-v1",
}
EXPECTED_PROFILE_ORDER = (
    "deterministic-reexecution-v1",
    "reproducible-ml-v1",
    "zk-v1",
    "tee-v1",
    "stake-quorum-v1",
    "optimistic-v1",
    "subjective-v1",
)
EXPECTED_PROFILE_STATES = {"design-only", "candidate-local"}
PROFILE_SHAPES = {
    "deterministic-reexecution-v1": ("objective", "design-only", ("runtime_digest", "input_commitment", "output_commitment", "execution_trace")),
    "reproducible-ml-v1": ("objective-with-tolerance-contract", "design-only", ("model_digest", "data_digest", "tokenizer_digest", "runtime_digest", "seed", "numeric_policy")),
    "zk-v1": ("objective-cryptographic", "design-only", ("proof", "public_statement", "verification_key_digest", "setup_or_image_digest")),
    "tee-v1": ("hardware-attested", "design-only", ("quote_or_report", "measurement", "tcb_status", "freshness", "revocation_state")),
    "stake-quorum-v1": ("economic-attestation", "candidate-local", ("statement_digest", "evidence_root", "unique_weighted_claims", "verifier_set_hash")),
    "optimistic-v1": ("objective-if-fraud-proof-complete", "design-only", ("bonded_assertion", "fraud_proof_vm", "challenge_window")),
    "subjective-v1": ("subjective", "design-only", ("declared_evaluator_policy", "audit_trail")),
}


class RegistryError(ValueError):
    """A malformed registry or independent semantic mismatch."""


def fail(message: str) -> NoReturn:
    raise RegistryError(message)


def _label(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str:
            fail("JSON object key is not a string")
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON constant is forbidden: {value}")


def reject_nonfinite_number(token: str) -> float:
    try:
        value = float(token)
    except ValueError:
        fail(f"invalid JSON number: {token}")
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def _skip_json_ws(text: str, index: int) -> int:
    while index < len(text) and text[index] in JSON_WS:
        index += 1
    return index


def strict_json_bytes(raw: bytes, label: str = "JSON") -> Any:
    """Decode one UTF-8 JSON value, rejecting duplicate/non-finite/trailing data."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"{label} is not valid UTF-8: {error}")
    decoder = json.JSONDecoder(
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_constant,
        parse_float=reject_nonfinite_number,
    )
    start = _skip_json_ws(text, 0)
    if start == len(text):
        fail(f"{label} is empty")
    try:
        value, end = decoder.raw_decode(text, start)
    except RegistryError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        fail(f"invalid JSON in {label}: {error}")
    end = _skip_json_ws(text, end)
    if end != len(text):
        fail(f"trailing JSON data in {label}")
    return value


def strict_json_file(path: Path, root: Path) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {_label(path, root)}: {error}")
    return strict_json_bytes(raw, _label(path, root)), raw


def strict_toml_file(path: Path, root: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as error:
        fail(f"invalid TOML in {_label(path, root)}: {error}")
    if not isinstance(value, dict):
        fail(f"{_label(path, root)} must contain a TOML table")
    return value, raw


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def exact_int(value: Any, label: str) -> int:
    # bool is an int subclass; exact type is intentional.
    if type(value) is not int:
        fail(f"{label} must be an integer (bool is not accepted as integer)")
    return value


def exact_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        fail(f"{label} must be a non-empty string")
    if any(ord(char) < 0x20 for char in value):
        fail(f"{label} contains a control character")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        fail(f"{label} contains an unpaired surrogate")
    return value


def exact_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def expect_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys differ: missing={sorted(expected - actual)!r} unknown={sorted(actual - expected)!r}")


def expect_status(value: dict[str, Any], label: str) -> None:
    if exact_string(value.get("status"), f"{label}.status") != REGISTRY_STATUS:
        fail(f"{label}.status must be {REGISTRY_STATUS!r}")


def exact_slug(value: Any, label: str) -> str:
    text = exact_string(value, label)
    if not text.isascii() or SLUG_RE.fullmatch(text) is None:
        fail(f"{label} is not a canonical ASCII slug")
    return text


def exact_code(value: Any, label: str) -> str:
    text = exact_string(value, label)
    if not text.isascii() or CODE_RE.fullmatch(text) is None:
        fail(f"{label} is not a canonical error code")
    return text


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        fail(f"cannot produce canonical JSON bytes: {error}")


def evidence_id_preimage(evidence: dict[str, Any]) -> dict[str, Any]:
    """Project an envelope onto stable, content-addressed identity fields.

    Branch names, dirty-path diagnostics, checkout paths, and checker paths are
    useful evidence metadata but are deliberately excluded: the same exact
    source and inputs must replay to the same ID in another worktree.  The
    source commit/tree, exact A08 tuple, checker content/result digests, all
    registry/corpus/plan digests, negative outcomes, corpus minimum/ordered IDs,
    and candidate flags remain bound.  This projection is also what prevents
    ``evidence_id`` self-reference.
    """

    source = exact_dict(evidence.get("source"), "evidence.source")
    upstream = exact_dict(evidence.get("upstream"), "evidence.upstream")
    checker = exact_dict(upstream.get("a08_checker"), "evidence.upstream.a08_checker")
    checker_binding = {
        key: checker[key]
        for key in ("status", "returncode", "script_sha256", "stdout_sha256", "stderr_sha256")
        if key in checker
    }
    stable_fields = (
        "schema",
        "agent_id",
        "package_id",
        "gate_id",
        "plan_id",
        "plan_sha256",
        "status",
        "classification",
        "scope",
        "evidence_scope",
        "data_scope",
        "authority",
        "inputs",
        "negative_cases",
        "negative_case_count",
        "negative_case_minimum",
        "negative_case_ids",
        "negative_controls",
        "negative_control_count",
        "global_cev1_conformance_complete",
        "normative_freeze",
        "node_support",
        "production_candidate",
        "known_gaps",
        "evidence_id_algorithm",
    )
    missing = [key for key in stable_fields if key not in evidence]
    if missing:
        fail(f"evidence ID preimage is missing fields: {missing!r}")
    projected = {key: evidence[key] for key in stable_fields}
    projected["source"] = {"commit": source.get("commit"), "tree": source.get("tree")}
    projected["upstream"] = {
        "agent_id": upstream.get("agent_id"),
        "registry_source": upstream.get("registry_source"),
        "a08_checker": checker_binding,
    }
    return projected


def derive_evidence_id(evidence: dict[str, Any]) -> str:
    """Derive a stable ID from the canonical stable-field projection."""

    digest = sha256_bytes(canonical_bytes(evidence_id_preimage(evidence)))
    return f"{EVIDENCE_ID_PREFIX}{digest[:EVIDENCE_ID_HEX_LENGTH]}"


def validate_evidence_id(evidence: dict[str, Any]) -> str:
    """Recompute and verify the deterministic ID in an evidence envelope."""

    supplied = evidence.get("evidence_id")
    if not isinstance(supplied, str) or re.fullmatch(
        rf"{re.escape(EVIDENCE_ID_PREFIX)}[0-9a-f]{{{EVIDENCE_ID_HEX_LENGTH}}}", supplied
    ) is None:
        fail("evidence_id has a non-canonical format")
    expected = derive_evidence_id(evidence)
    if supplied != expected:
        fail(f"evidence_id mismatch: expected {expected}, found {supplied}")
    return supplied


def check_catalog(document: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    label = _label(root / CATALOG_REL, root)
    expect_keys(document, {"schema_version", "catalog_id", "protocol_id", "protocol_major", "status", "normative", "implemented", "activation", "objects"}, label)
    if exact_int(document["schema_version"], f"{label}.schema_version") != 1:
        fail(f"{label}.schema_version must be 1")
    if exact_string(document["catalog_id"], f"{label}.catalog_id") != "trnm-poco-ai-native-v1-object-catalog-v1":
        fail(f"{label}.catalog_id mismatch")
    if exact_string(document["protocol_id"], f"{label}.protocol_id") != "trnm-poco-ai-native-v1":
        fail(f"{label}.protocol_id mismatch")
    if exact_int(document["protocol_major"], f"{label}.protocol_major") != 1:
        fail(f"{label}.protocol_major must be 1")
    if exact_string(document["status"], f"{label}.status") != CATALOG_STATUS:
        fail(f"{label}.status must be {CATALOG_STATUS!r}")
    for key in ("normative", "implemented", "activation"):
        if exact_bool(document[key], f"{label}.{key}") is not False:
            fail(f"{label}.{key} must remain false")
    objects = exact_list(document["objects"], f"{label}.objects")
    if len(objects) != len(EXPECTED_OBJECTS):
        fail(f"catalog object count drift: expected {len(EXPECTED_OBJECTS)}, found {len(objects)}")
    projection: list[dict[str, Any]] = []
    for index, raw_item in enumerate(objects):
        item_label = f"{label}.objects[{index}]"
        item = exact_dict(raw_item, item_label)
        expect_keys(item, {"id", "plane", "status", "implemented", "wire_schema_assigned", "activation"}, item_label)
        object_id = exact_string(item["id"], f"{item_label}.id")
        if OBJECT_ID_RE.fullmatch(object_id) is None:
            fail(f"{item_label}.id is not a canonical v1 identifier")
        expected_id, expected_plane = EXPECTED_OBJECTS[index]
        if object_id != expected_id:
            fail(f"catalog object order/id drift at index {index}: expected {expected_id}, found {object_id}")
        plane = exact_string(item["plane"], f"{item_label}.plane")
        if plane not in PLANES or plane != expected_plane:
            fail(f"catalog plane drift for {object_id}: expected {expected_plane!r}, found {plane!r}")
        if exact_string(item["status"], f"{item_label}.status") != "design-only":
            fail(f"{item_label}.status must remain design-only")
        if exact_bool(item["implemented"], f"{item_label}.implemented") is not False:
            fail(f"{item_label}.implemented must remain false")
        if exact_bool(item["wire_schema_assigned"], f"{item_label}.wire_schema_assigned") is not (object_id == "GlobalExecutionBindingV1"):
            fail(f"{item_label}.wire_schema_assigned drift")
        if exact_bool(item["activation"], f"{item_label}.activation") is not False:
            fail(f"{item_label}.activation must remain false")
        projection.append(item)
    return projection


def check_operation_registry(document: dict[str, Any]) -> None:
    label = "operation-registry-v1.json"
    expect_keys(document, {"schema", "status", "protocol_version", "slot_count", "global_activation", "operations"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-operation-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_int(document["protocol_version"], f"{label}.protocol_version") != 1:
        fail(f"{label}.protocol_version must be 1")
    if exact_int(document["slot_count"], f"{label}.slot_count") != len(EXPECTED_OPERATION_ROWS):
        fail(f"{label}.slot_count must be {len(EXPECTED_OPERATION_ROWS)}")
    if exact_bool(document["global_activation"], f"{label}.global_activation") is not False:
        fail(f"{label}.global_activation must remain false")
    rows = exact_list(document["operations"], f"{label}.operations")
    if len(rows) != len(EXPECTED_OPERATION_ROWS):
        fail(f"operation registry must contain exactly {len(EXPECTED_OPERATION_ROWS)} slots")
    seen_names: set[str] = set()
    for index, raw_row in enumerate(rows):
        row_label = f"{label}.operations[{index}]"
        row = exact_dict(raw_row, row_label)
        expected = EXPECTED_OPERATION_ROWS[index]
        allowed = {"kind", "name", "body_type", "plane", "status", "enabled", "authority", "nonce_lane"}
        if expected[-1] is not None:
            allowed.add("canonical_error")
        expect_keys(row, allowed, row_label)
        kind = exact_int(row["kind"], f"{row_label}.kind")
        name = exact_string(row["name"], f"{row_label}.name")
        body_type = exact_string(row["body_type"], f"{row_label}.body_type")
        plane = exact_string(row["plane"], f"{row_label}.plane")
        status = exact_string(row["status"], f"{row_label}.status")
        enabled = exact_bool(row["enabled"], f"{row_label}.enabled")
        authority = exact_slug(row["authority"], f"{row_label}.authority")
        nonce_lane = exact_slug(row["nonce_lane"], f"{row_label}.nonce_lane")
        if kind != index or kind != expected[0]:
            fail(f"operation kind {kind!r} is not canonical slot {index}")
        if not name.isascii() or re.fullmatch(r"[A-Z][A-Za-z0-9]*", name) is None:
            fail(f"{row_label}.name is not canonical")
        if not body_type.isascii() or BODY_TYPE_RE.fullmatch(body_type) is None:
            fail(f"{row_label}.body_type is not canonical")
        if plane not in OPERATION_PLANES:
            fail(f"{row_label}.plane is unknown: {plane!r}")
        if status not in {"candidate-assigned", "disabled"}:
            fail(f"{row_label}.status is unknown: {status!r}")
        expected_status = expected[4]
        if status != expected_status:
            fail(f"{row_label}.status must be {expected_status!r}")
        if expected[-1] is None and "canonical_error" in row:
            fail(f"{row_label} may not carry canonical_error")
        if expected[-1] is not None and row.get("canonical_error") != expected[-1]:
            fail(f"{row_label} must carry canonical error {expected[-1]!r}")
        if enabled is not False:
            fail(f"{row_label}.enabled must remain false")
        if name in seen_names:
            fail(f"duplicate operation name: {name}")
        seen_names.add(name)
        canonical_error = row.get("canonical_error")
        actual = (kind, name, body_type, plane, status, enabled, authority, nonce_lane, canonical_error)
        if actual != expected:
            fail(f"operation canonical mapping drift at kind {index}: expected {expected!r}, found {actual!r}")


def check_object_registry(document: dict[str, Any], catalog_objects: list[dict[str, Any]]) -> None:
    label = "object-registry-v1.json"
    expect_keys(document, {"schema", "status", "catalog_source", "global_activation", "objects"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-object-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_string(document["catalog_source"], f"{label}.catalog_source") != str(CATALOG_REL):
        fail(f"{label}.catalog_source mismatch")
    if exact_bool(document["global_activation"], f"{label}.global_activation") is not False:
        fail(f"{label}.global_activation must remain false")
    rows = exact_list(document["objects"], f"{label}.objects")
    if len(rows) != len(EXPECTED_OBJECTS) or len(rows) != len(catalog_objects):
        fail(f"object registry/catalog count mismatch: registry={len(rows)} catalog={len(catalog_objects)}")
    seen: set[str] = set()
    for index, raw_item in enumerate(rows):
        row_label = f"{label}.objects[{index}]"
        item = exact_dict(raw_item, row_label)
        expect_keys(item, {"id", "plane", "authority", "wire"}, row_label)
        object_id = exact_string(item["id"], f"{row_label}.id")
        plane = exact_string(item["plane"], f"{row_label}.plane")
        authority = exact_slug(item["authority"], f"{row_label}.authority")
        if authority not in OBJECT_AUTHORITIES:
            fail(f"{row_label}.authority is unknown: {authority!r}")
        wire = exact_string(item["wire"], f"{row_label}.wire")
        if object_id in seen:
            fail(f"duplicate object registry id: {object_id}")
        seen.add(object_id)
        expected_id, expected_plane = EXPECTED_OBJECTS[index]
        if object_id != expected_id:
            fail(f"object registry/catalog id mismatch at index {index}: expected {expected_id}, found {object_id}")
        if plane != expected_plane or plane != catalog_objects[index]["plane"]:
            fail(f"object registry/catalog plane mismatch for {object_id}: expected {expected_plane!r}, found {plane!r}")
        if wire not in WIRE_STATES:
            fail(f"{row_label}.wire is not an allowed candidate state: {wire!r}")
    if tuple(item["id"] for item in rows) != tuple(item[0] for item in EXPECTED_OBJECTS):
        fail("object registry IDs are not canonical catalog order")


def check_domain_registry(document: dict[str, Any]) -> None:
    label = "domain-registry-v1.json"
    expect_keys(document, {"schema", "status", "domains"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-domain-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    rows = exact_list(document["domains"], f"{label}.domains")
    if len(rows) != len(EXPECTED_DOMAIN_VALUES):
        fail(f"{label}.domains count drift: expected {len(EXPECTED_DOMAIN_VALUES)}, found {len(rows)}")
    ids: set[str] = set()
    ordered_ids: list[str] = []
    values: set[str] = set()
    for index, raw_item in enumerate(rows):
        row_label = f"{label}.domains[{index}]"
        item = exact_dict(raw_item, row_label)
        expect_keys(item, {"id", "value", "meaning"}, row_label)
        domain_id = exact_slug(item["id"], f"{row_label}.id")
        value = exact_string(item["value"], f"{row_label}.value")
        meaning = exact_string(item["meaning"], f"{row_label}.meaning")
        if domain_id in ids:
            fail(f"duplicate domain id: {domain_id}")
        if value in values:
            fail(f"duplicate domain value: {value}")
        ids.add(domain_id)
        ordered_ids.append(domain_id)
        values.add(value)
        if domain_id not in EXPECTED_DOMAIN_VALUES:
            fail(f"unknown domain id: {domain_id}")
        if value != EXPECTED_DOMAIN_VALUES[domain_id]:
            fail(f"domain value drift for {domain_id}: expected {EXPECTED_DOMAIN_VALUES[domain_id]!r}, found {value!r}")
        if not value.isascii() or not value.startswith("trnm.poco-ai.") or not value.endswith(".v1"):
            fail(f"{row_label}.value is not canonical ASCII v1 domain")
        if not meaning.strip():
            fail(f"{row_label}.meaning must not be blank")
    if ids != set(EXPECTED_DOMAIN_VALUES):
        fail("domain registry does not contain exactly the canonical domain IDs")
    if tuple(ordered_ids) != EXPECTED_DOMAIN_ORDER:
        fail("domain registry order is not canonical")


def check_error_registry(document: dict[str, Any]) -> None:
    label = "error-registry-v1.json"
    expect_keys(document, {"schema", "status", "errors"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-error-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    rows = exact_list(document["errors"], f"{label}.errors")
    if len(rows) != len(EXPECTED_ERROR_CODES):
        fail(f"{label}.errors count drift: expected {len(EXPECTED_ERROR_CODES)}, found {len(rows)}")
    seen: set[str] = set()
    ordered_codes: list[str] = []
    for index, raw_item in enumerate(rows):
        row_label = f"{label}.errors[{index}]"
        item = exact_dict(raw_item, row_label)
        expect_keys(item, {"code", "class", "retryable"}, row_label)
        code = exact_code(item["code"], f"{row_label}.code")
        klass = exact_string(item["class"], f"{row_label}.class")
        retryable = exact_bool(item["retryable"], f"{row_label}.retryable")
        if code in seen:
            fail(f"duplicate error code: {code}")
        seen.add(code)
        ordered_codes.append(code)
        if code not in EXPECTED_ERROR_CODES:
            fail(f"unknown error code: {code}")
        expected = EXPECTED_ERROR_CODES[code]
        if (klass, retryable) != expected:
            fail(f"error mapping drift for {code}: expected {expected!r}, found {(klass, retryable)!r}")
        if klass not in ERROR_CLASSES:
            fail(f"{row_label}.class is unknown: {klass!r}")
    if seen != set(EXPECTED_ERROR_CODES):
        fail("error registry does not contain exactly the canonical error codes")
    if tuple(ordered_codes) != EXPECTED_ERROR_ORDER:
        fail("error registry order is not canonical")


def check_limit_registry(document: dict[str, Any]) -> None:
    label = "limit-registry-v1.json"
    expect_keys(document, {"schema", "status", "units", "limits", "note"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-limit-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_string(document["units"], f"{label}.units") != "bytes/items/signature-work/execution-units":
        fail(f"{label}.units mismatch")
    exact_string(document["note"], f"{label}.note")
    limits = exact_dict(document["limits"], f"{label}.limits")
    if set(limits) != EXPECTED_LIMIT_NAMES:
        fail(f"{label}.limits keys drift: expected={sorted(EXPECTED_LIMIT_NAMES)!r} found={sorted(limits)!r}")
    for name, value in limits.items():
        if not isinstance(name, str) or LIMIT_NAME_RE.fullmatch(name) is None:
            fail(f"{label}.limits has a non-canonical name: {name!r}")
        if type(value) is int:
            if value <= 0:
                fail(f"nonpositive limit: {name}")
        elif isinstance(value, str) and DECIMAL_RE.fullmatch(value):
            pass
        else:
            fail(f"limit {name} must be a positive integer or decimal string")


def check_profile_registry(document: dict[str, Any]) -> None:
    label = "verification-profile-registry-v1.json"
    expect_keys(document, {"schema", "status", "fallback_allowed", "profiles"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-verification-profile-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_bool(document["fallback_allowed"], f"{label}.fallback_allowed") is not False:
        fail("verification fallback must remain false")
    rows = exact_list(document["profiles"], f"{label}.profiles")
    if len(rows) != len(EXPECTED_PROFILE_IDS):
        fail(f"{label}.profiles count drift")
    seen: set[str] = set()
    ordered_profiles: list[str] = []
    for index, raw_item in enumerate(rows):
        row_label = f"{label}.profiles[{index}]"
        item = exact_dict(raw_item, row_label)
        required = {"id", "class", "state", "globally_enabled", "required_evidence", "result_authority", "settlement_authority"}
        optional = {"objective_settlement_forbidden", "poco_weight_forbidden"}
        actual_keys = set(item)
        if not required.issubset(actual_keys) or actual_keys - required - optional:
            fail(f"{row_label} has an unexpected or missing field")
        profile_id = exact_slug(item["id"], f"{row_label}.id")
        if profile_id in seen:
            fail(f"duplicate profile id: {profile_id}")
        seen.add(profile_id)
        ordered_profiles.append(profile_id)
        if profile_id not in EXPECTED_PROFILE_IDS:
            fail(f"unknown profile id: {profile_id}")
        profile_class = exact_string(item["class"], f"{row_label}.class")
        state = exact_string(item["state"], f"{row_label}.state")
        if state not in EXPECTED_PROFILE_STATES:
            fail(f"{row_label}.state is unknown: {state!r}")
        expected_class, expected_state, expected_evidence = PROFILE_SHAPES[profile_id]
        if profile_class != expected_class or state != expected_state:
            fail(f"profile shape drift for {profile_id}: expected class/state {(expected_class, expected_state)!r}, found {(profile_class, state)!r}")
        if exact_bool(item["globally_enabled"], f"{row_label}.globally_enabled") is not False:
            fail(f"{row_label}.globally_enabled must remain false")
        evidence = exact_list(item["required_evidence"], f"{row_label}.required_evidence")
        if not evidence:
            fail(f"{row_label}.required_evidence must be non-empty")
        evidence_seen: set[str] = set()
        for evidence_index, evidence_item in enumerate(evidence):
            text = exact_string(evidence_item, f"{row_label}.required_evidence[{evidence_index}]")
            if text in evidence_seen:
                fail(f"{row_label}.required_evidence contains duplicates")
            evidence_seen.add(text)
        if tuple(evidence) != expected_evidence:
            fail(f"profile evidence shape drift for {profile_id}")
        if exact_bool(item["result_authority"], f"{row_label}.result_authority") is not False:
            fail(f"{row_label}.result_authority must remain false")
        if exact_bool(item["settlement_authority"], f"{row_label}.settlement_authority") is not False:
            fail(f"{row_label}.settlement_authority must remain false")
        if profile_id == "subjective-v1":
            for key in optional:
                if exact_bool(item.get(key), f"{row_label}.{key}") is not True:
                    fail(f"subjective authority boundary drift: {key}")
        elif actual_keys & optional:
            fail(f"{row_label} may not carry subjective-only authority fields")
    if seen != EXPECTED_PROFILE_IDS:
        fail("profile registry does not contain exactly the canonical profile IDs")
    if tuple(ordered_profiles) != EXPECTED_PROFILE_ORDER:
        fail("profile registry order is not canonical")


def check_registry(root: Path) -> dict[str, Any]:
    registry_dir = root / REGISTRY_REL
    catalog, catalog_raw = strict_toml_file(root / CATALOG_REL, root)
    catalog_objects = check_catalog(catalog, root)
    documents: dict[str, dict[str, Any]] = {}
    raw_files: dict[str, bytes] = {}
    for name in REGISTRY_FILES:
        value, raw = strict_json_file(registry_dir / name, root)
        if not isinstance(value, dict):
            fail(f"{name} must contain a top-level object")
        documents[name] = value
        raw_files[name] = raw
        expect_status(value, name)
    check_operation_registry(documents["operation-registry-v1.json"])
    check_object_registry(documents["object-registry-v1.json"], catalog_objects)
    check_domain_registry(documents["domain-registry-v1.json"])
    check_error_registry(documents["error-registry-v1.json"])
    check_limit_registry(documents["limit-registry-v1.json"])
    check_profile_registry(documents["verification-profile-registry-v1.json"])
    return {"documents": documents, "raw_files": raw_files, "catalog_raw": catalog_raw}


def validate_operation_fixture(path: Path, root: Path) -> dict[str, str]:
    value, _ = strict_json_file(path, root)
    if not isinstance(value, dict):
        fail("operation mapping fixture must be an object")
    expect_keys(value, {"schema", "status", "upstream_agent", "upstream_commit", "upstream_tree", "operations"}, "operation mapping fixture")
    if exact_string(value["schema"], "operation mapping fixture.schema") != "trnm-independent-cev1-operation-mapping-v1":
        fail("operation mapping fixture schema mismatch")
    if exact_string(value["status"], "operation mapping fixture.status") != REGISTRY_STATUS:
        fail("operation mapping fixture status mismatch")
    if exact_string(value["upstream_agent"], "operation mapping fixture.upstream_agent") != "A08":
        fail("operation mapping fixture upstream agent mismatch")
    pins: dict[str, str] = {}
    for key in ("upstream_commit", "upstream_tree"):
        pin = exact_string(value[key], f"operation mapping fixture.{key}")
        if pin != PENDING_PIN and HEX40_RE.fullmatch(pin) is None:
            fail(f"operation mapping fixture.{key} must be a 40-hex SHA or pending placeholder")
        pins[key] = pin
    rows = exact_list(value["operations"], "operation mapping fixture.operations")
    if len(rows) != len(EXPECTED_OPERATION_ROWS):
        fail("operation mapping fixture slot count mismatch")
    for index, raw_row in enumerate(rows):
        row_label = f"operation mapping fixture.operations[{index}]"
        row = exact_dict(raw_row, row_label)
        expected_keys = {"kind", "name", "body_type", "plane", "status", "enabled", "authority", "nonce_lane"}
        if EXPECTED_OPERATION_ROWS[index][-1] is not None:
            expected_keys.add("canonical_error")
        expect_keys(row, expected_keys, row_label)
        actual = (
            exact_int(row["kind"], f"{row_label}.kind"),
            exact_string(row["name"], f"{row_label}.name"),
            exact_string(row["body_type"], f"{row_label}.body_type"),
            exact_string(row["plane"], f"{row_label}.plane"),
            exact_string(row["status"], f"{row_label}.status"),
            exact_bool(row["enabled"], f"{row_label}.enabled"),
            exact_string(row["authority"], f"{row_label}.authority"),
            exact_string(row["nonce_lane"], f"{row_label}.nonce_lane"),
            row.get("canonical_error"),
        )
        if actual != EXPECTED_OPERATION_ROWS[index]:
            fail(f"operation mapping fixture drift at index {index}")
    return pins


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(["git", *args], cwd=root, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError:
        return None
    # Preserve leading porcelain status bytes (" M"/"??"); stripping them
    # corrupts the first dirty path and therefore the assessed source tuple.
    return result.stdout.rstrip("\r\n") if result.returncode == 0 else None


def git_source_tuple(root: Path) -> dict[str, Any]:
    commit = _git(root, "rev-parse", "--verify", "HEAD")
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")
    branch = _git(root, "symbolic-ref", "--short", "-q", "HEAD") or "(detached)"
    status = _git(root, "status", "--porcelain=v1") or ""
    dirty_paths = [line[3:] for line in status.splitlines() if len(line) >= 4]
    return {
        "commit": commit if commit and HEX40_RE.fullmatch(commit) else None,
        "tree": tree if tree and HEX40_RE.fullmatch(tree) else None,
        "branch": branch,
        "dirty": bool(dirty_paths),
        "dirty_paths": dirty_paths,
    }


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_hash_record(path: Path, root: Path, *, parsed: Any | None = None, raw: bytes | None = None, parse_json: bool = True) -> dict[str, Any]:
    if raw is None:
        try:
            raw = path.read_bytes()
        except OSError as error:
            fail(f"cannot hash {_label(path, root)}: {error}")
    if parsed is None and parse_json:
        parsed = strict_json_bytes(raw, _label(path, root))
    record = {"path": _label(path, root), "bytes": len(raw), "raw_sha256": sha256_bytes(raw)}
    if parsed is not None:
        record["canonical_sha256"] = sha256_bytes(canonical_bytes(parsed))
    return record


def run_a08_checker(root: Path, checker: Path) -> dict[str, Any]:
    if not checker.is_file():
        fail(f"A08 checker is missing: {checker}")
    try:
        result = subprocess.run([sys.executable, str(checker), "--root", str(root)], cwd=root, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as error:
        fail(f"cannot execute A08 checker: {error}")
    stdout = result.stdout.encode("utf-8", errors="replace")
    stderr = result.stderr.encode("utf-8", errors="replace")
    record = {"path": _label(checker, root), "returncode": result.returncode, "script_sha256": sha256_bytes(checker.read_bytes()), "stdout_sha256": sha256_bytes(stdout), "stderr_sha256": sha256_bytes(stderr)}
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip().replace("\n", " ")
        fail(f"A08 checker rejected candidate: {detail[:400]}")
    return record


def verify_upstream_pin(root: Path, commit: str, tree: str) -> dict[str, Any]:
    if commit == PENDING_PIN or tree == PENDING_PIN:
        return {"status": "pending", "commit": commit, "tree": tree, "verified": False}
    if HEX40_RE.fullmatch(commit) is None or HEX40_RE.fullmatch(tree) is None:
        fail("A08 source pin must contain 40-hex commit/tree values or placeholders")
    observed_tree = _git(root, "rev-parse", f"{commit}^{{tree}}")
    if observed_tree != tree:
        fail(f"A08 source tree mismatch: expected {tree}, observed {observed_tree}")
    missing: list[str] = []
    for relative in (CATALOG_REL, *[REGISTRY_REL / name for name in REGISTRY_FILES]):
        pinned_blob = _git(root, "rev-parse", f"{commit}:{relative}")
        if not pinned_blob:
            missing.append(str(relative))
            continue
        current_blob = _git(root, "hash-object", str(root / relative))
        if current_blob != pinned_blob:
            fail(f"A08 source input drift at {relative}: expected blob {pinned_blob}, found {current_blob}")
    if missing:
        fail(f"A08 source pin is missing required inputs: {missing!r}")
    return {"status": "verified", "commit": commit, "tree": tree, "verified": True}


def _replace_once(raw: bytes, old: bytes, new: bytes, label: str) -> bytes:
    if old not in raw:
        fail(f"mutation anchor missing for {label}")
    return raw.replace(old, new, 1)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def mutate_json_sandbox(sandbox: Path, case: dict[str, Any]) -> None:
    target = case["target"]
    mutation = case["mutation"]
    path = sandbox / REGISTRY_REL / target
    if target == "operation-mapping-v1.json":
        path = sandbox / OPERATION_MAP_REL
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read mutant target {target}: {error}")
    if mutation == "duplicate_top_level_key":
        path.write_bytes(_replace_once(raw, b'"schema":', b'"schema":"mutant","schema":', mutation))
        return
    if mutation == "duplicate_nested_key":
        path.write_bytes(_replace_once(raw, b'"kind":0,"name":', b'"kind":0,"name":"mutant","name":', mutation))
        return
    if mutation == "trailing_json":
        path.write_bytes(raw + b'\n{"trailing":true}\n')
        return
    if mutation == "nonfinite_number":
        if b'"slot_count": 30' in raw:
            path.write_bytes(_replace_once(raw, b'"slot_count": 30', b'"slot_count":NaN', mutation))
        else:
            path.write_bytes(_replace_once(raw, b'"slot_count":30', b'"slot_count":NaN', mutation))
        return
    if mutation == "nonfinite_exponent":
        if b'"slot_count": 30' in raw:
            path.write_bytes(_replace_once(raw, b'"slot_count": 30', b'"slot_count":1e999', mutation))
        else:
            path.write_bytes(_replace_once(raw, b'"slot_count":30', b'"slot_count":1e999', mutation))
        return
    value = strict_json_bytes(raw, target)
    if not isinstance(value, dict):
        fail(f"mutant target {target} is not an object")
    if mutation == "unknown_top_level_field":
        value["unknown_field"] = 1
    elif mutation == "unknown_nested_field":
        if target == "operation-registry-v1.json":
            value["operations"][0]["unknown_field"] = "x"
        elif target == "object-registry-v1.json":
            value["objects"][0]["unknown_field"] = "x"
        elif target == "domain-registry-v1.json":
            value["domains"][0]["unknown_field"] = "x"
        elif target == "error-registry-v1.json":
            value["errors"][0]["unknown_field"] = "x"
        elif target == "verification-profile-registry-v1.json":
            value["profiles"][0]["unknown_field"] = "x"
        else:
            value["limits"]["unknown_field"] = 1
    elif mutation == "wrong_container_type":
        if target == "operation-registry-v1.json":
            value["operations"] = {}
        elif target == "object-registry-v1.json":
            value["objects"] = {}
        elif target == "domain-registry-v1.json":
            value["domains"] = {}
        elif target == "error-registry-v1.json":
            value["errors"] = {}
        elif target == "verification-profile-registry-v1.json":
            value["profiles"] = {}
        else:
            value["limits"] = []
    elif mutation == "wrong_scalar_type":
        if target == "operation-registry-v1.json":
            value["global_activation"] = 0
        elif target == "object-registry-v1.json":
            value["global_activation"] = 0
        elif target == "domain-registry-v1.json":
            value["status"] = False
        elif target == "error-registry-v1.json":
            value["status"] = False
        elif target == "verification-profile-registry-v1.json":
            value["fallback_allowed"] = 0
        else:
            value["units"] = False
    elif mutation == "bool_as_int":
        if target == "operation-registry-v1.json":
            value["operations"][0]["kind"] = True
        elif target == "limit-registry-v1.json":
            value["limits"]["max_cev1_nesting"] = True
        else:
            value["protocol_version"] = True
    elif mutation == "operation_kind_out_of_range":
        value["operations"][0]["kind"] = 30
    elif mutation == "operation_body_type_drift":
        value["operations"][0]["body_type"] = "DifferentBodyV1"
    elif mutation == "operation_name_drift":
        value["operations"][0]["name"] = "DifferentOperation"
    elif mutation == "operation_plane_drift":
        value["operations"][0]["plane"] = "execution"
    elif mutation == "operation_authority_drift":
        value["operations"][0]["authority"] = "different-owner"
    elif mutation == "operation_nonce_drift":
        value["operations"][0]["nonce_lane"] = "different-lane"
    elif mutation == "operation_status_drift":
        value["operations"][0]["status"] = "enabled"
    elif mutation == "operation_enable":
        value["operations"][0]["enabled"] = True
    elif mutation == "operation_sentinel_error_drift":
        # The corrected map reserves disabled profile slots 20 and 27; kind 29
        # is a candidate EconomicObject row.  Mutate the first disabled slot.
        value["operations"][20]["canonical_error"] = "ERR_INTERNAL"
    elif mutation == "operation_kind27_disabled_drift":
        value["operations"][27]["status"] = "candidate-assigned"
    elif mutation == "operation_kind29_mapping_drift":
        value["operations"][29]["name"] = "EconomicObjectDrift"
    elif mutation == "object_id_drift":
        value["objects"][0]["id"] = "UnexpectedObjectV1"
    elif mutation == "object_plane_drift":
        value["objects"][0]["plane"] = "compute-verify"
    elif mutation == "object_wire_drift":
        value["objects"][0]["wire"] = "active"
    elif mutation == "domain_value_drift":
        value["domains"][0]["value"] = "trnm.poco-ai.other.v1"
    elif mutation == "domain_duplicate_id":
        value["domains"][1]["id"] = value["domains"][0]["id"]
    elif mutation == "error_class_drift":
        value["errors"][0]["class"] = "invalid"
    elif mutation == "error_retryable_type":
        value["errors"][0]["retryable"] = 0
    elif mutation == "limit_zero":
        value["limits"]["max_cev1_nesting"] = 0
    elif mutation == "limit_float":
        value["limits"]["max_cev1_nesting"] = 1.5
    elif mutation == "limit_unknown_name":
        value["limits"]["unknown_limit"] = 1
    elif mutation == "profile_fallback_enable":
        value["fallback_allowed"] = True
    elif mutation == "profile_unknown_field":
        value["profiles"][0]["unknown_field"] = "x"
    elif mutation == "profile_evidence_duplicate":
        evidence = value["profiles"][0]["required_evidence"]
        evidence.append(evidence[0])
    elif mutation == "profile_authority_type":
        value["profiles"][0]["result_authority"] = 0
    else:
        fail(f"unknown JSON mutation recipe: {mutation}")
    _write_json(path, value)


def mutate_catalog(sandbox: Path, mutation: str) -> None:
    path = sandbox / CATALOG_REL
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read catalog mutant target: {error}")
    if mutation == "catalog_unknown_field":
        path.write_bytes(raw + b"unknown_catalog_field = true\n")
    elif mutation == "catalog_id_drift":
        path.write_bytes(_replace_once(raw, b'id = "AgentIdentityV1"', b'id = "DifferentObjectV1"', mutation))
    elif mutation == "catalog_bool_as_int":
        path.write_bytes(_replace_once(raw, b"protocol_major = 1", b"protocol_major = true", mutation))
    else:
        fail(f"unknown catalog mutation recipe: {mutation}")


def load_negative_cases(path: Path, root: Path) -> list[dict[str, Any]]:
    value, _ = strict_json_file(path, root)
    if not isinstance(value, dict):
        fail("negative corpus must be an object")
    expect_keys(value, {"schema", "status", "cases"}, "negative corpus")
    if exact_string(value["schema"], "negative corpus.schema") != "trnm-independent-cev1-registry-negative-cases-v2":
        fail("negative corpus schema mismatch")
    if exact_string(value["status"], "negative corpus.status") != REGISTRY_STATUS:
        fail("negative corpus status mismatch")
    cases = exact_list(value["cases"], "negative corpus.cases")
    if not cases:
        fail("negative corpus must not be empty")
    if len(cases) < MIN_NEGATIVE_CASE_COUNT:
        fail(
            "negative corpus must retain at least "
            f"{MIN_NEGATIVE_CASE_COUNT} cases; found {len(cases)}"
        )
    output: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    allowed_targets = set(REGISTRY_FILES) | {"object-catalog-v1.toml", "operation-mapping-v1.json"}
    for index, raw_item in enumerate(cases):
        label = f"negative corpus.cases[{index}]"
        item = exact_dict(raw_item, label)
        expect_keys(item, {"id", "target", "mutation", "expected"}, label)
        case_id = exact_slug(item["id"], f"{label}.id")
        target = exact_string(item["target"], f"{label}.target")
        mutation = exact_string(item["mutation"], f"{label}.mutation")
        if not mutation.isascii() or re.fullmatch(r"[a-z][a-z0-9_-]*", mutation) is None:
            fail(f"{label}.mutation is not a canonical mutation identifier")
        expected = exact_string(item["expected"], f"{label}.expected")
        if case_id in seen_ids:
            fail(f"duplicate negative case id: {case_id}")
        if target not in allowed_targets:
            fail(f"negative case target is not allowed: {target}")
        seen_ids.add(case_id)
        output.append({"id": case_id, "target": target, "mutation": mutation, "expected": expected})
    by_id = {item["id"]: item for item in output}
    for required_id, (required_target, required_mutation) in REQUIRED_NEGATIVE_CASES.items():
        required = by_id.get(required_id)
        if required is None:
            fail(f"negative corpus is missing required retained mutant: {required_id}")
        if required["target"] != required_target or required["mutation"] != required_mutation:
            fail(
                f"negative corpus retained mutant {required_id} drifted: "
                f"expected {(required_target, required_mutation)!r}, "
                f"found {(required['target'], required['mutation'])!r}"
            )
    return output


def _copy_inputs(source_root: Path, sandbox: Path, mapping_path: Path, corpus_path: Path) -> None:
    registry = sandbox / REGISTRY_REL
    registry.mkdir(parents=True, exist_ok=True)
    for name in REGISTRY_FILES:
        (registry / name).write_bytes((source_root / REGISTRY_REL / name).read_bytes())
    catalog = sandbox / CATALOG_REL
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_bytes((source_root / CATALOG_REL).read_bytes())
    mapping = sandbox / OPERATION_MAP_REL
    mapping.parent.mkdir(parents=True, exist_ok=True)
    mapping.write_bytes(mapping_path.read_bytes())
    corpus = sandbox / NEGATIVE_CORPUS_REL
    corpus.parent.mkdir(parents=True, exist_ok=True)
    corpus.write_bytes(corpus_path.read_bytes())


def run_negative_cases(root: Path, corpus_path: Path, mapping_path: Path) -> list[dict[str, Any]]:
    cases = load_negative_cases(corpus_path, root)
    check_registry(root)
    validate_operation_fixture(mapping_path, root)
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="trnm-independent-cev1-") as temporary:
        sandbox = Path(temporary)
        for case in cases:
            _copy_inputs(root, sandbox, mapping_path, corpus_path)
            if case["target"] == "object-catalog-v1.toml":
                mutate_catalog(sandbox, case["mutation"])
            else:
                mutate_json_sandbox(sandbox, case)
            try:
                validate_operation_fixture(sandbox / OPERATION_MAP_REL, sandbox)
                check_registry(sandbox)
            except RegistryError as error:
                message = str(error)
                if case["expected"] not in message:
                    fail(f"{case['id']} rejected with wrong reason: expected {case['expected']!r}, got {message!r}")
                results.append({"id": case["id"], "target": case["target"], "mutation": case["mutation"], "result": "rejected", "error": message})
            else:
                fail(f"mutant unexpectedly accepted: {case['id']}")
    return results


def build_evidence(root: Path, registry_data: dict[str, Any], mapping_path: Path, corpus_path: Path, a08_result: dict[str, Any] | None, upstream_pin: dict[str, Any], negative_results: list[dict[str, Any]]) -> dict[str, Any]:
    if len(negative_results) < MIN_NEGATIVE_CASE_COUNT:
        fail(
            "retained negative result count is below the independent corpus "
            f"minimum {MIN_NEGATIVE_CASE_COUNT}: {len(negative_results)}"
        )
    source = git_source_tuple(root)
    registry_hashes = [file_hash_record(root / REGISTRY_REL / name, root, parsed=registry_data["documents"][name], raw=registry_data["raw_files"][name]) for name in REGISTRY_FILES]
    catalog_raw = registry_data["catalog_raw"]
    catalog_hash = {"path": str(CATALOG_REL), "bytes": len(catalog_raw), "raw_sha256": sha256_bytes(catalog_raw)}
    mapping_value, mapping_raw = strict_json_file(mapping_path, root)
    corpus_value, corpus_raw = strict_json_file(corpus_path, root)
    plan_hash = file_hash_record(root / PLAN_REL, root, parse_json=False) if (root / PLAN_REL).is_file() else None
    status = "MODULE_CLOSED_CANDIDATE" if upstream_pin["verified"] else "BLOCKED_UPSTREAM"
    # Build the complete deterministic preimage first.  Do not add a timestamp
    # or the eventual Git commit: either would make replay IDs unstable or
    # create a self-referential commit/hash cycle.
    evidence = {
        "schema": "trnm-independent-cev1-registry-evidence-v2",
        "agent_id": "A09",
        "package_id": "G15_INDEPENDENT_CONFORMANCE_V1",
        "gate_id": "G1.5",
        "plan_id": "trnm-ai-native-blockchain-development-plan-v1",
        "plan_sha256": plan_hash["raw_sha256"] if plan_hash else None,
        "evidence_id_algorithm": EVIDENCE_ID_ALGORITHM,
        "status": status,
        "classification": "candidate-non-normative",
        "scope": "fixture",
        "evidence_scope": "independent-registry-parser",
        "data_scope": "synthetic-candidate",
        "authority": "candidate",
        "source": source,
        "upstream": {"agent_id": "A08", "registry_source": upstream_pin, "a08_checker": a08_result or {"status": "skipped"}},
        "inputs": {
            "catalog": catalog_hash,
            "registries": registry_hashes,
            "operation_mapping_fixture": {"path": str(OPERATION_MAP_REL), "bytes": len(mapping_raw), "raw_sha256": sha256_bytes(mapping_raw), "canonical_sha256": sha256_bytes(canonical_bytes(mapping_value))},
            "negative_corpus": {"path": str(NEGATIVE_CORPUS_REL), "bytes": len(corpus_raw), "raw_sha256": sha256_bytes(corpus_raw), "canonical_sha256": sha256_bytes(canonical_bytes(corpus_value))},
            "plan": plan_hash,
        },
        "negative_cases": negative_results,
        "negative_case_count": len(negative_results),
        # Keep the contract and the ordered IDs in the stable evidence
        # projection.  The corpus raw/canonical digests above bind the exact
        # recipes; these fields make the promised minimum and dedicated
        # corrected-A08 mutants visible to downstream consumers.
        "negative_case_minimum": MIN_NEGATIVE_CASE_COUNT,
        "negative_case_ids": [item["id"] for item in negative_results],
        "negative_controls": [
            {
                "id": "evidence-id-payload-mutation",
                "target": "evidence-envelope",
                "mutation": "status-byte-change-id-retained",
                "expected": "evidence_id mismatch",
                "result": "rejected",
            }
        ],
        "negative_control_count": 1,
        "global_cev1_conformance_complete": False,
        "normative_freeze": False,
        "node_support": False,
        "production_candidate": False,
        "known_gaps": [
            *( ["A08 semantic-correction source pin is pending"] if not upstream_pin["verified"] else [] ),
            "full CEV1 binary object parser and light-client interoperability remain open",
            "G1 exit and normative review remain prerequisites",
        ],
    }
    evidence["evidence_id"] = derive_evidence_id(evidence)
    tampered = dict(evidence)
    tampered["status"] = "MUTATED"
    try:
        validate_evidence_id(tampered)
    except RegistryError as error:
        if "evidence_id mismatch" not in str(error):
            fail(f"evidence ID mutation rejected for wrong reason: {error}")
    else:
        fail("evidence ID mutation unexpectedly retained its identity")
    # Self-check before returning so callers cannot accidentally emit a
    # mismatched envelope if this payload is changed later.
    validate_evidence_id(evidence)
    return evidence


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_bytes(evidence) + b"\n")
    except OSError as error:
        fail(f"cannot write evidence {path}: {error}")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="candidate repository root")
    parser.add_argument("--evidence-out", type=Path, help="write canonical evidence JSON here")
    parser.add_argument("--a08-checker", type=Path, help="A08 checker path")
    parser.add_argument("--a08-source-commit", default=os.environ.get("A08_SOURCE_COMMIT", PENDING_PIN))
    parser.add_argument("--a08-source-tree", default=os.environ.get("A08_SOURCE_TREE", PENDING_PIN))
    parser.add_argument("--skip-a08-checker", action="store_true", help="local mutation mode; cross-check is recorded as skipped")
    parser.add_argument("--require-a08-pin", action="store_true", help="fail unless exact A08 commit/tree are supplied")
    parser.add_argument("--mutants-only", action="store_true", help="run retained local mutants only")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    mapping_path = root / OPERATION_MAP_REL
    corpus_path = root / NEGATIVE_CORPUS_REL
    checker = (args.a08_checker or (root / A08_CHECKER_REL)).resolve()
    try:
        fixture_pins = validate_operation_fixture(mapping_path, root)
        for argument_name, fixture_key in (("a08_source_commit", "upstream_commit"), ("a08_source_tree", "upstream_tree")):
            argument_value = getattr(args, argument_name)
            fixture_value = fixture_pins[fixture_key]
            if fixture_value == PENDING_PIN and argument_value != PENDING_PIN:
                fail(f"operation mapping fixture {fixture_key} remains pending; refresh it before supplying a pin")
            if fixture_value != PENDING_PIN and argument_value == PENDING_PIN:
                setattr(args, argument_name, fixture_value)
            elif fixture_value != PENDING_PIN and argument_value != PENDING_PIN and argument_value != fixture_value:
                fail(f"A08 {fixture_key} disagrees with operation mapping fixture")
        registry_data = check_registry(root)
        upstream_pin = verify_upstream_pin(root, args.a08_source_commit, args.a08_source_tree)
        if args.require_a08_pin and not upstream_pin["verified"]:
            fail("exact A08 source pin is required but remains pending")
        if args.mutants_only:
            negative_results = run_negative_cases(root, corpus_path, mapping_path)
            print(f"independent CEV1 retained mutants: ok cases={len(negative_results)}")
            return 0
        a08_result = None if args.skip_a08_checker else run_a08_checker(root, checker)
        negative_results = run_negative_cases(root, corpus_path, mapping_path)
        evidence = build_evidence(root, registry_data, mapping_path, corpus_path, a08_result, upstream_pin, negative_results)
        if args.evidence_out:
            write_evidence(args.evidence_out, evidence)
        print(json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except RegistryError as error:
        print(f"independent CEV1 registry: FAIL: {error}", file=sys.stderr)
        return 1
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"independent CEV1 registry: FAIL: malformed input: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
