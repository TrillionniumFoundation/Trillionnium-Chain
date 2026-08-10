//! Exact regular-block comparison and snapshot-owned validation seams.
//!
//! In addition to the inert exact-body cursor, this module contains a test-only
//! owning session that executes canonical transactions sequentially against one
//! authenticated SQLite snapshot plus its own uncommitted delta. A completed
//! session can plan the exact next JMT root on that same open snapshot, finish
//! the snapshot, rebuild native receipt commitments from the retained runtime
//! receipts, and compare all four roots against the retained regular header.
//! A narrow production carrier now consumes the opaque Core-issued validation
//! request, opens the exact positive-height parent retained by that
//! capability, and exact-decodes its complete application/evidence transport
//! under the active set and parameters authenticated from the same open
//! SQLite/JMT snapshot. It also consumes exact non-runtime payloads into the
//! closed PoCO/validator/unsupported family set and promotes only explicitly
//! snapshot-closed failures into the app-private outcome kernel. A production
//! sequential cursor now
//! begins behind the Core request's shared process-local one-shot claim and a
//! schema-v8 durable `(route, full ValidationId)` job reservation, so both cloned
//! replays and independently materialized exact duplicates are suppressed
//! before host or authenticated-state access. The durable row is congruence
//! and evaluation authority only. A narrow owning bridge can atomically persist
//! complete-body state/receipts mismatches as deterministic-invalid artifacts
//! plus callback-pending outbox records; Valid artifacts, JMT application,
//! callback delivery/acknowledgement, and crash takeover remain absent. The
//! production sequential cursor
//! freezes the initialized host signer policy, internal body index, exact
//! outer/inner bytes, strict signer/transaction decode, and derived execution
//! context facts while retaining that open snapshot. A second narrow carrier
//! now consumes one prepared transaction into the real runtime against only
//! the cursor's prior delta and that same snapshot. The cursor advances only
//! after runtime success, native-receipt conversion, and atomic mutation
//! staging all succeed. A complete cursor can now plan its exact next JMT
//! version through that same still-open snapshot and then close it, without
//! applying or persisting the plan. One legacy runtime-only owning comparator
//! rebuilds native receipts, matches all four roots plus strict ordinary
//! commitments, and retains the exact finished plan on either success or
//! mismatch. A consuming single-attempt non-runtime sealer can now bind
//! PoCO/validator family-local
//! writes back to the exact retained owner while preserving the original
//! unsealed attempt and open snapshot. A consuming success-only advance now
//! retains exact prior item provenance, continues the evolving PoCO overlay or
//! staged validator lifecycle, replaces the latest whole-prefix write seal,
//! and moves the internal cursor. A distinct complete-body owner now rebinds
//! that full cursor provenance, merges the final runtime delta, replace-only
//! PoCO prefix or mandatory cutoff refresh, and final or implicit validator
//! singleton, rejects raw-key/hash conflicts, and creates exactly one inert
//! exact-next JMT plan/seal before closing the snapshot. A distinct consuming
//! comparator now rebinds that complete owner, rebuilds exactly one receipt
//! per body item in body order, rederives the final merged writes, verifies the
//! retained plan/seal, and classifies state-before-receipts mismatches only
//! after strict four-root/static commitment validation. App-private `Valid`
//! promotion and plan application/persistence remain absent. A narrow owning
//! bridge can now consume only a complete-body state/receipts mismatch backed
//! by the exact durable reservation into an app-private prepared-invalid
//! capability; this module does not encode or persist the artifact, deliver a
//! callback, or execute Core. Owner-preserving typed failure promotion,
//! a consuming closed-set non-runtime family
//! dispatcher, owner-preserving strict PoCO/validator semantic decoders, and
//! same-snapshot family-state attempts are now present. The family-local seal
//! becomes cursor state only through that private consuming advance; neither
//! value is complete-block JMT or persistence authority and neither can form a
//! receipt, persist, callback, or advance Core.

use crate::{
    auth_tree::{AuthWrite, PlannedAuthUpdate, PlannedAuthUpdateSealV0},
    native_execution::{NativeBlockExecutionV0, NativeTransactionReceiptFactsV0},
    native_validation_artifact::DurableDeterministicInvalidReasonV0,
    store::{
        native_validation_request_fingerprint_v0, ApplicationStore,
        AuthenticatedRuntimeReadFailureV0, AuthenticatedRuntimeReadSnapshotV0,
        AuthenticatedRuntimeReadStageV0, DurableNativeValidationJobV0,
        FailedNativeValidationReservationV0, NativeValidationRequestRecordFailureV0,
        NativeValidationReservationDecisionV0, NativeValidationReservationFactsV0,
        NativeValidationReservationFailureCauseV0, NativeValidationReservationTokenV0,
    },
};
use anyhow::Context;
use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use trnm_consensus_core::{
    ClaimedPayloadValidationRequestV0, DuplicatePayloadValidationRequestV0, Effect, Input,
    PayloadValidationRequest, PayloadValidationResult, PayloadValidationRouteV0, ValidationId,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_application_payload_v0_exact_for_root_binding, decode_double_vote_evidence_v0_exact,
    Block, BlockBodyV0, BlockHeader, BlockId, BlockKind, BlockValidationErrorCode,
    ConsensusParametersV0, StateRoot, ValidatedBlockCommitmentsV0, ValidatorSet,
};
#[cfg(test)]
use trnm_consensus_types::{ChainId, Epoch, GenesisHash, ProtocolVersion};
use trnm_finality_types::SignedCommandEnvelopeV1;
use trnm_node::live::node::AuthorizedSignerV1;
use trnm_node::live::store::{ObjectMutation, StoredObject};
use trnm_protocol::{
    account_key, fee_policy_key, monetary_state_key, task_key, AccountV1, CanonicalCommandV1,
    FeePolicyV1, MonetaryStateV1, TaskV1, ACCOUNT_OBJECT_TYPE_V1, FEE_POLICY_OBJECT_TYPE_V1,
    MONETARY_STATE_OBJECT_TYPE_V1, TASK_OBJECT_TYPE_V1,
};
use trnm_protocol::{CanonicalTxV1, CANONICAL_TX_PAYLOAD_TYPE_V1};
use trnm_runtime::{
    try_execute_v0, validate_authenticated_task_state_v0, ExecutionContext,
    RuntimeExecutionAttemptFailureV0, RuntimeMutation, RuntimeReceipt, StateObject, TryStateViewV0,
};

/// A failure to derive the exact, versioned raw-source fingerprint before any
/// host or authenticated-state read. These cases are local invariants, never
/// source unavailability or a negative result for the target block.
type NativeValidationReservationFingerprintFailureV0 = NativeValidationRequestRecordFailureV0;

/// Derives the durable congruence fingerprint exclusively from one claimed
/// Core request. No caller-supplied header/body/parent, host configuration,
/// cache, SQLite connection, or authenticated state participates.
fn native_validation_reservation_fingerprint_v0(
    request: &ClaimedPayloadValidationRequestV0,
) -> Result<[u8; 32], NativeValidationReservationFingerprintFailureV0> {
    native_validation_request_fingerprint_v0(
        request.route(),
        request.id(),
        request.block(),
        request.parent(),
    )
}

/// Exact body retained after consuming one opaque Core validation capability.
///
/// This capability proves only that the body bytes came from that exact Core
/// request and passed canonical decoding, active-context comparison, strict
/// evidence verification, root recomputation, and the committed size bound.
/// The active set/parameters and lifecycle are recovered from the exact
/// parent snapshot retained by the Core capability. This is still not runtime,
/// terminal-result, vote, finality, or ABCI authority.
#[allow(dead_code)]
struct CoreAuthorizedExactRegularBodyV0 {
    reservation: CoreAuthorizedRegularReservationV0,
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    header: BlockHeader,
    body: BlockBodyV0,
    context: SnapshotAuthenticatedRegularContextV0,
}

/// Durable reservation authority retained by every production body owner.
/// The test-only marker permits isolated lower-layer fixtures without making
/// an optional or caller-constructible production token surface.
enum CoreAuthorizedRegularReservationV0 {
    Durable(NativeValidationReservationTokenV0),
    #[cfg(test)]
    TestOnly,
}

/// Process-local host authority borrowed only from one validated application
/// instance. Its sole production constructor consumes `AppCore`, so callers
/// cannot assemble a parallel store/chain/signer-policy tuple.
pub(super) struct NativeValidationHostV0<'a> {
    store: &'a ApplicationStore,
    chain_id: &'a str,
    authorized_signers: &'a [AuthorizedSignerV1],
}

impl<'a> NativeValidationHostV0<'a> {
    pub(super) fn from_app_core(core: &'a crate::AppCore) -> Option<Self> {
        Some(Self {
            store: core.store.as_ref()?,
            chain_id: &core.config.chain_id,
            authorized_signers: &core.config.authorized_signers,
        })
    }
}

/// Opaque signer-policy material frozen with the exact parent snapshot.
/// Cloning the bounded signer records here does not mint authority: this value
/// remains private, non-Clone, non-serializable, and owned by the open cursor.
struct NativeSignerPolicyBindingV0 {
    commitment: [u8; 32],
    authorized_signers: Vec<AuthorizedSignerV1>,
}

/// Active consensus and lifecycle facts recovered from one exact parent JMT
/// snapshot. Private fields, no derives, no serialization, and no conversion
/// surface keep this as process-local comparison authority only.
struct SnapshotAuthenticatedRegularContextV0 {
    parent_header: BlockHeader,
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    validator_lifecycle: crate::ValidatorLifecycleStateV1,
    signer_policy: NativeSignerPolicyBindingV0,
}

/// The joined carrier owns both the authenticated facts and the still-open
/// SQLite transaction. It cannot be cloned or serialized and must be finished
/// explicitly before any later phase may retain the joined facts.
#[must_use = "an open native validation carrier must finish its exact parent snapshot"]
struct OpenCoreAuthorizedRegularValidationV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    snapshot: AuthenticatedRuntimeReadSnapshotV0,
}

/// Exact Core request retained until parent authentication and body admission
/// either succeed together or close as one owning failure. A naked validation
/// identity, block, or parent cannot recreate this process-local owner.
struct ClaimedCoreIssuedRegularValidationOwnerV0 {
    request: ClaimedPayloadValidationRequestV0,
}

/// Claimed Core request joined to the unique fresh durable reservation. Only
/// this owner may proceed to host binding and an authenticated parent read.
struct CoreIssuedRegularValidationOwnerV0 {
    request: ClaimedPayloadValidationRequestV0,
    reservation: CoreAuthorizedRegularReservationV0,
}

/// An independently issued request joined an already-identical durable row.
/// This is suppression only and can never be converted into the fresh
/// reservation token required by the evaluation path.
#[must_use = "an existing durable Core job must be routed by recovery state"]
struct DurablyExistingCoreIssuedRegularValidationOwnerV0 {
    request: ClaimedPayloadValidationRequestV0,
    existing: Box<DurableNativeValidationJobV0>,
}

enum CoreIssuedRegularValidationReservationCauseV0 {
    FingerprintInvariant(NativeValidationReservationFingerprintFailureV0),
    RequestRecordInvariant(NativeValidationRequestRecordFailureV0),
    Store(Box<FailedNativeValidationReservationV0>),
}

/// Exhaustive outcome facts extracted from one complete pre-comparator failure
/// owner. These copyable facts are classification only: the promotion helpers
/// below always retain the non-cloneable owner that produced them.
pub(super) enum CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
    Unavailable {
        generation: u64,
        kind: CoreAuthorizedRegularPreExecutionUnavailableKindV0,
    },
    DeterministicallyInvalid {
        generation: u64,
        kind: CoreAuthorizedRegularPreExecutionInvalidKindV0,
    },
    Invariant {
        generation: u64,
        stage: CoreAuthorizedRegularPreExecutionInvariantStageV0,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreAuthorizedRegularPreExecutionUnavailableKindV0 {
    BodySource,
    ParentStateMissing,
    ParentStateUnauthenticated,
    Database,
    StorageIo,
    HostResource,
    ReservationCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreAuthorizedRegularPreExecutionInvalidKindV0 {
    BodyEvidence,
    TransactionEncodingOrAuthorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreAuthorizedRegularPreExecutionInvariantStageV0 {
    Open,
    Reservation,
    TransactionDecode,
    PostStatePlan,
}

/// Reservation failed after the volatile Core claim had been won. The exact
/// claimed request stays attached so a private retry cannot splice route,
/// identity, raw source, or parent facts.
#[must_use = "a reservation failure retains the exact claimed Core request"]
struct FailedCoreIssuedRegularValidationReservationV0 {
    owner: ClaimedCoreIssuedRegularValidationOwnerV0,
    cause: CoreIssuedRegularValidationReservationCauseV0,
}

/// Exact Core validation effect after its public wrapper has been checked
/// against the route privately frozen inside the request. This job is the only
/// raw admission input; callers cannot supply a detached route or boolean.
#[must_use = "a Core validation job retains its exact route-bound request"]
struct CoreIssuedRegularValidationJobV0 {
    request: PayloadValidationRequest,
}

/// A public `Effect` wrapper disagreed with the route frozen by Core inside
/// its request. The exact effect is retained for fail-stop diagnostics only;
/// this is neither duplicate suppression nor a block-result taxonomy.
#[must_use = "a Core validation route invariant must be reported, not classified"]
struct CoreRegularValidationEffectRouteInvariantV0 {
    _effect: Effect,
}

impl std::fmt::Debug for CoreRegularValidationEffectRouteInvariantV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreRegularValidationEffectRouteInvariantV0")
            .field("retains_exact_mismatched_effect", &true)
            .finish_non_exhaustive()
    }
}

/// Result of consuming one arbitrary Core effect at the native validation
/// boundary. Non-validation effects are returned intact. A route mismatch is
/// isolated before the request's one-shot claim or any host/state read.
#[must_use = "Core effect intake must preserve a job, invariant, or untouched effect"]
enum CoreRegularValidationEffectIntakeV0 {
    Job(Box<CoreIssuedRegularValidationJobV0>),
    RouteInvariant(Box<CoreRegularValidationEffectRouteInvariantV0>),
    Other(Box<Effect>),
}

/// Suppressed replay of one already-claimed Core request. This retains the
/// exact duplicate capability only so callers cannot confuse suppression with
/// a source, deterministic-invalid, or invariant validation result. This
/// private branch neither reopens validation nor emits a Core callback.
#[must_use = "a duplicate Core request is suppression, not a validation result"]
struct DuplicateCoreIssuedRegularValidationOwnerV0 {
    request: DuplicatePayloadValidationRequestV0,
}

impl std::fmt::Debug for DuplicateCoreIssuedRegularValidationOwnerV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DuplicateCoreIssuedRegularValidationOwnerV0")
            .field("retains_exact_duplicate_request", &true)
            .finish_non_exhaustive()
    }
}

/// Production admission after the complete Core effect wrapper and its
/// request-bound route have already been proved congruent. Exactly one clone
/// can become `Open`; later clones are suppressed before host validation or
/// any SQLite/JMT read begins.
#[must_use = "session admission retains the sole claimed or duplicate request owner"]
enum CoreAuthorizedRegularValidationSessionAdmissionV0 {
    Open(Box<OpenCoreAuthorizedRegularValidationV0>),
    FailedOpen(Box<FailedCoreIssuedRegularValidationOpenV0>),
    FailedReservation(Box<FailedCoreIssuedRegularValidationReservationV0>),
    Duplicate(Box<DuplicateCoreIssuedRegularValidationOwnerV0>),
    DurablyExisting(Box<DurablyExistingCoreIssuedRegularValidationOwnerV0>),
}

impl std::fmt::Debug for CoreAuthorizedRegularValidationSessionAdmissionV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let admission = match self {
            Self::Open(_) => "open",
            Self::FailedOpen(_) => "failed_open",
            Self::FailedReservation(_) => "failed_reservation",
            Self::Duplicate(_) => "duplicate",
            Self::DurablyExisting(_) => "durably_existing",
        };
        formatter
            .debug_struct("CoreAuthorizedRegularValidationSessionAdmissionV0")
            .field("admission", &admission)
            .field("retains_exact_request_owner", &true)
            .finish_non_exhaustive()
    }
}

/// Failed opening of one exact Core request. The complete request remains
/// owned after any opened snapshot has closed; the cause alone is never host,
/// terminal, Core-callback, or ABCI authority.
#[must_use = "an open failure still retains its exact Core-issued owner"]
struct FailedCoreIssuedRegularValidationOpenV0 {
    owner: CoreIssuedRegularValidationOwnerV0,
    cause: OpenCoreAuthorizedRegularValidationFailureV0,
}

impl std::fmt::Debug for FailedCoreIssuedRegularValidationOpenV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreIssuedRegularValidationOpenV0")
            .field("retains_exact_core_request", &true)
            .finish_non_exhaustive()
    }
}

/// Pending open failure binding the only Core request owner, the exact parent
/// snapshot opened for it, and its still-hidden cause. The close function must
/// consume this whole value so no generation A owner can be paired with a
/// snapshot or cause from generation B inside this module.
#[must_use = "a pending open failure must close its bound exact parent snapshot"]
struct PendingCoreIssuedRegularValidationOpenFailureV0 {
    snapshot: AuthenticatedRuntimeReadSnapshotV0,
    owner: CoreIssuedRegularValidationOwnerV0,
    pending_cause: OpenCoreAuthorizedRegularValidationFailureV0,
}

impl std::fmt::Debug for PendingCoreIssuedRegularValidationOpenFailureV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingCoreIssuedRegularValidationOpenFailureV0")
            .field("pending_explicit_snapshot_finish", &true)
            .field("retains_exact_core_request", &true)
            .finish_non_exhaustive()
    }
}

/// Narrow proof that the exact parent snapshot closed cleanly. This is body
/// provenance and parent-configuration authority only, not execution,
/// terminal payload, vote, finality, or ABCI authority.
struct FinishedCoreAuthorizedRegularValidationV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
}

/// Failed close of an otherwise authorized body/configuration carrier. The
/// authorized owner survives the snapshot error; no detached error can be
/// promoted or retried against a different Core generation.
#[must_use = "a validation close failure still retains its exact authorized owner"]
struct ClosedFailedCoreAuthorizedRegularValidationV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    cause: AuthenticatedRuntimeReadFailureV0,
}

impl std::fmt::Debug for ClosedFailedCoreAuthorizedRegularValidationV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedFailedCoreAuthorizedRegularValidationV0")
            .field("retains_exact_authorized_owner", &true)
            .finish_non_exhaustive()
    }
}

/// Sequential production cursor over the exact Core-authorized body. The
/// index is internal and the cursor continues to own the authenticated parent
/// transaction; callers cannot seek, repeat, or splice another body.
#[must_use = "an open transaction cursor still owns its exact parent snapshot"]
struct OpenCoreAuthorizedRegularTransactionCursorV0 {
    open: OpenCoreAuthorizedRegularValidationV0,
    next_transaction_index: u32,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
}

/// Latest whole-prefix PoCO state retained only inside the exact body cursor.
/// The unsealed overlay is the sole continuation source for a later same-block
/// operation; the plan and writes are a replace-only preview of that complete
/// prefix, never independent blocks or persistence authority.
struct CoreAuthorizedRegularPocoPrefixV0 {
    overlay: crate::poco_application::PocoApplicationBlockOverlayV0,
    plan: crate::poco_application::SealedPocoApplicationPlanV0,
    writes: Vec<AuthWrite>,
}

/// Latest staged validator lifecycle and its canonical singleton write. A
/// later transition must schedule from this lifecycle rather than reopening
/// the authenticated parent lifecycle.
struct CoreAuthorizedRegularValidatorPrefixV0 {
    lifecycle: crate::ValidatorLifecycleStateV1,
    write: AuthWrite,
}

/// Runtime context facts derived only from the retained target header and the
/// strictly verified exact envelope. This is not independently reusable
/// runtime authority; only the owning prepared carrier can consume it inside
/// the single attempt function below.
struct ExactRuntimeExecutionContextV0 {
    target_height: u64,
    target_block_id: BlockId,
    validation_timestamp_ms: u64,
    signer_id: String,
    signer_role: String,
    payload_len: usize,
}

/// Private decode result shared by the production owning cursor and legacy
/// test traversal. It is never returned from a production entry point.
struct DecodedCoreAuthorizedRuntimeTransactionV0 {
    index: u32,
    next_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
}

struct DecodedCoreAuthorizedNonRuntimePayloadV0 {
    index: u32,
    next_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    envelope: SignedCommandEnvelopeV1,
    context: ExactRuntimeExecutionContextV0,
}

enum DecodedCoreAuthorizedRegularPayloadV0 {
    Runtime(DecodedCoreAuthorizedRuntimeTransactionV0),
    NonRuntime(DecodedCoreAuthorizedNonRuntimePayloadV0),
}

/// One prepared exact transaction that still owns the cursor and its snapshot.
/// The next tranche must consume this whole value before any cursor advance;
/// there is deliberately no production skip/advance or parts conversion.
#[must_use = "a prepared transaction still owns its exact validation cursor"]
struct PreparedCoreAuthorizedRuntimeTransactionV0 {
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
    index: u32,
    next_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
}

/// Exact non-runtime envelope retained with the same cursor and snapshot for
/// a future family dispatcher. Recognition is not rejection: no classification
/// is emitted and no cursor advance exists until a dispatcher consumes this
/// whole carrier.
#[must_use = "a non-runtime payload still owns its exact validation cursor"]
struct CoreAuthorizedNonRuntimePayloadRoutingV0 {
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
    index: u32,
    next_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    envelope: SignedCommandEnvelopeV1,
    context: ExactRuntimeExecutionContextV0,
}

/// Family-specific owner produced only by consuming the exact non-runtime
/// routing carrier. It is still pre-execution: the PoCO operation decoder and
/// overlay transition must consume this whole value in a later slice.
#[must_use = "a routed PoCO application payload still owns its exact cursor"]
struct CoreAuthorizedPocoApplicationPayloadV0 {
    routed: CoreAuthorizedNonRuntimePayloadRoutingV0,
}

/// Family-specific owner for the authenticated validator-transition payload.
/// Dispatch does not decode, schedule, mutate, or advance the cursor.
#[must_use = "a routed validator transition still owns its exact cursor"]
struct CoreAuthorizedValidatorTransitionPayloadV0 {
    routed: CoreAuthorizedNonRuntimePayloadRoutingV0,
}

/// An exact, strictly authorized envelope whose payload family is unsupported
/// by the native v0 dispatcher. The owner is retained so a later invalid
/// outcome cannot be manufactured from a detached payload-type string.
#[must_use = "an unsupported non-runtime family still owns its exact cursor"]
struct CoreAuthorizedUnsupportedNonRuntimePayloadV0 {
    routed: CoreAuthorizedNonRuntimePayloadRoutingV0,
}

/// Strictly decoded PoCO application operation that still owns the exact
/// Core-authorized envelope, body cursor, and authenticated source snapshot.
/// State-authority checks and overlay execution remain later consuming steps.
#[must_use = "a decoded PoCO operation still owns its exact validation cursor"]
struct DecodedCoreAuthorizedPocoApplicationPayloadV0 {
    owner: CoreAuthorizedPocoApplicationPayloadV0,
    operation: crate::poco_application::PocoApplicationOperationV0,
}

/// Strictly decoded validator transition that still owns the exact
/// Core-authorized envelope, body cursor, and authenticated source snapshot.
/// Governance-state authorization and scheduling remain a later consuming
/// step.
#[must_use = "a decoded validator transition still owns its exact validation cursor"]
struct DecodedCoreAuthorizedValidatorTransitionPayloadV0 {
    owner: CoreAuthorizedValidatorTransitionPayloadV0,
    transition: crate::validator_lifecycle::ValidatorSetTransitionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedNonRuntimeSemanticDecodeCauseV0 {
    InvalidPocoApplicationOperation,
    PocoTargetHeightMismatch,
    InvalidValidatorTransition,
    NonCanonicalValidatorTransition,
    ValidatorTransitionSchemaMismatch,
    ValidatorTransitionChainMismatch,
    ValidatorTransitionCommandMismatch,
    ValidatorTransitionSignerRoleMismatch,
}

#[must_use = "a semantic decode failure still retains its exact family owner"]
enum FailedCoreAuthorizedNonRuntimeSemanticDecodeV0 {
    PocoApplication {
        owner: CoreAuthorizedPocoApplicationPayloadV0,
        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
    },
    ValidatorTransition {
        owner: CoreAuthorizedValidatorTransitionPayloadV0,
        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
    },
}

impl std::fmt::Debug for FailedCoreAuthorizedNonRuntimeSemanticDecodeV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedNonRuntimeSemanticDecodeV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

/// Snapshot-closed form of one exact non-runtime payload owner. Both the
/// committed cursor position and the decoded-but-uncommitted successor index
/// are retained so closing a failure cannot be mistaken for cursor advance.
#[must_use = "a closed non-runtime payload still retains its exact cursor owner"]
struct ClosedCoreAuthorizedNonRuntimePayloadOwnerV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    index: u32,
    decoded_next_transaction_index: u32,
    cursor_next_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    envelope: SignedCommandEnvelopeV1,
    context: ExactRuntimeExecutionContextV0,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
}

#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Decode(CoreAuthorizedNonRuntimeSemanticDecodeCauseV0),
}

#[must_use = "a closed semantic decode failure still retains its exact family owner"]
enum ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0 {
    PocoApplication {
        owner: ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
        cause: ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
    },
    ValidatorTransition {
        owner: ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
        cause: ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
    },
}

#[must_use = "semantic dispatch must preserve exactly one decoded or unsupported owner"]
enum DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0 {
    PocoApplication(DecodedCoreAuthorizedPocoApplicationPayloadV0),
    ValidatorTransition(DecodedCoreAuthorizedValidatorTransitionPayloadV0),
    Unsupported(CoreAuthorizedUnsupportedNonRuntimePayloadV0),
}

/// One PoCO operation authorized and executed against either the first overlay
/// constructed from the exact retained parent snapshot or the cursor's prior
/// unsealed same-block prefix. The cursor has not advanced and the overlay has
/// not been converted into a complete-body JMT plan.
#[must_use = "an authorized PoCO family attempt still owns its exact cursor"]
struct AuthorizedCorePocoApplicationAttemptV0 {
    decoded: DecodedCoreAuthorizedPocoApplicationPayloadV0,
    overlay: crate::poco_application::PocoApplicationBlockOverlayV0,
}

/// One validator transition scheduled against either the lifecycle
/// authenticated by the exact retained parent snapshot or the cursor's prior
/// staged same-block lifecycle. The cursor has not advanced and the successor
/// lifecycle has not yet replaced the cursor's canonical singleton write.
#[must_use = "an authorized validator family attempt still owns its exact cursor"]
struct AuthorizedCoreValidatorTransitionAttemptV0 {
    decoded: DecodedCoreAuthorizedValidatorTransitionPayloadV0,
    scheduled_lifecycle: crate::ValidatorLifecycleStateV1,
}

#[must_use = "family authorization must preserve exactly one attempted owner"]
enum AuthorizedCoreNonRuntimeFamilyAttemptV0 {
    PocoApplication(Box<AuthorizedCorePocoApplicationAttemptV0>),
    ValidatorTransition(Box<AuthorizedCoreValidatorTransitionAttemptV0>),
}

/// Owner-bound, family-local write seal for one successful PoCO prefix. The
/// original unsealed overlay remains inside `attempted` so a later cursor
/// tranche can continue same-block operations and regenerate the one final
/// block seal. These writes must not be concatenated as independent PoCO
/// blocks and are not a JMT plan or persistence authority.
#[must_use = "a PoCO write seal still owns its exact family attempt and open cursor"]
struct OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0 {
    attempted: Box<AuthorizedCorePocoApplicationAttemptV0>,
    plan: crate::poco_application::SealedPocoApplicationPlanV0,
    writes: Vec<AuthWrite>,
}

/// Owner-bound canonical lifecycle write for one successful validator
/// transition. The scheduled lifecycle and exact open cursor stay together;
/// no complete-body plan, receipt, persistence, or callback can be derived
/// from the write alone.
#[must_use = "a validator write seal still owns its exact family attempt and open cursor"]
struct OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0 {
    attempted: Box<AuthorizedCoreValidatorTransitionAttemptV0>,
    write: AuthWrite,
}

#[must_use = "a non-runtime write seal still owns exactly one successful family attempt"]
enum OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0 {
    PocoApplication(Box<OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0>),
    ValidatorTransition(Box<OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0>),
}

#[must_use = "a failed write seal still owns the exact successful family attempt"]
enum FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0 {
    PocoApplication {
        attempted: Box<AuthorizedCorePocoApplicationAttemptV0>,
        reason: CoreAuthorizedNonRuntimeWriteSealInvariantV0,
    },
    ValidatorTransition {
        attempted: Box<AuthorizedCoreValidatorTransitionAttemptV0>,
        reason: CoreAuthorizedNonRuntimeWriteSealInvariantV0,
    },
}

impl std::fmt::Debug for FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Seal(CoreAuthorizedNonRuntimeWriteSealInvariantV0),
}

#[must_use = "a closed write-seal failure still retains its exact attempted family owner"]
enum ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0 {
    PocoApplication {
        owner: Box<ClosedCoreAuthorizedNonRuntimePayloadOwnerV0>,
        operation: Box<crate::poco_application::PocoApplicationOperationV0>,
        overlay: Box<crate::poco_application::PocoApplicationBlockOverlayV0>,
        cause: ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0,
    },
    ValidatorTransition {
        owner: Box<ClosedCoreAuthorizedNonRuntimePayloadOwnerV0>,
        transition: Box<crate::validator_lifecycle::ValidatorSetTransitionV1>,
        scheduled_lifecycle: Box<crate::ValidatorLifecycleStateV1>,
        cause: ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0 {
    PocoGovernanceAuthorization,
    PocoOperation(crate::poco_application::PocoApplicationDeterministicInvalidV0),
    ValidatorTransition(crate::validator_lifecycle::ValidatorTransitionDeterministicInvalidV1),
    UnsupportedFamily,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedNonRuntimeFamilyInvariantV0 {
    PocoExecutionContext,
    PocoProjection,
    PocoOperation(crate::poco_application::PocoApplicationInvariantV0),
    ValidatorTransition(crate::validator_lifecycle::ValidatorTransitionInvariantV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedNonRuntimeWriteSealInvariantV0 {
    OwnerBinding,
    PocoSourceBinding,
    PocoSeal,
    PocoSealedPostcondition,
    PocoWriteEncoding,
    ValidatorScheduleRebind,
    ValidatorWriteEncoding,
    ValidatorWritePostcondition,
}

#[derive(Debug, PartialEq, Eq)]
enum CoreAuthorizedNonRuntimeFamilyAttemptCauseV0 {
    AuthenticatedSource(AuthenticatedRuntimeReadFailureV0),
    DeterministicallyInvalid(CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0),
    Invariant(CoreAuthorizedNonRuntimeFamilyInvariantV0),
}

/// Exact data-free terminal-invalid reason extracted only from one closed
/// non-runtime semantic or family owner. The retained owner remains the sole
/// source of route, validation identity, raw bytes, cursor, and snapshot facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0 {
    SemanticDecode(CoreAuthorizedNonRuntimeSemanticDecodeCauseV0),
    Family(CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0),
}

/// Data-free fail-stop provenance for a closed non-runtime failure. Snapshot
/// and authenticated-source invariants stay distinct from family invariants;
/// neither can be converted into a terminal callback result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedRegularNonRuntimeSourceInvariantV0 {
    AuthenticatedState,
    Host,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedRegularNonRuntimeUnavailableKindV0 {
    ParentStateMissing,
    ParentStateUnauthenticated,
    Database,
    StorageIo,
    HostResource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreAuthorizedRegularNonRuntimeInvariantV0 {
    SemanticDecodeSnapshot(CoreAuthorizedRegularNonRuntimeSourceInvariantV0),
    FamilySnapshot(CoreAuthorizedRegularNonRuntimeSourceInvariantV0),
    WriteSealSnapshot(CoreAuthorizedRegularNonRuntimeSourceInvariantV0),
    FamilyAuthenticatedSource(CoreAuthorizedRegularNonRuntimeSourceInvariantV0),
    Family(CoreAuthorizedNonRuntimeFamilyInvariantV0),
    WriteSeal(CoreAuthorizedNonRuntimeWriteSealInvariantV0),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoreAuthorizedRegularNonRuntimeFailureDispositionV0 {
    Unavailable {
        kind: CoreAuthorizedRegularNonRuntimeUnavailableKindV0,
    },
    DeterministicallyInvalid {
        reason: CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0,
    },
    Invariant {
        reason: CoreAuthorizedRegularNonRuntimeInvariantV0,
    },
}

/// Opaque outcome authority extracted only from a complete closed non-runtime
/// failure owner. Private fields prevent sibling modules from manufacturing a
/// detached generation or reason; consuming the token yields only the view
/// needed by the app-private outcome kernel.
#[must_use = "non-runtime failure facts must be consumed with their retained owner"]
pub(super) struct CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
    generation: u64,
    disposition: CoreAuthorizedRegularNonRuntimeFailureDispositionV0,
}

pub(super) enum CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0 {
    Unavailable {
        generation: u64,
        kind: CoreAuthorizedRegularNonRuntimeUnavailableKindV0,
    },
    DeterministicallyInvalid {
        generation: u64,
        reason: CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0,
    },
    Invariant {
        generation: u64,
        reason: CoreAuthorizedRegularNonRuntimeInvariantV0,
    },
}

impl CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
    fn unavailable(
        generation: u64,
        kind: CoreAuthorizedRegularNonRuntimeUnavailableKindV0,
    ) -> Self {
        Self {
            generation,
            disposition: CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Unavailable { kind },
        }
    }

    fn deterministically_invalid(
        generation: u64,
        reason: CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0,
    ) -> Self {
        Self {
            generation,
            disposition:
                CoreAuthorizedRegularNonRuntimeFailureDispositionV0::DeterministicallyInvalid {
                    reason,
                },
        }
    }

    fn invariant(generation: u64, reason: CoreAuthorizedRegularNonRuntimeInvariantV0) -> Self {
        Self {
            generation,
            disposition: CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Invariant { reason },
        }
    }

    pub(super) fn into_view_v0(self) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0 {
        match self.disposition {
            CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Unavailable { kind } => {
                CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::Unavailable {
                    generation: self.generation,
                    kind,
                }
            }
            CoreAuthorizedRegularNonRuntimeFailureDispositionV0::DeterministicallyInvalid {
                reason,
            } => CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::DeterministicallyInvalid {
                generation: self.generation,
                reason,
            },
            CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Invariant { reason } => {
                CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::Invariant {
                    generation: self.generation,
                    reason,
                }
            }
        }
    }
}

impl CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0 {
    pub(super) const fn code(self) -> &'static str {
        use crate::poco_application::PocoApplicationDeterministicInvalidV0 as Poco;
        use crate::validator_lifecycle::ValidatorTransitionDeterministicInvalidV1 as Validator;
        use CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0 as Family;
        use CoreAuthorizedNonRuntimeSemanticDecodeCauseV0 as Semantic;

        match self {
            Self::SemanticDecode(Semantic::InvalidPocoApplicationOperation) => {
                "native_regular_poco_operation_decode_invalid"
            }
            Self::SemanticDecode(Semantic::PocoTargetHeightMismatch) => {
                "native_regular_poco_target_height_mismatch"
            }
            Self::SemanticDecode(Semantic::InvalidValidatorTransition) => {
                "native_regular_validator_transition_decode_invalid"
            }
            Self::SemanticDecode(Semantic::NonCanonicalValidatorTransition) => {
                "native_regular_validator_transition_non_canonical"
            }
            Self::SemanticDecode(Semantic::ValidatorTransitionSchemaMismatch) => {
                "native_regular_validator_transition_schema_mismatch"
            }
            Self::SemanticDecode(Semantic::ValidatorTransitionChainMismatch) => {
                "native_regular_validator_transition_chain_mismatch"
            }
            Self::SemanticDecode(Semantic::ValidatorTransitionCommandMismatch) => {
                "native_regular_validator_transition_command_mismatch"
            }
            Self::SemanticDecode(Semantic::ValidatorTransitionSignerRoleMismatch) => {
                "native_regular_validator_transition_signer_role_mismatch"
            }
            Self::Family(Family::PocoGovernanceAuthorization) => {
                "native_regular_poco_governance_authorization_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::PerBlockCapacity)) => {
                "native_regular_poco_per_block_capacity"
            }
            Self::Family(Family::PocoOperation(Poco::TargetHeightMismatch)) => {
                "native_regular_poco_target_height_mismatch"
            }
            Self::Family(Family::PocoOperation(Poco::AuthorityRevisionMismatch)) => {
                "native_regular_poco_authority_revision_mismatch"
            }
            Self::Family(Family::PocoOperation(Poco::DuplicateOperation)) => {
                "native_regular_poco_duplicate_operation"
            }
            Self::Family(Family::PocoOperation(Poco::SemanticTransition)) => {
                "native_regular_poco_semantic_transition_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::MissingRequiredAuthorityFact)) => {
                "native_regular_poco_required_authority_fact_missing"
            }
            Self::Family(Family::PocoOperation(Poco::ProtocolWindowOrCap)) => {
                "native_regular_poco_protocol_window_or_cap"
            }
            Self::Family(Family::PocoOperation(Poco::NullifierProof)) => {
                "native_regular_poco_nullifier_proof_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::CryptographicProof)) => {
                "native_regular_poco_cryptographic_proof_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::GovernanceRule)) => {
                "native_regular_poco_governance_rule_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::ValidatorRule)) => {
                "native_regular_poco_validator_rule_invalid"
            }
            Self::Family(Family::PocoOperation(Poco::ChallengeNotPending)) => {
                "native_regular_poco_challenge_not_pending"
            }
            Self::Family(Family::PocoOperation(Poco::GovernanceApprovalMissing)) => {
                "native_regular_poco_governance_approval_missing"
            }
            Self::Family(Family::PocoOperation(Poco::ValidatorConsensusKeyAlreadyActive)) => {
                "native_regular_poco_validator_consensus_key_already_active"
            }
            Self::Family(Family::PocoOperation(Poco::NullifierNonMembershipRootMismatch)) => {
                "native_regular_poco_nullifier_non_membership_root_mismatch"
            }
            Self::Family(Family::ValidatorTransition(Validator::Schema)) => {
                "native_regular_validator_transition_schema_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::TransitionChainId)) => {
                "native_regular_validator_transition_chain_id_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::TransitionId)) => {
                "native_regular_validator_transition_id_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::GovernanceAuthorization)) => {
                "native_regular_validator_governance_authorization_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::GovernanceSequenceMismatch)) => {
                "native_regular_validator_governance_sequence_mismatch"
            }
            Self::Family(Family::ValidatorTransition(Validator::PendingTransitionExists)) => {
                "native_regular_validator_pending_transition_exists"
            }
            Self::Family(Family::ValidatorTransition(Validator::BaseValidatorSetHash)) => {
                "native_regular_validator_base_set_hash_mismatch"
            }
            Self::Family(Family::ValidatorTransition(Validator::ActivationHeight)) => {
                "native_regular_validator_activation_height_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::TargetValidatorSet)) => {
                "native_regular_validator_target_set_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::ValidatorSetOverlap)) => {
                "native_regular_validator_set_overlap"
            }
            Self::Family(Family::ValidatorTransition(Validator::NewValidatorProof)) => {
                "native_regular_validator_new_validator_proof_invalid"
            }
            Self::Family(Family::ValidatorTransition(Validator::NoActiveSetChange)) => {
                "native_regular_validator_no_active_set_change"
            }
            Self::Family(Family::UnsupportedFamily) => {
                "native_regular_non_runtime_family_unsupported"
            }
        }
    }

    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::SemanticDecode(_) => {
                "strict non-runtime semantic decoding rejected the signed payload"
            }
            Self::Family(_) => {
                "authenticated non-runtime family evaluation deterministically rejected the block"
            }
        }
    }
}

impl CoreAuthorizedRegularNonRuntimeInvariantV0 {
    pub(super) const fn code(self) -> &'static str {
        use crate::poco_application::PocoApplicationInvariantV0 as Poco;
        use crate::validator_lifecycle::ValidatorTransitionInvariantV1 as Validator;
        use CoreAuthorizedNonRuntimeFamilyInvariantV0 as Family;

        match self {
            Self::SemanticDecodeSnapshot(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::AuthenticatedState,
            ) => "native_regular_non_runtime_semantic_snapshot_authenticated_state_invariant",
            Self::SemanticDecodeSnapshot(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::Host,
            ) => "native_regular_non_runtime_semantic_snapshot_host_invariant",
            Self::FamilySnapshot(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::AuthenticatedState,
            ) => "native_regular_non_runtime_family_snapshot_authenticated_state_invariant",
            Self::FamilySnapshot(CoreAuthorizedRegularNonRuntimeSourceInvariantV0::Host) => {
                "native_regular_non_runtime_family_snapshot_host_invariant"
            }
            Self::WriteSealSnapshot(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::AuthenticatedState,
            ) => "native_regular_non_runtime_write_seal_snapshot_authenticated_state_invariant",
            Self::WriteSealSnapshot(CoreAuthorizedRegularNonRuntimeSourceInvariantV0::Host) => {
                "native_regular_non_runtime_write_seal_snapshot_host_invariant"
            }
            Self::FamilyAuthenticatedSource(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::AuthenticatedState,
            ) => "native_regular_non_runtime_authenticated_source_state_invariant",
            Self::FamilyAuthenticatedSource(
                CoreAuthorizedRegularNonRuntimeSourceInvariantV0::Host,
            ) => "native_regular_non_runtime_authenticated_source_host_invariant",
            Self::Family(Family::PocoExecutionContext) => {
                "native_regular_poco_execution_context_invariant"
            }
            Self::Family(Family::PocoProjection) => "native_regular_poco_projection_invariant",
            Self::Family(Family::PocoOperation(Poco::RawOwnerBounds)) => {
                "native_regular_poco_raw_owner_bounds_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::DecodedRawOwnerMismatch)) => {
                "native_regular_poco_decoded_raw_owner_mismatch_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::OperationReencode)) => {
                "native_regular_poco_operation_reencode_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::AuthenticatedOverlay)) => {
                "native_regular_poco_authenticated_overlay_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::PlannerArithmetic)) => {
                "native_regular_poco_planner_arithmetic_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::ProtocolCounterExhausted)) => {
                "native_regular_poco_protocol_counter_exhausted_invariant"
            }
            Self::Family(Family::PocoOperation(Poco::DerivedMutationPostcondition)) => {
                "native_regular_poco_derived_mutation_postcondition_invariant"
            }
            Self::Family(Family::ValidatorTransition(Validator::AuthenticatedLifecycle)) => {
                "native_regular_validator_authenticated_lifecycle_invariant"
            }
            Self::Family(Family::ValidatorTransition(Validator::LifecycleContextBinding)) => {
                "native_regular_validator_lifecycle_context_binding_invariant"
            }
            Self::Family(Family::ValidatorTransition(Validator::GovernanceSequenceExhausted)) => {
                "native_regular_validator_governance_sequence_exhausted_invariant"
            }
            Self::Family(Family::ValidatorTransition(Validator::ActivationDelayOverflow)) => {
                "native_regular_validator_activation_delay_overflow_invariant"
            }
            Self::Family(Family::ValidatorTransition(Validator::ActiveSetHash)) => {
                "native_regular_validator_active_set_hash_invariant"
            }
            Self::Family(Family::ValidatorTransition(
                Validator::ScheduledLifecyclePostcondition,
            )) => "native_regular_validator_scheduled_lifecycle_postcondition_invariant",
            Self::WriteSeal(CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding) => {
                "native_regular_non_runtime_write_seal_owner_binding_invariant"
            }
            Self::WriteSeal(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSourceBinding) => {
                "native_regular_poco_write_seal_source_binding_invariant"
            }
            Self::WriteSeal(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSeal) => {
                "native_regular_poco_write_seal_invariant"
            }
            Self::WriteSeal(
                CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSealedPostcondition,
            ) => "native_regular_poco_write_seal_postcondition_invariant",
            Self::WriteSeal(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoWriteEncoding) => {
                "native_regular_poco_write_encoding_invariant"
            }
            Self::WriteSeal(
                CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorScheduleRebind,
            ) => "native_regular_validator_write_seal_schedule_rebind_invariant",
            Self::WriteSeal(
                CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWriteEncoding,
            ) => "native_regular_validator_write_encoding_invariant",
            Self::WriteSeal(
                CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition,
            ) => "native_regular_validator_write_postcondition_invariant",
        }
    }

    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::SemanticDecodeSnapshot(_) => {
                "closing a non-runtime semantic-decode snapshot exposed an invariant"
            }
            Self::FamilySnapshot(_) => "closing a non-runtime family snapshot exposed an invariant",
            Self::WriteSealSnapshot(_) => {
                "closing a non-runtime write-seal snapshot exposed an invariant"
            }
            Self::FamilyAuthenticatedSource(_) => {
                "an authenticated non-runtime family source exposed an invariant"
            }
            Self::Family(_) => "non-runtime family evaluation requires host fail-stop",
            Self::WriteSeal(_) => "non-runtime family write sealing requires host fail-stop",
        }
    }
}

#[must_use = "a failed family attempt still retains its exact dispatched owner"]
enum FailedCoreAuthorizedNonRuntimeFamilyAttemptV0 {
    PocoApplication {
        decoded: DecodedCoreAuthorizedPocoApplicationPayloadV0,
        cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
    ValidatorTransition {
        decoded: DecodedCoreAuthorizedValidatorTransitionPayloadV0,
        cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
    Unsupported {
        owner: CoreAuthorizedUnsupportedNonRuntimePayloadV0,
        cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
}

impl std::fmt::Debug for FailedCoreAuthorizedNonRuntimeFamilyAttemptV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedNonRuntimeFamilyAttemptV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Attempt(CoreAuthorizedNonRuntimeFamilyAttemptCauseV0),
}

#[must_use = "a closed family attempt failure still retains its exact family owner"]
enum ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0 {
    PocoApplication {
        owner: ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
        operation: crate::poco_application::PocoApplicationOperationV0,
        cause: ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
    ValidatorTransition {
        owner: ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
        transition: crate::validator_lifecycle::ValidatorSetTransitionV1,
        cause: ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
    Unsupported {
        owner: ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
        cause: ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
    },
}

#[must_use = "non-runtime dispatch must preserve exactly one family owner"]
enum DispatchedCoreAuthorizedNonRuntimePayloadV0 {
    PocoApplication(CoreAuthorizedPocoApplicationPayloadV0),
    ValidatorTransition(CoreAuthorizedValidatorTransitionPayloadV0),
    Unsupported(CoreAuthorizedUnsupportedNonRuntimePayloadV0),
}

/// Consumes the sole exact non-runtime carrier and selects a closed set of
/// native families from its retained, signature-checked envelope. There is no
/// caller-supplied family tag, no cursor advance, and no fallback into runtime.
#[allow(dead_code)]
fn dispatch_core_authorized_non_runtime_payload_v0(
    routed: CoreAuthorizedNonRuntimePayloadRoutingV0,
) -> DispatchedCoreAuthorizedNonRuntimePayloadV0 {
    match routed.envelope.payload_type.as_str() {
        crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0 => {
            DispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(
                CoreAuthorizedPocoApplicationPayloadV0 { routed },
            )
        }
        crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1 => {
            DispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(
                CoreAuthorizedValidatorTransitionPayloadV0 { routed },
            )
        }
        _ => DispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(
            CoreAuthorizedUnsupportedNonRuntimePayloadV0 { routed },
        ),
    }
}

/// Consumes one family owner into strict semantic decode. Only intrinsic facts
/// and facts already authenticated by the retained signed envelope are bound
/// here. Application authority, validator governance state, overlay mutation,
/// and success-only cursor advance remain unavailable from this function.
#[allow(dead_code)]
fn decode_dispatched_core_authorized_non_runtime_payload_v0(
    dispatched: DispatchedCoreAuthorizedNonRuntimePayloadV0,
) -> Result<
    DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0,
    Box<FailedCoreAuthorizedNonRuntimeSemanticDecodeV0>,
> {
    match dispatched {
        DispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(owner) => {
            let operation = match crate::poco_application::PocoApplicationOperationV0::decode_exact(
                &owner.routed.exact_inner_bytes,
            ) {
                Ok(operation) => operation,
                Err(_) => {
                    return Err(Box::new(
                        FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                            owner,
                            cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::InvalidPocoApplicationOperation,
                        },
                    ));
                }
            };
            if operation.target_height() != owner.routed.context.target_height {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                        owner,
                        cause:
                            CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::PocoTargetHeightMismatch,
                    },
                ));
            }
            Ok(
                DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(
                    DecodedCoreAuthorizedPocoApplicationPayloadV0 { owner, operation },
                ),
            )
        }
        DispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(owner) => {
            let transition: crate::validator_lifecycle::ValidatorSetTransitionV1 =
                match serde_json::from_slice(&owner.routed.exact_inner_bytes) {
                    Ok(transition) => transition,
                    Err(_) => {
                        return Err(Box::new(
                            FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                                owner,
                                cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::InvalidValidatorTransition,
                            },
                        ));
                    }
                };
            if serde_json::to_vec(&transition).ok().as_deref()
                != Some(owner.routed.exact_inner_bytes.as_slice())
            {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                        owner,
                        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::NonCanonicalValidatorTransition,
                    },
                ));
            }
            if transition.schema != crate::validator_lifecycle::VALIDATOR_TRANSITION_SCHEMA_V1 {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                        owner,
                        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::ValidatorTransitionSchemaMismatch,
                    },
                ));
            }
            if transition.chain_id != owner.routed.envelope.chain_id {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                        owner,
                        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::ValidatorTransitionChainMismatch,
                    },
                ));
            }
            if transition.transition_id != owner.routed.envelope.command_id {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                        owner,
                        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::ValidatorTransitionCommandMismatch,
                    },
                ));
            }
            if owner.routed.context.signer_role != "operator" {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                        owner,
                        cause: CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::ValidatorTransitionSignerRoleMismatch,
                    },
                ));
            }
            Ok(
                DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(
                    DecodedCoreAuthorizedValidatorTransitionPayloadV0 { owner, transition },
                ),
            )
        }
        DispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(owner) => {
            Ok(DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(owner))
        }
    }
}

/// Closes the one snapshot nested in a family owner while retaining every
/// cursor and payload fact. The returned finish result is consumed immediately
/// by the two failure-closing functions below; it is never an authority token.
fn close_core_authorized_non_runtime_payload_owner_v0(
    routed: CoreAuthorizedNonRuntimePayloadRoutingV0,
) -> (
    ClosedCoreAuthorizedNonRuntimePayloadOwnerV0,
    std::result::Result<(), AuthenticatedRuntimeReadFailureV0>,
) {
    let CoreAuthorizedNonRuntimePayloadRoutingV0 {
        open,
        index,
        next_transaction_index: decoded_next_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        envelope,
        context,
    } = routed;
    let OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index: cursor_next_transaction_index,
        changes,
        applied,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
    } = open;
    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    let finish = snapshot.finish();
    (
        ClosedCoreAuthorizedNonRuntimePayloadOwnerV0 {
            authorized,
            index,
            decoded_next_transaction_index,
            cursor_next_transaction_index,
            exact_outer_bytes,
            exact_inner_bytes,
            envelope,
            context,
            changes,
            applied,
            applied_non_runtime,
            poco_prefix,
            validator_prefix,
        },
        finish,
    )
}

/// Reveals a semantic-decode cause only after the exact retained snapshot has
/// closed. Snapshot-finish failure consumes and outranks the pending cause.
#[allow(dead_code)]
fn finish_failed_core_authorized_non_runtime_semantic_decode_v0(
    failed: Box<FailedCoreAuthorizedNonRuntimeSemanticDecodeV0>,
) -> Box<ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0> {
    match *failed {
        FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication { owner, cause } => {
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Decode(cause),
                Err(error) => ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                    owner,
                    cause,
                },
            )
        }
        FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition { owner, cause } => {
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Decode(cause),
                Err(error) => ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                    owner,
                    cause,
                },
            )
        }
    }
}

/// Consumes one strictly decoded family owner into its authenticated family
/// state transition. Every state read comes from the same pinned parent
/// snapshot already owned by the cursor. Success still cannot advance the
/// cursor, seal writes, produce a receipt, or form a terminal result.
#[allow(dead_code)]
fn authorize_and_execute_decoded_core_non_runtime_family_v0(
    decoded: DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0,
) -> Result<
    AuthorizedCoreNonRuntimeFamilyAttemptV0,
    Box<FailedCoreAuthorizedNonRuntimeFamilyAttemptV0>,
> {
    match decoded {
        DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(decoded) => {
            let authenticated = &decoded.owner.routed.open.open.authorized.context;
            if decoded.owner.routed.context.signer_role != "operator"
                || decoded.owner.routed.context.signer_id
                    != authenticated.validator_lifecycle.governance.signer_id
            {
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                        decoded,
                        cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoGovernanceAuthorization,
                        ),
                    },
                ));
            }
            let mut overlay = if let Some(prefix) = &decoded.owner.routed.open.poco_prefix {
                prefix.overlay.clone()
            } else {
                let projection = match decoded
                    .owner
                    .routed
                    .open
                    .open
                    .snapshot
                    .load_authenticated_production_poco_projection_v0()
                {
                    Ok(projection) => projection,
                    Err(cause) => {
                        return Err(Box::new(
                            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                                decoded,
                                cause:
                                    CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(
                                        cause,
                                    ),
                            },
                        ));
                    }
                };
                let governing_lifecycle = if let Some(prefix) =
                    &decoded.owner.routed.open.validator_prefix
                {
                    prefix.lifecycle.clone()
                } else {
                    match prepared_core_authorized_validator_lifecycle_v0(
                        &decoded.owner.routed.open,
                    ) {
                        Ok(lifecycle) => lifecycle,
                        Err(_) => {
                            return Err(Box::new(
                                FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                                    decoded,
                                    cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                        CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoExecutionContext,
                                    ),
                                },
                            ));
                        }
                    }
                };
                if crate::poco_checkpoint::validate_application_validator_projection(
                    &authenticated.validator_set,
                    &governing_lifecycle.active_validators,
                )
                .is_err()
                {
                    return Err(Box::new(
                        FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                            decoded,
                            cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoProjection,
                            ),
                        },
                    ));
                }
                let context =
                    match crate::poco_application::AuthenticatedPocoApplicationContextV0::new(
                        authenticated.parent_header.height().get(),
                        *authenticated.parent_header.state_root().as_bytes(),
                        decoded.owner.routed.open.open.authorized.header.height(),
                        authenticated.validator_set.chain_id(),
                        authenticated.validator_set.genesis_hash(),
                        authenticated.validator_set.epoch(),
                        authenticated.parameters,
                        crate::poco_application_governance_signer_commitment_v0(
                            &governing_lifecycle,
                        ),
                    ) {
                        Ok(context) => context,
                        Err(_) => {
                            return Err(Box::new(
                            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                                decoded,
                                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                    CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoExecutionContext,
                                ),
                            },
                        ));
                        }
                    };
                match crate::poco_application::PocoApplicationBlockOverlayV0::from_projection(
                    context,
                    &projection,
                ) {
                    Ok(overlay) => overlay,
                    Err(_) => {
                        return Err(Box::new(
                            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                                decoded,
                                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                    CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoProjection,
                                ),
                            },
                        ));
                    }
                }
            };
            if let Err(error) = overlay
                .apply_decoded_exact(&decoded.owner.routed.exact_inner_bytes, &decoded.operation)
            {
                let cause = match error {
                    crate::poco_application::PocoApplicationApplyFailureV0::DeterministicallyInvalid(
                        reason,
                    ) => CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                        CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoOperation(reason),
                    ),
                    crate::poco_application::PocoApplicationApplyFailureV0::Invariant(reason) => {
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                            CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoOperation(reason),
                        )
                    }
                };
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                        decoded,
                        cause,
                    },
                ));
            }
            Ok(AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(
                Box::new(AuthorizedCorePocoApplicationAttemptV0 { decoded, overlay }),
            ))
        }
        DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(decoded) => {
            let mut lifecycle = if let Some(prefix) = &decoded.owner.routed.open.validator_prefix {
                prefix.lifecycle.clone()
            } else {
                match prepared_core_authorized_validator_lifecycle_v0(&decoded.owner.routed.open) {
                    Ok(lifecycle) => lifecycle,
                    Err(_) => {
                        return Err(Box::new(
                            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                                decoded,
                                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                    CoreAuthorizedNonRuntimeFamilyInvariantV0::ValidatorTransition(
                                        crate::validator_lifecycle::ValidatorTransitionInvariantV1::AuthenticatedLifecycle,
                                    ),
                                ),
                            },
                        ));
                    }
                }
            };
            let authorization = crate::validator_lifecycle::ValidatorTransitionAuthorization {
                command_id: &decoded.owner.routed.envelope.command_id,
                signer_id: &decoded.owner.routed.context.signer_id,
                signer_role: &decoded.owner.routed.context.signer_role,
                nonce: decoded.owner.routed.envelope.nonce,
                chain_id: decoded.owner.routed.envelope.chain_id.as_str(),
                accepted_height: decoded.owner.routed.context.target_height,
            };
            if let Err(failure) = lifecycle.schedule(decoded.transition.clone(), authorization) {
                let cause = match failure {
                    crate::validator_lifecycle::ValidatorTransitionScheduleFailureV1::DeterministicallyInvalid(
                        reason,
                    ) => CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                        CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::ValidatorTransition(
                            reason,
                        ),
                    ),
                    crate::validator_lifecycle::ValidatorTransitionScheduleFailureV1::Invariant(
                        reason,
                    ) => CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                        CoreAuthorizedNonRuntimeFamilyInvariantV0::ValidatorTransition(reason),
                    ),
                };
                return Err(Box::new(
                    FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                        decoded,
                        cause,
                    },
                ));
            }
            Ok(
                AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(Box::new(
                    AuthorizedCoreValidatorTransitionAttemptV0 {
                        decoded,
                        scheduled_lifecycle: lifecycle,
                    },
                )),
            )
        }
        DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(owner) => Err(Box::new(
            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported {
                owner,
                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                    CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::UnsupportedFamily,
                ),
            },
        )),
    }
}

fn validate_core_authorized_non_runtime_write_seal_owner_v0(
    routed: &CoreAuthorizedNonRuntimePayloadRoutingV0,
) -> anyhow::Result<()> {
    let expected_next = routed
        .index
        .checked_add(1)
        .context("non-runtime write-seal cursor index exhausted")?;
    anyhow::ensure!(
        routed.index == routed.open.next_transaction_index
            && routed.next_transaction_index == expected_next,
        "non-runtime write-seal cursor provenance drift"
    );
    let authorized = &routed.open.open.authorized;
    let index = usize::try_from(routed.index)
        .context("non-runtime write-seal cursor index does not fit host")?;
    anyhow::ensure!(
        authorized
            .body
            .application_payload()
            .transactions()
            .get(index)
            .map(Vec::as_slice)
            == Some(routed.exact_outer_bytes.as_slice()),
        "non-runtime write-seal raw body owner drift"
    );
    let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(&routed.exact_outer_bytes)
        .context("non-runtime write-seal envelope no longer decodes")?;
    anyhow::ensure!(
        envelope == routed.envelope,
        "non-runtime write-seal envelope owner drift"
    );
    let exact_inner_bytes = envelope
        .payload_bytes()
        .context("non-runtime write-seal envelope payload no longer decodes")?;
    anyhow::ensure!(
        exact_inner_bytes == routed.exact_inner_bytes,
        "non-runtime write-seal inner payload owner drift"
    );
    let signer = crate::validate_signed_command_envelope_against_policy_v1(
        &envelope,
        authorized.header.chain_id().as_str(),
        authorized.header.timestamp_ms(),
        &authorized.context.signer_policy.authorized_signers,
    )
    .context("non-runtime write-seal envelope authorization drift")?;
    anyhow::ensure!(
        routed.context.target_height == authorized.header.height().get()
            && routed.context.target_block_id == authorized.validation_id.block_id()
            && routed.context.validation_timestamp_ms == authorized.header.timestamp_ms()
            && routed.context.signer_id == signer.signer_id
            && routed.context.signer_role == signer.signer_role
            && routed.context.payload_len == routed.exact_inner_bytes.len(),
        "non-runtime write-seal target owner drift"
    );
    Ok(())
}

fn auth_writes_match_v0(left: &[AuthWrite], right: &[AuthWrite]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.key() == right.key() && left.value() == right.value())
}

fn prepared_core_authorized_validator_lifecycle_v0(
    open: &OpenCoreAuthorizedRegularTransactionCursorV0,
) -> anyhow::Result<crate::ValidatorLifecycleStateV1> {
    let mut lifecycle = open.open.authorized.context.validator_lifecycle.clone();
    lifecycle
        .prepare_height(open.open.authorized.header.height().get())
        .context("prepare authenticated validator lifecycle for target height")?;
    Ok(lifecycle)
}

fn validate_core_authorized_regular_cursor_prefix_v0(
    open: &OpenCoreAuthorizedRegularTransactionCursorV0,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let authorized = &open.open.authorized;
    let body = authorized.body.application_payload().transactions();
    let target_height = authorized.header.height().get();
    let target_block_id = authorized.validation_id.block_id();
    let exclusive_end = open.next_transaction_index;
    let mut indices = BTreeSet::new();
    let mut previous_runtime_index = None;
    for applied in &open.applied {
        let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(&applied.exact_outer_bytes)?;
        let signer = crate::validate_signed_command_envelope_against_policy_v1(
            &envelope,
            authorized.header.chain_id().as_str(),
            authorized.header.timestamp_ms(),
            &authorized.context.signer_policy.authorized_signers,
        )?;
        let exact_inner_bytes = envelope.payload_bytes()?;
        let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner_bytes)?;
        transaction.validate()?;
        let native_receipt =
            NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&applied.runtime_receipt)?;
        anyhow::ensure!(
            applied.index < exclusive_end
                && previous_runtime_index.is_none_or(|previous| previous < applied.index)
                && indices.insert(applied.index)
                && body.get(usize::try_from(applied.index)?).map(Vec::as_slice)
                    == Some(applied.exact_outer_bytes.as_slice())
                && envelope.payload_type == CANONICAL_TX_PAYLOAD_TYPE_V1
                && envelope.signer_id == transaction.sender
                && envelope.nonce == transaction.nonce
                && exact_inner_bytes == applied.exact_inner_bytes
                && transaction == applied.transaction
                && applied.context.target_height == target_height
                && applied.context.target_block_id == target_block_id
                && applied.context.validation_timestamp_ms == authorized.header.timestamp_ms()
                && applied.context.signer_id == signer.signer_id
                && applied.context.signer_role == signer.signer_role
                && applied.context.payload_len == applied.exact_inner_bytes.len()
                && native_receipt == applied.native_receipt,
            "non-runtime prefix runtime provenance drift"
        );
        previous_runtime_index = Some(applied.index);
    }

    let mut poco_raws = Vec::new();
    let mut rebuilt_validator = prepared_core_authorized_validator_lifecycle_v0(open)?;
    let mut validator_count = 0usize;
    let mut previous_non_runtime_index = None;
    for applied in &open.applied_non_runtime {
        let (index, exact_outer_bytes, exact_inner_bytes, envelope, context) = match applied {
            AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                index,
                exact_outer_bytes,
                exact_inner_bytes,
                envelope,
                context,
                operation,
            } => {
                anyhow::ensure!(
                    serde_json::to_vec(operation)? == *exact_inner_bytes
                        && envelope.payload_type
                            == crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    "non-runtime PoCO prefix semantic owner drift"
                );
                poco_raws.push(exact_inner_bytes.clone());
                (
                    *index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                )
            }
            AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition {
                index,
                exact_outer_bytes,
                exact_inner_bytes,
                envelope,
                context,
                transition,
            } => {
                anyhow::ensure!(
                    serde_json::to_vec(transition)? == *exact_inner_bytes
                        && envelope.payload_type
                            == crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
                    "non-runtime validator prefix semantic owner drift"
                );
                let authorization = crate::validator_lifecycle::ValidatorTransitionAuthorization {
                    command_id: &envelope.command_id,
                    signer_id: &context.signer_id,
                    signer_role: &context.signer_role,
                    nonce: envelope.nonce,
                    chain_id: envelope.chain_id.as_str(),
                    accepted_height: context.target_height,
                };
                rebuilt_validator
                    .schedule(transition.clone(), authorization)
                    .map_err(|_| anyhow::anyhow!("non-runtime validator prefix replay drift"))?;
                validator_count = validator_count
                    .checked_add(1)
                    .context("non-runtime validator prefix count exhausted")?;
                (
                    *index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                )
            }
        };
        anyhow::ensure!(
            index < exclusive_end
                && previous_non_runtime_index.is_none_or(|previous| previous < index)
                && indices.insert(index)
                && body.get(usize::try_from(index)?).map(Vec::as_slice)
                    == Some(exact_outer_bytes.as_slice()),
            "non-runtime prefix body sequence drift"
        );
        previous_non_runtime_index = Some(index);
        let decoded_envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(exact_outer_bytes)?;
        anyhow::ensure!(
            decoded_envelope == *envelope,
            "non-runtime prefix envelope drift"
        );
        anyhow::ensure!(
            decoded_envelope.payload_bytes()? == *exact_inner_bytes,
            "non-runtime prefix inner payload drift"
        );
        let signer = crate::validate_signed_command_envelope_against_policy_v1(
            &decoded_envelope,
            authorized.header.chain_id().as_str(),
            authorized.header.timestamp_ms(),
            &authorized.context.signer_policy.authorized_signers,
        )?;
        anyhow::ensure!(
            context.target_height == target_height
                && context.target_block_id == target_block_id
                && context.validation_timestamp_ms == authorized.header.timestamp_ms()
                && context.signer_id == signer.signer_id
                && context.signer_role == signer.signer_role
                && context.payload_len == exact_inner_bytes.len(),
            "non-runtime prefix context drift"
        );
    }
    anyhow::ensure!(
        usize::try_from(exclusive_end)? == indices.len()
            && (0..exclusive_end).all(|index| indices.contains(&index)),
        "non-runtime prefix does not cover the exact prior body"
    );

    match (&open.poco_prefix, poco_raws.is_empty()) {
        (None, true) => {}
        (Some(prefix), false) => {
            let authorized_parent = &authorized.context.parent_header;
            anyhow::ensure!(
                prefix.overlay.source_version() == authorized_parent.height().get()
                    && prefix.overlay.source_root() == *authorized_parent.state_root().as_bytes()
                    && prefix.overlay.target_height() == authorized.header.height()
                    && prefix.overlay.operation_count() == poco_raws.len()
                    && prefix.plan.source_version() == authorized_parent.height().get()
                    && prefix.plan.source_root() == *authorized_parent.state_root().as_bytes()
                    && prefix.plan.target_height() == authorized.header.height()
                    && prefix.plan.target_manifest().cutoff_height() == authorized.header.height()
                    && prefix.plan.binds_exact_operations_v0(&poco_raws),
                "non-runtime PoCO prefix source or operation binding drift"
            );
            let regenerated = prefix.overlay.clone().seal()?;
            anyhow::ensure!(
                regenerated.source_version() == prefix.plan.source_version()
                    && regenerated.source_root() == prefix.plan.source_root()
                    && regenerated.target_height() == prefix.plan.target_height()
                    && regenerated.operation_root() == prefix.plan.operation_root()
                    && regenerated.operation_count() == prefix.plan.operation_count()
                    && regenerated.mutation_root() == prefix.plan.mutation_root()
                    && regenerated.mutation_count() == prefix.plan.mutation_count()
                    && regenerated.target_manifest() == prefix.plan.target_manifest()
                    && regenerated
                        .namespace_writes()
                        .eq(prefix.plan.namespace_writes()),
                "non-runtime PoCO prefix seal drift"
            );
            let expected_writes =
                crate::poco_transition::auth_writes_from_sealed_poco_application_v0(&prefix.plan)?;
            anyhow::ensure!(
                auth_writes_match_v0(&prefix.writes, &expected_writes),
                "non-runtime PoCO prefix writes drift"
            );
        }
        _ => anyhow::bail!("non-runtime PoCO prefix presence drift"),
    }

    match (&open.validator_prefix, validator_count) {
        (None, 0) => {}
        (Some(prefix), count) if count > 0 => {
            anyhow::ensure!(
                prefix.lifecycle == rebuilt_validator,
                "non-runtime validator prefix lifecycle drift"
            );
            let expected = crate::authenticated_lifecycle_write(target_height, &rebuilt_validator)?;
            anyhow::ensure!(
                prefix.write.key() == expected.key() && prefix.write.value() == expected.value(),
                "non-runtime validator prefix write drift"
            );
        }
        _ => anyhow::bail!("non-runtime validator prefix presence drift"),
    }
    Ok(poco_raws)
}

/// Derives only family-local canonical writes from one complete successful
/// attempt. The exact attempt remains embedded beside those writes, including
/// its still-open parent snapshot and uncommitted cursor. PoCO sealing runs on
/// a bounded overlay clone so either branch retains the original owner. This
/// step does not concatenate PoCO prefixes, plan a JMT update, finish the
/// snapshot, advance the cursor, form a receipt, persist, callback, or call
/// Core.
#[allow(dead_code)]
fn seal_core_authorized_non_runtime_family_writes_v0(
    attempted: AuthorizedCoreNonRuntimeFamilyAttemptV0,
) -> std::result::Result<
    OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0,
    FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0,
> {
    match attempted {
        AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted) => {
            let sealed = (|| {
                validate_core_authorized_non_runtime_write_seal_owner_v0(
                    &attempted.decoded.owner.routed,
                )
                .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                let mut exact_poco_operations = validate_core_authorized_regular_cursor_prefix_v0(
                    &attempted.decoded.owner.routed.open,
                )
                .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                let reencoded = serde_json::to_vec(&attempted.decoded.operation)
                    .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                if reencoded != attempted.decoded.owner.routed.exact_inner_bytes {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding);
                }
                let routed = &attempted.decoded.owner.routed;
                if routed.envelope.payload_type
                    != crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0
                {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding);
                }
                let authorized = &routed.open.open.authorized;
                let expected_operation_count = exact_poco_operations
                    .len()
                    .checked_add(1)
                    .ok_or(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSourceBinding)?;
                if attempted.overlay.source_version()
                    != authorized.context.parent_header.height().get()
                    || attempted.overlay.source_root()
                        != *authorized.context.parent_header.state_root().as_bytes()
                    || attempted.overlay.target_height() != authorized.header.height()
                    || attempted.overlay.operation_count() != expected_operation_count
                    || attempted.decoded.operation.target_height()
                        != authorized.header.height().get()
                {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSourceBinding);
                }
                exact_poco_operations
                    .push(attempted.decoded.owner.routed.exact_inner_bytes.clone());
                let plan = attempted
                    .overlay
                    .clone()
                    .seal()
                    .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSeal)?;
                if plan.source_version() != authorized.context.parent_header.height().get()
                    || plan.source_root()
                        != *authorized.context.parent_header.state_root().as_bytes()
                    || plan.target_height() != authorized.header.height()
                    || plan.target_manifest().cutoff_height() != authorized.header.height()
                    || !plan.binds_exact_operations_v0(&exact_poco_operations)
                {
                    return Err(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSealedPostcondition,
                    );
                }
                let writes =
                    crate::poco_transition::auth_writes_from_sealed_poco_application_v0(&plan)
                        .map_err(|_| {
                            CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoWriteEncoding
                        })?;
                if writes.len() != plan.namespace_writes().len()
                    || !writes
                        .iter()
                        .zip(plan.namespace_writes())
                        .all(|(write, (key, value))| write.key() == key && write.value() == value)
                {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoWriteEncoding);
                }
                Ok((plan, writes))
            })();
            match sealed {
                Ok((plan, writes)) => Ok(
                    OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication(Box::new(
                        OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0 {
                            attempted,
                            plan,
                            writes,
                        },
                    )),
                ),
                Err(reason) => Err(
                    FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                        attempted,
                        reason,
                    },
                ),
            }
        }
        AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted) => {
            let sealed = (|| {
                validate_core_authorized_non_runtime_write_seal_owner_v0(
                    &attempted.decoded.owner.routed,
                )
                .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                validate_core_authorized_regular_cursor_prefix_v0(
                    &attempted.decoded.owner.routed.open,
                )
                .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                let reencoded = serde_json::to_vec(&attempted.decoded.transition)
                    .map_err(|_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding)?;
                if reencoded != attempted.decoded.owner.routed.exact_inner_bytes {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding);
                }
                let routed = &attempted.decoded.owner.routed;
                if routed.envelope.payload_type
                    != crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1
                {
                    return Err(CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding);
                }
                let mut rebuilt = if let Some(prefix) = &routed.open.validator_prefix {
                    prefix.lifecycle.clone()
                } else {
                    prepared_core_authorized_validator_lifecycle_v0(&routed.open).map_err(|_| {
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorScheduleRebind
                    })?
                };
                let authorization = crate::validator_lifecycle::ValidatorTransitionAuthorization {
                    command_id: &routed.envelope.command_id,
                    signer_id: &routed.context.signer_id,
                    signer_role: &routed.context.signer_role,
                    nonce: routed.envelope.nonce,
                    chain_id: routed.envelope.chain_id.as_str(),
                    accepted_height: routed.context.target_height,
                };
                rebuilt
                    .schedule(attempted.decoded.transition.clone(), authorization)
                    .map_err(|_| {
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorScheduleRebind
                    })?;
                if rebuilt != attempted.scheduled_lifecycle {
                    return Err(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorScheduleRebind,
                    );
                }
                let target_height = routed.open.open.authorized.header.height().get();
                let write = crate::authenticated_lifecycle_write(target_height, &rebuilt).map_err(
                    |_| CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWriteEncoding,
                )?;
                let expected_key = crate::auth_tree::validator_state_key().map_err(|_| {
                    CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition
                })?;
                if write.key() != expected_key.as_slice() {
                    return Err(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition,
                    );
                }
                let record =
                    crate::auth_tree::AuthenticatedObjectRecord::decode(write.value().ok_or(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition,
                    )?)
                    .map_err(|_| {
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition
                    })?;
                let lifecycle_bytes = serde_json::to_vec(&rebuilt).map_err(|_| {
                    CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWriteEncoding
                })?;
                if record.object_type != crate::VALIDATOR_LIFECYCLE_SCHEMA_V1
                    || record.object_version != target_height
                    || record.value != lifecycle_bytes
                {
                    return Err(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorWritePostcondition,
                    );
                }
                Ok(write)
            })();
            match sealed {
                Ok(write) => Ok(
                    OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition(
                        Box::new(OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0 {
                            attempted,
                            write,
                        }),
                    ),
                ),
                Err(reason) => Err(
                    FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                        attempted,
                        reason,
                    },
                ),
            }
        }
    }
}

/// Consumes the complete owner-bound family seal and commits exactly one
/// successful cursor step in memory. The latest whole-family prefix replaces
/// its predecessor; PoCO writes are never concatenated as separate blocks and
/// validator writes remain one singleton successor. All fallible owner,
/// prefix, seal, and encoding checks occurred before this capability existed.
/// This function does not finish the snapshot, form a receipt, plan/apply JMT,
/// persist, callback, or call Core.
#[allow(dead_code)]
fn advance_core_authorized_non_runtime_success_v0(
    sealed: OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0,
) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
    match sealed {
        OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication(sealed) => {
            let OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0 {
                attempted,
                plan,
                writes,
            } = *sealed;
            let AuthorizedCorePocoApplicationAttemptV0 { decoded, overlay } = *attempted;
            let DecodedCoreAuthorizedPocoApplicationPayloadV0 { owner, operation } = decoded;
            let CoreAuthorizedPocoApplicationPayloadV0 { routed } = owner;
            let CoreAuthorizedNonRuntimePayloadRoutingV0 {
                mut open,
                index,
                next_transaction_index,
                exact_outer_bytes,
                exact_inner_bytes,
                envelope,
                context,
            } = routed;
            debug_assert_eq!(open.next_transaction_index, index);
            debug_assert_eq!(index.checked_add(1), Some(next_transaction_index));
            open.applied_non_runtime.push(
                AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    operation,
                },
            );
            open.poco_prefix = Some(Box::new(CoreAuthorizedRegularPocoPrefixV0 {
                overlay,
                plan,
                writes,
            }));
            open.next_transaction_index = next_transaction_index;
            open
        }
        OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition(sealed) => {
            let OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0 { attempted, write } =
                *sealed;
            let AuthorizedCoreValidatorTransitionAttemptV0 {
                decoded,
                scheduled_lifecycle,
            } = *attempted;
            let DecodedCoreAuthorizedValidatorTransitionPayloadV0 { owner, transition } = decoded;
            let CoreAuthorizedValidatorTransitionPayloadV0 { routed } = owner;
            let CoreAuthorizedNonRuntimePayloadRoutingV0 {
                mut open,
                index,
                next_transaction_index,
                exact_outer_bytes,
                exact_inner_bytes,
                envelope,
                context,
            } = routed;
            debug_assert_eq!(open.next_transaction_index, index);
            debug_assert_eq!(index.checked_add(1), Some(next_transaction_index));
            open.applied_non_runtime.push(
                AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition {
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    transition,
                },
            );
            open.validator_prefix = Some(Box::new(CoreAuthorizedRegularValidatorPrefixV0 {
                lifecycle: scheduled_lifecycle,
                write,
            }));
            open.next_transaction_index = next_transaction_index;
            open
        }
    }
}

/// Closes a failed family-local write seal while retaining the attempted
/// overlay or scheduled lifecycle. Snapshot finish failure consumes and
/// outranks the pending seal invariant; no writes, plan, cursor advance,
/// receipt, terminal callback, or persistence authority escapes.
#[allow(dead_code)]
fn finish_failed_core_authorized_non_runtime_family_write_seal_v0(
    failed: FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0,
) -> Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0> {
    match failed {
        FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication { attempted, reason } => {
            let AuthorizedCorePocoApplicationAttemptV0 { decoded, overlay } = *attempted;
            let DecodedCoreAuthorizedPocoApplicationPayloadV0 { owner, operation } = decoded;
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(reason),
                Err(error) => ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                    owner: Box::new(owner),
                    operation: Box::new(operation),
                    overlay: Box::new(overlay),
                    cause,
                },
            )
        }
        FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
            attempted,
            reason,
        } => {
            let AuthorizedCoreValidatorTransitionAttemptV0 {
                decoded,
                scheduled_lifecycle,
            } = *attempted;
            let DecodedCoreAuthorizedValidatorTransitionPayloadV0 { owner, transition } = decoded;
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(reason),
                Err(error) => ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                    owner: Box::new(owner),
                    transition: Box::new(transition),
                    scheduled_lifecycle: Box::new(scheduled_lifecycle),
                    cause,
                },
            )
        }
    }
}

/// Closes a failed family attempt before its typed cause becomes observable.
/// A snapshot finish failure consumes and outranks deterministic, source, or
/// invariant attempt provenance; no terminal mapping or callback is formed.
#[allow(dead_code)]
fn finish_failed_core_authorized_non_runtime_family_attempt_v0(
    failed: Box<FailedCoreAuthorizedNonRuntimeFamilyAttemptV0>,
) -> Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0> {
    match *failed {
        FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { decoded, cause } => {
            let DecodedCoreAuthorizedPocoApplicationPayloadV0 { owner, operation } = decoded;
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(cause),
                Err(error) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                    owner,
                    operation,
                    cause,
                },
            )
        }
        FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { decoded, cause } => {
            let DecodedCoreAuthorizedValidatorTransitionPayloadV0 { owner, transition } = decoded;
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(cause),
                Err(error) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                    owner,
                    transition,
                    cause,
                },
            )
        }
        FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { owner, cause } => {
            let (owner, finish) = close_core_authorized_non_runtime_payload_owner_v0(owner.routed);
            let cause = match finish {
                Ok(()) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(cause),
                Err(error) => ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Snapshot(error),
            };
            Box::new(
                ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { owner, cause },
            )
        }
    }
}

enum PreparedCoreAuthorizedRegularPayloadV0 {
    Runtime(PreparedCoreAuthorizedRuntimeTransactionV0),
    NonRuntime(CoreAuthorizedNonRuntimePayloadRoutingV0),
}

/// One successful real runtime attempt retained only inside the owning
/// production cursor. This is execution evidence for later planning, not a
/// terminal outcome or a separately reusable receipt authority.
struct AppliedCoreAuthorizedRuntimeTransactionV0 {
    index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
    runtime_receipt: RuntimeReceipt,
    native_receipt: NativeTransactionReceiptFactsV0,
}

/// Successful non-runtime item provenance retained only inside the owning
/// cursor. These records are neither receipts nor independently reusable
/// writes; they exist to bind a later whole-prefix seal and body completion to
/// the exact signed item sequence.
enum AppliedCoreAuthorizedNonRuntimePayloadV0 {
    PocoApplication {
        index: u32,
        exact_outer_bytes: Vec<u8>,
        exact_inner_bytes: Vec<u8>,
        envelope: SignedCommandEnvelopeV1,
        context: ExactRuntimeExecutionContextV0,
        operation: crate::poco_application::PocoApplicationOperationV0,
    },
    ValidatorTransition {
        index: u32,
        exact_outer_bytes: Vec<u8>,
        exact_inner_bytes: Vec<u8>,
        envelope: SignedCommandEnvelopeV1,
        context: ExactRuntimeExecutionContextV0,
        transition: crate::validator_lifecycle::ValidatorSetTransitionV1,
    },
}

/// Closed PoCO write provenance retained by the complete-body planner. A
/// business-operation prefix keeps its high-level sealed plan; a scheduled
/// empty cutoff keeps the authenticated projection needed to rederive the one
/// mandatory manifest refresh. Neither variant is a receipt or persistence
/// capability.
enum FinishedCoreAuthorizedRegularPocoWriteSourceV0 {
    Operations(crate::poco_application::SealedPocoApplicationPlanV0),
    ScheduledCutoff(crate::poco_transition::ProductionPocoProjectionV0),
}

/// Snapshot-finished complete mixed-body evidence plus one inert exact-next
/// JMT plan. Runtime, PoCO, validator, and mandatory system writes have already
/// been merged and sealed against the same parent transaction, but this owner
/// cannot construct success receipts, compare header roots, persist, callback,
/// or cross a Core/ABCI boundary.
#[must_use = "a complete-body post-state plan still lacks receipts and root comparison"]
struct FinishedPlannedCoreAuthorizedRegularCompleteBodyV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    final_poco: Option<FinishedCoreAuthorizedRegularPocoWriteSourceV0>,
    final_validator_lifecycle: Option<crate::ValidatorLifecycleStateV1>,
    post_state_update: PlannedAuthUpdate,
    post_state_update_seal: PlannedAuthUpdateSealV0,
}

/// Exact body-wide receipts and four-root match for one already-finished
/// mixed regular body. This private carrier still has no execution-outcome,
/// callback, persistence, or Core authority.
#[must_use = "a matched mixed-body carrier is not terminal host authority"]
struct MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
    finished: FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
    native_execution: NativeBlockExecutionV0,
    validated_commitments: ValidatedBlockCommitmentsV0,
}

/// A mixed-body comparison failure retains the complete finished owner it
/// classified. No detached mismatch or invariant can be promoted on its own.
#[must_use = "a failed mixed-body comparison still owns its exact finished plan"]
struct FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0 {
    finished: FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
    cause: CoreAuthorizedRegularCommitmentComparisonCauseV0,
}

impl std::fmt::Debug for FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0")
            .field("retains_exact_finished_mixed_plan", &true)
            .finish_non_exhaustive()
    }
}

/// Owning deterministic-invalid branch produced only by the complete-body
/// classifier. The closed root-mismatch cause remains joined to the exact
/// finished body and its reservation until the consuming durable bridge
/// revalidates all three.
#[must_use = "a deterministic mixed-body mismatch still lacks durable artifact authority"]
struct DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
    failed: Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>,
}

/// App-private authority to encode and atomically persist one closed
/// deterministic-invalid artifact. Its fields are intentionally private and
/// it has no detached constructor: only the consuming complete-body bridge can
/// join the durable reservation to the stable closed reason.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a prepared durable invalid result must be consumed by the validation journal"]
pub(super) struct PreparedDurableInvalidV0 {
    reservation: NativeValidationReservationTokenV0,
    reason: DurableDeterministicInvalidReasonV0,
}

/// Narrow consuming view used by the validation store. Keeping the fields
/// private prevents sibling modules from assembling reservation/reason pairs;
/// the journal may inspect the retained identity and reason but cannot mint a
/// new preparation capability.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "prepared durable-invalid store parts retain one reservation authority"]
pub(super) struct PreparedDurableInvalidStorePartsV0 {
    reservation: NativeValidationReservationTokenV0,
    reason: DurableDeterministicInvalidReasonV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PreparedDurableInvalidV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.reservation.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.reservation.validation_id()
    }

    pub(super) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.reason
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.reservation.request_fingerprint()
    }

    pub(super) const fn immutable_checksum(&self) -> [u8; 32] {
        self.reservation.immutable_checksum()
    }

    pub(super) fn is_bound_to_store_v0(&self, store: &ApplicationStore) -> bool {
        self.reservation.is_bound_to_store_v0(store)
    }

    pub(super) fn into_store_parts_v0(self) -> PreparedDurableInvalidStorePartsV0 {
        PreparedDurableInvalidStorePartsV0 {
            reservation: self.reservation,
            reason: self.reason,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl PreparedDurableInvalidStorePartsV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.reservation.route()
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.reservation.validation_id()
    }

    pub(super) const fn reason(&self) -> DurableDeterministicInvalidReasonV0 {
        self.reason
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum PrepareDurableInvalidFailureCauseV0 {
    RetainedCauseInvariant,
    #[cfg(test)]
    TestOnlyReservation,
    ReservationRouteInvariant,
    ReservationValidationIdInvariant,
}

/// Failed preparation retains the complete deterministic-invalid owner so a
/// fail-stop caller cannot accidentally discard or substitute the classified
/// body while examining the private failure cause.
#[must_use = "a failed durable-invalid preparation retains its exact mismatch owner"]
#[cfg_attr(not(test), allow(dead_code))]
struct FailedPrepareDurableInvalidV0 {
    owner: DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0,
    cause: PrepareDurableInvalidFailureCauseV0,
}

impl std::fmt::Debug for FailedPrepareDurableInvalidV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedPrepareDurableInvalidV0")
            .field("cause", &self.cause)
            .field("retains_exact_deterministic_mismatch_owner", &true)
            .finish_non_exhaustive()
    }
}

/// Process-local disposition of one complete mixed-body comparison. It is
/// deliberately not an `ExecutionOutcomeV0`, payload result, or callback.
#[must_use = "a classified mixed-body comparison is not terminal host authority"]
enum ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
    Valid(Box<MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0>),
    DeterministicallyInvalid(
        DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0,
    ),
    InvariantFault(Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>),
}

/// Snapshot-finished complete-body runtime evidence plus an inert exact-next
/// JMT plan derived before that same parent transaction closed. This carrier
/// cannot apply the plan, compare header roots, mint a terminal outcome, or
/// cross a Core/ABCI boundary.
#[must_use = "a finished post-state plan must be consumed by the exact-root comparator"]
struct FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    post_state_update: PlannedAuthUpdate,
    post_state_update_seal: PlannedAuthUpdateSealV0,
}

/// Exact-root match proof that consumes one finished production plan and
/// rebuilds the native payload/receipts from its retained runtime attempts.
/// The embedded static commitment token remains private and cannot be returned
/// to Core, converted into an execution outcome, or used as ABCI authority.
#[must_use = "a matched runtime commitment carrier is not terminal execution authority"]
pub(super) struct MatchedCoreAuthorizedRegularRuntimeCommitmentsV0 {
    finished: FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0,
    native_execution: NativeBlockExecutionV0,
    validated_commitments: ValidatedBlockCommitmentsV0,
}

impl MatchedCoreAuthorizedRegularRuntimeCommitmentsV0 {
    pub(super) const fn validation_generation_v0(&self) -> u64 {
        self.finished.authorized.validation_id.generation()
    }

    const fn callback_facts_v0(
        &self,
    ) -> (
        PayloadValidationRouteV0,
        ValidationId,
        PayloadValidationResult,
    ) {
        (
            self.finished.authorized.route,
            self.finished.authorized.validation_id,
            PayloadValidationResult::Valid {
                commitments: self.validated_commitments,
            },
        )
    }
}

/// A comparison mismatch retains the exact finished plan it classified. A
/// later outcome bridge must consume this whole carrier; the copyable cause
/// alone can never recreate body, runtime, state-plan, or parent authority.
#[must_use = "a failed root comparison still owns its exact finished plan"]
pub(super) struct FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0 {
    finished: FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0,
    cause: CoreAuthorizedRegularCommitmentComparisonCauseV0,
}

pub(super) enum CoreAuthorizedRegularFailureOutcomeFactsV0 {
    DeterministicMismatch {
        generation: u64,
        mismatch: CoreAuthorizedRegularComputedRootMismatchV0,
    },
    Invariant {
        generation: u64,
    },
}

impl FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0 {
    pub(super) const fn outcome_facts_v0(&self) -> CoreAuthorizedRegularFailureOutcomeFactsV0 {
        let generation = self.finished.authorized.validation_id.generation();
        match self.cause {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(mismatch) => {
                CoreAuthorizedRegularFailureOutcomeFactsV0::DeterministicMismatch {
                    generation,
                    mismatch,
                }
            }
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(_) => {
                CoreAuthorizedRegularFailureOutcomeFactsV0::Invariant { generation }
            }
        }
    }

    const fn callback_facts_v0(
        &self,
    ) -> (
        PayloadValidationRouteV0,
        ValidationId,
        PayloadValidationResult,
    ) {
        (
            self.finished.authorized.route,
            self.finished.authorized.validation_id,
            PayloadValidationResult::DeterministicallyInvalid,
        )
    }
}

impl std::fmt::Debug for FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0")
            .field("retains_exact_finished_plan", &true)
            .finish_non_exhaustive()
    }
}

/// Process-local disposition of one complete owning comparator result. Every
/// branch retains the exact matched or failed carrier it classified; this is
/// deliberately not an execution outcome, payload-validation result, Core
/// callback, persistence token, or ABCI authority.
#[must_use = "a classified runtime commitment owner is not terminal host authority"]
enum ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 {
    Valid(Box<MatchedCoreAuthorizedRegularRuntimeCommitmentsV0>),
    DeterministicallyInvalid(Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>),
    InvariantFault(Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>),
}

/// App-private production execution authority after the owning comparator.
///
/// Only the `Valid` branch is promoted into the execution-outcome kernel in
/// this slice. Root mismatches and comparator invariants retain their exact
/// failed owner and cannot be converted into `Valid` by a detached cause.
#[must_use = "a promoted regular execution outcome still owns its exact comparator carrier"]
enum CoreAuthorizedRegularExecutionOutcomeV0 {
    Valid(
        crate::execution_outcome::ExecutionOutcomeV0<
            Box<MatchedCoreAuthorizedRegularRuntimeCommitmentsV0>,
        >,
    ),
    DeterministicallyInvalid(RetainedFailedCoreAuthorizedRegularExecutionOutcomeV0),
    InvariantFault(RetainedFailedCoreAuthorizedRegularExecutionOutcomeV0),
}

struct RetainedFailedCoreAuthorizedRegularExecutionOutcomeV0 {
    outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
    failed: Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>,
}

/// One consuming Core callback carrier derived only from the retained
/// route/full validation identity and terminal execution outcome. It has no
/// constructor accepting detached callback facts.
#[must_use = "a terminal payload-validation callback must be consumed exactly once"]
struct CoreAuthorizedRegularPayloadValidationCallbackV0 {
    outcome: CoreAuthorizedRegularExecutionOutcomeV0,
}

enum CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0 {
    Ready(CoreAuthorizedRegularPayloadValidationCallbackV0),
    InvariantFault(CoreAuthorizedRegularExecutionOutcomeV0),
}

impl CoreAuthorizedRegularPayloadValidationCallbackV0 {
    fn into_core_input(self) -> Input {
        let (route, id, result) = match &self.outcome {
            CoreAuthorizedRegularExecutionOutcomeV0::Valid(outcome) => outcome
                .successful_execution()
                .expect("Valid outcome structurally retains its matched owner")
                .callback_facts_v0(),
            CoreAuthorizedRegularExecutionOutcomeV0::DeterministicallyInvalid(retained) => {
                retained.failed.callback_facts_v0()
            }
            CoreAuthorizedRegularExecutionOutcomeV0::InvariantFault(_) => {
                unreachable!("invariant faults cannot construct a Core callback carrier")
            }
        };
        match route {
            PayloadValidationRouteV0::Proposal => Input::PayloadValidated { id, result },
            PayloadValidationRouteV0::Synced => Input::SyncedPayloadValidated { id, result },
        }
    }
}

impl std::fmt::Debug for CoreAuthorizedRegularExecutionOutcomeV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let disposition = match self {
            Self::Valid(_) => "valid",
            Self::DeterministicallyInvalid(_) => "deterministically_invalid_pending_promotion",
            Self::InvariantFault(_) => "invariant_fault_pending_promotion",
        };
        formatter
            .debug_struct("CoreAuthorizedRegularExecutionOutcomeV0")
            .field("disposition", &disposition)
            .field("retains_exact_owner", &true)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let disposition = match self {
            Self::Valid(_) => "valid",
            Self::DeterministicallyInvalid(_) => "deterministically_invalid",
            Self::InvariantFault(_) => "invariant_fault",
        };
        formatter
            .debug_struct("ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0")
            .field("disposition", &disposition)
            .field("retains_exact_owner", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CoreAuthorizedRegularPostStatePlanCauseV0 {
    IncompleteBody { executed: u32, expected: u32 },
    RuntimeProvenanceInvariant,
    ReceiptReplayStateRead(AuthenticatedRuntimeReadFailureV0),
    ReceiptMutationDeltaInvariant,
    StateDeltaProvenanceInvariant,
    PrepareWritesInvariant,
    Plan(AuthenticatedRuntimeReadFailureV0),
    PlanTargetInvariant,
    PlanSealInvariant,
}

/// A snapshot close failure always outranks a pending completeness, encoding,
/// or JMT-planning cause.
#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedRegularPostStatePlanCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Plan(CoreAuthorizedRegularPostStatePlanCauseV0),
}

/// Snapshot-closed post-state failure which retains the exact authorized body,
/// cursor index, final delta, and successful runtime attempts. A successful
/// plan/seal is deliberately discarded when snapshot close fails.
#[must_use = "a closed post-state failure still retains its exact cursor owner"]
struct ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    next_transaction_index: u32,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
    cause: ClosedCoreAuthorizedRegularPostStatePlanCauseV0,
}

#[derive(Debug, PartialEq, Eq)]
enum CoreAuthorizedRegularCompleteBodyPlanCauseV0 {
    IncompleteBody { executed: u32, expected: u32 },
    CompleteBodyProvenanceInvariant,
    ReceiptReplayStateRead(AuthenticatedRuntimeReadFailureV0),
    ReceiptMutationDeltaInvariant,
    StateDeltaProvenanceInvariant,
    PrepareWritesInvariant,
    ValidatorHeightPreparationInvariant,
    ValidatorWriteInvariant,
    PocoScheduleInvariant,
    PocoCutoffProjectionRead(AuthenticatedRuntimeReadFailureV0),
    PocoCutoffWriteInvariant,
    MergedWriteKeyConflictInvariant,
    MergedWriteHashCollisionInvariant,
    Plan(AuthenticatedRuntimeReadFailureV0),
    PlanWriteSetInvariant,
    PlanTargetInvariant,
    PlanSealInvariant,
}

#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Plan(CoreAuthorizedRegularCompleteBodyPlanCauseV0),
}

/// Snapshot-closed complete-body planning failure. This owner is deliberately
/// distinct from the runtime-only post-state failure that already has an
/// execution-outcome promotion bridge; no receipt or terminal classification
/// can be derived from this planning-only tranche.
#[must_use = "a failed complete-body plan retains its exact closed cursor"]
struct ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    next_transaction_index: u32,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
    cause: ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0,
}

impl std::fmt::Debug for ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0")
            .field("retains_exact_closed_mixed_cursor", &true)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedFailedCoreAuthorizedRegularPostStatePlanV0")
            .field("retains_exact_closed_cursor", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreAuthorizedRegularComputedRootMismatchV0 {
    State,
    Receipts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreAuthorizedRegularCommitmentInvariantV0 {
    TransactionCount,
    TransactionProvenance,
    ReceiptMutationDelta,
    PlannedStateDelta,
    NativeReceiptRebuild,
    NativeExecutionRebuild,
    PlannedStateSeal,
    PlannedStateVersion,
    CompleteBodyProvenance,
    CompleteBodyPocoWrites,
    CompleteBodyValidatorWrite,
    CompleteBodyMergedWrites,
    PayloadRootComputation,
    AuthorizedPayloadRootDrift,
    ReceiptsRootComputation,
    EvidenceRootComputation,
    AuthorizedEvidenceRootDrift,
    StaticCommitmentRevalidation,
    BlockIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreAuthorizedRegularCommitmentComparisonCauseV0 {
    DeterministicMismatch(CoreAuthorizedRegularComputedRootMismatchV0),
    Invariant(CoreAuthorizedRegularCommitmentInvariantV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreAuthorizedRegularTransactionDecodeCauseV0 {
    Exhausted,
    IndexOverflow,
    InvalidEnvelope,
    InvalidOrUnauthorizedEnvelope,
    NonRuntimePayload,
    InvalidCanonicalTransaction,
    SenderMismatch,
    NonceMismatch,
}

/// A pending decode failure cannot reveal its classification until the same
/// authenticated snapshot has explicitly finished. Debug intentionally omits
/// both the cause and retained authority.
#[must_use = "a failed transaction decode must explicitly finish its exact parent snapshot"]
struct FailedCoreAuthorizedRegularTransactionDecodeV0 {
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
    cause: CoreAuthorizedRegularTransactionDecodeCauseV0,
}

impl std::fmt::Debug for FailedCoreAuthorizedRegularTransactionDecodeV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedRegularTransactionDecodeV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClosedCoreAuthorizedRegularTransactionDecodeCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Decode(CoreAuthorizedRegularTransactionDecodeCauseV0),
}

/// Snapshot-closed decode failure retaining the exact authorized body and all
/// cursor facts produced before the failed index. This is not a terminal
/// classification and cannot be reconstructed from the copyable cause.
#[must_use = "a closed decode failure still retains its exact cursor owner"]
struct ClosedFailedCoreAuthorizedRegularTransactionDecodeV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    next_transaction_index: u32,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedCoreAuthorizedRuntimeTransactionV0>,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
    cause: ClosedCoreAuthorizedRegularTransactionDecodeCauseV0,
}

impl std::fmt::Debug for ClosedFailedCoreAuthorizedRegularTransactionDecodeV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedFailedCoreAuthorizedRegularTransactionDecodeV0")
            .field("retains_exact_closed_cursor", &true)
            .finish_non_exhaustive()
    }
}

fn authenticated_non_runtime_read_outcome_facts_v0(
    generation: u64,
    failure: &AuthenticatedRuntimeReadFailureV0,
    invariant: fn(
        CoreAuthorizedRegularNonRuntimeSourceInvariantV0,
    ) -> CoreAuthorizedRegularNonRuntimeInvariantV0,
) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
    let kind = match failure {
        AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { .. } => {
            CoreAuthorizedRegularNonRuntimeUnavailableKindV0::Database
        }
        AuthenticatedRuntimeReadFailureV0::StorageUnavailable { .. } => {
            CoreAuthorizedRegularNonRuntimeUnavailableKindV0::StorageIo
        }
        AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. } => {
            CoreAuthorizedRegularNonRuntimeUnavailableKindV0::HostResource
        }
        AuthenticatedRuntimeReadFailureV0::Pruned { .. } => {
            CoreAuthorizedRegularNonRuntimeUnavailableKindV0::ParentStateMissing
        }
        AuthenticatedRuntimeReadFailureV0::SourceMismatch { .. } => {
            CoreAuthorizedRegularNonRuntimeUnavailableKindV0::ParentStateUnauthenticated
        }
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. } => {
            return CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::invariant(
                generation,
                invariant(CoreAuthorizedRegularNonRuntimeSourceInvariantV0::AuthenticatedState),
            );
        }
        AuthenticatedRuntimeReadFailureV0::HostInvariant { .. } => {
            return CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::invariant(
                generation,
                invariant(CoreAuthorizedRegularNonRuntimeSourceInvariantV0::Host),
            );
        }
    };
    CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::unavailable(generation, kind)
}

trait ClosedCoreAuthorizedRegularNonRuntimeFailureV0 {
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0;
}

impl ClosedCoreAuthorizedRegularNonRuntimeFailureV0
    for ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0
{
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
        let (owner, cause) = match self {
            Self::PocoApplication { owner, cause } | Self::ValidatorTransition { owner, cause } => {
                (owner, cause)
            }
        };
        let generation = owner.authorized.validation_id.generation();
        match cause {
            ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Snapshot(failure) => {
                authenticated_non_runtime_read_outcome_facts_v0(
                    generation,
                    failure,
                    CoreAuthorizedRegularNonRuntimeInvariantV0::SemanticDecodeSnapshot,
                )
            }
            ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Decode(reason) => {
                CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::deterministically_invalid(
                    generation,
                    CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0::SemanticDecode(*reason),
                )
            }
        }
    }
}

impl ClosedCoreAuthorizedRegularNonRuntimeFailureV0
    for ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0
{
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
        let (owner, cause) = match self {
            Self::PocoApplication { owner, cause, .. }
            | Self::ValidatorTransition { owner, cause, .. }
            | Self::Unsupported { owner, cause } => (owner, cause),
        };
        let generation = owner.authorized.validation_id.generation();
        match cause {
            ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Snapshot(failure) => {
                authenticated_non_runtime_read_outcome_facts_v0(
                    generation,
                    failure,
                    CoreAuthorizedRegularNonRuntimeInvariantV0::FamilySnapshot,
                )
            }
            ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(failure),
            ) => authenticated_non_runtime_read_outcome_facts_v0(
                generation,
                failure,
                CoreAuthorizedRegularNonRuntimeInvariantV0::FamilyAuthenticatedSource,
            ),
            ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(reason),
            ) => CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::deterministically_invalid(
                generation,
                CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0::Family(*reason),
            ),
            ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(reason),
            ) => CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::invariant(
                generation,
                CoreAuthorizedRegularNonRuntimeInvariantV0::Family(*reason),
            ),
        }
    }
}

impl ClosedCoreAuthorizedRegularNonRuntimeFailureV0
    for ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0
{
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {
        let (owner, cause) = match self {
            Self::PocoApplication { owner, cause, .. }
            | Self::ValidatorTransition { owner, cause, .. } => (owner, cause),
        };
        let generation = owner.authorized.validation_id.generation();
        match cause {
            ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Snapshot(failure) => {
                authenticated_non_runtime_read_outcome_facts_v0(
                    generation,
                    failure,
                    CoreAuthorizedRegularNonRuntimeInvariantV0::WriteSealSnapshot,
                )
            }
            ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(reason) => {
                CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0::invariant(
                    generation,
                    CoreAuthorizedRegularNonRuntimeInvariantV0::WriteSeal(*reason),
                )
            }
        }
    }
}

fn authenticated_pre_execution_read_outcome_facts_v0(
    generation: u64,
    failure: &AuthenticatedRuntimeReadFailureV0,
    invariant_stage: CoreAuthorizedRegularPreExecutionInvariantStageV0,
) -> CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
    let kind = match failure {
        AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { .. } => {
            CoreAuthorizedRegularPreExecutionUnavailableKindV0::Database
        }
        AuthenticatedRuntimeReadFailureV0::StorageUnavailable { .. } => {
            CoreAuthorizedRegularPreExecutionUnavailableKindV0::StorageIo
        }
        AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. } => {
            CoreAuthorizedRegularPreExecutionUnavailableKindV0::HostResource
        }
        AuthenticatedRuntimeReadFailureV0::Pruned { .. } => {
            CoreAuthorizedRegularPreExecutionUnavailableKindV0::ParentStateMissing
        }
        AuthenticatedRuntimeReadFailureV0::SourceMismatch { .. } => {
            CoreAuthorizedRegularPreExecutionUnavailableKindV0::ParentStateUnauthenticated
        }
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        | AuthenticatedRuntimeReadFailureV0::HostInvariant { .. } => {
            return CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                generation,
                stage: invariant_stage,
            };
        }
    };
    CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Unavailable { generation, kind }
}

impl FailedCoreIssuedRegularValidationOpenV0 {
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
        let generation = self.owner.request.id().generation();
        match &self.cause {
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(failure) => {
                authenticated_pre_execution_read_outcome_facts_v0(
                    generation,
                    failure,
                    CoreAuthorizedRegularPreExecutionInvariantStageV0::Open,
                )
            }
            OpenCoreAuthorizedRegularValidationFailureV0::SourceUnavailable(_) => {
                CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Unavailable {
                    generation,
                    kind: CoreAuthorizedRegularPreExecutionUnavailableKindV0::BodySource,
                }
            }
            OpenCoreAuthorizedRegularValidationFailureV0::DeterministicallyInvalid(_) => {
                CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::DeterministicallyInvalid {
                    generation,
                    kind: CoreAuthorizedRegularPreExecutionInvalidKindV0::BodyEvidence,
                }
            }
            OpenCoreAuthorizedRegularValidationFailureV0::Invariant(_) => {
                CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                    generation,
                    stage: CoreAuthorizedRegularPreExecutionInvariantStageV0::Open,
                }
            }
        }
    }
}

impl FailedCoreIssuedRegularValidationReservationV0 {
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
        let generation = self.owner.request.id().generation();
        let kind = match &self.cause {
            CoreIssuedRegularValidationReservationCauseV0::FingerprintInvariant(_)
            | CoreIssuedRegularValidationReservationCauseV0::RequestRecordInvariant(_) => {
                return CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                    generation,
                    stage: CoreAuthorizedRegularPreExecutionInvariantStageV0::Reservation,
                };
            }
            CoreIssuedRegularValidationReservationCauseV0::Store(failed) => match failed.cause() {
                NativeValidationReservationFailureCauseV0::DatabaseUnavailable { .. } => {
                    CoreAuthorizedRegularPreExecutionUnavailableKindV0::Database
                }
                NativeValidationReservationFailureCauseV0::StorageUnavailable { .. } => {
                    CoreAuthorizedRegularPreExecutionUnavailableKindV0::StorageIo
                }
                NativeValidationReservationFailureCauseV0::HostResourceUnavailable { .. } => {
                    CoreAuthorizedRegularPreExecutionUnavailableKindV0::HostResource
                }
                NativeValidationReservationFailureCauseV0::Capacity { .. }
                | NativeValidationReservationFailureCauseV0::ByteCapacity { .. } => {
                    CoreAuthorizedRegularPreExecutionUnavailableKindV0::ReservationCapacity
                }
                NativeValidationReservationFailureCauseV0::Invariant { .. }
                | NativeValidationReservationFailureCauseV0::HostInvariant { .. } => {
                    return CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                        generation,
                        stage: CoreAuthorizedRegularPreExecutionInvariantStageV0::Reservation,
                    };
                }
            },
        };
        CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Unavailable { generation, kind }
    }
}

impl ClosedFailedCoreAuthorizedRegularTransactionDecodeV0 {
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
        let generation = self.authorized.validation_id.generation();
        match &self.cause {
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Snapshot(failure) => {
                authenticated_pre_execution_read_outcome_facts_v0(
                    generation,
                    failure,
                    CoreAuthorizedRegularPreExecutionInvariantStageV0::TransactionDecode,
                )
            }
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(
                CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope
                | CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidOrUnauthorizedEnvelope
                | CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction
                | CoreAuthorizedRegularTransactionDecodeCauseV0::SenderMismatch
                | CoreAuthorizedRegularTransactionDecodeCauseV0::NonceMismatch,
            ) => CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::DeterministicallyInvalid {
                generation,
                kind: CoreAuthorizedRegularPreExecutionInvalidKindV0::TransactionEncodingOrAuthorization,
            },
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(
                CoreAuthorizedRegularTransactionDecodeCauseV0::Exhausted
                | CoreAuthorizedRegularTransactionDecodeCauseV0::IndexOverflow
                | CoreAuthorizedRegularTransactionDecodeCauseV0::NonRuntimePayload,
            ) => CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                generation,
                stage: CoreAuthorizedRegularPreExecutionInvariantStageV0::TransactionDecode,
            },
        }
    }
}

impl ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {
    fn outcome_facts_v0(&self) -> CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0 {
        let generation = self.authorized.validation_id.generation();
        match &self.cause {
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(failure)
            | ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptReplayStateRead(failure)
                | CoreAuthorizedRegularPostStatePlanCauseV0::Plan(failure),
            ) => authenticated_pre_execution_read_outcome_facts_v0(
                generation,
                failure,
                CoreAuthorizedRegularPreExecutionInvariantStageV0::PostStatePlan,
            ),
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::IncompleteBody { .. }
                | CoreAuthorizedRegularPostStatePlanCauseV0::RuntimeProvenanceInvariant
                | CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
                | CoreAuthorizedRegularPostStatePlanCauseV0::StateDeltaProvenanceInvariant
                | CoreAuthorizedRegularPostStatePlanCauseV0::PrepareWritesInvariant
                | CoreAuthorizedRegularPostStatePlanCauseV0::PlanTargetInvariant
                | CoreAuthorizedRegularPostStatePlanCauseV0::PlanSealInvariant,
            ) => CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant {
                generation,
                stage: CoreAuthorizedRegularPreExecutionInvariantStageV0::PostStatePlan,
            },
        }
    }
}

#[allow(dead_code)]
struct RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<Owner> {
    outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
    failed: Box<Owner>,
}

fn retain_pre_execution_failure_outcome_v0<Owner>(
    failed: Box<Owner>,
    facts: CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0,
) -> RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<Owner> {
    let outcome =
        crate::execution_outcome::failure_from_core_authorized_regular_pre_execution_v0(facts);
    RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0 { outcome, failed }
}

#[allow(dead_code)]
fn promote_failed_core_issued_regular_validation_open_v0(
    failed: Box<FailedCoreIssuedRegularValidationOpenV0>,
) -> RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<
    FailedCoreIssuedRegularValidationOpenV0,
> {
    let facts = failed.outcome_facts_v0();
    retain_pre_execution_failure_outcome_v0(failed, facts)
}

#[allow(dead_code)]
fn promote_failed_core_issued_regular_validation_reservation_v0(
    failed: Box<FailedCoreIssuedRegularValidationReservationV0>,
) -> RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<
    FailedCoreIssuedRegularValidationReservationV0,
> {
    let facts = failed.outcome_facts_v0();
    retain_pre_execution_failure_outcome_v0(failed, facts)
}

#[allow(dead_code)]
fn promote_closed_core_authorized_regular_transaction_decode_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedRegularTransactionDecodeV0>,
) -> RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<
    ClosedFailedCoreAuthorizedRegularTransactionDecodeV0,
> {
    let facts = failed.outcome_facts_v0();
    retain_pre_execution_failure_outcome_v0(failed, facts)
}

#[allow(dead_code)]
fn promote_closed_core_authorized_regular_post_state_plan_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedRegularPostStatePlanV0>,
) -> RetainedCoreAuthorizedRegularPreExecutionFailureOutcomeV0<
    ClosedFailedCoreAuthorizedRegularPostStatePlanV0,
> {
    let facts = failed.outcome_facts_v0();
    retain_pre_execution_failure_outcome_v0(failed, facts)
}

/// Process-local disposition of one snapshot-closed non-runtime failure. Every
/// branch retains the complete semantic/family owner; the three-way type split
/// prevents retryable source loss and fail-stop invariants from being confused
/// with a terminal deterministic rejection. No branch is callback authority.
#[must_use = "a promoted non-runtime failure still retains its exact closed owner"]
enum RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0<Owner> {
    Unavailable {
        outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
        failed: Box<Owner>,
    },
    DeterministicallyInvalid {
        outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
        failed: Box<Owner>,
    },
    InvariantFault {
        outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
        failed: Box<Owner>,
    },
}

fn retain_non_runtime_failure_outcome_v0<Owner>(
    failed: Box<Owner>,
) -> RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0<Owner>
where
    Owner: ClosedCoreAuthorizedRegularNonRuntimeFailureV0,
{
    let facts = failed.outcome_facts_v0();
    match facts.disposition {
        CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Unavailable { .. } => {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable {
                outcome:
                    crate::execution_outcome::failure_from_core_authorized_regular_non_runtime_v0(
                        facts,
                    ),
                failed,
            }
        }
        CoreAuthorizedRegularNonRuntimeFailureDispositionV0::DeterministicallyInvalid {
            ..
        } => RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
            outcome: crate::execution_outcome::failure_from_core_authorized_regular_non_runtime_v0(
                facts,
            ),
            failed,
        },
        CoreAuthorizedRegularNonRuntimeFailureDispositionV0::Invariant { .. } => {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome:
                    crate::execution_outcome::failure_from_core_authorized_regular_non_runtime_v0(
                        facts,
                    ),
                failed,
            }
        }
    }
}

#[allow(dead_code)]
fn promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0>,
) -> RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0<
    ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0,
> {
    retain_non_runtime_failure_outcome_v0(failed)
}

#[allow(dead_code)]
fn promote_closed_core_authorized_non_runtime_family_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0>,
) -> RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0<
    ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0,
> {
    retain_non_runtime_failure_outcome_v0(failed)
}

#[allow(dead_code)]
fn promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0>,
) -> RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0<
    ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0,
> {
    retain_non_runtime_failure_outcome_v0(failed)
}

struct CoreAuthorizedRegularRuntimeStateViewV0<'a> {
    changes: &'a BTreeMap<String, StoredObject>,
    snapshot: &'a AuthenticatedRuntimeReadSnapshotV0,
}

impl TryStateViewV0 for CoreAuthorizedRegularRuntimeStateViewV0<'_> {
    type Error = AuthenticatedRuntimeReadFailureV0;

    fn try_get(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StateObject>, Self::Error> {
        let object = match self.changes.get(object_key_hex) {
            Some(object) => Some(object.clone()),
            None => self.snapshot.load(object_key_hex)?,
        };
        Ok(object.map(|object| StateObject {
            object_type: object.object_type,
            version: object.version,
            value_bytes: object.value_bytes,
        }))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CoreAuthorizedRegularRuntimeMutationStageFailureV0 {
    StateRead(AuthenticatedRuntimeReadFailureV0),
    Invariant(CoreAuthorizedRegularRuntimeMutationInvariantV0),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreAuthorizedRegularRuntimeMutationInvariantV0 {
    NonCanonicalAccountValue,
    NonCanonicalAccountIdentity,
    NonCanonicalTaskValue,
    NonCanonicalTaskIdentity,
    NonCanonicalFeePolicyValue,
    InvalidFeePolicyValue,
    NonCanonicalMonetaryStateValue,
    UnknownObjectType,
    CanonicalKeyMismatch,
    UnreachableTaskState,
    DuplicateObjectKey,
    PocoAuthorityWrite,
    ExpectedVersionMismatch,
    AuthenticatedObjectTypeMismatch,
    ObjectVersionExhausted,
    NextVersionMismatch,
}

impl CoreAuthorizedRegularRuntimeMutationInvariantV0 {
    #[cfg(test)]
    const fn reason(self) -> &'static str {
        match self {
            Self::NonCanonicalAccountValue => "runtime account mutation value is not canonical",
            Self::NonCanonicalAccountIdentity => {
                "runtime account mutation identity is not canonical"
            }
            Self::NonCanonicalTaskValue => "runtime task mutation value is not canonical",
            Self::NonCanonicalTaskIdentity => "runtime task mutation identity is not canonical",
            Self::NonCanonicalFeePolicyValue => {
                "runtime fee-policy mutation value is not canonical"
            }
            Self::InvalidFeePolicyValue => {
                "runtime fee-policy mutation value is outside canonical bounds"
            }
            Self::NonCanonicalMonetaryStateValue => {
                "runtime monetary-state mutation value is not canonical"
            }
            Self::UnknownObjectType => "runtime mutation uses an unknown object type",
            Self::CanonicalKeyMismatch => {
                "runtime mutation key differs from its canonical typed value"
            }
            Self::UnreachableTaskState => "runtime task mutation state is not reachable",
            Self::DuplicateObjectKey => "runtime receipt repeats an object key",
            Self::PocoAuthorityWrite => {
                "runtime receipt targets the immutable PoCO authority object"
            }
            Self::ExpectedVersionMismatch => {
                "runtime mutation expected version differs from the session view"
            }
            Self::AuthenticatedObjectTypeMismatch => {
                "runtime mutation changes an authenticated object type"
            }
            Self::ObjectVersionExhausted => "runtime mutation advances an exhausted object version",
            Self::NextVersionMismatch => "runtime mutation next version is not the exact successor",
        }
    }
}

enum CoreAuthorizedRegularRuntimeStepFailureV0 {
    Runtime(RuntimeExecutionAttemptFailureV0<AuthenticatedRuntimeReadFailureV0>),
    StateRead(AuthenticatedRuntimeReadFailureV0),
    NativeReceiptInvariant,
    MutationInvariant(CoreAuthorizedRegularRuntimeMutationInvariantV0),
}

/// A failed runtime step destroys every prior runtime delta and receipt but
/// retains any prior staged non-runtime prefix, the exact body/configuration,
/// failed prepared transaction, and open parent snapshot as one non-cloneable
/// value. Its classification is unavailable until explicit snapshot finish.
#[must_use = "a failed runtime attempt must explicitly finish its exact parent snapshot"]
struct FailedCoreAuthorizedRegularRuntimeAttemptV0 {
    open: OpenCoreAuthorizedRegularValidationV0,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
    failed_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
    cause: CoreAuthorizedRegularRuntimeStepFailureV0,
}

impl std::fmt::Debug for FailedCoreAuthorizedRegularRuntimeAttemptV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedCoreAuthorizedRegularRuntimeAttemptV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

enum ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Attempt(CoreAuthorizedRegularRuntimeStepFailureV0),
}

/// Snapshot-closed runtime failure provenance. It retains the exact authorized
/// body, failed transaction facts, and any prior staged non-runtime prefix, but
/// never prior mutable runtime delta/receipts (which the failed attempt
/// intentionally destroyed).
#[must_use = "a closed runtime failure still retains its exact attempt owner"]
pub(super) struct ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0 {
    authorized: CoreAuthorizedExactRegularBodyV0,
    applied_non_runtime: Vec<AppliedCoreAuthorizedNonRuntimePayloadV0>,
    poco_prefix: Option<Box<CoreAuthorizedRegularPocoPrefixV0>>,
    validator_prefix: Option<Box<CoreAuthorizedRegularValidatorPrefixV0>>,
    failed_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
    cause: ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoreAuthorizedRegularRuntimeUnavailableKindV0 {
    RuntimeDependency,
    Database,
    StorageIo,
    ParentStateMissing,
    ParentStateUnauthenticated,
}

pub(super) enum CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0 {
    Unavailable {
        generation: u64,
        kind: CoreAuthorizedRegularRuntimeUnavailableKindV0,
    },
    DeterministicallyInvalid {
        generation: u64,
        runtime_code: &'static str,
        runtime_reason: &'static str,
    },
    Invariant {
        generation: u64,
        runtime_detail: Option<(&'static str, &'static str)>,
    },
}

fn authenticated_runtime_read_outcome_facts_v0(
    generation: u64,
    failure: &AuthenticatedRuntimeReadFailureV0,
) -> CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0 {
    let kind = match failure {
        AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { .. } => {
            CoreAuthorizedRegularRuntimeUnavailableKindV0::Database
        }
        AuthenticatedRuntimeReadFailureV0::StorageUnavailable { .. } => {
            CoreAuthorizedRegularRuntimeUnavailableKindV0::StorageIo
        }
        AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. } => {
            CoreAuthorizedRegularRuntimeUnavailableKindV0::RuntimeDependency
        }
        AuthenticatedRuntimeReadFailureV0::Pruned { .. } => {
            CoreAuthorizedRegularRuntimeUnavailableKindV0::ParentStateMissing
        }
        AuthenticatedRuntimeReadFailureV0::SourceMismatch { .. } => {
            CoreAuthorizedRegularRuntimeUnavailableKindV0::ParentStateUnauthenticated
        }
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        | AuthenticatedRuntimeReadFailureV0::HostInvariant { .. } => {
            return CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Invariant {
                generation,
                runtime_detail: None,
            };
        }
    };
    CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Unavailable { generation, kind }
}

impl ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0 {
    pub(super) fn outcome_facts_v0(&self) -> CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0 {
        let generation = self.authorized.validation_id.generation();
        match &self.cause {
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Snapshot(failure)
            | ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(
                CoreAuthorizedRegularRuntimeStepFailureV0::StateRead(failure),
            ) => authenticated_runtime_read_outcome_facts_v0(generation, failure),
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(
                CoreAuthorizedRegularRuntimeStepFailureV0::Runtime(attempt),
            ) => {
                if let Some(failure) = attempt.deterministic_failure_v0() {
                    return match failure.disposition() {
                        trnm_runtime::DeterministicRuntimeFailureDispositionV0::TransactionReject => {
                            CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::DeterministicallyInvalid {
                                generation,
                                runtime_code: failure.code(),
                                runtime_reason: failure.reason(),
                            }
                        }
                        trnm_runtime::DeterministicRuntimeFailureDispositionV0::InvariantFault => {
                            CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Invariant {
                                generation,
                                runtime_detail: Some((failure.code(), failure.reason())),
                            }
                        }
                    };
                }
                authenticated_runtime_read_outcome_facts_v0(
                    generation,
                    attempt
                        .state_unavailable()
                        .expect("runtime attempt failure has one exhaustive opaque branch"),
                )
            }
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(
                CoreAuthorizedRegularRuntimeStepFailureV0::NativeReceiptInvariant
                | CoreAuthorizedRegularRuntimeStepFailureV0::MutationInvariant(_),
            ) => CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Invariant {
                generation,
                runtime_detail: None,
            },
        }
    }
}

struct RetainedClosedCoreAuthorizedRegularRuntimeFailureOutcomeV0 {
    outcome: crate::execution_outcome::ExecutionOutcomeV0<()>,
    failed: Box<ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0>,
}

#[allow(dead_code)]
fn promote_closed_core_authorized_regular_runtime_failure_v0(
    failed: Box<ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0>,
) -> RetainedClosedCoreAuthorizedRegularRuntimeFailureOutcomeV0 {
    let outcome =
        crate::execution_outcome::failure_from_core_authorized_regular_runtime_attempt_v0(&failed);
    RetainedClosedCoreAuthorizedRegularRuntimeFailureOutcomeV0 { outcome, failed }
}

impl std::fmt::Debug for ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0")
            .field("retains_exact_closed_attempt", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreAuthorizedExactRegularBodyFailureClassV0 {
    SourceUnavailable,
    DeterministicallyInvalid,
    Invariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreAuthorizedExactRegularBodyFailureV0 {
    class: CoreAuthorizedExactRegularBodyFailureClassV0,
    reason: &'static str,
}

impl CoreAuthorizedExactRegularBodyFailureV0 {
    const fn source_unavailable(reason: &'static str) -> Self {
        Self {
            class: CoreAuthorizedExactRegularBodyFailureClassV0::SourceUnavailable,
            reason,
        }
    }

    const fn deterministically_invalid(reason: &'static str) -> Self {
        Self {
            class: CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid,
            reason,
        }
    }

    const fn invariant(reason: &'static str) -> Self {
        Self {
            class: CoreAuthorizedExactRegularBodyFailureClassV0::Invariant,
            reason,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OpenCoreAuthorizedRegularValidationFailureV0 {
    AuthenticatedSource(AuthenticatedRuntimeReadFailureV0),
    SourceUnavailable(CoreAuthorizedExactRegularBodyFailureV0),
    DeterministicallyInvalid(CoreAuthorizedExactRegularBodyFailureV0),
    Invariant(CoreAuthorizedExactRegularBodyFailureV0),
}

fn classify_exact_regular_body_failure_v0(
    failure: CoreAuthorizedExactRegularBodyFailureV0,
) -> OpenCoreAuthorizedRegularValidationFailureV0 {
    match failure.class {
        CoreAuthorizedExactRegularBodyFailureClassV0::SourceUnavailable => {
            OpenCoreAuthorizedRegularValidationFailureV0::SourceUnavailable(failure)
        }
        CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid => {
            OpenCoreAuthorizedRegularValidationFailureV0::DeterministicallyInvalid(failure)
        }
        CoreAuthorizedExactRegularBodyFailureClassV0::Invariant => {
            OpenCoreAuthorizedRegularValidationFailureV0::Invariant(failure)
        }
    }
}

fn failed_core_issued_regular_validation_open_v0(
    owner: CoreIssuedRegularValidationOwnerV0,
    cause: OpenCoreAuthorizedRegularValidationFailureV0,
) -> Box<FailedCoreIssuedRegularValidationOpenV0> {
    Box::new(FailedCoreIssuedRegularValidationOpenV0 { owner, cause })
}

/// Consumes one complete Core effect and binds its public dispatch wrapper to
/// the route frozen inside the opaque validation request. Wrapper congruence
/// is checked before the request can be claimed.
#[allow(dead_code)]
fn take_core_regular_validation_job_v0(effect: Effect) -> CoreRegularValidationEffectIntakeV0 {
    match effect {
        Effect::ValidatePayload(request)
            if request.route() == PayloadValidationRouteV0::Proposal =>
        {
            CoreRegularValidationEffectIntakeV0::Job(Box::new(CoreIssuedRegularValidationJobV0 {
                request,
            }))
        }
        Effect::ValidateSyncedPayload(request)
            if request.route() == PayloadValidationRouteV0::Synced =>
        {
            CoreRegularValidationEffectIntakeV0::Job(Box::new(CoreIssuedRegularValidationJobV0 {
                request,
            }))
        }
        Effect::ValidatePayload(request) => CoreRegularValidationEffectIntakeV0::RouteInvariant(
            Box::new(CoreRegularValidationEffectRouteInvariantV0 {
                _effect: Effect::ValidatePayload(request),
            }),
        ),
        Effect::ValidateSyncedPayload(request) => {
            CoreRegularValidationEffectIntakeV0::RouteInvariant(Box::new(
                CoreRegularValidationEffectRouteInvariantV0 {
                    _effect: Effect::ValidateSyncedPayload(request),
                },
            ))
        }
        effect => CoreRegularValidationEffectIntakeV0::Other(Box::new(effect)),
    }
}

/// Claims one route-checked Core job before any host binding or
/// authenticated-state read. Every clone in the same request object graph
/// shares the one-shot gate installed by Core, so this private admission
/// branch suppresses concurrent or replayed clones without reading host state,
/// classifying a block result, or emitting a callback or storage action.
///
/// This volatile gate is not a registry keyed by `ValidationId`: distinct Core
/// instances can independently materialize the same identity. A route-aware
/// durable reservation below closes cross-instance congruence, while a later
/// evaluation artifact/outbox journal remains mandatory before terminal
/// persistence or callback wiring.
#[allow(dead_code)]
fn begin_core_authorized_regular_validation_session_v0(
    host: &NativeValidationHostV0<'_>,
    job: CoreIssuedRegularValidationJobV0,
) -> CoreAuthorizedRegularValidationSessionAdmissionV0 {
    let CoreIssuedRegularValidationJobV0 { request } = job;
    let request = match request.try_claim() {
        Ok(request) => request,
        Err(request) => {
            return CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate(Box::new(
                DuplicateCoreIssuedRegularValidationOwnerV0 { request: *request },
            ));
        }
    };
    reserve_claimed_core_authorized_regular_validation_session_v0(
        host,
        ClaimedCoreIssuedRegularValidationOwnerV0 { request },
    )
}

fn reserve_claimed_core_authorized_regular_validation_session_v0(
    host: &NativeValidationHostV0<'_>,
    owner: ClaimedCoreIssuedRegularValidationOwnerV0,
) -> CoreAuthorizedRegularValidationSessionAdmissionV0 {
    let fingerprint = match native_validation_reservation_fingerprint_v0(&owner.request) {
        Ok(fingerprint) => fingerprint,
        Err(cause) => {
            return CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(Box::new(
                FailedCoreIssuedRegularValidationReservationV0 {
                    owner,
                    cause: CoreIssuedRegularValidationReservationCauseV0::FingerprintInvariant(
                        cause,
                    ),
                },
            ));
        }
    };
    let facts = match NativeValidationReservationFactsV0::from_core_request_v0(
        owner.request.route(),
        owner.request.id(),
        owner.request.block(),
        owner.request.parent(),
        fingerprint,
    ) {
        Ok(facts) => facts,
        Err(cause) => {
            return CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(Box::new(
                FailedCoreIssuedRegularValidationReservationV0 {
                    owner,
                    cause: CoreIssuedRegularValidationReservationCauseV0::RequestRecordInvariant(
                        cause,
                    ),
                },
            ));
        }
    };
    let reservation = match host.store.reserve_or_reopen_native_validation_job_v0(facts) {
        Ok(NativeValidationReservationDecisionV0::Reserved(reservation)) => reservation,
        Ok(NativeValidationReservationDecisionV0::Existing(existing)) => {
            debug_assert_eq!(existing.route(), owner.request.route());
            debug_assert_eq!(existing.validation_id(), owner.request.id());
            return CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(Box::new(
                DurablyExistingCoreIssuedRegularValidationOwnerV0 {
                    request: owner.request,
                    existing,
                },
            ));
        }
        Err(cause) => {
            debug_assert_eq!(cause.route(), owner.request.route());
            debug_assert_eq!(cause.validation_id(), owner.request.id());
            return CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(Box::new(
                FailedCoreIssuedRegularValidationReservationV0 {
                    owner,
                    cause: CoreIssuedRegularValidationReservationCauseV0::Store(cause),
                },
            ));
        }
    };
    debug_assert_eq!(reservation.route(), owner.request.route());
    debug_assert_eq!(reservation.validation_id(), owner.request.id());
    let owner = CoreIssuedRegularValidationOwnerV0 {
        request: owner.request,
        reservation: CoreAuthorizedRegularReservationV0::Durable(reservation),
    };
    match open_core_authorized_regular_validation_v0(host, owner) {
        Ok(open) => CoreAuthorizedRegularValidationSessionAdmissionV0::Open(Box::new(open)),
        Err(failed) => CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(failed),
    }
}

/// Retries only by consuming the complete failed owner. The fingerprint and
/// all store facts are re-derived from its retained immutable Core request;
/// no detached route, identity, source hash, or parent can be supplied.
#[allow(dead_code)]
fn retry_failed_core_issued_regular_validation_reservation_v0(
    host: &NativeValidationHostV0<'_>,
    failed: Box<FailedCoreIssuedRegularValidationReservationV0>,
) -> CoreAuthorizedRegularValidationSessionAdmissionV0 {
    let FailedCoreIssuedRegularValidationReservationV0 { owner, cause: _ } = *failed;
    reserve_claimed_core_authorized_regular_validation_session_v0(host, owner)
}

/// Consumes one Core-issued request and opens the only parent/configuration
/// source it authorizes.
///
/// No overload accepts a separately supplied header, body, parent, height,
/// root, validator set, or parameters. The complete namespace-8 projection
/// and lifecycle are read through the same still-open parent transaction.
#[allow(dead_code)]
fn open_core_authorized_regular_validation_v0(
    host: &NativeValidationHostV0<'_>,
    owner: CoreIssuedRegularValidationOwnerV0,
) -> Result<OpenCoreAuthorizedRegularValidationV0, Box<FailedCoreIssuedRegularValidationOpenV0>> {
    if crate::validate_authorized_signers_v1(host.authorized_signers).is_err() {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "native validation host signer policy is not canonical",
                },
            ),
        ));
    }
    if host.chain_id != host.store.configured_chain_id_v0() {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "native validation host chain differs from application store",
                },
            ),
        ));
    }
    let signer_policy_commitment = crate::signer_policy_commitment(host.authorized_signers);
    let configured_signer_policy = match host.store.configured_signer_policy_commitment_v0() {
        Ok(commitment) => commitment,
        Err(error) => {
            return Err(failed_core_issued_regular_validation_open_v0(
                owner,
                OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(error),
            ));
        }
    };
    if signer_policy_commitment != configured_signer_policy {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "native validation host signer policy differs from application store",
                },
            ),
        ));
    }
    let validation_id = owner.request.id();
    let block = owner.request.block();
    let parent = owner.request.parent();
    let header = block.header();
    if validation_id.block_id() != block.id() || validation_id.view() != header.view() {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "Core validation capability differs from its retained block",
                },
            ),
        ));
    }
    if header.block_kind() != BlockKind::Regular {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "Core validation capability is not a regular block",
                },
            ),
        ));
    }
    let Some(parent_header) = parent.exact_header() else {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "trusted genesis parent has no canonical native state-root header",
                },
            ),
        ));
    };
    let expected_target_height = match parent_header.height().checked_next() {
        Ok(height) => height,
        Err(_) => {
            return Err(failed_core_issued_regular_validation_open_v0(
                owner,
                OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                    AuthenticatedRuntimeReadFailureV0::HostInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                        sqlite: None,
                        reason: "Core-authenticated parent height cannot advance",
                    },
                ),
            ));
        }
    };
    if header.parent_id() != parent_header.id() || header.height() != expected_target_height {
        return Err(failed_core_issued_regular_validation_open_v0(
            owner,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    sqlite: None,
                    reason: "Core-authenticated parent differs from retained target ancestry",
                },
            ),
        ));
    }

    let snapshot = match host
        .store
        .begin_authenticated_runtime_read_snapshot_for_core_parent_v0(parent)
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(failed_core_issued_regular_validation_open_v0(
                owner,
                OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(error),
            ));
        }
    };
    let joined = (|| {
        let projection = snapshot.load_authenticated_production_poco_projection_v0()?;
        let (validator_set, parameters) =
            crate::poco_checkpoint::active_consensus_configuration(&projection).map_err(|_| {
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                    sqlite: None,
                    reason: "authenticated parent lacks one exact active consensus configuration",
                }
            })?;
        let validator_lifecycle = snapshot.load_authenticated_validator_lifecycle_v0()?;
        if validator_lifecycle.authorized_signers_hash_hex != hex::encode(signer_policy_commitment)
        {
            return Err(AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                sqlite: None,
                reason: "native validation host signer policy differs from authenticated parent lifecycle",
            });
        }
        validate_snapshot_authenticated_regular_context_v0(
            header,
            parent_header,
            &validator_set,
            &parameters,
            &validator_lifecycle,
        )?;
        Ok(SnapshotAuthenticatedRegularContextV0 {
            parent_header: parent_header.clone(),
            validator_set,
            parameters,
            validator_lifecycle,
            signer_policy: NativeSignerPolicyBindingV0 {
                commitment: signer_policy_commitment,
                authorized_signers: host.authorized_signers.to_vec(),
            },
        })
    })();
    let context = match joined {
        Ok(context) => context,
        Err(error) => {
            return Err(finish_open_regular_validation_failure_v0(Box::new(
                PendingCoreIssuedRegularValidationOpenFailureV0 {
                    snapshot,
                    owner,
                    pending_cause:
                        OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(error),
                },
            )));
        }
    };
    let body = match decode_and_validate_exact_regular_body_v0(validation_id, block, &context) {
        Ok(body) => body,
        Err(error) => {
            return Err(finish_open_regular_validation_failure_v0(Box::new(
                PendingCoreIssuedRegularValidationOpenFailureV0 {
                    snapshot,
                    owner,
                    pending_cause: classify_exact_regular_body_failure_v0(error),
                },
            )));
        }
    };
    let CoreIssuedRegularValidationOwnerV0 {
        request,
        reservation,
    } = owner;
    let (route, validation_id, block, _parent) = request.into_parts();
    let authorized = CoreAuthorizedExactRegularBodyV0 {
        reservation,
        route,
        validation_id,
        header: block.header().clone(),
        body,
        context,
    };
    Ok(OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    })
}

fn decode_and_validate_exact_regular_body_v0(
    validation_id: ValidationId,
    block: &Block,
    context: &SnapshotAuthenticatedRegularContextV0,
) -> Result<BlockBodyV0, CoreAuthorizedExactRegularBodyFailureV0> {
    let validator_set = &context.validator_set;
    let parameters = &context.parameters;
    let header = block.header();
    if validation_id.block_id() != block.id() {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "Core validation identity differs from retained block",
        ));
    }
    if header.block_kind() != BlockKind::Regular {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "Core validation request does not carry a regular block",
        ));
    }
    if header.genesis_hash() != validator_set.genesis_hash()
        || header.chain_id() != validator_set.chain_id()
        || header.protocol_version() != validator_set.protocol_version()
        || header.epoch() != validator_set.epoch()
        || header.validator_set_id() != validator_set.id()
    {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "active validator-set context differs from retained header",
        ));
    }
    if header.consensus_parameters_hash() != parameters.hash()
        || parameters.protocol_version() != header.protocol_version().get()
    {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "active consensus parameters differ from retained header",
        ));
    }
    validator_set
        .validate_against_parameters(parameters)
        .map_err(|_| {
            CoreAuthorizedExactRegularBodyFailureV0::invariant(
                "active validator set fails consensus-parameter bounds",
            )
        })?;
    if validator_set.validator(header.proposer_id()).is_none() {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "retained header proposer is absent from active validator set",
        ));
    }

    let application_payload = decode_application_payload_v0_exact_for_root_binding(
        block.application_payload(),
        parameters,
    )
    .map_err(|_| {
        CoreAuthorizedExactRegularBodyFailureV0::source_unavailable(
            "retained application payload is not exact canonical CEV0",
        )
    })?;
    let evidence = block
        .evidence_objects()
        .iter()
        .map(|bytes| {
            decode_double_vote_evidence_v0_exact(bytes, validator_set).map_err(|_| {
                CoreAuthorizedExactRegularBodyFailureV0::source_unavailable(
                    "retained evidence object is not exact canonical CEV0",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let body = BlockBodyV0::new_admission(application_payload, evidence).map_err(|error| {
        match error.code() {
            BlockValidationErrorCode::NonCanonicalEvidenceOrder
            | BlockValidationErrorCode::DuplicateEvidence => {
                CoreAuthorizedExactRegularBodyFailureV0::source_unavailable(
                    "retained evidence list is not canonical and duplicate-free",
                )
            }
            BlockValidationErrorCode::LogicalBlockSizeExceeded => {
                CoreAuthorizedExactRegularBodyFailureV0::invariant(
                    "cannot admit retained evidence into a bounded canonical body",
                )
            }
            _ => CoreAuthorizedExactRegularBodyFailureV0::invariant(
                "unexpected retained evidence admission failure",
            ),
        }
    })?;

    // A body cannot become deterministically invalid until its exact source
    // bytes have decoded canonically and its payload/evidence commitments have
    // been shown to match the signed header. Computation failures are local
    // invariants; mismatched source material remains retryable Unavailable.
    let payload_root = body.payload_root().map_err(|_| {
        CoreAuthorizedExactRegularBodyFailureV0::invariant("cannot derive retained payload root")
    })?;
    if payload_root != header.payload_root() {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::source_unavailable(
            "retained payload root differs from header commitment",
        ));
    }
    let evidence_root = body.evidence_root().map_err(|_| {
        CoreAuthorizedExactRegularBodyFailureV0::invariant("cannot derive retained evidence root")
    })?;
    if evidence_root != header.evidence_root() {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::source_unavailable(
            "retained evidence root differs from header commitment",
        ));
    }
    body.verify_evidence(validator_set, &StrictEd25519Verifier)
        .map_err(|_| {
            CoreAuthorizedExactRegularBodyFailureV0::deterministically_invalid(
                "retained evidence fails strict Ed25519 verification",
            )
        })?;

    let canonical_logical_block_size = body.logical_block_size_v0(header).map_err(|_| {
        CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "cannot derive retained logical block size",
        )
    })?;
    let host_logical_block_size = usize::try_from(canonical_logical_block_size).map_err(|_| {
        CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "retained logical block size cannot fit the host",
        )
    })?;
    if block.logical_block_size() != host_logical_block_size {
        return Err(CoreAuthorizedExactRegularBodyFailureV0::invariant(
            "retained transport size differs from canonical logical block size",
        ));
    }
    if canonical_logical_block_size > u64::from(parameters.max_block_bytes()) {
        return Err(
            CoreAuthorizedExactRegularBodyFailureV0::deterministically_invalid(
                "retained header/body exceed committed block-size bound",
            ),
        );
    }

    Ok(body)
}

#[cfg(test)]
fn authorize_exact_regular_body_parts_v0(
    validation_id: ValidationId,
    block: Block,
    context: SnapshotAuthenticatedRegularContextV0,
) -> Result<CoreAuthorizedExactRegularBodyV0, CoreAuthorizedExactRegularBodyFailureV0> {
    let body = decode_and_validate_exact_regular_body_v0(validation_id, &block, &context)?;
    Ok(CoreAuthorizedExactRegularBodyV0 {
        reservation: CoreAuthorizedRegularReservationV0::TestOnly,
        route: PayloadValidationRouteV0::Proposal,
        validation_id,
        header: block.header().clone(),
        body,
        context,
    })
}

fn validate_snapshot_authenticated_regular_context_v0(
    header: &BlockHeader,
    parent_header: &BlockHeader,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    lifecycle: &crate::ValidatorLifecycleStateV1,
) -> Result<(), AuthenticatedRuntimeReadFailureV0> {
    let invalid = |reason| AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
        stage: AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
        sqlite: None,
        reason,
    };
    if !matches!(
        parent_header.block_kind(),
        BlockKind::Regular | BlockKind::EpochHandoff
    ) || header.genesis_hash() != parent_header.genesis_hash()
        || header.chain_id() != parent_header.chain_id()
        || header.protocol_version() != parent_header.protocol_version()
        || header.epoch() != parent_header.epoch()
    {
        return Err(invalid(
            "Core-authenticated parent consensus context differs from target header",
        ));
    }
    if header.genesis_hash() != validator_set.genesis_hash()
        || header.chain_id() != validator_set.chain_id()
        || header.protocol_version() != validator_set.protocol_version()
        || header.epoch() != validator_set.epoch()
        || header.validator_set_id() != validator_set.id()
        || parent_header.validator_set_id() != validator_set.id()
    {
        return Err(invalid(
            "authenticated validator configuration differs from native headers",
        ));
    }
    if header.consensus_parameters_hash() != parameters.hash()
        || parent_header.consensus_parameters_hash() != parameters.hash()
        || parameters.protocol_version() != header.protocol_version().get()
    {
        return Err(invalid(
            "authenticated consensus parameters differ from native headers",
        ));
    }
    validator_set
        .validate_against_parameters(parameters)
        .map_err(|_| invalid("authenticated validator set fails exact parameter bounds"))?;
    if validator_set.validator(header.proposer_id()).is_none() {
        return Err(invalid(
            "target proposer is absent from authenticated validator set",
        ));
    }
    crate::poco_checkpoint::validate_application_validator_projection(
        validator_set,
        &lifecycle.active_validators,
    )
    .map_err(|_| invalid("authenticated lifecycle differs from active validator set"))?;
    Ok(())
}

fn finish_open_regular_validation_failure_v0(
    pending: Box<PendingCoreIssuedRegularValidationOpenFailureV0>,
) -> Box<FailedCoreIssuedRegularValidationOpenV0> {
    let PendingCoreIssuedRegularValidationOpenFailureV0 {
        snapshot,
        owner,
        pending_cause,
    } = *pending;
    let cause = match snapshot.finish() {
        Ok(()) => pending_cause,
        Err(error) => OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(error),
    };
    failed_core_issued_regular_validation_open_v0(owner, cause)
}

#[allow(dead_code)]
fn finish_core_authorized_regular_validation_v0(
    open: OpenCoreAuthorizedRegularValidationV0,
) -> Result<
    FinishedCoreAuthorizedRegularValidationV0,
    Box<ClosedFailedCoreAuthorizedRegularValidationV0>,
> {
    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    match snapshot.finish() {
        Ok(()) => Ok(FinishedCoreAuthorizedRegularValidationV0 { authorized }),
        Err(cause) => Err(Box::new(ClosedFailedCoreAuthorizedRegularValidationV0 {
            authorized,
            cause,
        })),
    }
}

/// Opens the production sequential cursor without accepting a caller-supplied
/// body, parent, configuration, signer policy, or transaction index.
#[allow(dead_code)]
fn open_core_authorized_regular_transaction_cursor_from_open_v0(
    open: OpenCoreAuthorizedRegularValidationV0,
) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
    OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index: 0,
        changes: BTreeMap::new(),
        applied: Vec::new(),
        applied_non_runtime: Vec::new(),
        poco_prefix: None,
        validator_prefix: None,
    }
}

#[cfg(test)]
fn core_regular_validation_job_for_test_v0(
    request: PayloadValidationRequest,
) -> CoreIssuedRegularValidationJobV0 {
    let effect = match request.route() {
        PayloadValidationRouteV0::Proposal => Effect::ValidatePayload(request),
        PayloadValidationRouteV0::Synced => Effect::ValidateSyncedPayload(request),
    };
    match take_core_regular_validation_job_v0(effect) {
        CoreRegularValidationEffectIntakeV0::Job(job) => *job,
        CoreRegularValidationEffectIntakeV0::RouteInvariant(_) => {
            panic!("Core fixture request disagreed with its exact effect route")
        }
        CoreRegularValidationEffectIntakeV0::Other(_) => {
            panic!("Core fixture validation effect was returned as unrelated")
        }
    }
}

/// Lower-layer ownership tests intentionally reopen the same synthetic Core
/// identity while mutating later phases. They use this explicit marker rather
/// than durable evaluation authority; production admission never calls here.
#[cfg(test)]
fn open_core_authorized_regular_validation_with_test_only_reservation_v0(
    host: &NativeValidationHostV0<'_>,
    request: PayloadValidationRequest,
) -> Result<OpenCoreAuthorizedRegularValidationV0, Box<FailedCoreIssuedRegularValidationOpenV0>> {
    let CoreIssuedRegularValidationJobV0 { request } =
        core_regular_validation_job_for_test_v0(request);
    let request = claim_core_validation_request_for_test_v0(request);
    open_core_authorized_regular_validation_v0(
        host,
        CoreIssuedRegularValidationOwnerV0 {
            request,
            reservation: CoreAuthorizedRegularReservationV0::TestOnly,
        },
    )
}

#[cfg(test)]
fn open_core_authorized_regular_transaction_cursor_v0(
    host: &NativeValidationHostV0<'_>,
    request: PayloadValidationRequest,
) -> Result<
    OpenCoreAuthorizedRegularTransactionCursorV0,
    Box<FailedCoreIssuedRegularValidationOpenV0>,
> {
    open_core_authorized_regular_validation_with_test_only_reservation_v0(host, request)
        .map(open_core_authorized_regular_transaction_cursor_from_open_v0)
}

#[cfg(test)]
fn open_core_authorized_regular_validation_for_test_v0(
    host: &NativeValidationHostV0<'_>,
    request: PayloadValidationRequest,
) -> Result<OpenCoreAuthorizedRegularValidationV0, Box<FailedCoreIssuedRegularValidationOpenV0>> {
    match begin_core_authorized_regular_validation_session_v0(
        host,
        core_regular_validation_job_for_test_v0(request),
    ) {
        CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => Ok(*open),
        CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(failed) => Err(failed),
        CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate(_) => {
            panic!("fresh test fixture unexpectedly replayed one Core validation request")
        }
        CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(_) => {
            panic!("fresh test fixture unexpectedly joined a durable reservation")
        }
        CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(_) => {
            panic!("fresh test fixture could not reserve its Core validation request")
        }
    }
}

#[cfg(test)]
fn claim_core_validation_request_for_test_v0(
    request: PayloadValidationRequest,
) -> ClaimedPayloadValidationRequestV0 {
    match request.try_claim() {
        Ok(request) => request,
        Err(_) => panic!("fresh test fixture unexpectedly replayed one Core validation request"),
    }
}

fn decode_next_core_authorized_regular_payload_v0(
    open: &OpenCoreAuthorizedRegularTransactionCursorV0,
) -> Result<DecodedCoreAuthorizedRegularPayloadV0, CoreAuthorizedRegularTransactionDecodeCauseV0> {
    let authorized = &open.open.authorized;
    let header = &authorized.header;
    let index = open.next_transaction_index;
    let exact_outer_bytes = authorized
        .body
        .application_payload()
        .transaction(index)
        .ok_or(CoreAuthorizedRegularTransactionDecodeCauseV0::Exhausted)?
        .to_vec();
    let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(&exact_outer_bytes)
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope)?;
    let signer = crate::validate_signed_command_envelope_against_policy_v1(
        &envelope,
        header.chain_id().as_str(),
        header.timestamp_ms(),
        &authorized.context.signer_policy.authorized_signers,
    )
    .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidOrUnauthorizedEnvelope)?;
    let exact_inner_bytes = envelope
        .payload_bytes()
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope)?;
    let next_transaction_index = index
        .checked_add(1)
        .ok_or(CoreAuthorizedRegularTransactionDecodeCauseV0::IndexOverflow)?;
    let payload_len = exact_inner_bytes.len();
    let context = ExactRuntimeExecutionContextV0 {
        target_height: header.height().get(),
        target_block_id: authorized.validation_id.block_id(),
        validation_timestamp_ms: header.timestamp_ms(),
        signer_id: signer.signer_id.clone(),
        signer_role: signer.signer_role.clone(),
        payload_len,
    };
    if envelope.payload_type != CANONICAL_TX_PAYLOAD_TYPE_V1 {
        return Ok(DecodedCoreAuthorizedRegularPayloadV0::NonRuntime(
            DecodedCoreAuthorizedNonRuntimePayloadV0 {
                index,
                next_transaction_index,
                exact_outer_bytes,
                exact_inner_bytes,
                envelope,
                context,
            },
        ));
    }
    let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner_bytes)
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction)?;
    transaction
        .validate()
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction)?;
    if envelope.signer_id != transaction.sender {
        return Err(CoreAuthorizedRegularTransactionDecodeCauseV0::SenderMismatch);
    }
    if envelope.nonce != transaction.nonce {
        return Err(CoreAuthorizedRegularTransactionDecodeCauseV0::NonceMismatch);
    }
    Ok(DecodedCoreAuthorizedRegularPayloadV0::Runtime(
        DecodedCoreAuthorizedRuntimeTransactionV0 {
            index,
            next_transaction_index,
            exact_outer_bytes,
            exact_inner_bytes,
            transaction,
            context,
        },
    ))
}

/// Legacy test-only raw-input decoder. Production must enter through the
/// snapshot-owning cursor above and cannot supply any of these components.
#[cfg(test)]
fn decode_exact_authorized_runtime_transaction_for_test_v0(
    header: &BlockHeader,
    body: &BlockBodyV0,
    target_block_id: BlockId,
    authorized_signers: &[AuthorizedSignerV1],
    index: u32,
) -> Result<DecodedCoreAuthorizedRuntimeTransactionV0, CoreAuthorizedRegularTransactionDecodeCauseV0>
{
    let exact_outer_bytes = body
        .application_payload()
        .transaction(index)
        .ok_or(CoreAuthorizedRegularTransactionDecodeCauseV0::Exhausted)?
        .to_vec();
    let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(&exact_outer_bytes)
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope)?;
    let signer = crate::validate_signed_command_envelope_against_policy_v1(
        &envelope,
        header.chain_id().as_str(),
        header.timestamp_ms(),
        authorized_signers,
    )
    .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidOrUnauthorizedEnvelope)?;
    if envelope.payload_type != CANONICAL_TX_PAYLOAD_TYPE_V1 {
        return Err(CoreAuthorizedRegularTransactionDecodeCauseV0::NonRuntimePayload);
    }
    let exact_inner_bytes = envelope
        .payload_bytes()
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope)?;
    let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner_bytes)
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction)?;
    transaction
        .validate()
        .map_err(|_| CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction)?;
    if envelope.signer_id != transaction.sender {
        return Err(CoreAuthorizedRegularTransactionDecodeCauseV0::SenderMismatch);
    }
    if envelope.nonce != transaction.nonce {
        return Err(CoreAuthorizedRegularTransactionDecodeCauseV0::NonceMismatch);
    }
    let next_transaction_index = index
        .checked_add(1)
        .ok_or(CoreAuthorizedRegularTransactionDecodeCauseV0::IndexOverflow)?;
    let payload_len = exact_inner_bytes.len();
    Ok(DecodedCoreAuthorizedRuntimeTransactionV0 {
        index,
        next_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        transaction,
        context: ExactRuntimeExecutionContextV0 {
            target_height: header.height().get(),
            target_block_id,
            validation_timestamp_ms: header.timestamp_ms(),
            signer_id: signer.signer_id.clone(),
            signer_role: signer.signer_role.clone(),
            payload_len,
        },
    })
}

/// Prepares only the exact item selected by the internal cursor. The returned
/// value continues to own the open cursor and snapshot; no production API can
/// advance it before a future runtime attempt consumes the whole carrier.
#[allow(dead_code)]
fn prepare_next_core_authorized_regular_payload_v0(
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
) -> Result<
    PreparedCoreAuthorizedRegularPayloadV0,
    Box<FailedCoreAuthorizedRegularTransactionDecodeV0>,
> {
    let decoded = decode_next_core_authorized_regular_payload_v0(&open);
    match decoded {
        Ok(DecodedCoreAuthorizedRegularPayloadV0::Runtime(decoded)) => {
            Ok(PreparedCoreAuthorizedRegularPayloadV0::Runtime(
                PreparedCoreAuthorizedRuntimeTransactionV0 {
                    open,
                    index: decoded.index,
                    next_transaction_index: decoded.next_transaction_index,
                    exact_outer_bytes: decoded.exact_outer_bytes,
                    exact_inner_bytes: decoded.exact_inner_bytes,
                    transaction: decoded.transaction,
                    context: decoded.context,
                },
            ))
        }
        Ok(DecodedCoreAuthorizedRegularPayloadV0::NonRuntime(decoded)) => {
            Ok(PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(
                CoreAuthorizedNonRuntimePayloadRoutingV0 {
                    open,
                    index: decoded.index,
                    next_transaction_index: decoded.next_transaction_index,
                    exact_outer_bytes: decoded.exact_outer_bytes,
                    exact_inner_bytes: decoded.exact_inner_bytes,
                    envelope: decoded.envelope,
                    context: decoded.context,
                },
            ))
        }
        Err(cause) => Err(Box::new(FailedCoreAuthorizedRegularTransactionDecodeV0 {
            open,
            cause,
        })),
    }
}

/// Reveals a decode/routing cause only after the exact snapshot closes. A
/// finish failure consumes the pending cause and always wins precedence.
#[allow(dead_code)]
fn finish_failed_core_authorized_regular_transaction_decode_v0(
    failed: Box<FailedCoreAuthorizedRegularTransactionDecodeV0>,
) -> Box<ClosedFailedCoreAuthorizedRegularTransactionDecodeV0> {
    let FailedCoreAuthorizedRegularTransactionDecodeV0 { open, cause } = *failed;
    let OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index,
        changes,
        applied,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
    } = open;
    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    let cause = match snapshot.finish() {
        Ok(()) => ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(cause),
        Err(error) => ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Snapshot(error),
    };
    Box::new(ClosedFailedCoreAuthorizedRegularTransactionDecodeV0 {
        authorized,
        next_transaction_index,
        changes,
        applied,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
        cause,
    })
}

fn decode_canonical_runtime_object_value_v0<Value>(
    value_bytes: &[u8],
    reason: CoreAuthorizedRegularRuntimeMutationInvariantV0,
) -> std::result::Result<Value, CoreAuthorizedRegularRuntimeMutationStageFailureV0>
where
    Value: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<Value>(value_bytes)
        .map_err(|_| CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(reason))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|_| CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(reason))?;
    if canonical != value_bytes {
        return Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(reason));
    }
    Ok(value)
}

/// Exhaustively validates the active runtime's four native object families.
/// The target height is supplied only by the retained prepared context inside
/// the consuming attempt below.
fn validate_runtime_mutation_key_type_value_v0(
    target_height: u64,
    mutation: &RuntimeMutation,
) -> std::result::Result<(), CoreAuthorizedRegularRuntimeMutationStageFailureV0> {
    let mut task_state = None;
    let expected_key = match mutation.object_type.as_str() {
        ACCOUNT_OBJECT_TYPE_V1 => {
            let account = decode_canonical_runtime_object_value_v0::<AccountV1>(
                &mutation.value_bytes,
                CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalAccountValue,
            )?;
            CanonicalCommandV1::CreditAccount {
                account: account.account.clone(),
                amount: 1,
            }
            .validate()
            .map_err(|_| {
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalAccountIdentity,
                )
            })?;
            account_key(&account.account)
        }
        TASK_OBJECT_TYPE_V1 => {
            let task = decode_canonical_runtime_object_value_v0::<TaskV1>(
                &mutation.value_bytes,
                CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalTaskValue,
            )?;
            CanonicalCommandV1::CreateTask {
                task_id: task.task_id.clone(),
                reward: task.reward,
                worker_stake: task.worker_stake,
                result_deadline_height: task.result_deadline_height,
                challenge_window_blocks: task.challenge_window_blocks,
            }
            .validate()
            .map_err(|_| {
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalTaskIdentity,
                )
            })?;
            let expected_key = task_key(&task.task_id);
            task_state = Some(task);
            expected_key
        }
        FEE_POLICY_OBJECT_TYPE_V1 => {
            let policy = decode_canonical_runtime_object_value_v0::<FeePolicyV1>(
                &mutation.value_bytes,
                CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalFeePolicyValue,
            )?;
            CanonicalCommandV1::SetFeePolicy {
                gas_price: policy.gas_price,
                base_gas: policy.base_gas,
                byte_gas: policy.byte_gas,
            }
            .validate()
            .map_err(|_| {
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::InvalidFeePolicyValue,
                )
            })?;
            fee_policy_key()
        }
        MONETARY_STATE_OBJECT_TYPE_V1 => {
            let _ = decode_canonical_runtime_object_value_v0::<MonetaryStateV1>(
                &mutation.value_bytes,
                CoreAuthorizedRegularRuntimeMutationInvariantV0::NonCanonicalMonetaryStateValue,
            )?;
            monetary_state_key()
        }
        _ => {
            return Err(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::UnknownObjectType,
                ),
            );
        }
    };
    if mutation.object_key_hex != expected_key {
        return Err(
            CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                CoreAuthorizedRegularRuntimeMutationInvariantV0::CanonicalKeyMismatch,
            ),
        );
    }
    if let Some(task) = task_state {
        validate_authenticated_task_state_v0(&task, mutation.next_version, target_height).map_err(
            |_| {
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::UnreachableTaskState,
                )
            },
        )?;
    }
    Ok(())
}

/// Applies the complete receipt mutation set to a clone of the cursor delta.
/// The owned cursor changes only after every key/type/value/version relation
/// and every authenticated snapshot read succeeds.
fn stage_core_authorized_runtime_mutations_v0(
    snapshot: &AuthenticatedRuntimeReadSnapshotV0,
    target_height: u64,
    changes: &BTreeMap<String, StoredObject>,
    mutations: &[RuntimeMutation],
) -> std::result::Result<
    BTreeMap<String, StoredObject>,
    CoreAuthorizedRegularRuntimeMutationStageFailureV0,
> {
    let mut staged = changes.clone();
    let mut seen = BTreeSet::new();
    for mutation in mutations {
        if !seen.insert(mutation.object_key_hex.clone()) {
            return Err(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::DuplicateObjectKey,
                ),
            );
        }
        if mutation.object_key_hex == crate::poco_authority_object_key() {
            return Err(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::PocoAuthorityWrite,
                ),
            );
        }
        let current = match staged.get(&mutation.object_key_hex) {
            Some(object) => Some(object.clone()),
            None => snapshot
                .load(&mutation.object_key_hex)
                .map_err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::StateRead)?,
        };
        let current_version = current.as_ref().map(|object| object.version);
        if current_version != mutation.expected_version {
            return Err(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::ExpectedVersionMismatch,
                ),
            );
        }
        if let Some(current) = &current {
            if current.object_type != mutation.object_type {
                return Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::AuthenticatedObjectTypeMismatch,
                ));
            }
        }
        let expected_next_version = match current_version {
            Some(version) => version.checked_add(1).ok_or(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::ObjectVersionExhausted,
                ),
            )?,
            None => 1,
        };
        if mutation.next_version != expected_next_version {
            return Err(
                CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(
                    CoreAuthorizedRegularRuntimeMutationInvariantV0::NextVersionMismatch,
                ),
            );
        }
        validate_runtime_mutation_key_type_value_v0(target_height, mutation)?;
        let stored = ObjectMutation {
            object_key_hex: mutation.object_key_hex.clone(),
            object_type: mutation.object_type.clone(),
            expected_version: mutation.expected_version,
            next_version: mutation.next_version,
            value_bytes: mutation.value_bytes.clone(),
        }
        .into_stored();
        staged.insert(stored.object_key_hex.clone(), stored);
    }
    Ok(staged)
}

/// Replays each retained real receipt separately against the same parent
/// snapshot. Receipt-local duplicate keys remain invalid, while a later
/// transaction may update an earlier transaction's key only through the exact
/// version chain enforced by the staging kernel.
fn replay_core_authorized_runtime_receipt_changes_v0(
    snapshot: &AuthenticatedRuntimeReadSnapshotV0,
    target_height: u64,
    applied: &[AppliedCoreAuthorizedRuntimeTransactionV0],
) -> std::result::Result<
    BTreeMap<String, StoredObject>,
    CoreAuthorizedRegularRuntimeMutationStageFailureV0,
> {
    let mut replayed = BTreeMap::new();
    for attempt in applied {
        replayed = stage_core_authorized_runtime_mutations_v0(
            snapshot,
            target_height,
            &replayed,
            &attempt.runtime_receipt.mutations,
        )?;
    }
    Ok(replayed)
}

/// Reconstructs the final receipt-derived map after the parent snapshot has
/// closed. The owning planner has already authenticated the first read of each
/// key; this defensive pass freezes receipt-local uniqueness, canonical typed
/// values, and cross-transaction successor semantics against later in-module
/// drift.
fn rebuild_finished_runtime_receipt_changes_v0(
    target_height: u64,
    applied: &[AppliedCoreAuthorizedRuntimeTransactionV0],
) -> Option<BTreeMap<String, StoredObject>> {
    let mut rebuilt: BTreeMap<String, StoredObject> = BTreeMap::new();
    for attempt in applied {
        let mut seen = BTreeSet::new();
        for mutation in &attempt.runtime_receipt.mutations {
            if !seen.insert(mutation.object_key_hex.clone())
                || mutation.object_key_hex == crate::poco_authority_object_key()
                || validate_runtime_mutation_key_type_value_v0(target_height, mutation).is_err()
            {
                return None;
            }
            let expected_next = match mutation.expected_version {
                Some(version) => version.checked_add(1)?,
                None => 1,
            };
            if mutation.next_version != expected_next {
                return None;
            }
            if let Some(previous) = rebuilt.get(&mutation.object_key_hex) {
                if mutation.expected_version != Some(previous.version)
                    || mutation.object_type != previous.object_type
                {
                    return None;
                }
            }
            let stored = ObjectMutation {
                object_key_hex: mutation.object_key_hex.clone(),
                object_type: mutation.object_type.clone(),
                expected_version: mutation.expected_version,
                next_version: mutation.next_version,
                value_bytes: mutation.value_bytes.clone(),
            }
            .into_stored();
            rebuilt.insert(stored.object_key_hex.clone(), stored);
        }
    }
    Some(rebuilt)
}

/// Confirms that the inert JMT plan's exact value batch and preimage set are
/// the authenticated writes derived from the retained final changes. This is
/// deliberately a structural check only; applying or persisting the plan
/// remains outside this carrier.
fn planned_auth_update_matches_writes_v0(plan: &PlannedAuthUpdate, writes: &[AuthWrite]) -> bool {
    let mut expected_preimages = BTreeMap::new();
    let mut expected_values = BTreeMap::new();
    for write in writes {
        let Ok(hash) = crate::auth_tree::authenticated_key_hash(write.key()) else {
            return false;
        };
        if expected_preimages
            .insert(hash, write.key().to_vec())
            .is_some()
            || expected_values
                .insert(
                    (plan.version, hash),
                    write.value().map(|value| value.to_vec()),
                )
                .is_some()
        {
            return false;
        }
    }
    plan.preimages() == &expected_preimages
        && plan.tree_update_batch.node_batch.values() == &expected_values
}

fn planned_auth_update_matches_runtime_changes_v0(
    plan: &PlannedAuthUpdate,
    changes: &BTreeMap<String, StoredObject>,
) -> bool {
    let Ok(writes) = changes
        .values()
        .map(crate::authenticated_object_write)
        .collect::<anyhow::Result<Vec<_>>>()
    else {
        return false;
    };
    planned_auth_update_matches_writes_v0(plan, &writes)
}

fn validate_unique_complete_body_auth_writes_v0(
    writes: &[AuthWrite],
) -> std::result::Result<(), CoreAuthorizedRegularCompleteBodyPlanCauseV0> {
    let mut raw_keys = BTreeSet::new();
    let mut hashed_keys = BTreeMap::new();
    for write in writes {
        if !raw_keys.insert(write.key().to_vec()) {
            return Err(
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::MergedWriteKeyConflictInvariant,
            );
        }
        let hash = crate::auth_tree::authenticated_key_hash(write.key()).map_err(|_| {
            CoreAuthorizedRegularCompleteBodyPlanCauseV0::MergedWriteHashCollisionInvariant
        })?;
        if let Some(prior_key) = hashed_keys.insert(hash, write.key().to_vec()) {
            if prior_key != write.key() {
                return Err(
                    CoreAuthorizedRegularCompleteBodyPlanCauseV0::MergedWriteHashCollisionInvariant,
                );
            }
            return Err(
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::MergedWriteKeyConflictInvariant,
            );
        }
    }
    Ok(())
}

fn fail_prepared_core_authorized_runtime_transaction_v0(
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
    failed_transaction_index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_bytes: Vec<u8>,
    transaction: CanonicalTxV1,
    context: ExactRuntimeExecutionContextV0,
    cause: CoreAuthorizedRegularRuntimeStepFailureV0,
) -> Box<FailedCoreAuthorizedRegularRuntimeAttemptV0> {
    let OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index,
        changes: _,
        applied: _,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
    } = open;
    debug_assert_eq!(failed_transaction_index, next_transaction_index);
    Box::new(FailedCoreAuthorizedRegularRuntimeAttemptV0 {
        open,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
        failed_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        transaction,
        context,
        cause,
    })
}

/// Consumes one prepared exact transaction into the real runtime. No caller
/// supplies a tx, index, context, view, or mutation set. Only total success
/// returns a cursor advanced by one; every failure consumes the prior delta
/// and successful receipts into an owning failure awaiting snapshot finish.
#[allow(dead_code)]
fn attempt_prepared_core_authorized_runtime_transaction_v0(
    prepared: PreparedCoreAuthorizedRuntimeTransactionV0,
) -> std::result::Result<
    OpenCoreAuthorizedRegularTransactionCursorV0,
    Box<FailedCoreAuthorizedRegularRuntimeAttemptV0>,
> {
    let PreparedCoreAuthorizedRuntimeTransactionV0 {
        mut open,
        index,
        next_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        transaction,
        context,
    } = prepared;
    let attempt = {
        let view = CoreAuthorizedRegularRuntimeStateViewV0 {
            changes: &open.changes,
            snapshot: &open.open.snapshot,
        };
        let runtime_context = ExecutionContext {
            height: context.target_height,
            signer_id: &context.signer_id,
            signer_role: &context.signer_role,
            payload_len: context.payload_len,
        };
        try_execute_v0(&transaction, runtime_context, &view)
    };
    let runtime_receipt = match attempt {
        Ok(receipt) => receipt,
        Err(cause) => {
            return Err(fail_prepared_core_authorized_runtime_transaction_v0(
                open,
                index,
                exact_outer_bytes,
                exact_inner_bytes,
                transaction,
                context,
                CoreAuthorizedRegularRuntimeStepFailureV0::Runtime(cause),
            ));
        }
    };
    let native_receipt =
        match NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&runtime_receipt) {
            Ok(receipt) => receipt,
            Err(_) => {
                return Err(fail_prepared_core_authorized_runtime_transaction_v0(
                    open,
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    transaction,
                    context,
                    CoreAuthorizedRegularRuntimeStepFailureV0::NativeReceiptInvariant,
                ));
            }
        };
    let staged_changes = match stage_core_authorized_runtime_mutations_v0(
        &open.open.snapshot,
        context.target_height,
        &open.changes,
        &runtime_receipt.mutations,
    ) {
        Ok(changes) => changes,
        Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::StateRead(error)) => {
            return Err(fail_prepared_core_authorized_runtime_transaction_v0(
                open,
                index,
                exact_outer_bytes,
                exact_inner_bytes,
                transaction,
                context,
                CoreAuthorizedRegularRuntimeStepFailureV0::StateRead(error),
            ));
        }
        Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(reason)) => {
            return Err(fail_prepared_core_authorized_runtime_transaction_v0(
                open,
                index,
                exact_outer_bytes,
                exact_inner_bytes,
                transaction,
                context,
                CoreAuthorizedRegularRuntimeStepFailureV0::MutationInvariant(reason),
            ));
        }
    };
    open.changes = staged_changes;
    open.next_transaction_index = next_transaction_index;
    open.applied
        .push(AppliedCoreAuthorizedRuntimeTransactionV0 {
            index,
            exact_outer_bytes,
            exact_inner_bytes,
            transaction,
            context,
            runtime_receipt,
            native_receipt,
        });
    Ok(open)
}

/// Closes the exact snapshot before preserving a failed runtime attempt. A
/// snapshot finish failure consumes and outranks the pending runtime/state/
/// receipt/mutation cause.
#[allow(dead_code)]
fn finish_failed_core_authorized_regular_runtime_attempt_v0(
    failed: Box<FailedCoreAuthorizedRegularRuntimeAttemptV0>,
) -> Box<ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0> {
    let FailedCoreAuthorizedRegularRuntimeAttemptV0 {
        open,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
        failed_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        transaction,
        context,
        cause,
    } = *failed;
    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    let cause = match snapshot.finish() {
        Ok(()) => ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(cause),
        Err(error) => ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Snapshot(error),
    };
    Box::new(ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0 {
        authorized,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
        failed_transaction_index,
        exact_outer_bytes,
        exact_inner_bytes,
        transaction,
        context,
        cause,
    })
}

/// Plans the complete cursor's exact next authenticated state before closing
/// the same Core-parent snapshot that served every runtime read. The caller
/// supplies only the owning cursor: writes, target version, expected root, and
/// any persistence action remain unavailable at this boundary.
#[allow(dead_code)]
fn finish_and_plan_core_authorized_regular_post_state_v0(
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
) -> std::result::Result<
    FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0,
    Box<ClosedFailedCoreAuthorizedRegularPostStatePlanV0>,
> {
    let OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index,
        changes,
        applied,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
    } = open;
    let expected = open
        .authorized
        .body
        .application_payload()
        .transaction_count();
    let target_height = open.authorized.header.height().get();
    let target_block_id = open.authorized.validation_id.block_id();
    let planning = (|| {
        if next_transaction_index != expected {
            return Err(CoreAuthorizedRegularPostStatePlanCauseV0::IncompleteBody {
                executed: next_transaction_index,
                expected,
            });
        }
        if !applied_non_runtime.is_empty()
            || poco_prefix.is_some()
            || validator_prefix.is_some()
            || applied.len() != expected as usize
            || applied
                .iter()
                .zip(open.authorized.body.application_payload().transactions())
                .enumerate()
                .any(|(index, (applied, exact_outer_bytes))| {
                    u32::try_from(index) != Ok(applied.index)
                        || applied.exact_outer_bytes.as_slice() != exact_outer_bytes.as_slice()
                        || applied.context.target_height != target_height
                        || applied.context.target_block_id != target_block_id
                        || applied.context.validation_timestamp_ms
                            != open.authorized.header.timestamp_ms()
                        || applied.context.payload_len != applied.exact_inner_bytes.len()
                })
        {
            return Err(CoreAuthorizedRegularPostStatePlanCauseV0::RuntimeProvenanceInvariant);
        }
        if changes.iter().any(|(map_key, object)| {
            map_key != &object.object_key_hex
                || object.value_hash_hex
                    != hex::encode(trnm_finality_types::hash_domain(
                        "trnm.state.object.value.v1",
                        &[&object.value_bytes],
                    ))
        }) {
            return Err(CoreAuthorizedRegularPostStatePlanCauseV0::StateDeltaProvenanceInvariant);
        }
        let replayed_changes = replay_core_authorized_runtime_receipt_changes_v0(
            &open.snapshot,
            target_height,
            &applied,
        )
        .map_err(|cause| match cause {
            CoreAuthorizedRegularRuntimeMutationStageFailureV0::StateRead(error) => {
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptReplayStateRead(error)
            }
            CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(_) => {
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            }
        })?;
        if replayed_changes != changes {
            return Err(CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant);
        }
        let writes = replayed_changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|_| CoreAuthorizedRegularPostStatePlanCauseV0::PrepareWritesInvariant)?;
        let plan = open
            .snapshot
            .plan_exact_next_auth_update_v0(writes)
            .map_err(CoreAuthorizedRegularPostStatePlanCauseV0::Plan)?;
        if plan.version != target_height {
            return Err(CoreAuthorizedRegularPostStatePlanCauseV0::PlanTargetInvariant);
        }
        let plan_seal = plan
            .seal_v0()
            .map_err(|_| CoreAuthorizedRegularPostStatePlanCauseV0::PlanSealInvariant)?;
        Ok((plan, plan_seal, replayed_changes))
    })();

    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    // A close failure consumes and outranks any pending completeness,
    // provenance, write-encoding, or JMT-planning result.
    if let Err(error) = snapshot.finish() {
        return Err(Box::new(ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {
            authorized,
            next_transaction_index,
            changes,
            applied,
            applied_non_runtime,
            poco_prefix,
            validator_prefix,
            cause: ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(error),
        }));
    }
    let (post_state_update, post_state_update_seal, changes) = match planning {
        Ok(planned) => planned,
        Err(cause) => {
            return Err(Box::new(ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {
                authorized,
                next_transaction_index,
                changes,
                applied,
                applied_non_runtime,
                poco_prefix,
                validator_prefix,
                cause: ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(cause),
            }));
        }
    };
    Ok(FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0 {
        authorized,
        changes,
        applied,
        post_state_update,
        post_state_update_seal,
    })
}

/// Consumes one fully advanced mixed-family cursor into a single exact-next
/// authenticated-state plan. Runtime writes, the final replace-only PoCO
/// prefix, the final validator lifecycle, and mandatory block-height system
/// writes are merged exactly once on the retained parent snapshot. Success
/// closes that snapshot but deliberately has no receipt, root-comparator,
/// persistence, callback, or Core authority.
#[allow(dead_code)]
fn finish_and_plan_complete_core_authorized_regular_post_state_v0(
    open: OpenCoreAuthorizedRegularTransactionCursorV0,
) -> std::result::Result<
    FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
    Box<ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0>,
> {
    let expected = open
        .open
        .authorized
        .body
        .application_payload()
        .transaction_count();
    let target_height = open.open.authorized.header.height().get();
    let parent_lifecycle = &open.open.authorized.context.validator_lifecycle;
    let planning = (|| {
        if open.next_transaction_index != expected {
            return Err(
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::IncompleteBody {
                    executed: open.next_transaction_index,
                    expected,
                },
            );
        }
        validate_core_authorized_regular_cursor_prefix_v0(&open).map_err(|_| {
            CoreAuthorizedRegularCompleteBodyPlanCauseV0::CompleteBodyProvenanceInvariant
        })?;
        if open.changes.iter().any(|(map_key, object)| {
            map_key != &object.object_key_hex
                || object.value_hash_hex
                    != hex::encode(trnm_finality_types::hash_domain(
                        "trnm.state.object.value.v1",
                        &[&object.value_bytes],
                    ))
        }) {
            return Err(
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::StateDeltaProvenanceInvariant,
            );
        }
        let replayed_changes = replay_core_authorized_runtime_receipt_changes_v0(
            &open.open.snapshot,
            target_height,
            &open.applied,
        )
        .map_err(|cause| match cause {
            CoreAuthorizedRegularRuntimeMutationStageFailureV0::StateRead(error) => {
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::ReceiptReplayStateRead(error)
            }
            CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(_) => {
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::ReceiptMutationDeltaInvariant
            }
        })?;
        if replayed_changes != open.changes {
            return Err(
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::ReceiptMutationDeltaInvariant,
            );
        }

        let mut writes = replayed_changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|_| CoreAuthorizedRegularCompleteBodyPlanCauseV0::PrepareWritesInvariant)?;

        let prepared_lifecycle =
            prepared_core_authorized_validator_lifecycle_v0(&open).map_err(|_| {
                CoreAuthorizedRegularCompleteBodyPlanCauseV0::ValidatorHeightPreparationInvariant
            })?;
        let implicit_validator_lifecycle = if let Some(prefix) = &open.validator_prefix {
            writes.push(prefix.write.clone());
            None
        } else if prepared_lifecycle != *parent_lifecycle {
            writes.push(
                crate::authenticated_lifecycle_write(target_height, &prepared_lifecycle).map_err(
                    |_| CoreAuthorizedRegularCompleteBodyPlanCauseV0::ValidatorWriteInvariant,
                )?,
            );
            Some(prepared_lifecycle.clone())
        } else {
            None
        };

        let mut cutoff_projection = None;
        if let Some(prefix) = &open.poco_prefix {
            writes.extend(prefix.writes.iter().cloned());
        } else {
            crate::poco_checkpoint::validate_application_validator_projection(
                &open.open.authorized.context.validator_set,
                &prepared_lifecycle.active_validators,
            )
            .map_err(|_| CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoScheduleInvariant)?;
            let parameters = &open.open.authorized.context.parameters;
            let geometry = trnm_consensus_types::EpochGeometryV0::new(
                open.open.authorized.context.validator_set.epoch(),
                parameters,
            )
            .map_err(|_| CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoScheduleInvariant)?;
            let checkpoint_height = geometry.checkpoint_height().get();
            let cutoff_height = checkpoint_height
                .checked_sub(parameters.snapshot_lead_blocks())
                .ok_or(CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoScheduleInvariant)?;
            if cutoff_height >= checkpoint_height {
                return Err(CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoScheduleInvariant);
            }
            if target_height == cutoff_height {
                let projection = open
                    .open
                    .snapshot
                    .load_authenticated_production_poco_projection_v0()
                    .map_err(
                        CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoCutoffProjectionRead,
                    )?;
                writes.push(
                    crate::poco_transition::scheduled_cutoff_manifest_refresh_write_v0(
                        trnm_consensus_types::Height::new(target_height),
                        &projection,
                    )
                    .map_err(|_| {
                        CoreAuthorizedRegularCompleteBodyPlanCauseV0::PocoCutoffWriteInvariant
                    })?,
                );
                cutoff_projection = Some(projection);
            }
        }

        validate_unique_complete_body_auth_writes_v0(&writes)?;
        let plan = open
            .open
            .snapshot
            .plan_exact_next_auth_update_v0(writes.clone())
            .map_err(CoreAuthorizedRegularCompleteBodyPlanCauseV0::Plan)?;
        if plan.version != target_height {
            return Err(CoreAuthorizedRegularCompleteBodyPlanCauseV0::PlanTargetInvariant);
        }
        if !planned_auth_update_matches_writes_v0(&plan, &writes) {
            return Err(CoreAuthorizedRegularCompleteBodyPlanCauseV0::PlanWriteSetInvariant);
        }
        let plan_seal = plan
            .seal_v0()
            .map_err(|_| CoreAuthorizedRegularCompleteBodyPlanCauseV0::PlanSealInvariant)?;
        Ok((
            plan,
            plan_seal,
            replayed_changes,
            cutoff_projection,
            implicit_validator_lifecycle,
        ))
    })();

    let OpenCoreAuthorizedRegularTransactionCursorV0 {
        open,
        next_transaction_index,
        changes,
        applied,
        applied_non_runtime,
        poco_prefix,
        validator_prefix,
    } = open;
    let OpenCoreAuthorizedRegularValidationV0 {
        authorized,
        snapshot,
    } = open;
    if let Err(error) = snapshot.finish() {
        return Err(Box::new(
            ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0 {
                authorized,
                next_transaction_index,
                changes,
                applied,
                applied_non_runtime,
                poco_prefix,
                validator_prefix,
                cause: ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0::Snapshot(error),
            },
        ));
    }
    let (
        post_state_update,
        post_state_update_seal,
        changes,
        cutoff_projection,
        implicit_validator_lifecycle,
    ) = match planning {
        Ok(planned) => planned,
        Err(cause) => {
            return Err(Box::new(
                ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0 {
                    authorized,
                    next_transaction_index,
                    changes,
                    applied,
                    applied_non_runtime,
                    poco_prefix,
                    validator_prefix,
                    cause: ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0::Plan(cause),
                },
            ));
        }
    };
    let final_poco = match (poco_prefix, cutoff_projection) {
        (Some(prefix), None) => Some(FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(
            prefix.plan,
        )),
        (None, Some(projection)) => {
            Some(FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(projection))
        }
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("PoCO operations replace scheduled cutoff refresh"),
    };
    let final_validator_lifecycle = validator_prefix
        .map(|prefix| prefix.lifecycle)
        .or(implicit_validator_lifecycle);
    Ok(FinishedPlannedCoreAuthorizedRegularCompleteBodyV0 {
        authorized,
        changes,
        applied,
        applied_non_runtime,
        final_poco,
        final_validator_lifecycle,
        post_state_update,
        post_state_update_seal,
    })
}

fn validate_finished_complete_body_item_provenance_v0(
    finished: &FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
) -> std::result::Result<(), CoreAuthorizedRegularCommitmentComparisonCauseV0> {
    let invariant = |reason| CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(reason);
    let authorized = &finished.authorized;
    let transactions = authorized.body.application_payload().transactions();
    let mut indices = BTreeSet::new();
    if authorized.header.id() != authorized.validation_id.block_id()
        || finished
            .applied
            .windows(2)
            .any(|pair| pair[0].index >= pair[1].index)
        || finished.applied_non_runtime.windows(2).any(|pair| {
            let index = |applied: &AppliedCoreAuthorizedNonRuntimePayloadV0| match applied {
                AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication { index, .. }
                | AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition { index, .. } => {
                    *index
                }
            };
            index(&pair[0]) >= index(&pair[1])
        })
    {
        return Err(invariant(
            CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyProvenance,
        ));
    }
    for applied in &finished.applied {
        let index = usize::try_from(applied.index).map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let exact_outer = transactions.get(index).ok_or_else(|| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionCount)
        })?;
        let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(&applied.exact_outer_bytes)
            .map_err(|_| {
                invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
            })?;
        let signer = crate::validate_signed_command_envelope_against_policy_v1(
            &envelope,
            authorized.header.chain_id().as_str(),
            authorized.header.timestamp_ms(),
            &authorized.context.signer_policy.authorized_signers,
        )
        .map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let exact_inner = envelope.payload_bytes().map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let transaction: CanonicalTxV1 = serde_json::from_slice(&exact_inner).map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        transaction.validate().map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        if !indices.insert(applied.index)
            || exact_outer != &applied.exact_outer_bytes
            || envelope.payload_type != CANONICAL_TX_PAYLOAD_TYPE_V1
            || envelope.signer_id != transaction.sender
            || envelope.nonce != transaction.nonce
            || exact_inner != applied.exact_inner_bytes
            || transaction != applied.transaction
            || applied.context.target_height != authorized.header.height().get()
            || applied.context.target_block_id != authorized.validation_id.block_id()
            || applied.context.validation_timestamp_ms != authorized.header.timestamp_ms()
            || applied.context.signer_id != signer.signer_id
            || applied.context.signer_role != signer.signer_role
            || applied.context.payload_len != applied.exact_inner_bytes.len()
        {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance,
            ));
        }
    }
    for applied in &finished.applied_non_runtime {
        let (index, exact_outer_bytes, exact_inner_bytes, envelope, context, semantic_exact) =
            match applied {
                AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    operation,
                } => (
                    *index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    envelope.payload_type
                        == crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0
                        && serde_json::to_vec(operation).ok().as_ref() == Some(exact_inner_bytes),
                ),
                AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition {
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    transition,
                } => (
                    *index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    envelope,
                    context,
                    envelope.payload_type
                        == crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1
                        && serde_json::to_vec(transition).ok().as_ref() == Some(exact_inner_bytes),
                ),
            };
        let index_usize = usize::try_from(index).map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let exact_body = transactions.get(index_usize).ok_or_else(|| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionCount)
        })?;
        let decoded_envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(exact_outer_bytes)
            .map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let signer = crate::validate_signed_command_envelope_against_policy_v1(
            &decoded_envelope,
            authorized.header.chain_id().as_str(),
            authorized.header.timestamp_ms(),
            &authorized.context.signer_policy.authorized_signers,
        )
        .map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        let decoded_inner = decoded_envelope.payload_bytes().map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance)
        })?;
        if !indices.insert(index)
            || exact_body != exact_outer_bytes
            || decoded_envelope != *envelope
            || decoded_inner != *exact_inner_bytes
            || !semantic_exact
            || context.target_height != authorized.header.height().get()
            || context.target_block_id != authorized.validation_id.block_id()
            || context.validation_timestamp_ms != authorized.header.timestamp_ms()
            || context.signer_id != signer.signer_id
            || context.signer_role != signer.signer_role
            || context.payload_len != exact_inner_bytes.len()
        {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance,
            ));
        }
    }
    if indices.len() != transactions.len()
        || !(0..transactions.len()).all(|index| {
            u32::try_from(index)
                .ok()
                .is_some_and(|index| indices.contains(&index))
        })
    {
        return Err(invariant(
            CoreAuthorizedRegularCommitmentInvariantV0::TransactionCount,
        ));
    }
    Ok(())
}

fn rebuild_finished_complete_body_native_execution_v0(
    finished: &FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
) -> std::result::Result<NativeBlockExecutionV0, CoreAuthorizedRegularCommitmentComparisonCauseV0> {
    let invariant = |reason| CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(reason);
    // Keep this helper self-defending even though the consuming comparator
    // already performs the same provenance pass before final-state and plan
    // checks. Future in-module reuse must not admit detached receipt facts.
    validate_finished_complete_body_item_provenance_v0(finished)?;
    let transactions = finished
        .authorized
        .body
        .application_payload()
        .transactions();
    let mut receipts = vec![None; transactions.len()];
    for applied in &finished.applied {
        let index = usize::try_from(applied.index).map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild)
        })?;
        let rebuilt =
            NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&applied.runtime_receipt)
                .map_err(|_| {
                    invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild)
                })?;
        if rebuilt != applied.native_receipt {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            ));
        }
        let slot = receipts.get_mut(index).ok_or_else(|| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild)
        })?;
        if slot.replace(rebuilt).is_some() {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            ));
        }
    }
    for applied in &finished.applied_non_runtime {
        let index = match applied {
            AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication { index, .. }
            | AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition { index, .. } => *index,
        };
        let index = usize::try_from(index).map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild)
        })?;
        let slot = receipts.get_mut(index).ok_or_else(|| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild)
        })?;
        if slot
            .replace(NativeTransactionReceiptFactsV0::internal_operation())
            .is_some()
        {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            ));
        }
    }
    let receipt_facts = receipts
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invariant(CoreAuthorizedRegularCommitmentInvariantV0::TransactionCount))?;
    let transaction_bytes = transactions
        .iter()
        .map(|transaction| Bytes::copy_from_slice(transaction))
        .collect::<Vec<_>>();
    NativeBlockExecutionV0::try_new(&transaction_bytes, receipt_facts)
        .map_err(|_| invariant(CoreAuthorizedRegularCommitmentInvariantV0::NativeExecutionRebuild))
}

fn rebuild_finished_complete_body_auth_writes_v0(
    finished: &FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
) -> std::result::Result<Vec<AuthWrite>, CoreAuthorizedRegularCommitmentComparisonCauseV0> {
    let invariant = |reason| CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(reason);
    let authorized = &finished.authorized;
    let target_height = authorized.header.height().get();
    let rebuilt_changes =
        rebuild_finished_runtime_receipt_changes_v0(target_height, &finished.applied).ok_or_else(
            || invariant(CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta),
        )?;
    if rebuilt_changes != finished.changes {
        return Err(invariant(
            CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta,
        ));
    }
    let mut writes = rebuilt_changes
        .values()
        .map(crate::authenticated_object_write)
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyMergedWrites)
        })?;

    let parent_lifecycle = &authorized.context.validator_lifecycle;
    let mut rebuilt_lifecycle = parent_lifecycle.clone();
    rebuilt_lifecycle
        .prepare_height(target_height)
        .map_err(|_| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite)
        })?;
    let prepared_lifecycle = rebuilt_lifecycle.clone();
    let mut validator_count = 0usize;
    let mut poco_raws = Vec::new();
    for applied in &finished.applied_non_runtime {
        match applied {
            AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                exact_inner_bytes, ..
            } => poco_raws.push(exact_inner_bytes.clone()),
            AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition {
                envelope,
                context,
                transition,
                ..
            } => {
                let authorization = crate::validator_lifecycle::ValidatorTransitionAuthorization {
                    command_id: &envelope.command_id,
                    signer_id: &context.signer_id,
                    signer_role: &context.signer_role,
                    nonce: envelope.nonce,
                    chain_id: envelope.chain_id.as_str(),
                    accepted_height: context.target_height,
                };
                rebuilt_lifecycle
                    .schedule(transition.clone(), authorization)
                    .map_err(|_| {
                        invariant(
                            CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite,
                        )
                    })?;
                validator_count = validator_count.checked_add(1).ok_or_else(|| {
                    invariant(
                        CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite,
                    )
                })?;
            }
        }
    }
    let expected_final_lifecycle = if validator_count > 0 || prepared_lifecycle != *parent_lifecycle
    {
        Some(&rebuilt_lifecycle)
    } else {
        None
    };
    if finished.final_validator_lifecycle.as_ref() != expected_final_lifecycle {
        return Err(invariant(
            CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite,
        ));
    }
    if let Some(lifecycle) = expected_final_lifecycle {
        writes.push(
            crate::authenticated_lifecycle_write(target_height, lifecycle).map_err(|_| {
                invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite)
            })?,
        );
    }

    crate::poco_checkpoint::validate_application_validator_projection(
        &authorized.context.validator_set,
        &prepared_lifecycle.active_validators,
    )
    .map_err(|_| invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites))?;
    let parameters = &authorized.context.parameters;
    let geometry = trnm_consensus_types::EpochGeometryV0::new(
        authorized.context.validator_set.epoch(),
        parameters,
    )
    .map_err(|_| invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites))?;
    let checkpoint_height = geometry.checkpoint_height().get();
    let cutoff_height = checkpoint_height
        .checked_sub(parameters.snapshot_lead_blocks())
        .ok_or_else(|| {
            invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites)
        })?;
    if cutoff_height >= checkpoint_height {
        return Err(invariant(
            CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
        ));
    }
    match (
        &finished.final_poco,
        poco_raws.is_empty(),
        target_height == cutoff_height,
    ) {
        (Some(FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(plan)), false, _) => {
            let parent = &authorized.context.parent_header;
            let expected_operation_count = u32::try_from(poco_raws.len()).map_err(|_| {
                invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites)
            })?;
            if plan.source_version() != parent.height().get()
                || plan.source_root() != *parent.state_root().as_bytes()
                || plan.target_height() != authorized.header.height()
                || plan.target_manifest().cutoff_height() != authorized.header.height()
                || plan.operation_count() != expected_operation_count
                || !plan.binds_exact_operations_v0(&poco_raws)
            {
                return Err(invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
                ));
            }
            writes.extend(
                crate::poco_transition::auth_writes_from_sealed_poco_application_v0(plan).map_err(
                    |_| {
                        invariant(
                            CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
                        )
                    },
                )?,
            );
        }
        (
            Some(FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(projection)),
            true,
            true,
        ) => {
            if projection.manifest().cutoff_height().get()
                > authorized.context.parent_header.height().get()
            {
                return Err(invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
                ));
            }
            writes.push(
                crate::poco_transition::scheduled_cutoff_manifest_refresh_write_v0(
                    trnm_consensus_types::Height::new(target_height),
                    projection,
                )
                .map_err(|_| {
                    invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites)
                })?,
            );
        }
        (None, true, false) => {}
        _ => {
            return Err(invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
            ));
        }
    }
    validate_unique_complete_body_auth_writes_v0(&writes).map_err(|_| {
        invariant(CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyMergedWrites)
    })?;
    Ok(writes)
}

/// Rebuilds the exact body-wide receipt sequence and merged authenticated
/// write set from one snapshot-finished mixed-body owner, then compares the
/// resulting four roots with its only retained header. The comparator accepts
/// no detached body, plan, receipt, root, verifier, route, or validation ID.
/// It neither replans nor applies authenticated state and cannot construct an
/// execution outcome, callback, persistence record, or Core input.
#[allow(dead_code)]
fn match_finished_core_authorized_regular_complete_body_commitments_v0(
    finished: FinishedPlannedCoreAuthorizedRegularCompleteBodyV0,
) -> std::result::Result<
    MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0,
    Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>,
> {
    let comparison = (|| {
        validate_finished_complete_body_item_provenance_v0(&finished)?;
        let writes = rebuild_finished_complete_body_auth_writes_v0(&finished)?;
        finished
            .post_state_update
            .verify_seal_v0(&finished.post_state_update_seal)
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
                )
            })?;
        let header = &finished.authorized.header;
        if finished.post_state_update.version != header.height().get() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateVersion,
            ));
        }
        if !planned_auth_update_matches_writes_v0(&finished.post_state_update, &writes) {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyMergedWrites,
            ));
        }

        let native_execution = rebuild_finished_complete_body_native_execution_v0(&finished)?;
        if native_execution.application_payload() != finished.authorized.body.application_payload()
        {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeExecutionRebuild,
            ));
        }

        let body = &finished.authorized.body;
        let post_state_root = StateRoot::new(finished.post_state_update.root_hash.into());
        let payload_root = body.payload_root().map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PayloadRootComputation,
            )
        })?;
        if header.payload_root() != payload_root {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedPayloadRootDrift,
            ));
        }
        let receipts_root = native_execution
            .execution_receipts()
            .receipts_root()
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::ReceiptsRootComputation,
                )
            })?;
        let evidence_root = body.evidence_root().map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::EvidenceRootComputation,
            )
        })?;
        if header.evidence_root() != evidence_root {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedEvidenceRootDrift,
            ));
        }

        let computed_header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            payload_root,
            post_state_root,
            receipts_root,
            evidence_root,
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation,
            )
        })?;
        let validated_commitments = body
            .validate_ordinary_commitments(
                &computed_header,
                native_execution.execution_receipts(),
                &finished.authorized.context.parameters,
                &finished.authorized.context.validator_set,
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation,
                )
            })?;
        if validated_commitments.block_id() != computed_header.id()
            || header.id() != finished.authorized.validation_id.block_id()
        {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            ));
        }

        // Only successfully rebuilt state and receipt roots can become signed
        // deterministic mismatches. Every provenance, write-set, seal, static
        // commitment, and owner check above remains fail-stop. The order is a
        // stable state-before-receipts protocol decision.
        if header.state_root() != post_state_root {
            return Err(
                CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                    CoreAuthorizedRegularComputedRootMismatchV0::State,
                ),
            );
        }
        if header.receipts_root() != receipts_root {
            return Err(
                CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                    CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
                ),
            );
        }
        if computed_header.id() != finished.authorized.validation_id.block_id() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            ));
        }
        Ok((native_execution, validated_commitments))
    })();

    match comparison {
        Ok((native_execution, validated_commitments)) => {
            Ok(MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
                finished,
                native_execution,
                validated_commitments,
            })
        }
        Err(cause) => Err(Box::new(
            FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0 { finished, cause },
        )),
    }
}

/// Classifies the complete-body owning comparison without promoting it into
/// an execution outcome or granting callback/persistence authority. Snapshot
/// unavailability is structurally absent because the exact parent snapshot
/// was already closed by the complete-body planner.
#[allow(dead_code)]
fn classify_core_authorized_regular_complete_body_commitment_comparison_v0(
    comparison: std::result::Result<
        MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0,
        Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>,
    >,
) -> ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
    match comparison {
        Ok(matched) => {
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(Box::new(matched))
        }
        Err(failed) => match failed.cause {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State
                | CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
            ) => {
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                    DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
                        failed,
                    },
                )
            }
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(_) => {
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(failed)
            }
        },
    }
}

/// Consumes the only owning deterministic-invalid complete-body branch and
/// joins it to the durable reservation already retained by the exact Core
/// request. There is no overload accepting a detached route, validation ID,
/// reservation, mismatch, or reason code.
///
/// A test-only reservation, a retained invariant cause, or any route/full-ID
/// disagreement preserves the complete owner and cannot mint durable artifact
/// authority. Valid and invariant classifier branches are structurally unable
/// to call this function because they have different owner types.
#[allow(dead_code)]
fn prepare_durable_invalid_complete_body_v0(
    owner: DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0,
) -> Result<PreparedDurableInvalidV0, Box<FailedPrepareDurableInvalidV0>> {
    let reason = match owner.failed.cause {
        CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
            CoreAuthorizedRegularComputedRootMismatchV0::State,
        ) => DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
        CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
            CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
        ) => DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch,
        CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(_) => {
            return Err(Box::new(FailedPrepareDurableInvalidV0 {
                owner,
                cause: PrepareDurableInvalidFailureCauseV0::RetainedCauseInvariant,
            }));
        }
    };
    let authorized = &owner.failed.finished.authorized;
    #[cfg(not(test))]
    let CoreAuthorizedRegularReservationV0::Durable(reservation) = &authorized.reservation;
    #[cfg(test)]
    let reservation = match &authorized.reservation {
        CoreAuthorizedRegularReservationV0::Durable(reservation) => reservation,
        CoreAuthorizedRegularReservationV0::TestOnly => {
            return Err(Box::new(FailedPrepareDurableInvalidV0 {
                owner,
                cause: PrepareDurableInvalidFailureCauseV0::TestOnlyReservation,
            }));
        }
    };
    if reservation.route() != authorized.route {
        return Err(Box::new(FailedPrepareDurableInvalidV0 {
            owner,
            cause: PrepareDurableInvalidFailureCauseV0::ReservationRouteInvariant,
        }));
    }
    if reservation.validation_id() != authorized.validation_id {
        return Err(Box::new(FailedPrepareDurableInvalidV0 {
            owner,
            cause: PrepareDurableInvalidFailureCauseV0::ReservationValidationIdInvariant,
        }));
    }

    let DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0 { failed } = owner;
    let FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0 { finished, cause: _ } =
        *failed;
    let FinishedPlannedCoreAuthorizedRegularCompleteBodyV0 { authorized, .. } = finished;
    let CoreAuthorizedExactRegularBodyV0 { reservation, .. } = authorized;
    #[cfg(not(test))]
    let CoreAuthorizedRegularReservationV0::Durable(reservation) = reservation;
    #[cfg(test)]
    let reservation = match reservation {
        CoreAuthorizedRegularReservationV0::Durable(reservation) => reservation,
        CoreAuthorizedRegularReservationV0::TestOnly => {
            unreachable!("durable reservation was checked before consuming the exact owner")
        }
    };
    Ok(PreparedDurableInvalidV0 {
        reservation,
        reason,
    })
}

/// Rebuilds all commitment material from one finished production plan and
/// compares it to the only retained header. There is no second header, body,
/// plan, root, receipt, configuration, or verifier input, and neither success
/// nor failure is terminal/Core/ABCI authority.
#[allow(dead_code)]
fn match_finished_core_authorized_regular_runtime_commitments_v0(
    finished: FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0,
) -> std::result::Result<
    MatchedCoreAuthorizedRegularRuntimeCommitmentsV0,
    Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>,
> {
    let comparison = (|| {
        let body = &finished.authorized.body;
        let header = &finished.authorized.header;
        let transactions = body.application_payload().transactions();
        if finished.applied.len() != transactions.len() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::TransactionCount,
            ));
        }
        for (index, (applied, transaction)) in finished.applied.iter().zip(transactions).enumerate()
        {
            let expected_index = u32::try_from(index).map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance,
                )
            })?;
            if applied.index != expected_index
                || applied.exact_outer_bytes.as_slice() != transaction.as_slice()
                || applied.context.target_height != header.height().get()
                || applied.context.target_block_id != finished.authorized.validation_id.block_id()
                || applied.context.validation_timestamp_ms != header.timestamp_ms()
                || applied.context.payload_len != applied.exact_inner_bytes.len()
            {
                return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::TransactionProvenance,
                ));
            }
        }
        let rebuilt_changes =
            rebuild_finished_runtime_receipt_changes_v0(header.height().get(), &finished.applied)
                .ok_or(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta,
            ))?;
        if rebuilt_changes != finished.changes {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta,
            ));
        }

        let receipt_facts = finished
            .applied
            .iter()
            .map(|applied| {
                let rebuilt = NativeTransactionReceiptFactsV0::try_from_runtime_receipt(
                    &applied.runtime_receipt,
                )
                .map_err(|_| {
                    CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                        CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
                    )
                })?;
                if rebuilt != applied.native_receipt {
                    return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                        CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
                    ));
                }
                Ok(rebuilt)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let transaction_bytes = transactions
            .iter()
            .map(|transaction| Bytes::copy_from_slice(transaction))
            .collect::<Vec<_>>();
        let native_execution = NativeBlockExecutionV0::try_new(&transaction_bytes, receipt_facts)
            .map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeExecutionRebuild,
            )
        })?;
        if native_execution.application_payload() != body.application_payload() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeExecutionRebuild,
            ));
        }

        finished
            .post_state_update
            .verify_seal_v0(&finished.post_state_update_seal)
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
                )
            })?;
        if finished.post_state_update.version != header.height().get() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateVersion,
            ));
        }
        if !planned_auth_update_matches_runtime_changes_v0(
            &finished.post_state_update,
            &finished.changes,
        ) {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateDelta,
            ));
        }
        let post_state_root = StateRoot::new(finished.post_state_update.root_hash.into());
        let payload_root = body.payload_root().map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PayloadRootComputation,
            )
        })?;
        if header.payload_root() != payload_root {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedPayloadRootDrift,
            ));
        }
        let receipts_root = native_execution
            .execution_receipts()
            .receipts_root()
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::ReceiptsRootComputation,
                )
            })?;
        let evidence_root = body.evidence_root().map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::EvidenceRootComputation,
            )
        })?;
        if header.evidence_root() != evidence_root {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedEvidenceRootDrift,
            ));
        }

        // Rebuild the complete static commitment surface with the values just
        // computed from the retained body, runtime receipts, and same-snapshot
        // JMT plan. Static/configuration verification is an invariant gate and
        // therefore runs before any root mismatch can become a deterministic
        // invalidity candidate.
        let computed_header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            payload_root,
            post_state_root,
            receipts_root,
            evidence_root,
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .map_err(|_| {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation,
            )
        })?;
        let validated_commitments = body
            .validate_ordinary_commitments(
                &computed_header,
                native_execution.execution_receipts(),
                &finished.authorized.context.parameters,
                &finished.authorized.context.validator_set,
                &StrictEd25519Verifier,
            )
            .map_err(|_| {
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation,
                )
            })?;
        if validated_commitments.block_id() != computed_header.id()
            || header.id() != finished.authorized.validation_id.block_id()
        {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            ));
        }

        // Only roots that were computed successfully, survived every
        // provenance/static invariant above, and differ from the retained
        // authorized header enter the deterministic-mismatch taxonomy. The
        // order is stable and intentionally state-before-receipts.
        if header.state_root() != post_state_root {
            return Err(
                CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                    CoreAuthorizedRegularComputedRootMismatchV0::State,
                ),
            );
        }
        if header.receipts_root() != receipts_root {
            return Err(
                CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                    CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
                ),
            );
        }
        if computed_header.id() != finished.authorized.validation_id.block_id() {
            return Err(CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            ));
        }
        Ok((native_execution, validated_commitments))
    })();

    match comparison {
        Ok((native_execution, validated_commitments)) => {
            Ok(MatchedCoreAuthorizedRegularRuntimeCommitmentsV0 {
                finished,
                native_execution,
                validated_commitments,
            })
        }
        Err(cause) => Err(Box::new(
            FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0 { finished, cause },
        )),
    }
}

/// Classifies one complete owning comparison result without weakening its
/// authority boundary. Source unavailability is structurally absent because
/// it is resolved before runtime execution and can never reach this function.
/// Only successfully computed state/receipt mismatches are deterministic;
/// every comparator invariant remains fail-stop and retains its failed plan.
#[allow(dead_code)]
fn classify_core_authorized_regular_runtime_commitment_comparison_v0(
    comparison: std::result::Result<
        MatchedCoreAuthorizedRegularRuntimeCommitmentsV0,
        Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>,
    >,
) -> ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 {
    match comparison {
        Ok(matched) => {
            ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::Valid(Box::new(matched))
        }
        Err(failed) => match failed.cause {
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State
                | CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
            ) => ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::DeterministicallyInvalid(
                failed,
            ),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(_) => {
                ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::InvariantFault(failed)
            }
        },
    }
}

/// Consumes one complete owning comparator classification. The success branch
/// has no generation/header/root/body parameter and therefore cannot splice a
/// second validation attempt into the app-private `Valid` authority.
#[allow(dead_code)]
fn promote_core_authorized_regular_execution_outcome_v0(
    classified: ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0,
) -> CoreAuthorizedRegularExecutionOutcomeV0 {
    match classified {
        ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::Valid(matched) => {
            CoreAuthorizedRegularExecutionOutcomeV0::Valid(
                crate::execution_outcome::valid_from_core_authorized_regular_match_v0(matched),
            )
        }
        ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::DeterministicallyInvalid(failed) => {
            let outcome =
                crate::execution_outcome::failure_from_core_authorized_regular_comparison_v0(
                    &failed,
                );
            CoreAuthorizedRegularExecutionOutcomeV0::DeterministicallyInvalid(
                RetainedFailedCoreAuthorizedRegularExecutionOutcomeV0 { outcome, failed },
            )
        }
        ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::InvariantFault(failed) => {
            let outcome =
                crate::execution_outcome::failure_from_core_authorized_regular_comparison_v0(
                    &failed,
                );
            CoreAuthorizedRegularExecutionOutcomeV0::InvariantFault(
                RetainedFailedCoreAuthorizedRegularExecutionOutcomeV0 { outcome, failed },
            )
        }
    }
}

/// Admits only terminal, Core-representable outcomes to the consuming callback
/// carrier. Comparator invariants retain the exact owner on the fail-stop path
/// and cannot be downgraded to unavailable or deterministic rejection.
#[allow(dead_code)]
fn authorize_core_regular_payload_validation_callback_v0(
    outcome: CoreAuthorizedRegularExecutionOutcomeV0,
) -> CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0 {
    if matches!(
        outcome,
        CoreAuthorizedRegularExecutionOutcomeV0::InvariantFault(_)
    ) {
        CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::InvariantFault(outcome)
    } else {
        CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::Ready(
            CoreAuthorizedRegularPayloadValidationCallbackV0 { outcome },
        )
    }
}

/// Test-only stand-in for a future Core-authorized exact validation request.
///
/// This is inert comparison material. It does not prove a proposal signature,
/// leader schedule, justify QC/TC, lock rule, or authenticated parent state.
#[cfg(test)]
struct TestAuthorizedRegularRuntimeRequestV0 {
    block_id: BlockId,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    signer_policy_commitment: [u8; 32],
}

#[cfg(test)]
impl TestAuthorizedRegularRuntimeRequestV0 {
    fn from_exact_header_for_test_v0(
        header: &BlockHeader,
        signer_policy_commitment: [u8; 32],
    ) -> Self {
        Self {
            block_id: header.id(),
            genesis_hash: header.genesis_hash(),
            chain_id: header.chain_id(),
            protocol_version: header.protocol_version(),
            epoch: header.epoch(),
            signer_policy_commitment,
        }
    }
}

/// Exact regular-block comparison inputs.
///
/// The fields are private and the type deliberately implements neither
/// `Clone` nor serde/conversion traits. Holding it proves only the narrow joins
/// performed by the test-only fixture constructor below; it is not execution,
/// proposal, vote, or state-transition authority.
struct AuthenticatedRegularRuntimeInputsV0 {
    authorized_block_id: BlockId,
    header: BlockHeader,
    body: BlockBodyV0,
    parent_header: BlockHeader,
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    signer_policy: NativeSignerPolicyBindingV0,
}

impl AuthenticatedRegularRuntimeInputsV0 {
    fn parent_header(&self) -> &BlockHeader {
        &self.parent_header
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeRegularInputJoinFailureV0 {
    reason: &'static str,
}

#[cfg(test)]
impl NativeRegularInputJoinFailureV0 {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

/// Test-only exact join for the deliberately unsupported production carrier.
///
/// The duplicate signer-policy value is only fixture comparison material.
/// The snapshot-owned open step performs the actual test-store configuration
/// comparison. Neither entry point is a production constructor in this
/// tranche.
#[cfg(test)]
fn authenticate_regular_runtime_inputs_for_test_v0(
    request: TestAuthorizedRegularRuntimeRequestV0,
    header: BlockHeader,
    body: BlockBodyV0,
    parent_header: BlockHeader,
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    fixture_authorized_signers: Vec<AuthorizedSignerV1>,
) -> Result<AuthenticatedRegularRuntimeInputsV0, NativeRegularInputJoinFailureV0> {
    crate::validate_authorized_signers_v1(&fixture_authorized_signers).map_err(|_| {
        NativeRegularInputJoinFailureV0::new("fixture signer policy is not canonical")
    })?;
    let fixture_signer_policy_commitment =
        crate::signer_policy_commitment(&fixture_authorized_signers);
    if request.block_id != header.id() {
        return Err(NativeRegularInputJoinFailureV0::new(
            "authorized request BlockId differs from exact header",
        ));
    }
    if request.genesis_hash != header.genesis_hash()
        || request.chain_id != header.chain_id()
        || request.protocol_version != header.protocol_version()
        || request.epoch != header.epoch()
    {
        return Err(NativeRegularInputJoinFailureV0::new(
            "authorized request context differs from exact header",
        ));
    }
    if request.signer_policy_commitment != fixture_signer_policy_commitment {
        return Err(NativeRegularInputJoinFailureV0::new(
            "authorized signer policy differs from fixture comparison value",
        ));
    }
    if header.block_kind() != BlockKind::Regular || parent_header.block_kind() != BlockKind::Regular
    {
        return Err(NativeRegularInputJoinFailureV0::new(
            "only a regular block with a regular same-epoch parent is supported",
        ));
    }
    if header.parent_id() != parent_header.id() {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact parent BlockId differs from header parent_id",
        ));
    }
    let expected_height = parent_header
        .height()
        .checked_next()
        .map_err(|_| NativeRegularInputJoinFailureV0::new("exact parent height cannot advance"))?;
    if header.height() != expected_height {
        return Err(NativeRegularInputJoinFailureV0::new(
            "target height is not immediately after exact parent",
        ));
    }
    if header.genesis_hash() != parent_header.genesis_hash()
        || header.chain_id() != parent_header.chain_id()
        || header.protocol_version() != parent_header.protocol_version()
        || header.epoch() != parent_header.epoch()
    {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact parent consensus context differs from target header",
        ));
    }
    if header.genesis_hash() != validator_set.genesis_hash()
        || header.chain_id() != validator_set.chain_id()
        || header.protocol_version() != validator_set.protocol_version()
        || header.epoch() != validator_set.epoch()
        || header.validator_set_id() != validator_set.id()
        || parent_header.validator_set_id() != validator_set.id()
    {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact validator-set context differs from header chain context",
        ));
    }
    if header.consensus_parameters_hash() != parameters.hash()
        || parent_header.consensus_parameters_hash() != parameters.hash()
        || parameters.protocol_version() != header.protocol_version().get()
    {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact consensus parameters differ from header commitments",
        ));
    }
    validator_set
        .validate_against_parameters(&parameters)
        .map_err(|_| {
            NativeRegularInputJoinFailureV0::new(
                "validator set fails exact consensus-parameter bounds",
            )
        })?;
    if validator_set.validator(header.proposer_id()).is_none() {
        return Err(NativeRegularInputJoinFailureV0::new(
            "header proposer is absent from exact validator set",
        ));
    }
    let payload_root = body.payload_root().map_err(|_| {
        NativeRegularInputJoinFailureV0::new("cannot derive exact body payload root")
    })?;
    if payload_root != header.payload_root() {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact body payload root differs from header commitment",
        ));
    }
    let evidence_root = body.evidence_root().map_err(|_| {
        NativeRegularInputJoinFailureV0::new("cannot derive exact body evidence root")
    })?;
    if evidence_root != header.evidence_root() {
        return Err(NativeRegularInputJoinFailureV0::new(
            "exact body evidence root differs from header commitment",
        ));
    }
    body.validate_max_block_bytes(&header, parameters.max_block_bytes())
        .map_err(|_| {
            NativeRegularInputJoinFailureV0::new(
                "exact header/body exceed committed block-size bound",
            )
        })?;

    Ok(AuthenticatedRegularRuntimeInputsV0 {
        authorized_block_id: request.block_id,
        header,
        body,
        parent_header,
        validator_set,
        parameters,
        signer_policy: NativeSignerPolicyBindingV0 {
            commitment: fixture_signer_policy_commitment,
            authorized_signers: fixture_authorized_signers,
        },
    })
}

/// One exact body item observed by the internal, sequential inert cursor.
///
/// Its index, bytes, and derived envelope/transaction facts come only from the
/// retained native body/header plus the store-bound test signer policy. It
/// intentionally contains no executable runtime context, receipt, mutation,
/// or terminal disposition.
struct InertExactBodyTransactionObservationV0 {
    index: u32,
    exact_outer_bytes: Vec<u8>,
    exact_inner_payload_bytes: Vec<u8>,
    target_height: u64,
    target_block_id: BlockId,
    validation_timestamp_ms: u64,
    signer_id: String,
    signer_role: String,
    nonce: u64,
    payload_len: u32,
}

/// Non-authoritative observations owned by the inert test traversal.
struct InertRegularBodyTraversalObservationV0 {
    transactions: Vec<InertExactBodyTransactionObservationV0>,
}

/// Whole open traversal: exact inputs, the one authenticated SQLite snapshot,
/// and the inert observation are owned by one non-cloneable value.
#[must_use = "dropping an open traversal cannot produce a finished traversal"]
struct OpenInertRegularBodyTraversalV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    snapshot: AuthenticatedRuntimeReadSnapshotV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    next_transaction_index: u32,
    observation: InertRegularBodyTraversalObservationV0,
}

/// Consumed cursor failure which still owns the exact inputs and SQLite
/// snapshot. Callers must explicitly finish this value before the cursor
/// rejection can be observed; Drop alone never yields a terminal fact.
#[cfg(test)]
#[must_use = "a failed inert traversal must be explicitly finished before its cursor classification can be observed"]
struct FailedInertRegularBodyTraversalV0 {
    open: OpenInertRegularBodyTraversalV0,
    cause: InertRegularBodyCursorFailureV0,
}

#[cfg(test)]
impl std::fmt::Debug for FailedInertRegularBodyTraversalV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedInertRegularBodyTraversalV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

/// Opaque proof that the exact inert traversal's own snapshot finished cleanly.
///
/// This type has no conversion into `ExecutionOutcomeV0` and carries no
/// execution result. It exists only to freeze the ownership shape required by
/// the future real dispatcher/session implementation.
struct FinishedInertRegularBodyTraversalV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    observation: InertRegularBodyTraversalObservationV0,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InertRegularBodyCursorFailureV0 {
    Exhausted,
    IndexOverflow,
    InvalidEnvelope,
    InvalidOrUnauthorizedEnvelope,
    UnsupportedPayloadType,
    InvalidCanonicalTransaction,
    SenderMismatch,
    NonceMismatch,
    PayloadLengthOverflow,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum InertRegularBodyFinishFailureV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    IncompleteBody { observed: u32, expected: u32 },
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum FinishedInertRegularBodyCursorFailureV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    Cursor(InertRegularBodyCursorFailureV0),
}

#[cfg(test)]
struct DecodedExactBodyRuntimeTransactionV0 {
    observation: InertExactBodyTransactionObservationV0,
    transaction: CanonicalTxV1,
    next_transaction_index: u32,
}

/// Decodes exactly the item selected by the owning cursor. Every runtime
/// context field is derived from the retained header, exact envelope, and
/// store-bound signer policy; callers cannot supply a second tx or context.
#[cfg(test)]
fn decode_next_exact_body_runtime_transaction_for_test_v0(
    inputs: &AuthenticatedRegularRuntimeInputsV0,
    index: u32,
) -> Result<DecodedExactBodyRuntimeTransactionV0, InertRegularBodyCursorFailureV0> {
    let decoded = decode_exact_authorized_runtime_transaction_for_test_v0(
        &inputs.header,
        &inputs.body,
        inputs.authorized_block_id,
        &inputs.signer_policy.authorized_signers,
        index,
    )
    .map_err(|cause| match cause {
        CoreAuthorizedRegularTransactionDecodeCauseV0::Exhausted => {
            InertRegularBodyCursorFailureV0::Exhausted
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::IndexOverflow => {
            InertRegularBodyCursorFailureV0::IndexOverflow
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope => {
            InertRegularBodyCursorFailureV0::InvalidEnvelope
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidOrUnauthorizedEnvelope => {
            InertRegularBodyCursorFailureV0::InvalidOrUnauthorizedEnvelope
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::NonRuntimePayload => {
            InertRegularBodyCursorFailureV0::UnsupportedPayloadType
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidCanonicalTransaction => {
            InertRegularBodyCursorFailureV0::InvalidCanonicalTransaction
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::SenderMismatch => {
            InertRegularBodyCursorFailureV0::SenderMismatch
        }
        CoreAuthorizedRegularTransactionDecodeCauseV0::NonceMismatch => {
            InertRegularBodyCursorFailureV0::NonceMismatch
        }
    })?;
    let payload_len = u32::try_from(decoded.context.payload_len)
        .map_err(|_| InertRegularBodyCursorFailureV0::PayloadLengthOverflow)?;
    let nonce = decoded.transaction.nonce;
    Ok(DecodedExactBodyRuntimeTransactionV0 {
        observation: InertExactBodyTransactionObservationV0 {
            index: decoded.index,
            exact_outer_bytes: decoded.exact_outer_bytes,
            exact_inner_payload_bytes: decoded.exact_inner_bytes,
            target_height: decoded.context.target_height,
            target_block_id: decoded.context.target_block_id,
            validation_timestamp_ms: decoded.context.validation_timestamp_ms,
            signer_id: decoded.context.signer_id,
            signer_role: decoded.context.signer_role,
            nonce,
            payload_len,
        },
        transaction: decoded.transaction,
        next_transaction_index: decoded.next_transaction_index,
    })
}

#[cfg(test)]
fn open_inert_regular_body_traversal_for_test_v0(
    store: &ApplicationStore,
    inputs: AuthenticatedRegularRuntimeInputsV0,
) -> Result<OpenInertRegularBodyTraversalV0, AuthenticatedRuntimeReadFailureV0> {
    let configured_signer_policy = store.configured_signer_policy_commitment_v0()?;
    if inputs.signer_policy.commitment != configured_signer_policy {
        return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
            sqlite: None,
            reason: "joined signer policy differs from local application-store configuration",
        });
    }
    if inputs.header.chain_id().as_str() != store.configured_chain_id_v0() {
        return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
            sqlite: None,
            reason: "exact header chain differs from local application-store configuration",
        });
    }
    // The caller supplies no expected height/root. They are derived only from
    // the exact parent retained by the already-joined input capability.
    let parent = inputs.parent_header();
    let snapshot = store.begin_authenticated_runtime_read_snapshot_for_test_v0(
        parent.height().get(),
        *parent.state_root().as_bytes(),
    )?;
    let lifecycle_join = snapshot
        .load_authenticated_validator_lifecycle_v0()
        .and_then(|lifecycle| {
            crate::poco_checkpoint::validate_application_validator_projection(
                &inputs.validator_set,
                &lifecycle.active_validators,
            )
            .map_err(|_| {
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyObject,
                    sqlite: None,
                    reason: "retained validator set differs from authenticated parent lifecycle",
                }
            })?;
            Ok(lifecycle)
        });
    let authenticated_validator_lifecycle = match lifecycle_join {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            return Err(match snapshot.finish() {
                Ok(()) => error,
                Err(finish_error) => finish_error,
            });
        }
    };
    let observation = InertRegularBodyTraversalObservationV0 {
        transactions: Vec::new(),
    };
    Ok(OpenInertRegularBodyTraversalV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        next_transaction_index: 0,
        observation,
    })
}

#[cfg(test)]
fn observe_next_exact_body_transaction_for_test_v0(
    mut open: OpenInertRegularBodyTraversalV0,
) -> Result<OpenInertRegularBodyTraversalV0, Box<FailedInertRegularBodyTraversalV0>> {
    match decode_next_exact_body_runtime_transaction_for_test_v0(
        &open.inputs,
        open.next_transaction_index,
    ) {
        Ok(decoded) => {
            open.observation.transactions.push(decoded.observation);
            open.next_transaction_index = decoded.next_transaction_index;
            Ok(open)
        }
        Err(cause) => Err(Box::new(FailedInertRegularBodyTraversalV0 { open, cause })),
    }
}

#[cfg(test)]
fn finish_failed_inert_regular_body_traversal_for_test_v0(
    failed: Box<FailedInertRegularBodyTraversalV0>,
) -> FinishedInertRegularBodyCursorFailureV0 {
    let FailedInertRegularBodyTraversalV0 { open, cause } = *failed;
    let OpenInertRegularBodyTraversalV0 { snapshot, .. } = open;
    match snapshot.finish() {
        Ok(()) => FinishedInertRegularBodyCursorFailureV0::Cursor(cause),
        Err(error) => FinishedInertRegularBodyCursorFailureV0::Snapshot(error),
    }
}

#[cfg(test)]
fn finish_inert_regular_body_traversal_for_test_v0(
    open: OpenInertRegularBodyTraversalV0,
) -> Result<FinishedInertRegularBodyTraversalV0, InertRegularBodyFinishFailureV0> {
    let OpenInertRegularBodyTraversalV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        next_transaction_index,
        observation,
    } = open;
    // No independently reusable finish marker is returned. A rollback/close
    // failure consumes the whole traversal and prevents construction of the
    // finished capability.
    snapshot
        .finish()
        .map_err(InertRegularBodyFinishFailureV0::Snapshot)?;
    let expected = inputs.body.application_payload().transaction_count();
    if next_transaction_index != expected {
        return Err(InertRegularBodyFinishFailureV0::IncompleteBody {
            observed: next_transaction_index,
            expected,
        });
    }
    Ok(FinishedInertRegularBodyTraversalV0 {
        inputs,
        authenticated_validator_lifecycle,
        observation,
    })
}

#[cfg(test)]
fn inject_snapshot_finish_failure_for_test_v0(
    mut open: OpenInertRegularBodyTraversalV0,
) -> OpenInertRegularBodyTraversalV0 {
    open.snapshot.inject_finish_failure_for_test_v0();
    open
}

/// One successful, exact transaction attempt retained only inside the owning
/// test session. Neither receipt representation is execution authority.
#[cfg(test)]
struct AppliedExactRuntimeTransactionV0 {
    observation: InertExactBodyTransactionObservationV0,
    canonical_transaction: CanonicalTxV1,
    runtime_receipt: RuntimeReceipt,
    native_receipt: NativeTransactionReceiptFactsV0,
}

/// Test-only block execution session. The exact inputs, one authenticated
/// parent snapshot, all uncommitted changes, and all successful receipts move
/// together and cannot be cloned or serialized.
#[cfg(test)]
#[must_use = "an open test runtime execution must be explicitly finished"]
struct OpenTestRegularRuntimeExecutionV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    snapshot: AuthenticatedRuntimeReadSnapshotV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    next_transaction_index: u32,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedExactRuntimeTransactionV0>,
}

#[cfg(test)]
struct TestRegularRuntimeStateViewV0<'a> {
    changes: &'a BTreeMap<String, StoredObject>,
    snapshot: &'a AuthenticatedRuntimeReadSnapshotV0,
}

#[cfg(test)]
impl TryStateViewV0 for TestRegularRuntimeStateViewV0<'_> {
    type Error = AuthenticatedRuntimeReadFailureV0;

    fn try_get(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StateObject>, Self::Error> {
        let object = match self.changes.get(object_key_hex) {
            Some(object) => Some(object.clone()),
            None => self.snapshot.load(object_key_hex)?,
        };
        Ok(object.map(|object| StateObject {
            object_type: object.object_type,
            version: object.version,
            value_bytes: object.value_bytes,
        }))
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum TestRegularRuntimeMutationStageFailureV0 {
    StateRead(AuthenticatedRuntimeReadFailureV0),
    Invariant(&'static str),
}

#[cfg(test)]
#[derive(Debug)]
enum TestRegularRuntimeStepFailureV0 {
    Cursor(InertRegularBodyCursorFailureV0),
    Runtime(RuntimeExecutionAttemptFailureV0<AuthenticatedRuntimeReadFailureV0>),
    StateRead(AuthenticatedRuntimeReadFailureV0),
    NativeReceiptInvariant,
    MutationInvariant(&'static str),
}

/// Exact decoded transaction provenance retained across a failed step.
///
/// This value is deliberately not cloneable or serializable. Cursor failures
/// that happen before a complete envelope/transaction decode retain `None`;
/// runtime, receipt, and mutation-stage failures retain the exact decoded item
/// selected internally from the body.
#[cfg(test)]
struct FailedExactRuntimeTransactionV0 {
    observation: InertExactBodyTransactionObservationV0,
    canonical_transaction: CanonicalTxV1,
}

/// A failed step retains the immutable exact block/configuration provenance and
/// the snapshot needed for mandatory explicit finish. Previous changes and
/// successful receipts are destroyed before this value is returned, while the
/// exact inputs, authenticated lifecycle, failed index, and decoded failed item
/// remain inseparable from the pending cause. Its Debug representation hides
/// both the cause and retained exact values.
#[cfg(test)]
#[must_use = "a failed test runtime execution must be explicitly finished before its classification can be observed"]
struct FailedTestRegularRuntimeExecutionV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    snapshot: AuthenticatedRuntimeReadSnapshotV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    failed_transaction_index: u32,
    decoded_failed_transaction: Option<FailedExactRuntimeTransactionV0>,
    cause: TestRegularRuntimeStepFailureV0,
}

#[cfg(test)]
impl std::fmt::Debug for FailedTestRegularRuntimeExecutionV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FailedTestRegularRuntimeExecutionV0")
            .field("pending_explicit_snapshot_finish", &true)
            .finish_non_exhaustive()
    }
}

/// Whole, snapshot-finished successful execution plus the post-state plan
/// derived from the same still-open authenticated parent transaction.
///
/// The plan never exists as a separately returned marker. This value has no
/// clone, serde, conversion, or `into_parts` surface and is consumed as a whole
/// by the exact-root comparator below.
#[cfg(test)]
struct FinishedPlannedTestRegularRuntimeExecutionV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    changes: BTreeMap<String, StoredObject>,
    applied: Vec<AppliedExactRuntimeTransactionV0>,
    post_state_update: PlannedAuthUpdate,
}

/// Inert proof that one finished test execution's independently planned state
/// and runtime-derived native commitments exactly match its retained header.
/// This is not a terminal execution outcome, proposal/vote authority, or
/// checkpoint authority.
#[cfg(test)]
struct MatchedTestRegularRuntimeCommitmentsV0 {
    finished: FinishedPlannedTestRegularRuntimeExecutionV0,
    native_execution: NativeBlockExecutionV0,
    validated_commitments: ValidatedBlockCommitmentsV0,
}

/// Whole, snapshot-finished failure capability for the exact test session.
///
/// There is no `into_parts`, conversion trait, clone/serde surface, or API that
/// accepts a second input capability. Classification is observable only through
/// narrow methods on this value after the owned snapshot finished successfully.
#[cfg(test)]
struct FinishedFailedTestRegularRuntimeExecutionV0 {
    inputs: AuthenticatedRegularRuntimeInputsV0,
    authenticated_validator_lifecycle: crate::ValidatorLifecycleStateV1,
    failed_transaction_index: u32,
    decoded_failed_transaction: Option<FailedExactRuntimeTransactionV0>,
    cause: TestRegularRuntimeStepFailureV0,
}

#[cfg(test)]
impl std::fmt::Debug for FinishedFailedTestRegularRuntimeExecutionV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinishedFailedTestRegularRuntimeExecutionV0")
            .field("snapshot_finished", &true)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl FinishedFailedTestRegularRuntimeExecutionV0 {
    fn block_id(&self) -> BlockId {
        self.inputs.authorized_block_id
    }

    fn authenticated_validator_count(&self) -> usize {
        self.authenticated_validator_lifecycle
            .active_validators
            .len()
    }

    fn failed_transaction_index(&self) -> u32 {
        self.failed_transaction_index
    }

    fn decoded_failed_transaction(&self) -> Option<&FailedExactRuntimeTransactionV0> {
        self.decoded_failed_transaction.as_ref()
    }

    fn deterministic_runtime_failure_code(&self) -> Option<&'static str> {
        match &self.cause {
            TestRegularRuntimeStepFailureV0::Runtime(attempt) => attempt
                .deterministic_failure_v0()
                .map(|failure| failure.code()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum TestRegularRuntimeFinishFailureV0 {
    Snapshot(AuthenticatedRuntimeReadFailureV0),
    IncompleteBody { executed: u32, expected: u32 },
    PrepareWritesInvariant,
    Plan(AuthenticatedRuntimeReadFailureV0),
    PlanTargetInvariant,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestRegularRuntimeCommitmentComparisonFailureV0 {
    TransactionCountMismatch,
    TransactionProvenanceMismatch,
    NativeReceiptInvariant,
    NativeExecutionInvariant,
    PlannedStateVersionMismatch,
    StateRootMismatch,
    PayloadRootMismatch,
    ReceiptsRootMismatch,
    EvidenceRootMismatch,
    StaticCommitmentsInvalid,
    BlockIdMismatch,
}

/// The legacy test session delegates to the same production atomic staging
/// kernel so its exhaustive mutation matrix exercises the live cursor path.
#[cfg(test)]
fn stage_runtime_mutations_for_test_v0(
    open: &OpenTestRegularRuntimeExecutionV0,
    mutations: &[RuntimeMutation],
) -> std::result::Result<BTreeMap<String, StoredObject>, TestRegularRuntimeMutationStageFailureV0> {
    match stage_core_authorized_runtime_mutations_v0(
        &open.snapshot,
        open.inputs.header.height().get(),
        &open.changes,
        mutations,
    ) {
        Ok(changes) => Ok(changes),
        Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::StateRead(error)) => {
            Err(TestRegularRuntimeMutationStageFailureV0::StateRead(error))
        }
        Err(CoreAuthorizedRegularRuntimeMutationStageFailureV0::Invariant(reason)) => Err(
            TestRegularRuntimeMutationStageFailureV0::Invariant(reason.reason()),
        ),
    }
}

#[cfg(test)]
fn open_test_regular_runtime_execution_for_test_v0(
    store: &ApplicationStore,
    inputs: AuthenticatedRegularRuntimeInputsV0,
) -> std::result::Result<OpenTestRegularRuntimeExecutionV0, AuthenticatedRuntimeReadFailureV0> {
    let inert = open_inert_regular_body_traversal_for_test_v0(store, inputs)?;
    let OpenInertRegularBodyTraversalV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        ..
    } = inert;
    Ok(OpenTestRegularRuntimeExecutionV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        next_transaction_index: 0,
        changes: BTreeMap::new(),
        applied: Vec::new(),
    })
}

#[cfg(test)]
fn fail_test_regular_runtime_execution_for_test_v0(
    open: OpenTestRegularRuntimeExecutionV0,
    decoded_failed_transaction: Option<DecodedExactBodyRuntimeTransactionV0>,
    cause: TestRegularRuntimeStepFailureV0,
) -> Box<FailedTestRegularRuntimeExecutionV0> {
    let OpenTestRegularRuntimeExecutionV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        next_transaction_index,
        changes: _,
        applied: _,
    } = open;
    let decoded_failed_transaction = decoded_failed_transaction.map(|decoded| {
        debug_assert_eq!(decoded.observation.index, next_transaction_index);
        FailedExactRuntimeTransactionV0 {
            observation: decoded.observation,
            canonical_transaction: decoded.transaction,
        }
    });
    Box::new(FailedTestRegularRuntimeExecutionV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        failed_transaction_index: next_transaction_index,
        decoded_failed_transaction,
        cause,
    })
}

#[cfg(test)]
fn execute_next_exact_runtime_transaction_for_test_v0(
    mut open: OpenTestRegularRuntimeExecutionV0,
) -> std::result::Result<OpenTestRegularRuntimeExecutionV0, Box<FailedTestRegularRuntimeExecutionV0>>
{
    let decoded = match decode_next_exact_body_runtime_transaction_for_test_v0(
        &open.inputs,
        open.next_transaction_index,
    ) {
        Ok(decoded) => decoded,
        Err(cause) => {
            return Err(fail_test_regular_runtime_execution_for_test_v0(
                open,
                None,
                TestRegularRuntimeStepFailureV0::Cursor(cause),
            ));
        }
    };
    let attempt = {
        let view = TestRegularRuntimeStateViewV0 {
            changes: &open.changes,
            snapshot: &open.snapshot,
        };
        let context = ExecutionContext {
            height: decoded.observation.target_height,
            signer_id: &decoded.observation.signer_id,
            signer_role: &decoded.observation.signer_role,
            payload_len: decoded.observation.exact_inner_payload_bytes.len(),
        };
        try_execute_v0(&decoded.transaction, context, &view)
    };
    let runtime_receipt = match attempt {
        Ok(receipt) => receipt,
        Err(cause) => {
            return Err(fail_test_regular_runtime_execution_for_test_v0(
                open,
                Some(decoded),
                TestRegularRuntimeStepFailureV0::Runtime(cause),
            ));
        }
    };
    let native_receipt =
        match NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&runtime_receipt) {
            Ok(receipt) => receipt,
            Err(_) => {
                return Err(fail_test_regular_runtime_execution_for_test_v0(
                    open,
                    Some(decoded),
                    TestRegularRuntimeStepFailureV0::NativeReceiptInvariant,
                ));
            }
        };
    let staged_changes =
        match stage_runtime_mutations_for_test_v0(&open, &runtime_receipt.mutations) {
            Ok(changes) => changes,
            Err(TestRegularRuntimeMutationStageFailureV0::StateRead(error)) => {
                return Err(fail_test_regular_runtime_execution_for_test_v0(
                    open,
                    Some(decoded),
                    TestRegularRuntimeStepFailureV0::StateRead(error),
                ));
            }
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(reason)) => {
                return Err(fail_test_regular_runtime_execution_for_test_v0(
                    open,
                    Some(decoded),
                    TestRegularRuntimeStepFailureV0::MutationInvariant(reason),
                ));
            }
        };
    open.changes = staged_changes;
    open.next_transaction_index = decoded.next_transaction_index;
    open.applied.push(AppliedExactRuntimeTransactionV0 {
        observation: decoded.observation,
        canonical_transaction: decoded.transaction,
        runtime_receipt,
        native_receipt,
    });
    Ok(open)
}

#[cfg(test)]
fn finish_failed_test_regular_runtime_execution_for_test_v0(
    failed: Box<FailedTestRegularRuntimeExecutionV0>,
) -> std::result::Result<
    FinishedFailedTestRegularRuntimeExecutionV0,
    AuthenticatedRuntimeReadFailureV0,
> {
    let FailedTestRegularRuntimeExecutionV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        failed_transaction_index,
        decoded_failed_transaction,
        cause,
    } = *failed;
    snapshot.finish()?;
    Ok(FinishedFailedTestRegularRuntimeExecutionV0 {
        inputs,
        authenticated_validator_lifecycle,
        failed_transaction_index,
        decoded_failed_transaction,
        cause,
    })
}

#[cfg(test)]
fn finish_and_plan_test_regular_runtime_execution_for_test_v0(
    open: OpenTestRegularRuntimeExecutionV0,
) -> std::result::Result<
    FinishedPlannedTestRegularRuntimeExecutionV0,
    TestRegularRuntimeFinishFailureV0,
> {
    let OpenTestRegularRuntimeExecutionV0 {
        inputs,
        snapshot,
        authenticated_validator_lifecycle,
        next_transaction_index,
        changes,
        applied,
    } = open;
    let expected = inputs.body.application_payload().transaction_count();
    let target_height = inputs.header.height().get();
    let planning = if next_transaction_index != expected {
        Err(TestRegularRuntimeFinishFailureV0::IncompleteBody {
            executed: next_transaction_index,
            expected,
        })
    } else {
        let writes = changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|_| TestRegularRuntimeFinishFailureV0::PrepareWritesInvariant);
        writes.and_then(|writes| {
            let plan = snapshot
                .plan_exact_next_auth_update_v0(writes)
                .map_err(TestRegularRuntimeFinishFailureV0::Plan)?;
            if plan.version != target_height {
                return Err(TestRegularRuntimeFinishFailureV0::PlanTargetInvariant);
            }
            Ok(plan)
        })
    };

    // Planning and completeness errors remain inert until the exact snapshot
    // has explicitly finished. A finish error always outranks either result.
    snapshot
        .finish()
        .map_err(TestRegularRuntimeFinishFailureV0::Snapshot)?;
    let post_state_update = planning?;
    Ok(FinishedPlannedTestRegularRuntimeExecutionV0 {
        inputs,
        authenticated_validator_lifecycle,
        changes,
        applied,
        post_state_update,
    })
}

#[cfg(test)]
fn match_finished_test_regular_runtime_commitments_for_test_v0(
    finished: FinishedPlannedTestRegularRuntimeExecutionV0,
) -> std::result::Result<
    MatchedTestRegularRuntimeCommitmentsV0,
    TestRegularRuntimeCommitmentComparisonFailureV0,
> {
    let body = &finished.inputs.body;
    let header = &finished.inputs.header;
    let transactions = body.application_payload().transactions();
    if finished.applied.len() != transactions.len() {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::TransactionCountMismatch);
    }
    for (index, (applied, transaction)) in finished.applied.iter().zip(transactions).enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| {
            TestRegularRuntimeCommitmentComparisonFailureV0::TransactionProvenanceMismatch
        })?;
        if applied.observation.index != expected_index
            || applied.observation.target_height != header.height().get()
            || applied.observation.target_block_id != finished.inputs.authorized_block_id
            || applied.observation.exact_outer_bytes.as_slice() != transaction.as_slice()
        {
            return Err(
                TestRegularRuntimeCommitmentComparisonFailureV0::TransactionProvenanceMismatch,
            );
        }
    }

    let receipt_facts = finished
        .applied
        .iter()
        .map(|applied| {
            NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&applied.runtime_receipt)
                .map_err(|_| {
                    TestRegularRuntimeCommitmentComparisonFailureV0::NativeReceiptInvariant
                })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let transaction_bytes = transactions
        .iter()
        .map(|transaction| Bytes::copy_from_slice(transaction))
        .collect::<Vec<_>>();
    let native_execution = NativeBlockExecutionV0::try_new(&transaction_bytes, receipt_facts)
        .map_err(|_| TestRegularRuntimeCommitmentComparisonFailureV0::NativeExecutionInvariant)?;
    if native_execution.application_payload() != body.application_payload() {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::NativeExecutionInvariant);
    }

    if finished.post_state_update.version != header.height().get() {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::PlannedStateVersionMismatch);
    }
    let post_state_root = StateRoot::new(finished.post_state_update.root_hash.into());
    if header.state_root() != post_state_root {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::StateRootMismatch);
    }
    let payload_root = body
        .payload_root()
        .map_err(|_| TestRegularRuntimeCommitmentComparisonFailureV0::PayloadRootMismatch)?;
    if header.payload_root() != payload_root {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::PayloadRootMismatch);
    }
    let receipts_root = native_execution
        .execution_receipts()
        .receipts_root()
        .map_err(|_| TestRegularRuntimeCommitmentComparisonFailureV0::ReceiptsRootMismatch)?;
    if header.receipts_root() != receipts_root {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::ReceiptsRootMismatch);
    }
    let evidence_root = body
        .evidence_root()
        .map_err(|_| TestRegularRuntimeCommitmentComparisonFailureV0::EvidenceRootMismatch)?;
    if header.evidence_root() != evidence_root {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::EvidenceRootMismatch);
    }
    let validated_commitments = body
        .validate_ordinary_commitments(
            header,
            native_execution.execution_receipts(),
            &finished.inputs.parameters,
            &finished.inputs.validator_set,
            &StrictEd25519Verifier,
        )
        .map_err(|_| TestRegularRuntimeCommitmentComparisonFailureV0::StaticCommitmentsInvalid)?;
    if validated_commitments.block_id() != finished.inputs.authorized_block_id
        || header.id() != finished.inputs.authorized_block_id
    {
        return Err(TestRegularRuntimeCommitmentComparisonFailureV0::BlockIdMismatch);
    }
    Ok(MatchedTestRegularRuntimeCommitmentsV0 {
        finished,
        native_execution,
        validated_commitments,
    })
}

#[cfg(test)]
fn inject_test_runtime_snapshot_finish_failure_for_test_v0(
    mut open: OpenTestRegularRuntimeExecutionV0,
) -> OpenTestRegularRuntimeExecutionV0 {
    open.snapshot.inject_finish_failure_for_test_v0();
    open
}

#[cfg(test)]
impl FinishedPlannedTestRegularRuntimeExecutionV0 {
    fn block_id(&self) -> BlockId {
        self.inputs.authorized_block_id
    }

    fn authenticated_validator_count(&self) -> usize {
        self.authenticated_validator_lifecycle
            .active_validators
            .len()
    }

    fn changes(&self) -> &BTreeMap<String, StoredObject> {
        &self.changes
    }

    fn applied(&self, index: usize) -> &AppliedExactRuntimeTransactionV0 {
        &self.applied[index]
    }

    fn applied_count(&self) -> usize {
        self.applied.len()
    }

    fn planned_state_root(&self) -> StateRoot {
        StateRoot::new(self.post_state_update.root_hash.into())
    }
}

#[cfg(test)]
impl MatchedTestRegularRuntimeCommitmentsV0 {
    fn block_id(&self) -> BlockId {
        self.validated_commitments.block_id()
    }

    fn post_state_root(&self) -> StateRoot {
        self.finished.planned_state_root()
    }

    fn receipts_root(&self) -> trnm_consensus_types::ReceiptsRoot {
        self.native_execution
            .execution_receipts()
            .receipts_root()
            .expect("matched native receipt root was already computed")
    }

    fn finished(&self) -> &FinishedPlannedTestRegularRuntimeExecutionV0 {
        &self.finished
    }
}

#[cfg(test)]
impl FinishedInertRegularBodyTraversalV0 {
    fn block_id(&self) -> BlockId {
        self.inputs.authorized_block_id
    }

    fn exact_header_id(&self) -> BlockId {
        self.inputs.header.id()
    }

    fn parent_block_id(&self) -> BlockId {
        self.inputs.parent_header.id()
    }

    fn transaction_count(&self) -> u32 {
        u32::try_from(self.observation.transactions.len())
            .expect("observed exact transaction count originated from a u32-bounded body")
    }

    fn transaction_observation(&self, index: usize) -> &InertExactBodyTransactionObservationV0 {
        &self.observation.transactions[index]
    }

    fn signer_policy_commitment(&self) -> [u8; 32] {
        self.inputs.signer_policy.commitment
    }

    fn authenticated_validator_count(&self) -> usize {
        self.authenticated_validator_lifecycle
            .active_validators
            .len()
    }

    fn validator_set_id(&self) -> trnm_consensus_types::ValidatorSetId {
        self.inputs.validator_set.id()
    }

    fn parameters_hash(&self) -> trnm_consensus_types::ConsensusParametersHash {
        self.inputs.parameters.hash()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_core::{
        Core, CoreConfig, Effect, Input, PayloadValidationRequest, PayloadValidationResult,
        PayloadValidationRouteV0, SafetyState, ValidationId,
    };
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockId, BlockKind, ChainId,
        ConsensusParametersV0, ConsensusPublicKey, DoubleVoteEvidenceV0, Epoch, EvidenceRoot,
        ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, PayloadDigest, ProposalWitnessV0,
        ProtocolVersion, QcReferenceV0, QuorumCertificate, ReceiptsRoot, SignatureBytes,
        SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot, Validator, ValidatorId,
        ValidatorSet, View, Vote, VotingPower, SIGNATURE_BYTES,
    };
    use trnm_finality_types::SignedCommandEnvelopeV1;
    use trnm_node::live::{node::AuthorizedSignerV1, store::ObjectMutation as NodeObjectMutation};
    use trnm_protocol::{
        account_key, fee_policy_key, monetary_state_key, task_key, AccountV1, CanonicalCommandV1,
        CanonicalTxV1, FeePolicyV1, MonetaryStateV1, TaskStatusV1, TaskV1, ACCOUNT_OBJECT_TYPE_V1,
        CANONICAL_TX_PAYLOAD_TYPE_V1, CANONICAL_TX_SCHEMA_V1, FEE_POLICY_OBJECT_TYPE_V1,
        MONETARY_STATE_OBJECT_TYPE_V1, TASK_OBJECT_TYPE_V1,
    };
    use trnm_runtime::RuntimeMutation;

    use super::{
        advance_core_authorized_non_runtime_success_v0,
        attempt_prepared_core_authorized_runtime_transaction_v0,
        authenticate_regular_runtime_inputs_for_test_v0,
        authorize_and_execute_decoded_core_non_runtime_family_v0,
        authorize_core_regular_payload_validation_callback_v0,
        authorize_exact_regular_body_parts_v0, begin_core_authorized_regular_validation_session_v0,
        claim_core_validation_request_for_test_v0,
        classify_core_authorized_regular_complete_body_commitment_comparison_v0,
        classify_core_authorized_regular_runtime_commitment_comparison_v0,
        core_regular_validation_job_for_test_v0,
        decode_dispatched_core_authorized_non_runtime_payload_v0,
        dispatch_core_authorized_non_runtime_payload_v0,
        execute_next_exact_runtime_transaction_for_test_v0,
        finish_and_plan_complete_core_authorized_regular_post_state_v0,
        finish_and_plan_core_authorized_regular_post_state_v0,
        finish_and_plan_test_regular_runtime_execution_for_test_v0,
        finish_core_authorized_regular_validation_v0,
        finish_failed_core_authorized_non_runtime_family_attempt_v0,
        finish_failed_core_authorized_non_runtime_family_write_seal_v0,
        finish_failed_core_authorized_non_runtime_semantic_decode_v0,
        finish_failed_core_authorized_regular_runtime_attempt_v0,
        finish_failed_core_authorized_regular_transaction_decode_v0,
        finish_failed_inert_regular_body_traversal_for_test_v0,
        finish_failed_test_regular_runtime_execution_for_test_v0,
        finish_inert_regular_body_traversal_for_test_v0, finish_open_regular_validation_failure_v0,
        inject_snapshot_finish_failure_for_test_v0,
        inject_test_runtime_snapshot_finish_failure_for_test_v0,
        match_finished_core_authorized_regular_complete_body_commitments_v0,
        match_finished_core_authorized_regular_runtime_commitments_v0,
        match_finished_test_regular_runtime_commitments_for_test_v0,
        native_validation_reservation_fingerprint_v0,
        observe_next_exact_body_transaction_for_test_v0,
        open_core_authorized_regular_transaction_cursor_from_open_v0,
        open_core_authorized_regular_transaction_cursor_v0,
        open_core_authorized_regular_validation_for_test_v0,
        open_inert_regular_body_traversal_for_test_v0,
        open_test_regular_runtime_execution_for_test_v0, prepare_durable_invalid_complete_body_v0,
        prepare_next_core_authorized_regular_payload_v0,
        promote_closed_core_authorized_non_runtime_family_failure_v0,
        promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0,
        promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0,
        promote_closed_core_authorized_regular_post_state_plan_failure_v0,
        promote_closed_core_authorized_regular_runtime_failure_v0,
        promote_closed_core_authorized_regular_transaction_decode_failure_v0,
        promote_core_authorized_regular_execution_outcome_v0,
        promote_failed_core_issued_regular_validation_open_v0,
        seal_core_authorized_non_runtime_family_writes_v0, stage_runtime_mutations_for_test_v0,
        take_core_regular_validation_job_v0, validate_snapshot_authenticated_regular_context_v0,
        ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0,
        ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0,
        ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
        ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0,
        ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
        ClosedCoreAuthorizedRegularPostStatePlanCauseV0,
        ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0,
        ClosedCoreAuthorizedRegularTransactionDecodeCauseV0,
        ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0,
        ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0,
        ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0,
        CoreAuthorizedExactRegularBodyFailureClassV0, CoreAuthorizedExactRegularBodyFailureV0,
        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0,
        CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0,
        CoreAuthorizedNonRuntimeFamilyInvariantV0, CoreAuthorizedNonRuntimeSemanticDecodeCauseV0,
        CoreAuthorizedNonRuntimeWriteSealInvariantV0,
        CoreAuthorizedRegularCommitmentComparisonCauseV0,
        CoreAuthorizedRegularCommitmentInvariantV0, CoreAuthorizedRegularComputedRootMismatchV0,
        CoreAuthorizedRegularExecutionOutcomeV0,
        CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0,
        CoreAuthorizedRegularPostStatePlanCauseV0, CoreAuthorizedRegularReservationV0,
        CoreAuthorizedRegularRuntimeStepFailureV0, CoreAuthorizedRegularTransactionDecodeCauseV0,
        CoreAuthorizedRegularValidationSessionAdmissionV0, CoreIssuedRegularValidationJobV0,
        CoreIssuedRegularValidationOwnerV0, CoreIssuedRegularValidationReservationCauseV0,
        CoreRegularValidationEffectIntakeV0, DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0,
        DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0,
        DispatchedCoreAuthorizedNonRuntimePayloadV0, FailedCoreAuthorizedNonRuntimeFamilyAttemptV0,
        FailedCoreAuthorizedRegularRuntimeAttemptV0, FinishedFailedTestRegularRuntimeExecutionV0,
        FinishedInertRegularBodyCursorFailureV0,
        FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0, InertRegularBodyCursorFailureV0,
        InertRegularBodyFinishFailureV0, NativeBlockExecutionV0, NativeSignerPolicyBindingV0,
        NativeTransactionReceiptFactsV0, NativeValidationHostV0,
        OpenCoreAuthorizedRegularTransactionCursorV0, OpenCoreAuthorizedRegularValidationFailureV0,
        PrepareDurableInvalidFailureCauseV0, PreparedCoreAuthorizedRegularPayloadV0,
        PreparedCoreAuthorizedRuntimeTransactionV0,
        RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0,
        SnapshotAuthenticatedRegularContextV0, TestAuthorizedRegularRuntimeRequestV0,
        TestRegularRuntimeCommitmentComparisonFailureV0, TestRegularRuntimeFinishFailureV0,
        TestRegularRuntimeMutationStageFailureV0,
    };
    use crate::{
        auth_tree::{validator_state_key, AuthWrite, AuthenticatedObjectRecord, InMemoryAuthTree},
        native_validation_artifact::DurableDeterministicInvalidReasonV0,
        poco_snapshot::{PocoSnapshotEntryKindV0, PocoSnapshotEntryV0},
        poco_transition::{
            encode_poco_snapshot_value_envelope_v0, genesis_poco_snapshot_writes_v0,
        },
        store::{
            ApplicationStore, AuthenticatedRuntimeReadFailureV0,
            NativeValidationInvalidSealDecisionV0, NativeValidationInvalidSealFailpointV0,
            NativeValidationInvalidSealFailureCauseV0, NativeValidationJobStateV0,
            NativeValidationReservationDecisionV0, NativeValidationReservationFactsV0,
            NativeValidationReservationFailureCauseV0, NativeValidationReservationInvariantV0,
        },
        validator_lifecycle::{
            ConsensusValidatorV1, ScheduledValidatorTransitionV1, ValidatorGovernanceV1,
            ValidatorLifecycleStateV1, VALIDATOR_GOVERNANCE_SCHEMA_V1,
            VALIDATOR_LIFECYCLE_SCHEMA_V1,
        },
        AppState, BlockDelta, PendingBlock, APP_VERSION,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-native-input-session-test");

    struct TestStore {
        root: PathBuf,
        store: ApplicationStore,
        authorized_signers: Vec<AuthorizedSignerV1>,
        parent_state_root: [u8; 32],
        authenticated_parent: InMemoryAuthTree,
        validator_lifecycle: ValidatorLifecycleStateV1,
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct FixtureProfile {
        parent: BlockHeader,
        header: BlockHeader,
        body: BlockBodyV0,
        validator_set: ValidatorSet,
        parameters: ConsensusParametersV0,
        authorized_signers: Vec<AuthorizedSignerV1>,
    }

    fn unique_test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-native-input-session-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ))
    }

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_authorized_signers() -> Vec<AuthorizedSignerV1> {
        [
            (81, "did:operator:1", "operator"),
            (82, "did:client:1", "hepta"),
        ]
        .into_iter()
        .map(|(seed, signer_id, signer_role)| AuthorizedSignerV1 {
            signer_id: signer_id.to_string(),
            signer_role: signer_role.to_string(),
            public_key_hex: hex::encode(test_signing_key(seed).verifying_key().to_bytes()),
        })
        .collect()
    }

    fn signed_canonical_transaction_bytes(
        discriminator: u8,
        command_id: &str,
        signer_seed: u8,
        signer_id: &str,
        signer_role: &str,
        transaction: &CanonicalTxV1,
    ) -> Vec<u8> {
        let payload = serde_json::to_vec(transaction).expect("encode canonical test transaction");
        signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            format!("native-input-{discriminator}-{command_id}"),
            signer_seed,
            signer_id,
            signer_role,
            transaction.nonce,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_envelope_bytes(
        chain_id: &str,
        command_id: String,
        signer_seed: u8,
        signer_id: &str,
        signer_role: &str,
        nonce: u64,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        payload_type: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        let envelope = SignedCommandEnvelopeV1::sign(
            chain_id,
            command_id,
            signer_id,
            signer_role,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            payload_type,
            payload,
            &test_signing_key(signer_seed),
        )
        .expect("sign exact test envelope");
        serde_json::to_vec(&envelope).expect("encode exact signed test envelope")
    }

    fn test_store() -> TestStore {
        build_test_store(false)
    }

    fn test_store_with_poco_application_authority() -> TestStore {
        build_test_store(true)
    }

    fn test_store_with_governance_sequence(governance_sequence: u64) -> TestStore {
        build_test_store_with_lifecycle(false, |lifecycle| {
            lifecycle.governance_sequence = governance_sequence;
        })
    }

    fn compact_cutoff_at_two_parameters() -> ConsensusParametersV0 {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.epoch_length_blocks = 7;
        fields.snapshot_lead_blocks = 3;
        ConsensusParametersV0::new(fields).expect("construct compact cutoff-at-two parameters")
    }

    fn build_test_store(include_poco_application_authority: bool) -> TestStore {
        build_test_store_with_lifecycle(include_poco_application_authority, |_| {})
    }

    fn build_test_store_with_lifecycle(
        include_poco_application_authority: bool,
        configure_lifecycle: impl FnOnce(&mut ValidatorLifecycleStateV1),
    ) -> TestStore {
        build_test_store_with_parameters_and_lifecycle(
            include_poco_application_authority,
            ConsensusParametersV0::reference_shadow_v0(),
            1,
            configure_lifecycle,
        )
    }

    fn build_test_store_with_parameters_at_height(
        include_poco_application_authority: bool,
        parameters: ConsensusParametersV0,
        parent_height: u64,
    ) -> TestStore {
        build_test_store_with_parameters_and_lifecycle(
            include_poco_application_authority,
            parameters,
            parent_height,
            |_| {},
        )
    }

    fn build_test_store_with_parameters_and_lifecycle(
        include_poco_application_authority: bool,
        parameters: ConsensusParametersV0,
        parent_height: u64,
        configure_lifecycle: impl FnOnce(&mut ValidatorLifecycleStateV1),
    ) -> TestStore {
        assert!(parent_height > 0);
        let root = unique_test_root();
        fs::create_dir_all(&root).expect("create native-input test directory");
        let status_path = root.join("state.json");
        let authorized_signers = test_authorized_signers();
        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&authorized_signers));
        let store =
            ApplicationStore::open(&status_path, TEST_CHAIN.as_str(), &signer_policy_hash_hex)
                .expect("construct native-input test store");
        let expected = store
            .load_or_migrate()
            .expect("initialize native-input test store");
        let native_validator_set = validator_set(&parameters, 0);
        let active_validators = native_validator_set
            .validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect::<Vec<_>>();
        let mut lifecycle = ValidatorLifecycleStateV1::from_genesis(
            TEST_CHAIN.as_str().to_string(),
            APP_VERSION,
            signer_policy_hash_hex,
            ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            active_validators,
        )
        .expect("construct native-input test validator lifecycle");
        configure_lifecycle(&mut lifecycle);
        lifecycle
            .validate()
            .expect("validate configured native-input test lifecycle");
        let lifecycle_record = AuthenticatedObjectRecord::new(
            VALIDATOR_LIFECYCLE_SCHEMA_V1.to_string(),
            1,
            serde_json::to_vec(&lifecycle).expect("encode native-input test lifecycle"),
        )
        .and_then(|record| record.encode())
        .expect("encode authenticated native-input lifecycle record");
        let lifecycle_write = AuthWrite::put(
            validator_state_key().expect("derive native-input lifecycle key"),
            lifecycle_record,
        )
        .expect("construct native-input lifecycle write");
        let mut active_identity = vec![1];
        active_identity.extend_from_slice(&native_validator_set.epoch().get().to_be_bytes());
        let (set_logical_key, set_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ValidatorConfiguration,
            1,
            &active_identity,
            &native_validator_set
                .try_cev0_bytes()
                .expect("encode native-input active validator set"),
        )
        .expect("encode native-input validator configuration envelope");
        let (parameters_logical_key, parameters_value) = encode_poco_snapshot_value_envelope_v0(
            PocoSnapshotEntryKindV0::ConsensusParameters,
            1,
            &active_identity,
            &parameters.canonical_bytes(),
        )
        .expect("encode native-input active parameters envelope");
        let mut config_entries = vec![
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::ValidatorConfiguration,
                set_logical_key,
                set_value,
            )
            .expect("construct native-input validator configuration entry"),
            PocoSnapshotEntryV0::new(
                PocoSnapshotEntryKindV0::ConsensusParameters,
                parameters_logical_key,
                parameters_value,
            )
            .expect("construct native-input parameters entry"),
        ];
        if include_poco_application_authority {
            config_entries.push(
                crate::poco_application::genesis_poco_application_authority_entry_v0()
                    .expect("construct native-input PoCO application authority entry"),
            );
        }
        config_entries.sort_by(|left, right| {
            (left.kind, left.logical_key.as_slice())
                .cmp(&(right.kind, right.logical_key.as_slice()))
        });
        let mut parent_writes = genesis_poco_snapshot_writes_v0(&config_entries)
            .expect("construct native-input authenticated configuration writes");
        parent_writes.push(lifecycle_write);
        let mut authenticated = InMemoryAuthTree::default();
        let genesis_update = authenticated
            .plan_put_value_set(0, Vec::new())
            .expect("plan empty authenticated genesis version");
        authenticated
            .apply(genesis_update)
            .expect("apply empty authenticated genesis version");
        let parent_update = authenticated
            .plan_put_value_set(1, parent_writes)
            .expect("plan authenticated parent configuration version");
        let mut parent_state_root = authenticated
            .apply(parent_update)
            .map(<[u8; 32]>::from)
            .expect("apply authenticated parent version");
        for version in 2..=parent_height {
            let update = authenticated
                .plan_put_value_set(version, Vec::new())
                .expect("plan empty authenticated parent continuation");
            parent_state_root = authenticated
                .apply(update)
                .map(<[u8; 32]>::from)
                .expect("apply empty authenticated parent continuation");
        }
        let state = AppState {
            height: parent_height,
            app_hash: parent_state_root,
            validator_lifecycle: Some(lifecycle),
            ..AppState::default()
        };
        store
            .replace_empty_state_from_tree(&expected, &state, &authenticated)
            .expect("persist empty authenticated test head");

        TestStore {
            root,
            store,
            authorized_signers,
            parent_state_root,
            authenticated_parent: authenticated,
            validator_lifecycle: state
                .validator_lifecycle
                .expect("persisted native-input lifecycle"),
        }
    }

    fn test_store_with_pending_validator_activation_at_height_three() -> TestStore {
        let mut test = test_store_with_poco_application_authority();
        let current = test.store.load_or_migrate().unwrap();
        let mut lifecycle = test.validator_lifecycle.clone();
        lifecycle.pending_transition = Some(ScheduledValidatorTransitionV1 {
            transition_id: "native-implicit-height-three".to_string(),
            base_validator_set_hash_hex: lifecycle.active_set_hash_hex().unwrap(),
            accepted_height: 1,
            activation_height: 3,
            target_validators: lifecycle.active_validators.clone(),
        });
        lifecycle.validate().unwrap();
        let write = crate::authenticated_lifecycle_write(2, &lifecycle).unwrap();
        let update = test.store.plan_auth_update(2, [write]).unwrap();
        let update_for_tree = update.clone();
        let next_root: [u8; 32] = update.root_hash.into();
        let pending = PendingBlock {
            height: 2,
            app_hash: next_root,
            tx_results: Vec::new(),
            native_execution: crate::test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                2,
                next_root,
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta {
                validator_lifecycle: Some(lifecycle.clone()),
                ..BlockDelta::default()
            },
            auth_update: update,
            poco_checkpoint_execution: None,
        };
        test.store
            .persist_transition(&current, &pending, 0)
            .unwrap();
        let tree_root: [u8; 32] = test
            .authenticated_parent
            .apply(update_for_tree)
            .map(Into::into)
            .unwrap();
        assert_eq!(tree_root, next_root);
        test.parent_state_root = next_root;
        test.validator_lifecycle = lifecycle;
        test
    }

    fn test_native_validation_host(store: &TestStore) -> NativeValidationHostV0<'_> {
        NativeValidationHostV0 {
            store: &store.store,
            chain_id: TEST_CHAIN.as_str(),
            authorized_signers: &store.authorized_signers,
        }
    }

    fn open_exact_test_authorized_regular_cursor(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
        let snapshot = store
            .store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(
                profile.parent.height().get(),
                *profile.parent.state_root().as_bytes(),
            )
            .expect("open exact test-only parent snapshot");
        let lifecycle = snapshot
            .load_authenticated_validator_lifecycle_v0()
            .expect("load exact test-only parent lifecycle");
        assert_eq!(lifecycle, store.validator_lifecycle);
        crate::poco_checkpoint::validate_application_validator_projection(
            &profile.validator_set,
            &lifecycle.active_validators,
        )
        .expect("bind exact test-only validator projection");
        OpenCoreAuthorizedRegularTransactionCursorV0 {
            open: super::OpenCoreAuthorizedRegularValidationV0 {
                authorized: super::CoreAuthorizedExactRegularBodyV0 {
                    reservation: CoreAuthorizedRegularReservationV0::TestOnly,
                    route: PayloadValidationRouteV0::Proposal,
                    validation_id: ValidationId::new(profile.header.id(), profile.header.view(), 0),
                    header: profile.header.clone(),
                    body: profile.body.clone(),
                    context: SnapshotAuthenticatedRegularContextV0 {
                        parent_header: profile.parent.clone(),
                        validator_set: profile.validator_set.clone(),
                        parameters: profile.parameters,
                        validator_lifecycle: lifecycle,
                        signer_policy: NativeSignerPolicyBindingV0 {
                            commitment: crate::signer_policy_commitment(&store.authorized_signers),
                            authorized_signers: store.authorized_signers.clone(),
                        },
                    },
                },
                snapshot,
            },
            next_transaction_index: 0,
            changes: BTreeMap::new(),
            applied: Vec::new(),
            applied_non_runtime: Vec::new(),
            poco_prefix: None,
            validator_prefix: None,
        }
    }

    fn load_test_authenticated_poco_projection(
        store: &TestStore,
    ) -> crate::poco_transition::ProductionPocoProjectionV0 {
        let snapshot = store
            .store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(1, store.parent_state_root)
            .expect("open authenticated PoCO projection authoring snapshot");
        let projection = snapshot
            .load_authenticated_production_poco_projection_v0()
            .expect("load authenticated PoCO projection for operation authoring");
        snapshot
            .finish()
            .expect("finish authenticated PoCO projection authoring snapshot");
        projection
    }

    fn author_valid_poco_application_operation(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> (crate::poco_transition::ProductionPocoProjectionV0, Vec<u8>) {
        let projection = load_test_authenticated_poco_projection(store);
        let context = crate::poco_application::AuthenticatedPocoApplicationContextV0::new(
            profile.parent.height().get(),
            *profile.parent.state_root().as_bytes(),
            profile.header.height(),
            profile.validator_set.chain_id(),
            profile.validator_set.genesis_hash(),
            profile.validator_set.epoch(),
            profile.parameters,
            crate::poco_application_governance_signer_commitment_v0(&store.validator_lifecycle),
        )
        .expect("construct exact retained PoCO operation context");
        let overlay = crate::poco_application::PocoApplicationBlockOverlayV0::from_projection(
            context,
            &projection,
        )
        .expect("construct PoCO operation-authoring overlay");
        let raw = overlay
            .test_define_meter_operation_v0()
            .expect("author one exact valid PoCO operation");
        (projection, raw)
    }

    fn author_two_valid_poco_application_operations(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> (
        crate::poco_transition::ProductionPocoProjectionV0,
        Vec<Vec<u8>>,
    ) {
        let projection = load_test_authenticated_poco_projection(store);
        let context = crate::poco_application::AuthenticatedPocoApplicationContextV0::new(
            profile.parent.height().get(),
            *profile.parent.state_root().as_bytes(),
            profile.header.height(),
            profile.validator_set.chain_id(),
            profile.validator_set.genesis_hash(),
            profile.validator_set.epoch(),
            profile.parameters,
            crate::poco_application_governance_signer_commitment_v0(&store.validator_lifecycle),
        )
        .expect("construct two-operation PoCO context");
        let overlay = crate::poco_application::PocoApplicationBlockOverlayV0::from_projection(
            context,
            &projection,
        )
        .expect("construct two-operation PoCO authoring overlay");
        let operations = overlay
            .test_two_define_meter_operations_v0()
            .expect("author two ordered PoCO operations");
        (projection, operations)
    }

    fn decode_only_non_runtime_family(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0 {
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(store),
            core_validation_request(profile),
        )
        .expect("open exact non-runtime family cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare exact non-runtime family payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("non-runtime family entered runtime")
            }
        };
        decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode exact non-runtime family")
    }

    fn valid_validator_transition_bytes(store: &TestStore, command_id: &str) -> Vec<u8> {
        let mut target_validators = store.validator_lifecycle.active_validators.clone();
        let replacement_key = test_signing_key(99);
        let replacement_public_key_hex = hex::encode(replacement_key.verifying_key().to_bytes());
        target_validators[0].public_key_hex = replacement_public_key_hex.clone();
        target_validators.sort_by(|left, right| left.public_key_hex.cmp(&right.public_key_hex));
        let base_validator_set_hash_hex = store
            .validator_lifecycle
            .active_set_hash_hex()
            .expect("hash authenticated source validator set");
        let message = crate::validator_lifecycle::validator_key_proof_message(
            TEST_CHAIN.as_str(),
            command_id,
            &base_validator_set_hash_hex,
            4,
            &target_validators,
        )
        .expect("derive replacement validator proof message");
        let transition = crate::validator_lifecycle::ValidatorSetTransitionV1 {
            schema: crate::validator_lifecycle::VALIDATOR_TRANSITION_SCHEMA_V1.to_string(),
            chain_id: TEST_CHAIN.as_str().to_string(),
            transition_id: command_id.to_string(),
            base_validator_set_hash_hex,
            activation_height: 4,
            target_validators,
            new_validator_proofs: vec![crate::validator_lifecycle::ValidatorKeyProofV1 {
                public_key_hex: replacement_public_key_hex,
                signature_hex: hex::encode(replacement_key.sign(&message).to_bytes()),
            }],
        };
        serde_json::to_vec(&transition).expect("encode validator transition")
    }

    fn validator_set(parameters: &ConsensusParametersV0, validator_offset: u8) -> ValidatorSet {
        let validators = (1_u8..=4)
            .map(|value| {
                Validator::new(
                    ValidatorId::new([value + validator_offset; 32]),
                    ConsensusPublicKey::new([value + validator_offset + 32; 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("construct test validator")
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            TEST_CHAIN,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("construct test validator set")
    }

    fn fixture_profile(parent_state_root: [u8; 32], discriminator: u8) -> FixtureProfile {
        fixture_profile_at_height(
            parent_state_root,
            1,
            ConsensusParametersV0::reference_shadow_v0(),
            discriminator,
        )
    }

    fn fixture_profile_at_height(
        parent_state_root: [u8; 32],
        parent_height: u64,
        parameters: ConsensusParametersV0,
        discriminator: u8,
    ) -> FixtureProfile {
        let target_height = parent_height.checked_add(1).unwrap();
        let validator_set = validator_set(&parameters, discriminator);
        let credit = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 10_000 + u128::from(discriminator),
            },
        };
        let create = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreateTask {
                task_id: format!("native-task-{discriminator}"),
                reward: 1_000,
                worker_stake: 500,
                result_deadline_height: 20,
                challenge_window_blocks: 10,
            },
        };
        let empty_body = BlockBodyV0::new(
            ApplicationPayloadV0::new(Vec::new()).expect("empty parent payload"),
            Vec::new(),
        )
        .expect("empty parent body");
        let empty_receipts_root =
            ExecutionReceiptsV0::new(empty_body.application_payload(), Vec::new())
                .and_then(|receipts| receipts.receipts_root())
                .expect("derive empty parent receipts root");
        let parent = BlockHeader::new(
            validator_set.genesis_hash(),
            TEST_CHAIN,
            ProtocolVersion::V0,
            validator_set.epoch(),
            View::new(1),
            Height::new(parent_height),
            BlockKind::Regular,
            BlockId::new(*validator_set.genesis_hash().as_bytes()),
            trnm_consensus_core::leader_for(&validator_set, View::new(1)),
            validator_set.id(),
            parameters.hash(),
            empty_body.payload_root().expect("parent payload root"),
            StateRoot::new(parent_state_root),
            empty_receipts_root,
            empty_body.evidence_root().expect("parent evidence root"),
            1_700_000_000_000 + u64::from(discriminator),
            None,
        )
        .expect("construct exact parent header");
        let body = BlockBodyV0::new(
            ApplicationPayloadV0::new(vec![
                signed_canonical_transaction_bytes(
                    discriminator,
                    "credit",
                    81,
                    "did:operator:1",
                    "operator",
                    &credit,
                ),
                signed_canonical_transaction_bytes(
                    discriminator,
                    "create",
                    82,
                    "did:client:1",
                    "hepta",
                    &create,
                ),
            ])
            .expect("target payload"),
            Vec::new(),
        )
        .expect("target body");
        let header = BlockHeader::new(
            validator_set.genesis_hash(),
            TEST_CHAIN,
            ProtocolVersion::V0,
            validator_set.epoch(),
            View::new(2),
            Height::new(target_height),
            BlockKind::Regular,
            parent.id(),
            trnm_consensus_core::leader_for(&validator_set, View::new(2)),
            validator_set.id(),
            parameters.hash(),
            body.payload_root().expect("target payload root"),
            StateRoot::new([51 + discriminator; 32]),
            empty_receipts_root,
            body.evidence_root().expect("target evidence root"),
            1_700_000_001_000 + u64::from(discriminator),
            None,
        )
        .expect("construct exact target header");
        FixtureProfile {
            parent,
            header,
            body,
            validator_set,
            parameters,
            authorized_signers: test_authorized_signers(),
        }
    }

    fn replace_profile_transactions(
        mut profile: FixtureProfile,
        transactions: Vec<Vec<u8>>,
    ) -> FixtureProfile {
        let body = BlockBodyV0::new(
            ApplicationPayloadV0::new(transactions).expect("replace exact test payload"),
            Vec::new(),
        )
        .expect("replace exact test body");
        let header = BlockHeader::new(
            profile.header.genesis_hash(),
            profile.header.chain_id(),
            profile.header.protocol_version(),
            profile.header.epoch(),
            profile.header.view(),
            profile.header.height(),
            profile.header.block_kind(),
            profile.header.parent_id(),
            profile.header.proposer_id(),
            profile.header.validator_set_id(),
            profile.header.consensus_parameters_hash(),
            body.payload_root().expect("replacement payload root"),
            profile.header.state_root(),
            profile.header.receipts_root(),
            body.evidence_root().expect("replacement evidence root"),
            profile.header.timestamp_ms(),
            profile.header.next_epoch_commitment_hash(),
        )
        .expect("replace exact test header body commitments");
        profile.header = header;
        profile.body = body;
        profile
    }

    fn replace_profile_execution_roots(
        mut profile: FixtureProfile,
        state_root: StateRoot,
        receipts_root: ReceiptsRoot,
    ) -> FixtureProfile {
        profile.header = BlockHeader::new(
            profile.header.genesis_hash(),
            profile.header.chain_id(),
            profile.header.protocol_version(),
            profile.header.epoch(),
            profile.header.view(),
            profile.header.height(),
            profile.header.block_kind(),
            profile.header.parent_id(),
            profile.header.proposer_id(),
            profile.header.validator_set_id(),
            profile.header.consensus_parameters_hash(),
            profile
                .body
                .payload_root()
                .expect("honest replacement payload root"),
            state_root,
            receipts_root,
            profile
                .body
                .evidence_root()
                .expect("honest replacement evidence root"),
            profile.header.timestamp_ms(),
            profile.header.next_epoch_commitment_hash(),
        )
        .expect("replace exact test execution commitments");
        profile
    }

    fn replace_finished_header_roots(
        finished: &mut FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0,
        payload_root: PayloadDigest,
        state_root: StateRoot,
        receipts_root: ReceiptsRoot,
        evidence_root: EvidenceRoot,
    ) {
        let header = finished.authorized.header.clone();
        finished.authorized.header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            payload_root,
            state_root,
            receipts_root,
            evidence_root,
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .expect("replace finished comparison header roots");
    }

    fn replace_profile_parent_state_root(
        mut profile: FixtureProfile,
        parent_state_root: StateRoot,
    ) -> FixtureProfile {
        profile.parent = BlockHeader::new(
            profile.parent.genesis_hash(),
            profile.parent.chain_id(),
            profile.parent.protocol_version(),
            profile.parent.epoch(),
            profile.parent.view(),
            profile.parent.height(),
            profile.parent.block_kind(),
            profile.parent.parent_id(),
            profile.parent.proposer_id(),
            profile.parent.validator_set_id(),
            profile.parent.consensus_parameters_hash(),
            profile.parent.payload_root(),
            parent_state_root,
            profile.parent.receipts_root(),
            profile.parent.evidence_root(),
            profile.parent.timestamp_ms(),
            profile.parent.next_epoch_commitment_hash(),
        )
        .expect("replace exact parent state root");
        profile.header = BlockHeader::new(
            profile.header.genesis_hash(),
            profile.header.chain_id(),
            profile.header.protocol_version(),
            profile.header.epoch(),
            profile.header.view(),
            profile.header.height(),
            profile.header.block_kind(),
            profile.parent.id(),
            profile.header.proposer_id(),
            profile.header.validator_set_id(),
            profile.header.consensus_parameters_hash(),
            profile.header.payload_root(),
            profile.header.state_root(),
            profile.header.receipts_root(),
            profile.header.evidence_root(),
            profile.header.timestamp_ms(),
            profile.header.next_epoch_commitment_hash(),
        )
        .expect("rebind target to replaced exact parent");
        profile
    }

    fn replace_profile_parent_kind(
        mut profile: FixtureProfile,
        parent_kind: BlockKind,
    ) -> FixtureProfile {
        let next_epoch_commitment = match parent_kind {
            BlockKind::Regular | BlockKind::EpochHandoff => None,
            BlockKind::EpochCheckpoint | BlockKind::EpochSeal1 | BlockKind::EpochSeal2 => Some(
                trnm_consensus_types::NextEpochCommitmentHash::new([0x7c; 32]),
            ),
        };
        profile.parent = BlockHeader::new(
            profile.parent.genesis_hash(),
            profile.parent.chain_id(),
            profile.parent.protocol_version(),
            profile.parent.epoch(),
            profile.parent.view(),
            profile.parent.height(),
            parent_kind,
            profile.parent.parent_id(),
            profile.parent.proposer_id(),
            profile.parent.validator_set_id(),
            profile.parent.consensus_parameters_hash(),
            profile.parent.payload_root(),
            profile.parent.state_root(),
            profile.parent.receipts_root(),
            profile.parent.evidence_root(),
            profile.parent.timestamp_ms(),
            next_epoch_commitment,
        )
        .expect("replace exact parent block kind");
        profile.header = BlockHeader::new(
            profile.header.genesis_hash(),
            profile.header.chain_id(),
            profile.header.protocol_version(),
            profile.header.epoch(),
            profile.header.view(),
            profile.header.height(),
            profile.header.block_kind(),
            profile.parent.id(),
            profile.header.proposer_id(),
            profile.header.validator_set_id(),
            profile.header.consensus_parameters_hash(),
            profile.header.payload_root(),
            profile.header.state_root(),
            profile.header.receipts_root(),
            profile.header.evidence_root(),
            profile.header.timestamp_ms(),
            profile.header.next_epoch_commitment_hash(),
        )
        .expect("rebind target to replaced exact parent kind");
        profile
    }

    /// Independently authors the expected header roots before exercising the
    /// comparator. The state root comes from a cloned in-memory parent tree,
    /// while the receipt root comes from freshly converting the real runtime
    /// receipts. Neither value is supplied to the comparator as an argument.
    fn honest_runtime_profile(test_store: &TestStore) -> FixtureProfile {
        let authoring_profile = fixture_profile(test_store.parent_state_root, 0);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(authoring_profile),
        )
        .expect("open fixture-authoring runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("author first exact fixture transaction");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("author second exact fixture transaction");

        let writes = open
            .changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("encode independent fixture state writes");
        let independent_plan = test_store
            .authenticated_parent
            .plan_put_value_set(2, writes)
            .expect("independently plan honest fixture state root");
        let state_root = StateRoot::new(independent_plan.root_hash.into());

        let receipt_facts = open
            .applied
            .iter()
            .map(|applied| {
                NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&applied.runtime_receipt)
                    .expect("convert honest fixture runtime receipt")
            })
            .collect::<Vec<_>>();
        let transaction_bytes = open
            .inputs
            .body
            .application_payload()
            .transactions()
            .iter()
            .map(|transaction| Bytes::copy_from_slice(transaction))
            .collect::<Vec<_>>();
        let native_execution = NativeBlockExecutionV0::try_new(&transaction_bytes, receipt_facts)
            .expect("build independent honest fixture native execution");
        let receipts_root = native_execution
            .execution_receipts()
            .receipts_root()
            .expect("derive independent honest fixture receipt root");

        let planned = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("finish fixture-authoring session after independent computation");
        assert_eq!(planned.planned_state_root(), state_root);
        drop(planned);

        replace_profile_execution_roots(
            fixture_profile(test_store.parent_state_root, 0),
            state_root,
            receipts_root,
        )
    }

    fn authenticate(profile: FixtureProfile) -> super::AuthenticatedRegularRuntimeInputsV0 {
        let signer_policy_commitment = crate::signer_policy_commitment(&profile.authorized_signers);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            signer_policy_commitment,
        );
        authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            profile.body,
            profile.parent,
            profile.validator_set,
            profile.parameters,
            profile.authorized_signers,
        )
        .expect("authenticate exact regular runtime inputs")
    }

    fn exact_transport_block(profile: &FixtureProfile) -> Block {
        Block::new(
            profile.header.clone(),
            profile
                .body
                .application_payload()
                .try_cev0_bytes()
                .expect("encode exact fixture application payload"),
            profile
                .body
                .evidence()
                .iter()
                .map(|item| {
                    item.try_cev0_bytes()
                        .expect("encode exact fixture evidence")
                })
                .collect(),
        )
        .expect("construct exact fixture transport block")
    }

    fn snapshot_context(
        profile: &FixtureProfile,
        lifecycle: &ValidatorLifecycleStateV1,
    ) -> SnapshotAuthenticatedRegularContextV0 {
        SnapshotAuthenticatedRegularContextV0 {
            parent_header: profile.parent.clone(),
            validator_set: profile.validator_set.clone(),
            parameters: profile.parameters,
            validator_lifecycle: lifecycle.clone(),
            signer_policy: NativeSignerPolicyBindingV0 {
                commitment: crate::signer_policy_commitment(&test_authorized_signers()),
                authorized_signers: test_authorized_signers(),
            },
        }
    }

    #[derive(Clone, Copy)]
    struct CoreRootSignatures;

    impl SignatureVerifier for CoreRootSignatures {
        fn verify(
            &self,
            _validator: &Validator,
            signing_root: &SigningRoot,
            signature: &SignatureBytes,
        ) -> bool {
            signature.as_bytes()[..32] == signing_root.as_bytes()[..]
                && signature.as_bytes()[32..] == signing_root.as_bytes()[..]
        }
    }

    fn core_signature(root: SigningRoot) -> SignatureBytes {
        let mut bytes = [0_u8; SIGNATURE_BYTES];
        bytes[..32].copy_from_slice(root.as_bytes());
        bytes[32..].copy_from_slice(root.as_bytes());
        SignatureBytes::from_array(bytes)
    }

    fn exact_parent_body() -> BlockBodyV0 {
        BlockBodyV0::new(
            ApplicationPayloadV0::new(Vec::new()).expect("empty Core parent payload"),
            Vec::new(),
        )
        .expect("empty Core parent body")
    }

    fn exact_parent_transport_block(profile: &FixtureProfile) -> Block {
        let body = exact_parent_body();
        Block::new(
            profile.parent.clone(),
            body.application_payload()
                .try_cev0_bytes()
                .expect("encode exact Core parent payload"),
            Vec::new(),
        )
        .expect("construct exact Core parent transport")
    }

    fn core_vote(
        set: &ValidatorSet,
        view: View,
        height: Height,
        block_id: BlockId,
        author: ValidatorId,
    ) -> Vote {
        let root = Vote::signing_root_for_set(set, view, height, block_id)
            .expect("derive Core fixture vote root");
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            view,
            height,
            block_id,
            set.id(),
            author,
            core_signature(root),
            set,
        )
        .expect("construct Core fixture vote")
    }

    fn core_parent_qc(profile: &FixtureProfile) -> QuorumCertificate {
        let set = &profile.validator_set;
        let votes = set.validators()[..3]
            .iter()
            .map(|validator| {
                core_vote(
                    set,
                    profile.parent.view(),
                    profile.parent.height(),
                    profile.parent.id(),
                    validator.id(),
                )
            })
            .collect();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            profile.parent.view(),
            profile.parent.height(),
            profile.parent.id(),
            set.id(),
            votes,
            set,
        )
        .expect("construct Core fixture parent QC")
    }

    fn core_signed_proposal(
        profile: &FixtureProfile,
        block: Block,
        justify: QcReferenceV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> SignedProposalV0 {
        let root = ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
            .expect("derive Core fixture proposal root");
        let witness = ProposalWitnessV0::new(
            block.header(),
            justify,
            None,
            None,
            core_signature(root),
            &profile.validator_set,
            None,
            &profile.parameters,
            authenticated_parent_timestamp_ms,
        )
        .expect("construct Core fixture proposal witness");
        SignedProposalV0::new(
            block,
            witness,
            &profile.validator_set,
            None,
            &profile.parameters,
            authenticated_parent_timestamp_ms,
        )
        .expect("construct Core fixture signed proposal")
    }

    fn release_core_persisted_effects(core: &mut Core, effects: Vec<Effect>) -> Vec<Effect> {
        let barrier = effects.iter().find_map(|effect| match effect {
            Effect::PersistSafetyState { barrier, .. } => Some(*barrier),
            _ => None,
        });
        match barrier {
            Some(barrier) => core
                .step(Input::StorageAck { barrier }, &CoreRootSignatures)
                .expect("acknowledge Core fixture persistence"),
            None => effects,
        }
    }

    fn core_synced_validation_effect(profile: &FixtureProfile) -> Effect {
        core_target_validation_effect(profile, PayloadValidationRouteV0::Synced)
    }

    struct LiveCoreTargetValidationFixtureV0 {
        core: Core,
        effect: Effect,
        registered_state: SafetyState,
    }

    fn live_core_target_validation_fixture_v0(
        profile: &FixtureProfile,
        target_route: PayloadValidationRouteV0,
    ) -> LiveCoreTargetValidationFixtureV0 {
        let trusted_genesis_timestamp_ms = profile
            .parent
            .timestamp_ms()
            .checked_sub(1_000)
            .expect("fixture parent follows trusted genesis");
        let config = CoreConfig::new(
            profile.validator_set.validators()[0].id(),
            profile.validator_set.clone(),
            profile.parameters,
            trusted_genesis_timestamp_ms,
            32,
            64,
        )
        .expect("construct Core fixture config");
        let genesis = GenesisQcV0::new(
            profile.validator_set.genesis_hash(),
            profile.validator_set.chain_id(),
            &profile.validator_set,
        )
        .expect("construct Core fixture genesis QC");
        let mut core =
            Core::new(config, genesis.clone(), &CoreRootSignatures).expect("start Core fixture");

        let parent_block = exact_parent_transport_block(profile);
        let parent_proposal = core_signed_proposal(
            profile,
            parent_block.clone(),
            QcReferenceV0::genesis_anchor(genesis),
            trusted_genesis_timestamp_ms,
        );
        let effects = core
            .step(
                Input::SyncedProposal(Box::new(parent_proposal)),
                &CoreRootSignatures,
            )
            .expect("install exact Core fixture parent");
        let effects = release_core_persisted_effects(&mut core, effects);
        let parent_validation_id = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::ValidateSyncedPayload(request) => Some(request.id()),
                _ => None,
            })
            .expect("Core requests exact parent payload validation");
        let parent_body = exact_parent_body();
        let parent_receipts =
            ExecutionReceiptsV0::new(parent_body.application_payload(), Vec::new())
                .expect("construct Core parent receipts");
        let parent_commitments = parent_body
            .validate_ordinary_commitments(
                parent_block.header(),
                &parent_receipts,
                &profile.parameters,
                &profile.validator_set,
                &CoreRootSignatures,
            )
            .expect("validate Core fixture parent commitments");
        let effects = core
            .step(
                Input::SyncedPayloadValidated {
                    id: parent_validation_id,
                    result: PayloadValidationResult::Valid {
                        commitments: parent_commitments,
                    },
                },
                &CoreRootSignatures,
            )
            .expect("accept exact Core fixture parent payload");
        assert!(
            release_core_persisted_effects(&mut core, effects).is_empty(),
            "synced parent validation should leave no vote outbox"
        );

        let target_block = exact_transport_block(profile);
        let target_proposal = core_signed_proposal(
            profile,
            target_block,
            QcReferenceV0::ordinary(core_parent_qc(profile)),
            profile.parent.timestamp_ms(),
        );
        let target_input = match target_route {
            PayloadValidationRouteV0::Proposal => Input::Proposal(Box::new(target_proposal)),
            PayloadValidationRouteV0::Synced => Input::SyncedProposal(Box::new(target_proposal)),
        };
        let effects = core
            .step(target_input, &CoreRootSignatures)
            .expect("admit exact Core fixture target");
        let registered_state = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::PersistSafetyState { state, .. } => Some(state.as_ref().clone()),
                _ => None,
            })
            .expect("target admission persists its exact validation obligation");
        let effect = release_core_persisted_effects(&mut core, effects)
            .into_iter()
            .find(|effect| {
                matches!(
                    (target_route, effect),
                    (
                        PayloadValidationRouteV0::Proposal,
                        Effect::ValidatePayload(_)
                    ) | (
                        PayloadValidationRouteV0::Synced,
                        Effect::ValidateSyncedPayload(_)
                    )
                )
            })
            .expect("Core emits exact target validation effect");
        let validation_id = match &effect {
            Effect::ValidatePayload(request) | Effect::ValidateSyncedPayload(request) => {
                request.id()
            }
            _ => unreachable!("target validation fixture retained a non-validation effect"),
        };
        assert_eq!(core.safety_state(), &registered_state);
        assert_eq!(core.pending_validation_count(), 1);
        assert!(core
            .safety_state()
            .payload_validation_obligations()
            .iter()
            .any(|obligation| {
                obligation.route() == target_route && obligation.id() == validation_id
            }));
        LiveCoreTargetValidationFixtureV0 {
            core,
            effect,
            registered_state,
        }
    }

    fn core_target_validation_effect(
        profile: &FixtureProfile,
        target_route: PayloadValidationRouteV0,
    ) -> Effect {
        let LiveCoreTargetValidationFixtureV0 {
            core,
            effect,
            registered_state,
        } = live_core_target_validation_fixture_v0(profile, target_route);
        assert_eq!(core.safety_state(), &registered_state);
        effect
    }

    fn core_validation_effect(profile: &FixtureProfile) -> Effect {
        core_target_validation_effect(profile, PayloadValidationRouteV0::Proposal)
    }

    fn core_validation_request(profile: &FixtureProfile) -> PayloadValidationRequest {
        match core_validation_effect(profile) {
            Effect::ValidatePayload(request) => request,
            _ => panic!("Core direct validation fixture changed effect route"),
        }
    }

    fn fixture_signer_policy_commitment(profile: &FixtureProfile) -> [u8; 32] {
        crate::signer_policy_commitment(&profile.authorized_signers)
    }

    fn first_production_decode_failure(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> Box<super::ClosedFailedCoreAuthorizedRegularTransactionDecodeV0> {
        let request = core_validation_request(profile);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(store),
            request,
        )
        .expect("open production exact transaction cursor");
        let failed = prepare_next_core_authorized_regular_payload_v0(open)
            .err()
            .expect("first production transaction prepare must fail");
        finish_failed_core_authorized_regular_transaction_decode_v0(failed)
    }

    fn expect_prepared_runtime_transaction(
        prepared: PreparedCoreAuthorizedRegularPayloadV0,
    ) -> PreparedCoreAuthorizedRuntimeTransactionV0 {
        match prepared {
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(prepared) => prepared,
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(_) => {
                panic!("expected exact runtime transaction payload")
            }
        }
    }

    fn attempt_next_production_runtime_transaction(
        open: OpenCoreAuthorizedRegularTransactionCursorV0,
    ) -> Result<
        OpenCoreAuthorizedRegularTransactionCursorV0,
        Box<FailedCoreAuthorizedRegularRuntimeAttemptV0>,
    > {
        let prepared = expect_prepared_runtime_transaction(
            prepare_next_core_authorized_regular_payload_v0(open)
                .expect("prepare exact production runtime transaction"),
        );
        attempt_prepared_core_authorized_runtime_transaction_v0(prepared)
    }

    fn advance_next_production_non_runtime_payload(
        open: OpenCoreAuthorizedRegularTransactionCursorV0,
    ) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare exact production non-runtime payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("expected exact non-runtime payload")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode exact production non-runtime payload");
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .expect("execute exact production non-runtime family");
        let sealed = seal_core_authorized_non_runtime_family_writes_v0(attempted)
            .expect("seal exact production non-runtime family writes");
        advance_core_authorized_non_runtime_success_v0(sealed)
    }

    fn complete_production_runtime_cursor(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(store),
            core_validation_request(profile),
        )
        .expect("open complete production runtime cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first exact production transaction");
        attempt_next_production_runtime_transaction(open)
            .expect("execute second exact production transaction")
    }

    fn all_family_complete_body_profile(store: &TestStore) -> FixtureProfile {
        let base = fixture_profile(store.parent_state_root, 0);
        let runtime = base.body.application_payload().transactions()[0].clone();
        let (_, poco_inner) = author_two_valid_poco_application_operations(store, &base);
        let validator_id = "native-complete-poco-validator-poco";
        let validator_inner = valid_validator_transition_bytes(store, validator_id);
        replace_profile_transactions(
            base,
            vec![
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    "native-complete-poco-validator-first".to_string(),
                    81,
                    "did:operator:1",
                    "operator",
                    1,
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    &poco_inner[0],
                ),
                runtime,
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    validator_id.to_string(),
                    81,
                    "did:operator:1",
                    "operator",
                    1,
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
                    &validator_inner,
                ),
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    "native-complete-poco-validator-second".to_string(),
                    81,
                    "did:operator:1",
                    "operator",
                    2,
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    &poco_inner[1],
                ),
            ],
        )
    }

    fn complete_production_all_family_cursor(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(store),
            core_validation_request(profile),
        )
        .expect("open complete PoCO/runtime/validator/PoCO cursor");
        complete_production_all_family_cursor_from_cursor_v0(open)
    }

    fn complete_production_all_family_cursor_from_cursor_v0(
        open: OpenCoreAuthorizedRegularTransactionCursorV0,
    ) -> OpenCoreAuthorizedRegularTransactionCursorV0 {
        let open = advance_next_production_non_runtime_payload(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute runtime item in all-family complete body");
        let open = advance_next_production_non_runtime_payload(open);
        advance_next_production_non_runtime_payload(open)
    }

    /// Independently authors the complete mixed-body state and receipt roots
    /// before rerunning the same exact body through the consuming comparator.
    /// The state root comes from the merged final writes on a cloned parent;
    /// the receipt root is built explicitly as empty/runtime/empty/empty.
    fn honest_all_family_complete_body_profile(store: &TestStore) -> FixtureProfile {
        let profile = all_family_complete_body_profile(store);
        let open = complete_production_all_family_cursor(store, &profile);
        assert_eq!(open.applied.len(), 1);
        assert_eq!(open.applied[0].index, 1);
        assert_eq!(
            open.applied_non_runtime
                .iter()
                .map(|applied| match applied {
                    super::AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                        index,
                        ..
                    }
                    | super::AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition {
                        index,
                        ..
                    } => *index,
                })
                .collect::<Vec<_>>(),
            vec![0, 2, 3]
        );
        let mut expected_writes = open
            .changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("encode independent mixed runtime writes");
        expected_writes.extend(open.poco_prefix.as_ref().unwrap().writes.iter().cloned());
        expected_writes.push(open.validator_prefix.as_ref().unwrap().write.clone());
        let target_height = profile.header.height().get();
        let independent_plan = store
            .authenticated_parent
            .plan_put_value_set(target_height, expected_writes)
            .expect("independently plan complete mixed state root");
        let state_root = StateRoot::new(independent_plan.root_hash.into());

        let runtime_facts = NativeTransactionReceiptFactsV0::try_from_runtime_receipt(
            &open.applied[0].runtime_receipt,
        )
        .expect("convert independent mixed runtime receipt");
        let transaction_bytes = profile
            .body
            .application_payload()
            .transactions()
            .iter()
            .map(|transaction| Bytes::copy_from_slice(transaction))
            .collect::<Vec<_>>();
        let native_execution = NativeBlockExecutionV0::try_new(
            &transaction_bytes,
            vec![
                NativeTransactionReceiptFactsV0::internal_operation(),
                runtime_facts,
                NativeTransactionReceiptFactsV0::internal_operation(),
                NativeTransactionReceiptFactsV0::internal_operation(),
            ],
        )
        .expect("independently construct complete mixed receipt sequence");
        let receipts_root = native_execution
            .execution_receipts()
            .receipts_root()
            .expect("derive independent complete mixed receipt root");

        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("finish authoring complete mixed-body plan");
        assert_eq!(
            finished.post_state_update.root_hash,
            independent_plan.root_hash
        );
        drop(finished);
        replace_profile_execution_roots(profile, state_root, receipts_root)
    }

    fn classify_all_family_complete_body(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
            complete_production_all_family_cursor(store, profile),
        )
        .expect("finish exact all-family body before root classification");
        classify_core_authorized_regular_complete_body_commitment_comparison_v0(
            match_finished_core_authorized_regular_complete_body_commitments_v0(finished),
        )
    }

    fn durable_invalid_all_family_complete_body_owner_from_effect_v0(
        store: &TestStore,
        effect: Effect,
    ) -> DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
        let request = match effect {
            Effect::ValidatePayload(request)
                if request.route() == PayloadValidationRouteV0::Proposal =>
            {
                request
            }
            Effect::ValidateSyncedPayload(request)
                if request.route() == PayloadValidationRouteV0::Synced =>
            {
                request
            }
            Effect::ValidatePayload(_) | Effect::ValidateSyncedPayload(_) => {
                panic!("durable invalid complete-body fixture effect disagreed with its route")
            }
            _ => panic!("durable invalid complete-body fixture requires a validation effect"),
        };
        let job = core_regular_validation_job_for_test_v0(request);
        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("durable invalid complete-body fixture did not open: {other:?}"),
        };
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
            complete_production_all_family_cursor_from_cursor_v0(
                open_core_authorized_regular_transaction_cursor_from_open_v0(open),
            ),
        )
        .expect("finish durable-invalid all-family complete-body plan");
        match classify_core_authorized_regular_complete_body_commitment_comparison_v0(
            match_finished_core_authorized_regular_complete_body_commitments_v0(finished),
        ) {
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                owner,
            ) => owner,
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(_)
            | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(_) => {
                panic!("poisoned durable complete-body roots changed disposition")
            }
        }
    }

    fn durable_invalid_all_family_complete_body_owner(
        store: &TestStore,
        poison_state: Option<StateRoot>,
        poison_receipts: Option<ReceiptsRoot>,
    ) -> DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0 {
        let honest = honest_all_family_complete_body_profile(store);
        let state_root = poison_state.unwrap_or_else(|| honest.header.state_root());
        let receipts_root = poison_receipts.unwrap_or_else(|| honest.header.receipts_root());
        let profile = replace_profile_execution_roots(honest, state_root, receipts_root);
        durable_invalid_all_family_complete_body_owner_from_effect_v0(
            store,
            core_validation_effect(&profile),
        )
    }

    fn finish_production_runtime_plan(
        store: &TestStore,
        profile: &FixtureProfile,
    ) -> FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0 {
        finish_and_plan_core_authorized_regular_post_state_v0(complete_production_runtime_cursor(
            store, profile,
        ))
        .expect("finish exact production post-state plan")
    }

    fn closed_production_post_state_failure(
        open: OpenCoreAuthorizedRegularTransactionCursorV0,
    ) -> Box<super::ClosedFailedCoreAuthorizedRegularPostStatePlanV0> {
        finish_and_plan_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("post-state failure must retain its exact closed cursor")
    }

    fn first_cursor_error(
        store: &ApplicationStore,
        profile: FixtureProfile,
    ) -> InertRegularBodyCursorFailureV0 {
        let open = open_inert_regular_body_traversal_for_test_v0(store, authenticate(profile))
            .expect("open exact traversal for cursor rejection");
        let failed = observe_next_exact_body_transaction_for_test_v0(open)
            .err()
            .expect("first exact body transaction must be rejected");
        match finish_failed_inert_regular_body_traversal_for_test_v0(failed) {
            FinishedInertRegularBodyCursorFailureV0::Cursor(cause) => cause,
            FinishedInertRegularBodyCursorFailureV0::Snapshot(error) => {
                panic!("cursor rejection snapshot finish failed: {error}")
            }
        }
    }

    fn fixture_profile_with_second_runtime_reject(parent_state_root: [u8; 32]) -> FixtureProfile {
        fixture_profile_with_named_second_runtime_reject(
            parent_state_root,
            "native-task-reject",
            "create-reject",
            20_000,
        )
    }

    fn fixture_profile_with_named_second_runtime_reject(
        parent_state_root: [u8; 32],
        task_id: &str,
        command_id: &str,
        reward: u128,
    ) -> FixtureProfile {
        let profile = fixture_profile(parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let rejected = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreateTask {
                task_id: task_id.to_string(),
                reward,
                worker_stake: 500,
                result_deadline_height: 20,
                challenge_window_blocks: 10,
            },
        };
        transactions[1] = signed_canonical_transaction_bytes(
            0,
            command_id,
            82,
            "did:client:1",
            "hepta",
            &rejected,
        );
        replace_profile_transactions(profile, transactions)
    }

    fn runtime_mutation<Value: serde::Serialize>(
        object_key_hex: String,
        object_type: &str,
        expected_version: Option<u64>,
        next_version: u64,
        value: &Value,
    ) -> RuntimeMutation {
        RuntimeMutation {
            object_key_hex,
            object_type: object_type.to_string(),
            expected_version,
            next_version,
            value_bytes: serde_json::to_vec(value).expect("encode canonical runtime mutation"),
        }
    }

    fn open_task(task_id: &str) -> TaskV1 {
        TaskV1 {
            task_id: task_id.to_string(),
            client: "did:client:1".to_string(),
            worker: None,
            reward: 1_000,
            worker_stake: 500,
            result_deadline_height: 20,
            challenge_window_blocks: 10,
            status: TaskStatusV1::Open,
            commitment_hex: None,
            result_hash_hex: None,
            reveal_salt_hex: None,
            challenge_deadline_height: None,
            consumer: None,
            consumed_units: 0,
            consumption_payment: 0,
            receipt_hash_hex: None,
            challenger: None,
            challenge_bond: 0,
            evidence_hash_hex: None,
        }
    }

    fn assert_runtime_fixture_objects_absent(store: &ApplicationStore) {
        for object_key in [
            account_key("did:operator:1"),
            account_key("did:client:1"),
            monetary_state_key(),
            task_key("native-task-0"),
            task_key("native-task-reject"),
        ] {
            assert!(
                store
                    .load_object(&object_key)
                    .expect("read persisted runtime fixture object")
                    .is_none(),
                "test-only execution must not persist {object_key}"
            );
        }
    }

    fn finished_runtime_reject_code(
        failure: &FinishedFailedTestRegularRuntimeExecutionV0,
    ) -> &'static str {
        failure
            .deterministic_runtime_failure_code()
            .expect("fixture failure must be a deterministic runtime rejection")
    }

    #[test]
    fn fixture_consistent_regular_input_join_and_store_binding_succeed() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let expected_header = profile.header.id();
        let expected_parent = profile.parent.id();
        let expected_set = profile.validator_set.id();
        let expected_parameters = profile.parameters.hash();
        let expected_policy = fixture_signer_policy_commitment(&profile);
        let expected_timestamp = profile.header.timestamp_ms();
        let expected_outer = profile.body.application_payload().transactions().to_vec();
        let open =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .expect("open exact snapshot-owned inert traversal");
        let open = observe_next_exact_body_transaction_for_test_v0(open)
            .expect("observe first exact body transaction");
        let open = observe_next_exact_body_transaction_for_test_v0(open)
            .expect("observe second exact body transaction");
        let finished = finish_inert_regular_body_traversal_for_test_v0(open)
            .expect("finish exact snapshot-owned inert traversal");
        assert_eq!(finished.block_id(), expected_header);
        assert_eq!(finished.exact_header_id(), expected_header);
        assert_eq!(finished.parent_block_id(), expected_parent);
        assert_eq!(finished.transaction_count(), 2);
        let first = finished.transaction_observation(0);
        assert_eq!(first.index, 0);
        assert_eq!(first.exact_outer_bytes, expected_outer[0]);
        let first_envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&expected_outer[0]).expect("decode expected first envelope");
        assert_eq!(
            first.exact_inner_payload_bytes,
            first_envelope
                .payload_bytes()
                .expect("decode first payload")
        );
        assert_eq!(first.target_height, 2);
        assert_eq!(first.target_block_id, expected_header);
        assert_eq!(first.validation_timestamp_ms, expected_timestamp);
        assert_eq!(first.signer_id, "did:operator:1");
        assert_eq!(first.signer_role, "operator");
        assert_eq!(first.nonce, 1);
        assert_eq!(
            first.payload_len as usize,
            first.exact_inner_payload_bytes.len()
        );
        let second = finished.transaction_observation(1);
        assert_eq!(second.index, 1);
        assert_eq!(second.exact_outer_bytes, expected_outer[1]);
        let second_envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&expected_outer[1]).expect("decode expected second envelope");
        assert_eq!(
            second.exact_inner_payload_bytes,
            second_envelope
                .payload_bytes()
                .expect("decode second payload")
        );
        assert_eq!(second.target_height, 2);
        assert_eq!(second.target_block_id, expected_header);
        assert_eq!(second.validation_timestamp_ms, expected_timestamp);
        assert_eq!(second.signer_id, "did:client:1");
        assert_eq!(second.signer_role, "hepta");
        assert_eq!(second.nonce, 1);
        assert_eq!(
            second.payload_len as usize,
            second.exact_inner_payload_bytes.len()
        );
        assert_eq!(finished.validator_set_id(), expected_set);
        assert_eq!(finished.parameters_hash(), expected_parameters);
        assert_eq!(finished.signer_policy_commitment(), expected_policy);
        assert_eq!(finished.authenticated_validator_count(), 4);
    }

    #[test]
    fn owning_runtime_session_executes_two_exact_transactions_with_prior_delta_visible() {
        let test_store = test_store();
        let committed_before = test_store
            .store
            .load_or_migrate()
            .expect("read committed state before test-only execution");
        assert_runtime_fixture_objects_absent(&test_store.store);
        let profile = honest_runtime_profile(&test_store);
        let expected_block_id = profile.header.id();
        let expected_state_root = profile.header.state_root();
        let expected_receipts_root = profile.header.receipts_root();
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact owning runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute exact operator credit");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute exact task creation using prior credit delta");
        let finished = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("finish exact owning runtime session");
        let matched = match_finished_test_regular_runtime_commitments_for_test_v0(finished)
            .expect("match independently authored exact regular commitments");
        assert_eq!(matched.block_id(), expected_block_id);
        assert_eq!(matched.post_state_root(), expected_state_root);
        assert_eq!(matched.receipts_root(), expected_receipts_root);
        let finished = matched.finished();

        assert_eq!(finished.block_id(), expected_block_id);
        assert_eq!(finished.authenticated_validator_count(), 4);
        assert_eq!(finished.applied_count(), 2);
        assert_eq!(finished.applied(0).observation.index, 0);
        assert_eq!(finished.applied(1).observation.index, 1);
        assert_eq!(
            finished.applied(0).canonical_transaction.sender,
            "did:operator:1"
        );
        assert_eq!(
            finished.applied(1).canonical_transaction.sender,
            "did:client:1"
        );
        assert_eq!(finished.applied(0).runtime_receipt.fee_charged, 0);
        assert_eq!(
            NativeTransactionReceiptFactsV0::try_from_runtime_receipt(
                &finished.applied(1).runtime_receipt
            )
            .expect("rebuild second native receipt facts"),
            finished.applied(1).native_receipt
        );

        let client_key = account_key("did:client:1");
        let client_mutation = finished
            .applied(1)
            .runtime_receipt
            .mutations
            .iter()
            .find(|mutation| mutation.object_key_hex == client_key)
            .expect("second transaction must update the prior client delta");
        assert_eq!(client_mutation.expected_version, Some(1));
        assert_eq!(client_mutation.next_version, 2);
        let client = finished
            .changes()
            .get(&client_key)
            .expect("session must retain the updated client account");
        assert_eq!(client.version, 2);
        let client_value: AccountV1 =
            serde_json::from_slice(&client.value_bytes).expect("decode staged client account");
        assert_eq!(client_value.nonce, 1);
        assert_eq!(
            client_value.balance,
            10_000 - finished.applied(1).runtime_receipt.fee_charged - 1_000
        );
        assert!(finished.changes().contains_key(&task_key("native-task-0")));

        // The parent database contained no client account. The second tx can
        // succeed only by reading the first tx's session-owned version-1 delta.
        assert_runtime_fixture_objects_absent(&test_store.store);
        let committed_after = test_store
            .store
            .load_or_migrate()
            .expect("read committed state after test-only execution");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn independent_writer_cannot_move_an_open_runtime_snapshot_or_its_post_state_plan() {
        let test_store = test_store();
        let profile = honest_runtime_profile(&test_store);
        let expected_block_id = profile.header.id();
        let expected_state_root = profile.header.state_root();
        let expected_receipts_root = profile.header.receipts_root();
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact runtime session before sibling writer");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute first transaction and establish the parent snapshot");

        // This is deliberately a separately opened handle to the same SQLite
        // file. Its gates and pin counter are independent, which models an
        // external WAL writer rather than bypassing the original store's
        // maintenance/pin safety gate. The committed sibling is a legitimate
        // empty exact-next block through the existing persistence seam.
        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&test_authorized_signers()));
        let writer = ApplicationStore::open(
            &test_store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("open independent sibling writer");
        let current = writer
            .load_or_migrate()
            .expect("load sibling writer parent state");
        assert_eq!(current.height, 1);
        assert_eq!(current.app_hash, test_store.parent_state_root);
        let sibling_update = writer
            .plan_auth_update(2, Vec::new())
            .expect("plan legitimate empty sibling transition");
        let sibling_app_hash: [u8; 32] = sibling_update.root_hash.into();
        let sibling = PendingBlock {
            height: 2,
            app_hash: sibling_app_hash,
            tx_results: Vec::new(),
            native_execution: crate::test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                2,
                sibling_app_hash,
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update: sibling_update,
            poco_checkpoint_execution: None,
        };
        writer
            .persist_transition(&current, &sibling, 0)
            .expect("commit legitimate empty sibling through existing writer seam");
        let sibling_head = writer
            .load_or_migrate()
            .expect("reload committed sibling head");
        assert_eq!(sibling_head.height, 2);
        assert_eq!(sibling_head.app_hash, sibling_app_hash);
        assert_ne!(StateRoot::new(sibling_app_hash), expected_state_root);

        // The already-open session must continue against parent version 1:
        // the second transaction observes the first transaction's local
        // delta, while every persisted miss and the JMT planner stay on the
        // read snapshot established before the sibling commit.
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute second transaction against fixed parent plus local delta");
        let finished = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("plan exact transaction sibling from the original parent snapshot");
        assert_eq!(finished.planned_state_root(), expected_state_root);
        let matched = match_finished_test_regular_runtime_commitments_for_test_v0(finished)
            .expect("match independently authored old-parent execution roots");
        assert_eq!(matched.block_id(), expected_block_id);
        assert_eq!(matched.post_state_root(), expected_state_root);
        assert_eq!(matched.receipts_root(), expected_receipts_root);
        assert_eq!(matched.finished().applied_count(), 2);
        assert_eq!(
            matched.finished().applied(1).observation.index,
            1,
            "the second exact body item remained ordered after the sibling commit"
        );

        let visible_head = test_store
            .store
            .load_or_migrate()
            .expect("original handle observes sibling only after snapshot finish");
        assert_eq!(visible_head.height, 2);
        assert_eq!(visible_head.app_hash, sibling_app_hash);
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn canonical_state_root_substitution_is_rejected_only_by_the_internal_comparator() {
        let test_store = test_store();
        let honest = honest_runtime_profile(&test_store);
        let receipts_root = honest.header.receipts_root();
        let profile =
            replace_profile_execution_roots(honest, StateRoot::new([0xe1; 32]), receipts_root);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open state-root substitution session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute first state-root substitution transaction");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute second state-root substitution transaction");
        let finished = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("plan state-root substitution from the fixed parent");
        assert!(matches!(
            match_finished_test_regular_runtime_commitments_for_test_v0(finished),
            Err(TestRegularRuntimeCommitmentComparisonFailureV0::StateRootMismatch)
        ));
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn empty_runtime_delta_still_plans_and_matches_the_exact_next_version() {
        let test_store = test_store();
        let independent_plan = test_store
            .authenticated_parent
            .plan_put_value_set(2, Vec::new())
            .expect("independently plan empty exact-next fixture state");
        let state_root = StateRoot::new(independent_plan.root_hash.into());
        let native_execution = NativeBlockExecutionV0::try_new(&[], Vec::new())
            .expect("construct empty honest native execution");
        let receipts_root = native_execution
            .execution_receipts()
            .receipts_root()
            .expect("derive empty honest receipt root");
        let profile = replace_profile_execution_roots(
            replace_profile_transactions(
                fixture_profile(test_store.parent_state_root, 0),
                Vec::new(),
            ),
            state_root,
            receipts_root,
        );
        let expected_block_id = profile.header.id();
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open empty exact-next runtime session");
        let finished = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("plan empty exact-next runtime state");
        assert_eq!(finished.post_state_update.version, 2);
        let matched = match_finished_test_regular_runtime_commitments_for_test_v0(finished)
            .expect("match empty exact-next runtime commitments");
        assert_eq!(matched.block_id(), expected_block_id);
        assert_eq!(matched.post_state_root(), state_root);
        assert_eq!(matched.receipts_root(), receipts_root);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn canonical_receipts_root_substitution_is_rejected_only_by_the_internal_comparator() {
        let test_store = test_store();
        let honest = honest_runtime_profile(&test_store);
        let state_root = honest.header.state_root();
        let profile =
            replace_profile_execution_roots(honest, state_root, ReceiptsRoot::new([0xe2; 32]));
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open receipts-root substitution session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute first receipts-root substitution transaction");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute second receipts-root substitution transaction");
        let finished = finish_and_plan_test_regular_runtime_execution_for_test_v0(open)
            .expect("plan receipts-root substitution from the fixed parent");
        assert!(matches!(
            match_finished_test_regular_runtime_commitments_for_test_v0(finished),
            Err(TestRegularRuntimeCommitmentComparisonFailureV0::ReceiptsRootMismatch)
        ));
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn second_runtime_rejection_drops_prior_changes_and_receipts_without_persistence() {
        let test_store = test_store();
        let profile = fixture_profile_with_second_runtime_reject(test_store.parent_state_root);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact owning runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute prior credit before rejected transaction");
        let failed = execute_next_exact_runtime_transaction_for_test_v0(open)
            .err()
            .expect("second transaction must deterministically reject");
        let pending_debug = format!("{failed:?}");
        assert!(!pending_debug.contains("insufficient_balance"));
        assert!(!pending_debug.contains("cause"));
        let finished = finish_failed_test_regular_runtime_execution_for_test_v0(failed)
            .expect("finish exact rejected runtime session");
        assert_eq!(
            finished_runtime_reject_code(&finished),
            "insufficient_balance"
        );
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn finished_runtime_failure_retains_one_exact_profile_without_a_second_join() {
        let test_store = test_store();
        let profile = fixture_profile_with_named_second_runtime_reject(
            test_store.parent_state_root,
            "native-task-reject-a",
            "create-reject-a",
            20_000,
        );
        let expected_block_id = profile.header.id();
        let expected_outer = profile.body.application_payload().transactions()[1].clone();
        let expected_envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&expected_outer).expect("decode exact rejected envelope");
        let expected_inner = expected_envelope
            .payload_bytes()
            .expect("decode exact rejected payload");
        let foreign = fixture_profile_with_named_second_runtime_reject(
            test_store.parent_state_root,
            "native-task-reject-b",
            "create-reject-b",
            30_000,
        );
        let foreign_block_id = foreign.header.id();
        assert_ne!(expected_block_id, foreign_block_id);

        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact provenance runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute prior exact credit");
        let failed = execute_next_exact_runtime_transaction_for_test_v0(open)
            .err()
            .expect("second exact transaction must reject");
        let pending_debug = format!("{failed:?}");
        assert_eq!(
            pending_debug,
            "FailedTestRegularRuntimeExecutionV0 { pending_explicit_snapshot_finish: true, .. }"
        );
        let finished = finish_failed_test_regular_runtime_execution_for_test_v0(failed)
            .expect("finish exact failed runtime provenance");
        assert_eq!(
            format!("{finished:?}"),
            "FinishedFailedTestRegularRuntimeExecutionV0 { snapshot_finished: true, .. }"
        );
        assert_eq!(finished.block_id(), expected_block_id);
        assert_ne!(finished.block_id(), foreign_block_id);
        assert_eq!(finished.authenticated_validator_count(), 4);
        assert_eq!(finished.failed_transaction_index(), 1);
        let retained = finished
            .decoded_failed_transaction()
            .expect("runtime rejection must retain its exact decoded transaction");
        assert_eq!(retained.observation.index, 1);
        assert_eq!(retained.observation.target_block_id, expected_block_id);
        assert_eq!(retained.observation.exact_outer_bytes, expected_outer);
        assert_eq!(
            retained.observation.exact_inner_payload_bytes,
            expected_inner
        );
        assert_eq!(retained.canonical_transaction.sender, "did:client:1");
        assert_eq!(
            finished_runtime_reject_code(&finished),
            "insufficient_balance"
        );

        // The foreign profile is independently valid against the same parent
        // snapshot and signer/configuration context. It forms its own finished
        // failure; neither finish API accepts the other's inputs or cause.
        let foreign_open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(foreign),
        )
        .expect("open independently valid foreign runtime profile");
        let foreign_open = execute_next_exact_runtime_transaction_for_test_v0(foreign_open)
            .expect("execute foreign profile prior credit");
        let foreign_failed = execute_next_exact_runtime_transaction_for_test_v0(foreign_open)
            .err()
            .expect("foreign profile second transaction must reject");
        let foreign_finished =
            finish_failed_test_regular_runtime_execution_for_test_v0(foreign_failed)
                .expect("finish independently valid foreign runtime failure");
        assert_eq!(foreign_finished.block_id(), foreign_block_id);
        assert_ne!(foreign_finished.block_id(), finished.block_id());
        assert_eq!(foreign_finished.failed_transaction_index(), 1);
        assert_ne!(
            foreign_finished
                .decoded_failed_transaction()
                .expect("foreign decoded failure")
                .observation
                .exact_outer_bytes,
            finished
                .decoded_failed_transaction()
                .expect("retained primary decoded failure")
                .observation
                .exact_outer_bytes
        );
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn dropping_pending_runtime_failure_releases_snapshot_without_a_classification() {
        let test_store = test_store();
        let profile = fixture_profile_with_second_runtime_reject(test_store.parent_state_root);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact runtime session for failed Drop boundary");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute prior credit before pending Drop");
        let failed = execute_next_exact_runtime_transaction_for_test_v0(open)
            .err()
            .expect("second transaction must reject before pending Drop");
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            1
        );
        drop(failed);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
        assert_runtime_fixture_objects_absent(&test_store.store);
    }

    #[test]
    fn successful_post_state_plan_plus_finish_failure_prevents_finished_artifacts() {
        let test_store = test_store();
        let profile = honest_runtime_profile(&test_store);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact owning runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute first exact transaction");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute second exact transaction");
        let open = inject_test_runtime_snapshot_finish_failure_for_test_v0(open);
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            ))
        ));
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn snapshot_finish_failure_outranks_incomplete_runtime_body() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open incomplete runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute only the first exact transaction");
        let open = inject_test_runtime_snapshot_finish_failure_for_test_v0(open);
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            ))
        ));
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn snapshot_finish_failure_outranks_post_state_write_preparation_failure() {
        let test_store = test_store();
        let complete_session = || {
            let profile = honest_runtime_profile(&test_store);
            let open = open_test_regular_runtime_execution_for_test_v0(
                &test_store.store,
                authenticate(profile),
            )
            .expect("open complete write-preparation session");
            let open = execute_next_exact_runtime_transaction_for_test_v0(open)
                .expect("execute first write-preparation transaction");
            execute_next_exact_runtime_transaction_for_test_v0(open)
                .expect("execute second write-preparation transaction")
        };
        let invalid_write = || {
            NodeObjectMutation {
                object_key_hex: String::new(),
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                expected_version: None,
                next_version: 1,
                value_bytes: Vec::new(),
            }
            .into_stored()
        };

        let mut control = complete_session();
        control.changes.insert(String::new(), invalid_write());
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(control),
            Err(TestRegularRuntimeFinishFailureV0::PrepareWritesInvariant)
        ));

        let mut open = complete_session();
        open.changes.insert(String::new(), invalid_write());
        let open = inject_test_runtime_snapshot_finish_failure_for_test_v0(open);
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            ))
        ));
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn post_state_and_root_comparator_api_surface_remains_narrow_and_unwired() {
        let source = include_str!("native_payload_validation.rs");
        let implementation_source = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("native payload validation test module boundary")
            .0;
        let legacy_plan_call = [".plan_auth_", "update("].concat();
        let legacy_qualified_plan = ["ApplicationStore::plan_auth_", "update"].concat();
        assert!(!implementation_source.contains(&legacy_plan_call));
        assert!(!implementation_source.contains(&legacy_qualified_plan));
        let comparator_signature = [
            "fn match_finished_test_regular_runtime_",
            "commitments_for_test_v0(\n    finished: FinishedPlannedTestRegularRuntimeExecutionV0,\n)",
        ]
        .concat();
        assert!(source.contains(&comparator_signature));
        let generic_comparator = [
            "fn match_finished_test_regular_runtime_",
            "commitments_for_test_v0<V",
        ]
        .concat();
        assert!(!source.contains(&generic_comparator));
        let strict_verifier = ["&StrictEd", "25519Verifier"].concat();
        assert!(source.contains(&strict_verifier));
        assert!(implementation_source.contains(
            "fn take_core_regular_validation_job_v0(effect: Effect) -> CoreRegularValidationEffectIntakeV0"
        ));
        assert!(implementation_source.contains(
            "fn begin_core_authorized_regular_validation_session_v0(\n    host: &NativeValidationHostV0<'_>,\n    job: CoreIssuedRegularValidationJobV0,"
        ));
        assert!(!implementation_source.contains(
            "fn begin_core_authorized_regular_validation_session_v0(\n    host: &NativeValidationHostV0<'_>,\n    request: PayloadValidationRequest,"
        ));
        assert!(implementation_source.contains(
            "fn open_core_authorized_regular_validation_v0(\n    host: &NativeValidationHostV0<'_>,\n    owner: CoreIssuedRegularValidationOwnerV0,"
        ));
        let intake_offset = implementation_source
            .find("fn take_core_regular_validation_job_v0(")
            .expect("complete Core effect route intake");
        let admission_offset = implementation_source
            .find("fn begin_core_authorized_regular_validation_session_v0(")
            .expect("route-checked Core job session admission");
        let open_offset = implementation_source
            .find("fn open_core_authorized_regular_validation_v0(")
            .expect("owning Core validation open");
        assert!(intake_offset < admission_offset);
        let intake_body = &implementation_source[intake_offset..admission_offset];
        for required_route_binding in [
            "Effect::ValidatePayload(request)",
            "request.route() == PayloadValidationRouteV0::Proposal",
            "Effect::ValidateSyncedPayload(request)",
            "request.route() == PayloadValidationRouteV0::Synced",
            "CoreRegularValidationEffectIntakeV0::RouteInvariant",
            "CoreRegularValidationEffectIntakeV0::Other(Box::new(effect))",
        ] {
            assert!(
                intake_body.contains(required_route_binding),
                "Core effect intake lost route binding: {required_route_binding}"
            );
        }
        assert!(!intake_body.contains("try_claim()"));
        let admission_body = &implementation_source[admission_offset..open_offset];
        assert!(admission_body.contains("let CoreIssuedRegularValidationJobV0 { request } = job;"));
        let claim_offset = admission_body
            .find("request.try_claim()")
            .expect("Core request one-shot claim");
        let fingerprint_offset = admission_body
            .find("native_validation_reservation_fingerprint_v0(&owner.request)")
            .expect("claimed-request durable fingerprint");
        let reserve_offset = admission_body
            .find("reserve_or_reopen_native_validation_job_v0(facts)")
            .expect("durable validation job reservation or reopen");
        let claimed_open_offset = admission_body
            .find("open_core_authorized_regular_validation_v0(host, owner)")
            .expect("only a freshly reserved owner reaches parent authentication");
        assert!(claim_offset < fingerprint_offset);
        assert!(fingerprint_offset < reserve_offset);
        assert!(reserve_offset < claimed_open_offset);
        assert!(
            admission_body.contains("CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate")
        );
        assert!(admission_body
            .contains("CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting"));
        assert!(admission_body
            .contains("CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation"));
        assert!(
            admission_body.contains("NativeValidationReservationDecisionV0::Reserved(reservation)")
        );
        assert!(
            admission_body.contains("NativeValidationReservationDecisionV0::Existing(existing)")
        );
        assert!(admission_body
            .contains("reservation: CoreAuthorizedRegularReservationV0::Durable(reservation)"));
        assert!(!admission_body.contains("CoreAuthorizedRegularReservationV0::TestOnly"));
        let open_body = &implementation_source[open_offset..];
        assert!(open_body.contains("Box<FailedCoreIssuedRegularValidationOpenV0>"));
        let borrowed_body_offset = open_body
            .find("decode_and_validate_exact_regular_body_v0(validation_id, block, &context)")
            .expect("borrowed exact body authorization");
        let consume_request_offset = open_body
            .find("let (route, validation_id, block, _parent) = request.into_parts();")
            .expect("success-only Core request consumption");
        assert!(borrowed_body_offset < consume_request_offset);
        assert!(open_body
            .contains("CoreAuthorizedExactRegularBodyV0 {\n        reservation,\n        route,"));
        let fingerprint_body = implementation_source
            .split_once(
                "fn native_validation_reservation_fingerprint_v0(\n    request: &ClaimedPayloadValidationRequestV0,",
            )
            .expect("claimed-request reservation fingerprint")
            .1
            .split_once("/// Exact body retained after consuming one opaque Core validation capability.")
            .expect("reservation fingerprint end")
            .0;
        for required_fingerprint_fact in [
            "request.route()",
            "request.id()",
            "request.block()",
            "request.parent()",
            "native_validation_request_fingerprint_v0",
        ] {
            assert!(
                fingerprint_body.contains(required_fingerprint_fact),
                "durable fingerprint lost exact Core source fact: {required_fingerprint_fact}"
            );
        }
        for forbidden_fingerprint_input in [
            "NativeValidationHostV0",
            "ApplicationStore",
            "SQLite",
            "snapshot",
            "cache",
            "serde",
            "serde_json",
            "Debug",
        ] {
            assert!(
                !fingerprint_body.contains(forbidden_fingerprint_input),
                "durable fingerprint gained external input: {forbidden_fingerprint_input}"
            );
        }
        let store_source = include_str!("store.rs");
        let fingerprint_kernel = store_source
            .split_once("pub(super) fn native_validation_request_fingerprint_v0(")
            .expect("shared durable fingerprint kernel")
            .1
            .split_once("struct NativeValidationRequestBodyRecordV0")
            .expect("shared durable fingerprint kernel end")
            .0;
        for required_fingerprint_fact in [
            "let target_header_cev0 = block",
            ".header()",
            ".try_cev0_bytes()",
            "block.application_payload()",
            "block.evidence_objects()",
            "parent.tip()",
            ".exact_header()",
            "hash_native_validation_reservation_frame_v0",
        ] {
            assert!(
                fingerprint_kernel.contains(required_fingerprint_fact),
                "shared durable fingerprint lost exact Core source fact: {required_fingerprint_fact}"
            );
        }
        assert!(store_source.contains("NATIVE_VALIDATION_RESERVATION_FINGERPRINT_CODEC_V0"));
        let frame_body = store_source
            .split_once("fn hash_native_validation_reservation_frame_v0(")
            .expect("checked fingerprint frame helper")
            .1
            .split_once("fn begin_native_validation_reservation_fingerprint_v0(")
            .expect("fingerprint frame helper end")
            .0;
        assert!(frame_body.contains("u32::try_from(frame.len())"));
        assert!(frame_body.contains("hasher.update(length.to_be_bytes())"));
        assert!(frame_body.contains("hasher.update(frame)"));
        assert!(implementation_source.contains("classify_exact_regular_body_failure_v0(error)"));
        for required_class in [
            "CoreAuthorizedExactRegularBodyFailureClassV0::SourceUnavailable",
            "CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid",
            "CoreAuthorizedExactRegularBodyFailureClassV0::Invariant",
            "OpenCoreAuthorizedRegularValidationFailureV0::SourceUnavailable",
            "OpenCoreAuthorizedRegularValidationFailureV0::DeterministicallyInvalid",
            "OpenCoreAuthorizedRegularValidationFailureV0::Invariant",
        ] {
            assert!(
                implementation_source.contains(required_class),
                "exact body boundary lost typed failure class: {required_class}"
            );
        }
        assert!(!implementation_source.contains("CoreAuthorizedExactRegularBodyFailureV0::new("));
        assert!(!implementation_source.contains("DeterministicallyInvalid(error)"));
        assert!(!implementation_source.contains("match failure.reason"));
        assert!(!implementation_source.contains("match error.reason"));
        let body_authorizer = implementation_source
            .split_once("fn decode_and_validate_exact_regular_body_v0(")
            .expect("exact body authorizer")
            .1
            .split_once("#[cfg(test)]\nfn authorize_exact_regular_body_parts_v0(")
            .expect("exact body authorizer end")
            .0;
        assert!(body_authorizer.contains("decode_application_payload_v0_exact_for_root_binding("));
        assert!(!body_authorizer.contains("decode_application_payload_v0_exact("));
        let payload_root_offset = body_authorizer
            .find("let payload_root = body.payload_root()")
            .expect("payload root computation");
        let evidence_root_offset = body_authorizer
            .find("let evidence_root = body.evidence_root()")
            .expect("evidence root computation");
        let verify_evidence_offset = body_authorizer
            .find("body.verify_evidence(")
            .expect("strict evidence verification");
        let canonical_size_offset = body_authorizer
            .find("let canonical_logical_block_size = body.logical_block_size_v0(header)")
            .expect("canonical logical size computation");
        let maximum_offset = body_authorizer
            .find("canonical_logical_block_size > u64::from(parameters.max_block_bytes())")
            .expect("deterministic maximum comparison");
        assert!(payload_root_offset < verify_evidence_offset);
        assert!(evidence_root_offset < verify_evidence_offset);
        assert!(verify_evidence_offset < canonical_size_offset);
        assert!(canonical_size_offset < maximum_offset);
        assert!(body_authorizer.contains("match error.code()"));
        assert!(body_authorizer.contains("BlockValidationErrorCode::LogicalBlockSizeExceeded =>"));
        assert!(!body_authorizer.contains("validate_max_block_bytes("));
        assert!(implementation_source.contains(
            "fn open_core_authorized_regular_transaction_cursor_from_open_v0(\n    open: OpenCoreAuthorizedRegularValidationV0,"
        ));
        assert!(implementation_source.contains(
            "#[cfg(test)]\nfn open_core_authorized_regular_transaction_cursor_v0(\n    host: &NativeValidationHostV0<'_>,\n    request: PayloadValidationRequest,"
        ));
        let test_only_open_offset = implementation_source
            .find("#[cfg(test)]\nfn open_core_authorized_regular_validation_with_test_only_reservation_v0(")
            .expect("explicit test-only reservation bypass");
        let test_cursor_offset = implementation_source
            .find("#[cfg(test)]\nfn open_core_authorized_regular_transaction_cursor_v0(")
            .expect("test-only production cursor helper");
        let production_test_open_offset = implementation_source
            .find("#[cfg(test)]\nfn open_core_authorized_regular_validation_for_test_v0(")
            .expect("production-reservation test open helper");
        assert!(open_offset < test_only_open_offset);
        assert!(test_only_open_offset < test_cursor_offset);
        assert!(test_cursor_offset < production_test_open_offset);
        let test_only_open_body = &implementation_source[test_only_open_offset..test_cursor_offset];
        for required_test_only_boundary in [
            "core_regular_validation_job_for_test_v0(request)",
            "claim_core_validation_request_for_test_v0(request)",
            "reservation: CoreAuthorizedRegularReservationV0::TestOnly",
            "open_core_authorized_regular_validation_v0(",
        ] {
            assert!(
                test_only_open_body.contains(required_test_only_boundary),
                "test-only lower-layer open lost its explicit boundary: {required_test_only_boundary}"
            );
        }
        for forbidden_test_only_authority in [
            "reserve_or_reopen_native_validation_job_v0",
            "NativeValidationReservationDecisionV0::Reserved",
            "NativeValidationReservationDecisionV0::Existing",
            "CoreAuthorizedRegularReservationV0::Durable",
        ] {
            assert!(
                !test_only_open_body.contains(forbidden_test_only_authority),
                "test-only lower-layer open gained production reservation authority: {forbidden_test_only_authority}"
            );
        }
        let test_cursor_body =
            &implementation_source[test_cursor_offset..production_test_open_offset];
        assert!(test_cursor_body.contains(
            "open_core_authorized_regular_validation_with_test_only_reservation_v0(host, request)"
        ));
        assert!(!test_cursor_body.contains("begin_core_authorized_regular_validation_session_v0"));
        assert!(!test_cursor_body.contains("reserve_or_reopen_native_validation_job_v0"));
        let prepare_offset = implementation_source
            .find("fn prepare_next_core_authorized_regular_payload_v0(")
            .expect("production exact transaction prepare function");
        let prepare_signature_end = implementation_source[prepare_offset..]
            .find(" {\n")
            .map(|offset| prepare_offset + offset)
            .expect("production exact transaction prepare signature end");
        let prepare_signature = &implementation_source[prepare_offset..prepare_signature_end];
        assert!(prepare_signature.contains("open: OpenCoreAuthorizedRegularTransactionCursorV0"));
        for forbidden_parameter in [
            "index:",
            "AuthorizedSignerV1]",
            "ExecutionContext",
            "height:",
            "timestamp_ms:",
            "transaction: CanonicalTxV1",
        ] {
            assert!(
                !prepare_signature.contains(forbidden_parameter),
                "production transaction prepare gained caller input: {forbidden_parameter}"
            );
        }
        let decode_offset = implementation_source
            .find("fn decode_next_core_authorized_regular_payload_v0(")
            .expect("production exact payload decoder");
        let decode_signature_end = implementation_source[decode_offset..]
            .find(" {\n")
            .map(|offset| decode_offset + offset)
            .expect("production exact payload decoder signature end");
        let decode_signature = &implementation_source[decode_offset..decode_signature_end];
        assert!(decode_signature.contains("open: &OpenCoreAuthorizedRegularTransactionCursorV0"));
        for forbidden_parameter in [
            "header:",
            "body:",
            "BlockId",
            "AuthorizedSignerV1",
            "index:",
        ] {
            assert!(
                !decode_signature.contains(forbidden_parameter),
                "production payload decoder gained raw authority input: {forbidden_parameter}"
            );
        }
        assert!(implementation_source
            .contains("#[cfg(test)]\nfn decode_exact_authorized_runtime_transaction_for_test_v0("));
        let attempt_offset = implementation_source
            .find("fn attempt_prepared_core_authorized_runtime_transaction_v0(")
            .expect("production consuming runtime attempt");
        let attempt_signature_end = implementation_source[attempt_offset..]
            .find(" {\n")
            .map(|offset| attempt_offset + offset)
            .expect("production runtime attempt signature end");
        let attempt_signature = &implementation_source[attempt_offset..attempt_signature_end];
        assert!(attempt_signature.contains("prepared: PreparedCoreAuthorizedRuntimeTransactionV0"));
        for forbidden_parameter in [
            "tx:",
            "transaction:",
            "index:",
            "ExecutionContext",
            "view:",
            "changes:",
            "snapshot:",
            "RuntimeMutation",
            "verifier:",
        ] {
            assert!(
                !attempt_signature.contains(forbidden_parameter),
                "production runtime attempt gained caller input: {forbidden_parameter}"
            );
        }
        let family_attempt_offset = implementation_source
            .find("fn authorize_and_execute_decoded_core_non_runtime_family_v0(")
            .expect("production consuming non-runtime family attempt");
        let family_attempt_signature_end = implementation_source[family_attempt_offset..]
            .find(" {\n")
            .map(|offset| family_attempt_offset + offset)
            .expect("production family attempt signature end");
        let family_attempt_signature =
            &implementation_source[family_attempt_offset..family_attempt_signature_end];
        assert!(family_attempt_signature
            .contains("decoded: DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0"));
        assert!(!family_attempt_signature
            .contains("authorize_and_execute_decoded_core_non_runtime_family_v0<"));
        for forbidden_parameter in [
            "projection:",
            "lifecycle:",
            "snapshot:",
            "header:",
            "body:",
            "context:",
            "validator_set:",
            "parameters:",
            "loader:",
        ] {
            assert!(
                !family_attempt_signature.contains(forbidden_parameter),
                "production family attempt gained caller authority: {forbidden_parameter}"
            );
        }
        let family_attempt_body = implementation_source[family_attempt_offset..]
            .split_once("fn finish_failed_core_authorized_non_runtime_family_attempt_v0(")
            .expect("production family attempt body boundary")
            .0;
        assert_eq!(
            family_attempt_body
                .matches(".load_authenticated_production_poco_projection_v0()")
                .count(),
            1,
            "PoCO family attempt must have one retained-snapshot projection source"
        );
        assert!(family_attempt_body
            .contains("if let Some(prefix) = &decoded.owner.routed.open.poco_prefix"));
        assert!(family_attempt_body
            .contains("if let Some(prefix) = &decoded.owner.routed.open.validator_prefix"));
        assert!(family_attempt_body.contains("prefix.lifecycle.clone()"));
        assert!(family_attempt_body.contains(
            "prepared_core_authorized_validator_lifecycle_v0(&decoded.owner.routed.open)"
        ));
        for forbidden_surface in [
            "with_poco_projection_loader",
            "ProductionPocoProjectionV0,",
            "Input::",
            "core.step(",
            "persist_transition(",
            "snapshot.finish()",
        ] {
            assert!(
                !family_attempt_body.contains(forbidden_surface),
                "production family attempt gained a forbidden source/output surface: {forbidden_surface}"
            );
        }
        let write_seal_owner_offset = implementation_source
            .find("fn validate_core_authorized_non_runtime_write_seal_owner_v0(")
            .expect("production non-runtime write-seal owner rebind");
        let prefix_rebind_offset = implementation_source
            .find("fn validate_core_authorized_regular_cursor_prefix_v0(")
            .expect("production non-runtime staged-prefix rebind");
        let write_seal_offset = implementation_source
            .find("fn seal_core_authorized_non_runtime_family_writes_v0(")
            .expect("production consuming non-runtime family write sealer");
        assert!(write_seal_owner_offset < prefix_rebind_offset);
        assert!(prefix_rebind_offset < write_seal_offset);
        let write_seal_owner_body =
            &implementation_source[write_seal_owner_offset..write_seal_offset];
        for required_binding in [
            "serde_json::from_slice(&routed.exact_outer_bytes)",
            "envelope == routed.envelope",
            "exact_inner_bytes == routed.exact_inner_bytes",
            "validate_signed_command_envelope_against_policy_v1(",
            "routed.context.signer_id == signer.signer_id",
            "routed.context.signer_role == signer.signer_role",
        ] {
            assert!(
                write_seal_owner_body.contains(required_binding),
                "production write-seal owner rebind lost: {required_binding}"
            );
        }
        for forbidden_surface in [
            "next_transaction_index = ",
            "next_transaction_index +=",
            "snapshot.finish()",
            "plan_exact_next_auth_update_v0",
            "ExecutionOutcomeV0",
            "Input::",
            "Core::step",
            "persist_transition(",
        ] {
            assert!(
                !write_seal_owner_body.contains(forbidden_surface),
                "production write-seal owner rebind gained authority: {forbidden_surface}"
            );
        }
        let prefix_rebind_signature_end = implementation_source[prefix_rebind_offset..]
            .find(" {\n")
            .map(|offset| prefix_rebind_offset + offset)
            .expect("production staged-prefix rebind signature end");
        let prefix_rebind_signature =
            &implementation_source[prefix_rebind_offset..prefix_rebind_signature_end];
        assert!(
            prefix_rebind_signature.contains("open: &OpenCoreAuthorizedRegularTransactionCursorV0")
        );
        for forbidden_parameter in [
            "route:",
            "validation_id:",
            "index:",
            "snapshot:",
            "plan:",
            "writes:",
            "lifecycle:",
        ] {
            assert!(
                !prefix_rebind_signature.contains(forbidden_parameter),
                "production staged-prefix rebind gained caller authority: {forbidden_parameter}"
            );
        }
        let prefix_rebind_body = &implementation_source[prefix_rebind_offset..write_seal_offset];
        for required_binding in [
            "indices.insert(applied.index)",
            "indices.insert(index)",
            "serde_json::from_slice(&applied.exact_outer_bytes)",
            "exact_inner_bytes == applied.exact_inner_bytes",
            "transaction == applied.transaction",
            "native_receipt == applied.native_receipt",
            "prefix.overlay.clone().seal()?",
            "prefix.plan.binds_exact_operations_v0(&poco_raws)",
            "auth_writes_match_v0(&prefix.writes, &expected_writes)",
            "prefix.lifecycle == rebuilt_validator",
        ] {
            assert!(
                prefix_rebind_body.contains(required_binding),
                "production staged-prefix rebind lost: {required_binding}"
            );
        }
        for forbidden_surface in [
            "plan_exact_next_auth_update_v0",
            ".seal_v0()",
            "snapshot.finish()",
            "next_transaction_index = ",
            "next_transaction_index +=",
            "finish_and_plan_core_authorized_regular_post_state_v0",
            "ExecutionOutcomeV0",
            "PayloadValidationResult",
            "Input::",
            "into_core_input",
            "Core::step",
            "core.step(",
            "persist_transition(",
            "receipt:",
        ] {
            assert!(
                !prefix_rebind_body.contains(forbidden_surface),
                "production staged-prefix rebind gained forbidden authority: {forbidden_surface}"
            );
        }
        let write_seal_signature_end = implementation_source[write_seal_offset..]
            .find(" {\n")
            .map(|offset| write_seal_offset + offset)
            .expect("production family write-seal signature end");
        let write_seal_signature =
            &implementation_source[write_seal_offset..write_seal_signature_end];
        assert!(write_seal_signature.contains("attempted: AuthorizedCoreNonRuntimeFamilyAttemptV0"));
        for forbidden_parameter in [
            "route:",
            "validation_id:",
            "snapshot:",
            "header:",
            "height:",
            "version:",
            "root:",
            "raw:",
            "writes:",
            "lifecycle:",
            "plan:",
        ] {
            assert!(
                !write_seal_signature.contains(forbidden_parameter),
                "production family write seal gained caller authority: {forbidden_parameter}"
            );
        }
        let write_seal_body = implementation_source[write_seal_offset..]
            .split_once("fn advance_core_authorized_non_runtime_success_v0(")
            .expect("production family write-seal body boundary")
            .0;
        assert!(write_seal_body
            .contains(".overlay\n                    .clone()\n                    .seal()"));
        assert!(write_seal_body.contains(
            "crate::poco_transition::auth_writes_from_sealed_poco_application_v0(&plan)"
        ));
        assert!(write_seal_body
            .contains("crate::authenticated_lifecycle_write(target_height, &rebuilt)"));
        for forbidden_surface in [
            "plan_exact_next_auth_update_v0",
            ".seal_v0()",
            "snapshot.finish()",
            "next_transaction_index = ",
            "next_transaction_index +=",
            "finish_and_plan_core_authorized_regular_post_state_v0",
            "ExecutionOutcomeV0",
            "PayloadValidationResult",
            "Input::",
            "into_core_input",
            "Core::step",
            "core.step(",
            "persist_transition(",
            "receipt:",
        ] {
            assert!(
                !write_seal_body.contains(forbidden_surface),
                "production family write seal gained a forbidden authority: {forbidden_surface}"
            );
        }
        assert_eq!(
            write_seal_body
                .matches("validate_core_authorized_regular_cursor_prefix_v0(")
                .count(),
            2,
            "both family seal arms must rebind the exact prior cursor prefix"
        );
        assert!(write_seal_body.contains("plan.binds_exact_operations_v0(&exact_poco_operations)"));
        assert!(write_seal_body.contains("if let Some(prefix) = &routed.open.validator_prefix"));
        assert!(write_seal_body
            .contains("prepared_core_authorized_validator_lifecycle_v0(&routed.open)"));

        let non_runtime_advance_offset = implementation_source
            .find("fn advance_core_authorized_non_runtime_success_v0(")
            .expect("production consuming non-runtime cursor advance");
        let non_runtime_advance_signature_end = implementation_source[non_runtime_advance_offset..]
            .find(" {\n")
            .map(|offset| non_runtime_advance_offset + offset)
            .expect("production non-runtime cursor advance signature end");
        let non_runtime_advance_signature =
            &implementation_source[non_runtime_advance_offset..non_runtime_advance_signature_end];
        assert!(non_runtime_advance_signature
            .contains("sealed: OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0"));
        for forbidden_parameter in [
            "route:",
            "validation_id:",
            "index:",
            "snapshot:",
            "writes:",
            "plan:",
            "lifecycle:",
        ] {
            assert!(
                !non_runtime_advance_signature.contains(forbidden_parameter),
                "production non-runtime advance gained caller authority: {forbidden_parameter}"
            );
        }
        let non_runtime_advance_body = implementation_source[non_runtime_advance_offset..]
            .split_once("fn finish_failed_core_authorized_non_runtime_family_write_seal_v0(")
            .expect("production non-runtime cursor advance body boundary")
            .0;
        for required_surface in [
            "open.applied_non_runtime.push(",
            "open.poco_prefix = Some(",
            "open.validator_prefix = Some(",
            "open.next_transaction_index = next_transaction_index",
        ] {
            assert!(
                non_runtime_advance_body.contains(required_surface),
                "production non-runtime advance lost staged state: {required_surface}"
            );
        }
        for forbidden_surface in [
            "plan_exact_next_auth_update_v0",
            ".seal_v0()",
            "snapshot.finish()",
            "finish_and_plan_core_authorized_regular_post_state_v0",
            "ExecutionOutcomeV0",
            "PayloadValidationResult",
            "Input::",
            "into_core_input",
            "Core::step",
            "core.step(",
            "persist_transition(",
            "receipt:",
        ] {
            assert!(
                !non_runtime_advance_body.contains(forbidden_surface),
                "production non-runtime advance gained forbidden authority: {forbidden_surface}"
            );
        }
        let plan_offset = implementation_source
            .find("fn finish_and_plan_core_authorized_regular_post_state_v0(")
            .expect("production consuming post-state planner");
        let plan_signature_end = implementation_source[plan_offset..]
            .find(" {\n")
            .map(|offset| plan_offset + offset)
            .expect("production post-state planner signature end");
        let plan_signature = &implementation_source[plan_offset..plan_signature_end];
        assert!(plan_signature.contains("open: OpenCoreAuthorizedRegularTransactionCursorV0"));
        assert!(plan_signature.contains("Box<ClosedFailedCoreAuthorizedRegularPostStatePlanV0>"));
        for forbidden_parameter in [
            "writes:",
            "version:",
            "root:",
            "header:",
            "body:",
            "changes:",
            "receipts:",
            "snapshot:",
            "verifier:",
        ] {
            assert!(
                !plan_signature.contains(forbidden_parameter),
                "production post-state planner gained caller input: {forbidden_parameter}"
            );
        }
        for (function, owning_parameter, owning_return) in [
            (
                "fn finish_open_regular_validation_failure_v0(",
                "pending: Box<PendingCoreIssuedRegularValidationOpenFailureV0>",
                "Box<FailedCoreIssuedRegularValidationOpenV0>",
            ),
            (
                "fn finish_core_authorized_regular_validation_v0(",
                "open: OpenCoreAuthorizedRegularValidationV0",
                "Box<ClosedFailedCoreAuthorizedRegularValidationV0>",
            ),
            (
                "fn finish_failed_core_authorized_regular_transaction_decode_v0(",
                "failed: Box<FailedCoreAuthorizedRegularTransactionDecodeV0>",
                "Box<ClosedFailedCoreAuthorizedRegularTransactionDecodeV0>",
            ),
            (
                "fn finish_failed_core_authorized_regular_runtime_attempt_v0(",
                "failed: Box<FailedCoreAuthorizedRegularRuntimeAttemptV0>",
                "Box<ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0>",
            ),
            (
                "fn finish_failed_core_authorized_non_runtime_semantic_decode_v0(",
                "failed: Box<FailedCoreAuthorizedNonRuntimeSemanticDecodeV0>",
                "Box<ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0>",
            ),
            (
                "fn finish_failed_core_authorized_non_runtime_family_attempt_v0(",
                "failed: Box<FailedCoreAuthorizedNonRuntimeFamilyAttemptV0>",
                "Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0>",
            ),
            (
                "fn finish_failed_core_authorized_non_runtime_family_write_seal_v0(",
                "failed: FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0",
                "Box<ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0>",
            ),
        ] {
            let offset = implementation_source
                .find(function)
                .unwrap_or_else(|| panic!("missing owning finish function: {function}"));
            let signature_end = implementation_source[offset..]
                .find(" {\n")
                .map(|relative| offset + relative)
                .expect("owning finish signature end");
            let signature = &implementation_source[offset..signature_end];
            assert!(signature.contains(owning_parameter));
            assert!(signature.contains(owning_return));
            for forbidden in [
                "ValidationId",
                "generation:",
                "header: BlockHeader",
                "body: BlockBodyV0",
                "cause: CoreAuthorized",
            ] {
                assert!(
                    !signature.contains(forbidden),
                    "owning finish gained detached input: {function} / {forbidden}"
                );
            }
        }
        let closed_runtime_owner = implementation_source
            .split_once("struct ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0 {")
            .expect("closed runtime failure owner")
            .1
            .split_once("}\n")
            .expect("closed runtime failure owner end")
            .0;
        assert!(!closed_runtime_owner.contains("changes:"));
        assert!(!closed_runtime_owner.contains("applied:"));
        assert!(closed_runtime_owner.contains("applied_non_runtime:"));
        assert!(closed_runtime_owner.contains("poco_prefix:"));
        assert!(closed_runtime_owner.contains("validator_prefix:"));
        let closed_plan_owner = implementation_source
            .split_once("struct ClosedFailedCoreAuthorizedRegularPostStatePlanV0 {")
            .expect("closed post-state failure owner")
            .1
            .split_once("}\n")
            .expect("closed post-state failure owner end")
            .0;
        assert!(!closed_plan_owner.contains("post_state_update"));
        assert!(!closed_plan_owner.contains("seal"));
        assert!(!closed_plan_owner.contains("plan:"));
        let production_plan_body = implementation_source[plan_offset..]
            .split_once("fn finish_and_plan_complete_core_authorized_regular_post_state_v0(")
            .expect("production post-state planner body boundary")
            .0;
        assert!(production_plan_body
            .contains("let replayed_changes = replay_core_authorized_runtime_receipt_changes_v0("));
        assert!(
            production_plan_body.contains("let writes = replayed_changes\n            .values()")
        );
        assert!(production_plan_body.contains("let plan_seal = plan\n            .seal_v0()"));
        assert!(!production_plan_body.contains("let writes = changes\n            .values()"));
        let complete_plan_offset = implementation_source
            .find("fn finish_and_plan_complete_core_authorized_regular_post_state_v0(")
            .expect("production consuming complete-body planner");
        let complete_plan_signature_end = implementation_source[complete_plan_offset..]
            .find(" {\n")
            .map(|offset| complete_plan_offset + offset)
            .expect("production complete-body planner signature end");
        let complete_plan_signature =
            &implementation_source[complete_plan_offset..complete_plan_signature_end];
        assert!(
            complete_plan_signature.contains("open: OpenCoreAuthorizedRegularTransactionCursorV0")
        );
        assert!(
            complete_plan_signature.contains("FinishedPlannedCoreAuthorizedRegularCompleteBodyV0")
        );
        assert!(complete_plan_signature
            .contains("Box<ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0>"));
        for forbidden_parameter in [
            "writes:",
            "version:",
            "root:",
            "header:",
            "body:",
            "changes:",
            "receipts:",
            "snapshot:",
            "verifier:",
        ] {
            assert!(
                !complete_plan_signature.contains(forbidden_parameter),
                "production complete-body planner gained caller input: {forbidden_parameter}"
            );
        }
        let complete_plan_body = implementation_source[complete_plan_offset..]
            .split_once("fn validate_finished_complete_body_item_provenance_v0(")
            .expect("production complete-body planner body boundary")
            .0;
        assert_eq!(
            complete_plan_body
                .matches(".plan_exact_next_auth_update_v0(")
                .count(),
            1,
            "complete-body planner must derive one exact-next JMT plan"
        );
        assert_eq!(
            complete_plan_body.matches(".seal_v0()").count(),
            1,
            "complete-body planner must seal one exact-next JMT plan"
        );
        assert_eq!(
            complete_plan_body.matches("snapshot.finish()").count(),
            1,
            "complete-body planner must close its one retained snapshot"
        );
        for forbidden_surface in [
            "NativeBlockExecutionV0::try_new",
            "internal_operation(",
            "match_finished_core_authorized_regular_runtime_commitments_v0(",
            "ExecutionOutcomeV0",
            "PayloadValidationResult",
            "Input::",
            "into_core_input",
            "Core::step",
            "core.step(",
            "persist_transition(",
            ".apply(",
        ] {
            assert!(
                !complete_plan_body.contains(forbidden_surface),
                "complete-body planner gained forbidden authority: {forbidden_surface}"
            );
        }
        let complete_provenance_offset = implementation_source
            .find("fn validate_finished_complete_body_item_provenance_v0(")
            .expect("complete-body item provenance rebind");
        let complete_comparator_offset = implementation_source
            .find("fn match_finished_core_authorized_regular_complete_body_commitments_v0(")
            .expect("production consuming mixed-body comparator");
        let complete_classifier_offset = implementation_source
            .find("fn classify_core_authorized_regular_complete_body_commitment_comparison_v0(")
            .expect("production owning mixed-body classifier");
        let complete_invalid_bridge_offset = implementation_source
            .find("fn prepare_durable_invalid_complete_body_v0(")
            .expect("production owning deterministic-invalid durable bridge");
        let production_comparator_offset = implementation_source
            .find("fn match_finished_core_authorized_regular_runtime_commitments_v0(")
            .expect("production consuming four-root comparator");
        assert!(complete_plan_offset < complete_provenance_offset);
        assert!(complete_provenance_offset < complete_comparator_offset);
        assert!(complete_comparator_offset < complete_classifier_offset);
        assert!(complete_classifier_offset < complete_invalid_bridge_offset);
        assert!(complete_invalid_bridge_offset < production_comparator_offset);

        let complete_comparator_signature_end = implementation_source[complete_comparator_offset..]
            .find(" {\n")
            .map(|offset| complete_comparator_offset + offset)
            .expect("mixed-body comparator signature end");
        let complete_comparator_signature =
            &implementation_source[complete_comparator_offset..complete_comparator_signature_end];
        assert!(complete_comparator_signature
            .contains("finished: FinishedPlannedCoreAuthorizedRegularCompleteBodyV0"));
        assert!(complete_comparator_signature
            .contains("MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0"));
        assert!(complete_comparator_signature
            .contains("Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>"));
        for forbidden_parameter in [
            "header:",
            "body:",
            "plan:",
            "root:",
            "receipts:",
            "validator_set:",
            "parameters:",
            "verifier:",
            "native_execution:",
            "route:",
            "validation_id:",
        ] {
            assert!(
                !complete_comparator_signature.contains(forbidden_parameter),
                "mixed-body comparator gained detached caller input: {forbidden_parameter}"
            );
        }
        let complete_comparator_surface =
            &implementation_source[complete_provenance_offset..production_comparator_offset];
        assert_eq!(
            complete_comparator_surface
                .matches("NativeBlockExecutionV0::try_new(")
                .count(),
            1,
            "mixed-body comparator must build one body-wide receipt execution"
        );
        assert_eq!(
            complete_comparator_surface
                .matches("NativeTransactionReceiptFactsV0::internal_operation()")
                .count(),
            1,
            "all non-runtime items must share the one frozen empty-receipt constructor"
        );
        assert_eq!(
            complete_comparator_surface
                .matches(".verify_seal_v0(&finished.post_state_update_seal)")
                .count(),
            1,
            "mixed-body comparator must verify its one retained plan seal"
        );
        assert_eq!(
            complete_comparator_surface
                .matches(".validate_ordinary_commitments(")
                .count(),
            1,
            "mixed-body comparator must run one static commitment kernel"
        );
        assert_eq!(
            complete_comparator_surface.matches(".windows(2)").count(),
            2,
            "runtime and non-runtime provenance vectors must both remain strictly ordered"
        );
        for required_surface in [
            "CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyProvenance",
            "authorized.header.id() != authorized.validation_id.block_id()",
            "rebuild_finished_runtime_receipt_changes_v0(",
            "planned_auth_update_matches_writes_v0(&finished.post_state_update, &writes)",
            "validate_unique_complete_body_auth_writes_v0(&writes)",
            "plan.binds_exact_operations_v0(&poco_raws)",
            "NativeTransactionReceiptFactsV0::try_from_runtime_receipt(",
            "&StrictEd25519Verifier",
        ] {
            assert!(
                complete_comparator_surface.contains(required_surface),
                "mixed-body comparator lost required binding: {required_surface}"
            );
        }
        for forbidden_surface in [
            "plan_exact_next_auth_update_v0",
            ".seal_v0()",
            "snapshot.finish()",
            "FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0",
            "MatchedCoreAuthorizedRegularRuntimeCommitmentsV0",
            "match_finished_core_authorized_regular_runtime_commitments_v0(",
            "ExecutionOutcomeV0",
            "PayloadValidationResult",
            "Input::",
            "into_core_input",
            "Core::step",
            "core.step(",
            "persist_transition(",
            ".apply(",
        ] {
            assert!(
                !complete_comparator_surface.contains(forbidden_surface),
                "mixed-body comparator gained forbidden authority: {forbidden_surface}"
            );
        }
        let complete_comparator_body =
            &implementation_source[complete_comparator_offset..complete_classifier_offset];
        let provenance_offset = complete_comparator_body
            .find("validate_finished_complete_body_item_provenance_v0(&finished)")
            .expect("mixed item provenance gate");
        let state_source_offset = complete_comparator_body
            .find("rebuild_finished_complete_body_auth_writes_v0(&finished)")
            .expect("mixed final-state source rebind");
        let plan_seal_offset = complete_comparator_body
            .find(".verify_seal_v0(&finished.post_state_update_seal)")
            .expect("mixed plan seal invariant");
        let receipt_execution_offset = complete_comparator_body
            .find("rebuild_finished_complete_body_native_execution_v0(&finished)")
            .expect("mixed receipt execution rebuild");
        let static_commitment_offset = complete_comparator_body
            .find("let computed_header = BlockHeader::new(")
            .expect("mixed static commitment rebuild");
        let block_identity_offset = complete_comparator_body
            .find("if validated_commitments.block_id() != computed_header.id()")
            .expect("mixed BlockId invariant");
        let state_mismatch_offset = complete_comparator_body
            .find("if header.state_root() != post_state_root")
            .expect("mixed state mismatch");
        let receipts_mismatch_offset = complete_comparator_body
            .find("if header.receipts_root() != receipts_root")
            .expect("mixed receipts mismatch");
        assert!(provenance_offset < state_source_offset);
        assert!(state_source_offset < plan_seal_offset);
        assert!(plan_seal_offset < receipt_execution_offset);
        assert!(receipt_execution_offset < static_commitment_offset);
        assert!(static_commitment_offset < block_identity_offset);
        assert!(block_identity_offset < state_mismatch_offset);
        assert!(state_mismatch_offset < receipts_mismatch_offset);

        let complete_classifier_signature_end = implementation_source[complete_classifier_offset..]
            .find(" {\n")
            .map(|offset| complete_classifier_offset + offset)
            .expect("mixed-body classifier signature end");
        let complete_classifier_signature =
            &implementation_source[complete_classifier_offset..complete_classifier_signature_end];
        assert!(complete_classifier_signature.contains("comparison: std::result::Result<"));
        for forbidden_parameter in [
            "cause:",
            "root:",
            "generation:",
            "validation_id:",
            "finished:",
            "header:",
            "body:",
            "plan:",
        ] {
            assert!(
                !complete_classifier_signature.contains(forbidden_parameter),
                "mixed-body classifier gained detached input: {forbidden_parameter}"
            );
        }
        let complete_disposition_enum = implementation_source
            .split_once("enum ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0 {")
            .expect("mixed-body disposition enum")
            .1
            .split_once("}\n")
            .expect("mixed-body disposition enum end")
            .0;
        for required_variant in [
            "Valid(Box<MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0>)",
            "DeterministicallyInvalid(",
            "DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            "InvariantFault(Box<FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0>)",
        ] {
            assert!(complete_disposition_enum.contains(required_variant));
        }
        assert!(!complete_disposition_enum.contains("Unavailable"));

        let complete_invalid_bridge_signature_end = implementation_source
            [complete_invalid_bridge_offset..]
            .find(" {\n")
            .map(|offset| complete_invalid_bridge_offset + offset)
            .expect("deterministic-invalid durable bridge signature end");
        let complete_invalid_bridge_signature = &implementation_source
            [complete_invalid_bridge_offset..complete_invalid_bridge_signature_end];
        assert!(complete_invalid_bridge_signature.contains(
            "owner: DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0"
        ));
        assert!(complete_invalid_bridge_signature.contains("Result<PreparedDurableInvalidV0,"));
        for forbidden_parameter in [
            "ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            "MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            "FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0",
            "cause:",
            "reason:",
            "reservation:",
            "route:",
            "validation_id:",
        ] {
            assert!(
                !complete_invalid_bridge_signature.contains(forbidden_parameter),
                "durable-invalid bridge gained detached input: {forbidden_parameter}"
            );
        }
        let complete_invalid_bridge_body =
            &implementation_source[complete_invalid_bridge_offset..production_comparator_offset];
        for required_binding in [
            "CoreAuthorizedRegularComputedRootMismatchV0::State",
            "DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch",
            "CoreAuthorizedRegularComputedRootMismatchV0::Receipts",
            "DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch",
            "CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(_)",
            "CoreAuthorizedRegularReservationV0::Durable(reservation)",
            "CoreAuthorizedRegularReservationV0::TestOnly",
            "reservation.route() != authorized.route",
            "reservation.validation_id() != authorized.validation_id",
        ] {
            assert!(
                complete_invalid_bridge_body.contains(required_binding),
                "durable-invalid bridge lost required owner binding: {required_binding}"
            );
        }
        for forbidden_surface in [
            "PayloadValidationResult",
            "Input::",
            "Core::step",
            "core.step(",
            "persist_transition(",
            "seal_evaluated_and_enqueue",
        ] {
            assert!(
                !complete_invalid_bridge_body.contains(forbidden_surface),
                "durable-invalid bridge crossed a later authority: {forbidden_surface}"
            );
        }
        let prepared_invalid_declaration_offset = implementation_source
            .find("pub(super) struct PreparedDurableInvalidV0 {")
            .expect("opaque prepared durable-invalid capability");
        let prepared_invalid_declaration = implementation_source
            [prepared_invalid_declaration_offset..]
            .split_once("pub(super) struct PreparedDurableInvalidV0 {")
            .expect("prepared durable-invalid declaration body")
            .1
            .split_once("}\n")
            .expect("prepared durable-invalid capability end")
            .0;
        assert!(prepared_invalid_declaration
            .contains("reservation: NativeValidationReservationTokenV0"));
        assert!(
            prepared_invalid_declaration.contains("reason: DurableDeterministicInvalidReasonV0")
        );
        assert!(!prepared_invalid_declaration.contains("pub "));
        for forbidden_constructor in [
            "impl From<",
            "impl TryFrom<",
            "fn new(",
            "fn from_parts",
            "fn from_reason",
        ] {
            assert!(
                !implementation_source
                    [prepared_invalid_declaration_offset..complete_invalid_bridge_offset]
                    .contains(forbidden_constructor),
                "prepared durable-invalid authority gained detached construction: {forbidden_constructor}"
            );
        }
        let production_source = implementation_source;
        for forbidden_capability_surface in [
            "impl Clone for PreparedDurableInvalidV0",
            "impl Serialize for PreparedDurableInvalidV0",
            "impl serde::Serialize for PreparedDurableInvalidV0",
            "impl Deserialize for PreparedDurableInvalidV0",
            "impl serde::Deserialize for PreparedDurableInvalidV0",
            "impl From<PreparedDurableInvalidV0",
            "impl TryFrom<PreparedDurableInvalidV0",
        ] {
            assert!(
                !production_source.contains(forbidden_capability_surface),
                "prepared durable-invalid authority became reconstructible: {forbidden_capability_surface}"
            );
        }

        let production_comparator_signature_end = implementation_source
            [production_comparator_offset..]
            .find(" {\n")
            .map(|offset| production_comparator_offset + offset)
            .expect("production four-root comparator signature end");
        let production_comparator_signature = &implementation_source
            [production_comparator_offset..production_comparator_signature_end];
        assert!(production_comparator_signature
            .contains("finished: FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0"));
        assert!(!production_comparator_signature.contains("<V"));
        for forbidden_parameter in [
            "header:",
            "body:",
            "plan:",
            "root:",
            "receipts:",
            "validator_set:",
            "parameters:",
            "verifier:",
            "native_execution:",
            "matched:",
        ] {
            assert!(
                !production_comparator_signature.contains(forbidden_parameter),
                "production four-root comparator gained caller input: {forbidden_parameter}"
            );
        }
        assert!(implementation_source[production_comparator_offset..]
            .contains("&StrictEd25519Verifier"));
        let production_comparator_body = &implementation_source[production_comparator_offset..];
        let disposition_offset = implementation_source
            .find("fn classify_core_authorized_regular_runtime_commitment_comparison_v0(")
            .expect("owning comparator disposition classifier");
        let disposition_signature_end = implementation_source[disposition_offset..]
            .find(" {\n")
            .map(|offset| disposition_offset + offset)
            .expect("owning comparator disposition signature end");
        let disposition_signature =
            &implementation_source[disposition_offset..disposition_signature_end];
        assert!(disposition_signature.contains("comparison: std::result::Result<"));
        for forbidden_parameter in [
            "cause:",
            "root:",
            "generation:",
            "validation_id:",
            "commitments:",
            "finished:",
            "header:",
            "body:",
            "plan:",
        ] {
            assert!(
                !disposition_signature.contains(forbidden_parameter),
                "owning disposition classifier gained detached input: {forbidden_parameter}"
            );
        }
        let disposition_enum = implementation_source
            .split_once("enum ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 {")
            .expect("owning comparator disposition enum")
            .1
            .split_once("}\n")
            .expect("owning comparator disposition enum end")
            .0;
        for required_variant in [
            "Valid(Box<MatchedCoreAuthorizedRegularRuntimeCommitmentsV0>)",
            "DeterministicallyInvalid(Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>)",
            "InvariantFault(Box<FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0>)",
        ] {
            assert!(disposition_enum.contains(required_variant));
        }
        assert!(!disposition_enum.contains("Unavailable"));
        let mismatch_enum = implementation_source
            .split_once("enum CoreAuthorizedRegularComputedRootMismatchV0 {")
            .expect("computed-root mismatch enum")
            .1
            .split_once("}\n")
            .expect("computed-root mismatch enum end")
            .0;
        assert!(mismatch_enum.contains("State,"));
        assert!(mismatch_enum.contains("Receipts,"));
        assert!(!mismatch_enum.contains("Payload"));
        assert!(!mismatch_enum.contains("Evidence"));
        for required_invariant in [
            "rebuild_finished_runtime_receipt_changes_v0(",
            "planned_auth_update_matches_runtime_changes_v0(",
            ".verify_seal_v0(&finished.post_state_update_seal)",
            "CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal",
            "CoreAuthorizedRegularCommitmentInvariantV0::PayloadRootComputation",
            "CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedPayloadRootDrift",
            "CoreAuthorizedRegularCommitmentInvariantV0::ReceiptsRootComputation",
            "CoreAuthorizedRegularCommitmentInvariantV0::EvidenceRootComputation",
            "CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedEvidenceRootDrift",
            "CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation",
            "CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity",
            "CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(",
        ] {
            assert!(
                production_comparator_body.contains(required_invariant),
                "production comparator lost required invariant: {required_invariant}"
            );
        }
        let plan_seal_verify_offset = production_comparator_body
            .find(".verify_seal_v0(&finished.post_state_update_seal)")
            .expect("complete JMT plan seal verification");
        let state_mismatch_offset = production_comparator_body
            .find("if header.state_root() != post_state_root")
            .expect("state-root mismatch classification");
        let receipts_mismatch_offset = production_comparator_body
            .find("if header.receipts_root() != receipts_root")
            .expect("receipts-root mismatch classification");
        let planned_root_read_offset = production_comparator_body
            .find(
                "let post_state_root = StateRoot::new(finished.post_state_update.root_hash.into())",
            )
            .expect("sealed planned root read");
        let static_revalidation_offset = production_comparator_body
            .find("let computed_header = BlockHeader::new(")
            .expect("static commitment revalidation");
        let block_identity_offset = production_comparator_body
            .find("if validated_commitments.block_id() != computed_header.id()")
            .expect("BlockId invariant gate");
        assert!(plan_seal_verify_offset < planned_root_read_offset);
        assert!(planned_root_read_offset < static_revalidation_offset);
        assert!(static_revalidation_offset < block_identity_offset);
        assert!(block_identity_offset < state_mismatch_offset);
        assert!(state_mismatch_offset < receipts_mismatch_offset);
        for forbidden_alternate in [
            "fn skip_core_authorized",
            "fn advance_core_authorized_regular",
            "fn resume_core_authorized",
            "fn retry_core_authorized",
        ] {
            assert!(!implementation_source.contains(forbidden_alternate));
        }
        assert_eq!(
            implementation_source
                .matches("fn advance_core_authorized_non_runtime_success_v0(")
                .count(),
            1,
            "non-runtime cursor advance must have one consuming implementation"
        );
        assert!(implementation_source
            .contains("pub(super) fn from_app_core(core: &'a crate::AppCore) -> Option<Self>"));
        assert!(!implementation_source.contains("fn new_native_validation_host_v0("));
        assert!(!implementation_source.contains("NativeValidationHostV0::new("));
        assert!(!implementation_source.contains("fn authorize_core_exact_regular_body_v0("));
        assert!(!implementation_source
            .contains("request: PayloadValidationRequest,\n    validator_set:"));
        assert!(
            !implementation_source.contains("request: PayloadValidationRequest,\n    parameters:")
        );
        assert!(implementation_source.contains("let validation_id = owner.request.id();"));
        assert!(implementation_source.contains("let block = owner.request.block();"));
        assert!(implementation_source.contains("let parent = owner.request.parent();"));
        assert!(implementation_source
            .contains("let (route, validation_id, block, _parent) = request.into_parts();"));
        assert!(implementation_source.contains(
            "struct CoreAuthorizedExactRegularBodyV0 {\n    reservation: CoreAuthorizedRegularReservationV0,\n    route: PayloadValidationRouteV0,"
        ));
        assert!(implementation_source
            .contains(".begin_authenticated_runtime_read_snapshot_for_core_parent_v0(parent)"));
        assert!(implementation_source.contains(
            "let projection = snapshot.load_authenticated_production_poco_projection_v0()?;"
        ));
        assert!(implementation_source
            .contains("snapshot.load_authenticated_validator_lifecycle_v0()?;"));
        assert!(!implementation_source.contains(".production_poco_projection("));
        assert!(!implementation_source.contains(".plan_block("));
        assert!(!implementation_source.contains(".apply_tx("));
        assert!(!implementation_source.contains(".persist_transition("));
        assert!(!implementation_source.contains("authorize_native_checkpoint_execution_v0("));
        assert!(!implementation_source.contains("valid_after_matching_roots_v0("));
        assert!(!implementation_source.contains("classify_computed_root_mismatch_v0("));
        let core_model_source = include_str!("../../trnm-consensus-core/src/model.rs");
        let core_implementation_source = include_str!("../../trnm-consensus-core/src/core.rs");
        fn item_prelude<'a>(source: &'a str, declaration: &str) -> &'a str {
            let declaration_offset = source.find(declaration).expect("item declaration");
            let previous_item_end = source[..declaration_offset]
                .rfind("\n}\n")
                .map_or(0, |offset| offset + 3);
            let previous_blank_end = source[..declaration_offset]
                .rfind("\n\n")
                .map_or(0, |offset| offset + 2);
            let item_start = previous_item_end.max(previous_blank_end);
            &source[item_start..declaration_offset]
        }
        fn item_attribute_lines<'a>(source: &'a str, declaration: &str) -> Vec<&'a str> {
            item_prelude(source, declaration)
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("#["))
                .collect()
        }
        fn item_attribute_source(source: &str, declaration: &str) -> String {
            let mut attributes = String::new();
            let mut bracket_depth = 0_i32;
            for line in item_prelude(source, declaration).lines() {
                let line = line.trim();
                if bracket_depth == 0 && !line.starts_with("#[") {
                    continue;
                }
                attributes.push_str(line);
                attributes.push('\n');
                bracket_depth += line.matches('[').count() as i32;
                bracket_depth -= line.matches(']').count() as i32;
                assert!(bracket_depth >= 0, "malformed item attribute surface");
            }
            assert_eq!(bracket_depth, 0, "unterminated item attribute surface");
            attributes
        }
        assert_eq!(
            core_implementation_source
                .matches("PayloadValidationRequest::new(")
                .count(),
            1,
            "Core gained a second request materialization site"
        );
        assert!(core_model_source.contains(
            "pub(crate) fn new(\n        route: PayloadValidationRouteV0,\n        id: ValidationId,"
        ));
        assert!(
            !core_model_source.contains("pub fn new(\n        route: PayloadValidationRouteV0,")
        );
        assert!(core_model_source.contains("route: PayloadValidationRouteV0,"));
        assert!(core_model_source.contains("pub const fn route(&self) -> PayloadValidationRouteV0"));
        assert_eq!(
            core_model_source
                .matches("pub const fn route(&self) -> PayloadValidationRouteV0")
                .count(),
            5,
            "raw, claimed, duplicate, durable-obligation, and durable-completion surfaces must retain Core-bound route"
        );
        assert_eq!(
            item_attribute_lines(core_model_source, "pub enum PayloadValidationRouteV0 {"),
            ["#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]"],
            "process-local route gained a derive or attribute surface"
        );
        assert!(
            item_attribute_lines(core_model_source, "pub struct PayloadValidationRequest {")
                .is_empty(),
            "raw Core request gained a derive or attribute reconstruction surface"
        );
        let route_body = core_model_source
            .split_once("pub enum PayloadValidationRouteV0 {")
            .expect("Core-bound validation route declaration")
            .1
            .split_once("}\n")
            .expect("Core-bound validation route end")
            .0;
        assert_eq!(route_body.trim(), "Proposal,\n    Synced,");
        let request_body = core_model_source
            .split_once("pub struct PayloadValidationRequest {")
            .expect("raw Core request declaration")
            .1
            .split_once("}\n")
            .expect("raw Core request declaration end")
            .0;
        assert_eq!(
            request_body.trim(),
            "route: PayloadValidationRouteV0,\n    id: ValidationId,\n    block: Block,\n    parent: PayloadValidationParentV0,\n    claimed: Arc<AtomicBool>,"
        );
        for forbidden_route_surface in [
            "Serialize for PayloadValidationRouteV0",
            "Deserialize for PayloadValidationRouteV0",
            "BorshSerialize for PayloadValidationRouteV0",
            "BorshDeserialize for PayloadValidationRouteV0",
        ] {
            assert!(!core_model_source.contains(forbidden_route_surface));
        }
        let direct_registration_body = core_implementation_source
            .split_once("fn register_validation(")
            .expect("direct validation registration")
            .1
            .split_once("\n    fn payload_validation_completion(")
            .expect("direct validation registration end")
            .0;
        assert!(direct_registration_body.contains(
            "self.insert_payload_validation_obligation(\n            PayloadValidationRouteV0::Proposal,"
        ));
        assert!(!direct_registration_body.contains("PayloadValidationRouteV0::Synced"));
        let synced_registration_body = core_implementation_source
            .split_once("fn register_sync_validation(")
            .expect("synced validation registration")
            .1
            .split_once("\n    fn next_validation_id(")
            .expect("synced validation registration end")
            .0;
        assert!(synced_registration_body.contains(
            "self.insert_payload_validation_obligation(PayloadValidationRouteV0::Synced,"
        ));
        assert!(!synced_registration_body.contains("PayloadValidationRouteV0::Proposal"));
        assert!(core_model_source.contains("pub const SAFETY_STATE_SCHEMA_VERSION: u16 = 6;"));
        assert_eq!(
            item_attribute_lines(
                core_model_source,
                "pub struct DurablePayloadValidationObligationV0 {"
            ),
            ["#[derive(Debug, Clone, PartialEq, Eq)]"],
            "durable obligation gained an unreviewed derive or attribute surface"
        );
        let durable_obligation_body = core_model_source
            .split_once("pub struct DurablePayloadValidationObligationV0 {")
            .expect("durable validation obligation declaration")
            .1
            .split_once("}\n")
            .expect("durable validation obligation declaration end")
            .0;
        assert_eq!(
            durable_obligation_body.trim(),
            "route: PayloadValidationRouteV0,\n    id: ValidationId,\n    proposal: SignedProposalV0,\n    parent: PayloadValidationParentV0,\n    first_recorded_revision: u64,"
        );
        assert!(core_model_source.contains(
            "pub(crate) fn new(\n        route: PayloadValidationRouteV0,\n        id: ValidationId,\n        proposal: SignedProposalV0,\n        parent: PayloadValidationParentV0,\n        first_recorded_revision: u64,"
        ));
        assert!(!core_model_source.contains(
            "pub fn new(\n        route: PayloadValidationRouteV0,\n        id: ValidationId,\n        proposal: SignedProposalV0,"
        ));
        assert_eq!(
            item_attribute_lines(
                core_model_source,
                "pub struct DurablePayloadValidationCompletionV0 {"
            ),
            ["#[derive(Debug, Clone, PartialEq, Eq)]"],
            "durable completion gained an unreviewed derive or attribute surface"
        );
        let durable_completion_body = core_model_source
            .split_once("pub struct DurablePayloadValidationCompletionV0 {")
            .expect("durable validation completion declaration")
            .1
            .split_once("}\n")
            .expect("durable validation completion declaration end")
            .0;
        assert_eq!(
            durable_completion_body.trim(),
            "route: PayloadValidationRouteV0,\n    id: ValidationId,\n    result: PayloadValidationResult,\n    first_recorded_revision: u64,"
        );
        assert!(core_model_source.contains(
            "pub(crate) const fn new(\n        route: PayloadValidationRouteV0,\n        id: ValidationId,\n        result: PayloadValidationResult,\n        first_recorded_revision: u64,"
        ));
        assert!(!core_model_source.contains(
            "pub const fn new(\n        route: PayloadValidationRouteV0,\n        id: ValidationId,\n        result: PayloadValidationResult,"
        ));
        assert!(!core_implementation_source.contains("resolved_validations"));
        assert!(core_implementation_source.contains(
            "payload_validation_obligations()\n            .len()\n            .checked_add(self.safety.payload_validation_completions().len())"
        ));
        assert!(core_implementation_source
            .contains("self.safety.set_payload_validation_completions(completions);"));
        assert!(core_implementation_source.contains(
            "durable payload validation completion was removed without an acknowledged outbox retirement"
        ));
        let obligation_insert_body = core_implementation_source
            .split_once("fn insert_payload_validation_obligation(")
            .expect("durable validation obligation insertion")
            .1
            .split_once("\n    /// Computes one deterministic, process-local resource weight")
            .expect("durable validation obligation insertion end")
            .0;
        let aggregate_bound_offset = obligation_insert_body
            .find("let aggregate_resource_size = obligations")
            .expect("aggregate durable obligation resource bound");
        let obligation_commit_offset = obligation_insert_body
            .find("self.safety.set_payload_validation_obligations(obligations);")
            .expect("durable obligation commit");
        assert!(aggregate_bound_offset < obligation_commit_offset);
        assert!(obligation_insert_body.contains("max_consensus_message_bytes() as usize"));
        let recovery_body = core_implementation_source
            .split_once("pub fn recover<V: SignatureVerifier>(")
            .expect("Core recovery")
            .1
            .split_once("\n    pub const fn config(&self)")
            .expect("Core recovery end")
            .0;
        let recovery_validation_offset = recovery_body
            .find("value.validate_runtime(verifier, true)?;")
            .expect("durable recovery validation");
        let nonempty_fail_closed_offset = recovery_body
            .find("if !value.safety.payload_validation_obligations().is_empty()")
            .expect("nonempty durable obligation fail-closed gate");
        assert!(recovery_validation_offset < nonempty_fail_closed_offset);
        assert!(recovery_body.contains("authenticated replay ticket before recovery can reissue"));
        assert!(core_model_source
            .contains("pub(crate) fn from_exact_header(header: BlockHeader) -> Self"));
        assert!(
            !core_model_source.contains("pub fn from_exact_header(header: BlockHeader) -> Self")
        );
        assert!(core_model_source.contains("pub fn try_claim("));
        assert!(core_model_source.contains("Arc::clone(&self.claimed)"));
        assert!(core_model_source.contains("compare_exchange("));
        let request_clone = core_model_source
            .split_once("impl Clone for PayloadValidationRequest {")
            .expect("manual request clone sharing one claim gate")
            .1
            .split_once("}\n")
            .expect("manual request clone end")
            .0;
        assert!(request_clone.contains("Arc::clone(&self.claimed)"));
        assert!(!request_clone.contains("AtomicBool::new"));
        assert!(request_clone.contains("route: self.route"));
        let request_debug = core_model_source
            .split_once("impl fmt::Debug for PayloadValidationRequest {")
            .expect("manual request debug implementation")
            .1
            .split_once("impl Clone for PayloadValidationRequest")
            .expect("manual request debug implementation end")
            .0;
        assert!(!request_debug.contains("claimed"));
        assert!(request_debug.contains(".field(\"route\", &self.route)"));
        let request_equality = core_model_source
            .split_once("impl PartialEq for PayloadValidationRequest {")
            .expect("manual request equality implementation")
            .1
            .split_once("impl Eq for PayloadValidationRequest")
            .expect("manual request equality implementation end")
            .0;
        assert!(!request_equality.contains("claimed"));
        assert!(request_equality.contains("self.route == other.route"));
        assert!(!core_model_source.contains("pub fn try_claim_validation_id"));
        assert!(!core_model_source.contains("pub fn reclaim"));
        let raw_request_impl = core_model_source
            .split_once("impl PayloadValidationRequest {")
            .expect("raw Core request implementation")
            .1
            .split_once("impl fmt::Debug for PayloadValidationRequest")
            .expect("raw Core request implementation end")
            .0;
        assert!(!raw_request_impl.contains("into_parts"));
        let raw_public_functions = raw_request_impl
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub") && line.contains("fn "))
            .collect::<Vec<_>>();
        assert_eq!(
            raw_public_functions,
            [
                "pub(crate) fn new(",
                "pub const fn route(&self) -> PayloadValidationRouteV0 {",
                "pub const fn id(&self) -> ValidationId {",
                "pub const fn block(&self) -> &Block {",
                "pub const fn parent(&self) -> &PayloadValidationParentV0 {",
                "pub fn try_claim(",
            ],
            "raw Core request method surface changed"
        );
        assert_eq!(
            raw_request_impl
                .matches("route: PayloadValidationRouteV0")
                .count(),
            1,
            "raw Core request gained an alternate route input"
        );
        assert_eq!(
            raw_request_impl
                .matches("-> PayloadValidationRouteV0")
                .count(),
            1,
            "raw Core request gained an alternate route extractor"
        );
        assert!(!raw_request_impl.contains("&mut self"));
        let try_claim_body = raw_request_impl
            .split_once("pub fn try_claim(")
            .expect("raw Core request claim method")
            .1;
        assert!(!try_claim_body.contains("self.route"));
        assert!(!try_claim_body.contains("PayloadValidationRouteV0"));
        assert!(!try_claim_body.contains("route:"));
        for forbidden in [
            "impl Drop for PayloadValidationRequest",
            "impl Serialize for PayloadValidationRequest",
            "impl serde::Serialize for PayloadValidationRequest",
            "impl Deserialize for PayloadValidationRequest",
            "impl serde::Deserialize for PayloadValidationRequest",
            "impl BorshSerialize for PayloadValidationRequest",
            "impl BorshDeserialize for PayloadValidationRequest",
            "impl From<PayloadValidationRequest",
            "impl TryFrom<PayloadValidationRequest",
        ] {
            assert!(
                !core_model_source.contains(forbidden),
                "raw Core request gained a forbidden claim-bypass surface: {forbidden}"
            );
        }
        for capability in [
            "ClaimedPayloadValidationRequestV0",
            "DuplicatePayloadValidationRequestV0",
        ] {
            let declaration = format!("pub struct {capability} {{");
            let attributes = item_attribute_source(core_model_source, &declaration);
            assert!(
                !["derive(", "serde::", "#[serde", "borsh::", "Borsh"]
                    .iter()
                    .any(|forbidden| attributes.contains(forbidden)),
                "Core one-shot carrier gained a reconstruction attribute: {capability}"
            );
            for forbidden in [
                format!("impl Clone for {capability}"),
                format!("impl Serialize for {capability}"),
                format!("impl serde::Serialize for {capability}"),
                format!("impl Deserialize for {capability}"),
                format!("impl serde::Deserialize for {capability}"),
                format!("impl BorshSerialize for {capability}"),
                format!("impl BorshDeserialize for {capability}"),
                format!("impl Drop for {capability}"),
                format!("impl From<{capability}"),
                format!("impl TryFrom<{capability}"),
            ] {
                assert!(
                    !core_model_source.contains(&forbidden),
                    "Core one-shot carrier gained a forbidden surface: {forbidden}"
                );
            }
        }
        let duplicate_request_impl = core_model_source
            .split_once("impl DuplicatePayloadValidationRequestV0 {")
            .expect("duplicate Core request implementation")
            .1
            .split_once("#[derive(Debug, Clone, PartialEq, Eq)]\npub enum Effect")
            .expect("duplicate Core request implementation end")
            .0;
        assert!(!duplicate_request_impl.contains("into_parts"));
        assert!(!duplicate_request_impl.contains("try_claim"));

        for capability in [
            "CoreAuthorizedExactRegularBodyV0",
            "NativeValidationHostV0<'a>",
            "NativeSignerPolicyBindingV0",
            "SnapshotAuthenticatedRegularContextV0",
            "OpenCoreAuthorizedRegularValidationV0",
            "ClaimedCoreIssuedRegularValidationOwnerV0",
            "CoreIssuedRegularValidationOwnerV0",
            "DurablyExistingCoreIssuedRegularValidationOwnerV0",
            "CoreIssuedRegularValidationJobV0",
            "CoreRegularValidationEffectRouteInvariantV0",
            "DuplicateCoreIssuedRegularValidationOwnerV0",
            "FailedCoreIssuedRegularValidationReservationV0",
            "FailedCoreIssuedRegularValidationOpenV0",
            "PendingCoreIssuedRegularValidationOpenFailureV0",
            "FinishedCoreAuthorizedRegularValidationV0",
            "ClosedFailedCoreAuthorizedRegularValidationV0",
            "OpenCoreAuthorizedRegularTransactionCursorV0",
            "CoreAuthorizedRegularPocoPrefixV0",
            "CoreAuthorizedRegularValidatorPrefixV0",
            "ExactRuntimeExecutionContextV0",
            "DecodedCoreAuthorizedRuntimeTransactionV0",
            "DecodedCoreAuthorizedNonRuntimePayloadV0",
            "PreparedCoreAuthorizedRuntimeTransactionV0",
            "CoreAuthorizedNonRuntimePayloadRoutingV0",
            "CoreAuthorizedPocoApplicationPayloadV0",
            "CoreAuthorizedValidatorTransitionPayloadV0",
            "CoreAuthorizedUnsupportedNonRuntimePayloadV0",
            "DecodedCoreAuthorizedPocoApplicationPayloadV0",
            "DecodedCoreAuthorizedValidatorTransitionPayloadV0",
            "ClosedCoreAuthorizedNonRuntimePayloadOwnerV0",
            "AuthorizedCorePocoApplicationAttemptV0",
            "AuthorizedCoreValidatorTransitionAttemptV0",
            "OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0",
            "OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0",
            "AppliedCoreAuthorizedRuntimeTransactionV0",
            "FinishedPlannedCoreAuthorizedRegularCompleteBodyV0",
            "MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            "FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0",
            "FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0",
            "MatchedCoreAuthorizedRegularRuntimeCommitmentsV0",
            "FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0",
            "CoreAuthorizedRegularRuntimeStateViewV0<'a>",
            "FailedCoreAuthorizedRegularTransactionDecodeV0",
            "ClosedFailedCoreAuthorizedRegularTransactionDecodeV0",
            "FailedCoreAuthorizedRegularRuntimeAttemptV0",
            "ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0",
            "ClosedFailedCoreAuthorizedRegularPostStatePlanV0",
            "ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0",
        ] {
            let declaration = format!("struct {capability} {{");
            let attributes = item_attribute_source(implementation_source, &declaration);
            assert!(
                !["derive(", "serde::", "#[serde", "borsh::", "Borsh"]
                    .iter()
                    .any(|forbidden| attributes.contains(forbidden)),
                "authenticated parent capability gained a reconstruction attribute: {capability}"
            );
            assert!(
                !implementation_source.contains(&format!("pub struct {capability}")),
                "authenticated parent capability became public: {capability}"
            );
            for forbidden in [
                format!("impl Clone for {capability}"),
                format!("impl Serialize for {capability}"),
                format!("impl serde::Serialize for {capability}"),
                format!("impl Deserialize for {capability}"),
                format!("impl serde::Deserialize for {capability}"),
                format!("impl BorshSerialize for {capability}"),
                format!("impl BorshDeserialize for {capability}"),
                format!("impl Drop for {capability}"),
                format!("impl From<{capability}"),
                format!("impl TryFrom<{capability}"),
                "fn into_parts(self)".to_string(),
            ] {
                assert!(
                    !implementation_source.contains(&forbidden),
                    "authenticated parent capability gained a forbidden surface: {forbidden}"
                );
            }
        }

        let store_source = include_str!("store.rs");
        let reservation_decision = store_source
            .split_once("pub(super) enum NativeValidationReservationDecisionV0 {")
            .expect("durable reservation decision")
            .1
            .split_once("}\n")
            .expect("durable reservation decision end")
            .0;
        assert!(reservation_decision.contains("Reserved(NativeValidationReservationTokenV0)"));
        assert!(reservation_decision.contains("Existing(Box<DurableNativeValidationJobV0>)"));
        assert!(!store_source.contains("fn token(&self)"));
        assert!(!store_source.contains("PayloadValidationRequest"));
        assert!(store_source.contains(
            "pub(super) fn reserve_or_reopen_native_validation_job_v0(\n        &self,\n        facts: NativeValidationReservationFactsV0,"
        ));
        let reservation_transaction = store_source
            .split_once("fn reserve_or_reopen_native_validation_job_inner_v0(")
            .expect("durable reservation transaction")
            .1
            .split_once("fn connect_native_validation_job_v0(")
            .expect("durable reservation transaction end")
            .0;
        let begin_offset = reservation_transaction
            .find("transaction_with_behavior(TransactionBehavior::Immediate)")
            .expect("durable reservation BEGIN IMMEDIATE");
        let binding_offset = reservation_transaction
            .find("validate_native_validation_job_bindings_v0(&transaction, self)")
            .expect("durable reservation binding validation");
        let existing_offset = reservation_transaction
            .find("load_native_validation_job_v0(&transaction, facts.validation_id)")
            .expect("durable reservation existing-row lookup");
        let capacity_offset = reservation_transaction
            .find("read_bounded_native_validation_journal_accounting_v0(")
            .expect("constant-time bounded durable journal gate");
        let insert_offset = reservation_transaction
            .find("insert_native_validation_job_v0(&transaction, facts, self)")
            .expect("durable reservation insert");
        let commit_offset = reservation_transaction
            .find("transaction.commit()")
            .expect("durable reservation commit");
        assert!(begin_offset < binding_offset);
        assert!(binding_offset < existing_offset);
        assert!(existing_offset < capacity_offset);
        assert!(capacity_offset < insert_offset);
        assert!(insert_offset < commit_offset);
        assert!(!reservation_transaction.contains("SELECT COUNT(*) FROM validation_jobs_v0"));
        assert!(!reservation_transaction.contains("SUM("));
        assert!(reservation_transaction.contains(
            "NativeValidationReservationInnerDecisionV0::CommitUncertainExisting(existing)"
        ));
        let invalid_seal_transaction = store_source
            .split_once("fn seal_durable_invalid_and_enqueue_callback_inner_v0(")
            .expect("durable invalid seal transaction")
            .1
            .split_once("fn confirm_durable_invalid_callback_v0(")
            .expect("durable invalid seal transaction end")
            .0;
        assert!(
            !invalid_seal_transaction
                .contains("NativeValidationInvalidSealFailureCauseV0::Storage("),
            "durable invalid seal bypassed the typed nested-failure mapper"
        );
        let reserved_only_gate = store_source
            .split_once("fn read_reserved_only_native_validation_journal_accounting_v0(")
            .expect("reserved-only validation journal gate")
            .1
            .split_once("fn native_validation_runtime_profile_ref_v0(")
            .expect("reserved-only validation journal gate end")
            .0;
        assert!(reserved_only_gate
            .contains("SELECT EXISTS(SELECT 1 FROM validation_callback_outbox_v0 LIMIT 1)"));
        assert!(
            reserved_only_gate.contains("SELECT 1 FROM validation_jobs_v0 WHERE state<>0 LIMIT 1")
        );
        assert!(store_source.contains(
            "CREATE INDEX IF NOT EXISTS validation_jobs_non_reserved_v0\n        ON validation_jobs_v0(state) WHERE state<>0;"
        ));
        let startup = store_source
            .split_once("pub(super) fn load_or_migrate(&self) -> Result<AppState> {")
            .expect("application-store startup")
            .1
            .split_once("pub(super) fn load_object(")
            .expect("application-store startup end")
            .0;
        assert!(startup.contains("self.visit_native_validation_recovery_work_v0("));
        let request_semantics = store_source
            .split_once("fn validate_native_validation_request_record_semantics_v0(")
            .expect("durable request semantic rebind")
            .1
            .split_once("fn native_validation_route_code_v0(")
            .expect("durable request semantic rebind end")
            .0;
        for required in [
            "facts.parent_height.checked_add(1)",
            "target_header.genesis_hash().as_bytes()",
            "target_header.block_kind() == BlockKind::Regular",
            "target_header.block_kind() == BlockKind::EpochHandoff",
            "native_validation_reservation_fingerprint_from_record_v0(facts)",
        ] {
            assert!(request_semantics.contains(required));
        }
        let snapshot_scrub = store_source
            .split_once("pub(super) fn build_snapshot_database(")
            .expect("snapshot builder")
            .1
            .split_once("pub(super) fn pin_snapshot(")
            .expect("snapshot builder end")
            .0;
        let outbox_delete = snapshot_scrub
            .find("DELETE FROM validation_callback_outbox_v0")
            .expect("snapshot child-outbox scrub");
        let job_delete = snapshot_scrub
            .find("DELETE FROM validation_jobs_v0")
            .expect("snapshot validation-job scrub");
        assert!(outbox_delete < job_delete);
        let v6_to_v7_migration = store_source
            .split_once("fn migrate_store_schema_v6_to_v7(")
            .expect("schema-v6 to schema-v7 migration")
            .1
            .split_once("fn migrate_store_schema_v7_to_v8(")
            .expect("schema-v6 to schema-v7 migration end")
            .0;
        assert!(v6_to_v7_migration.contains("params![STORE_SCHEMA_VERSION_V7]"));
        assert!(
            !v6_to_v7_migration.contains("params![STORE_SCHEMA_VERSION]"),
            "schema-v6 migration used the moving active-version alias"
        );
        let v7_to_v8_migration = store_source
            .split_once("fn migrate_store_schema_v7_to_v8(")
            .expect("schema-v7 to schema-v8 migration")
            .1
            .split_once("fn ensure_metadata_binding(")
            .expect("schema-v7 to schema-v8 migration end")
            .0;
        assert!(v7_to_v8_migration.contains("params![STORE_SCHEMA_VERSION_V8]"));
        assert!(v7_to_v8_migration.contains("visit_native_validation_recovery_work_v0"));
        assert!(
            !v7_to_v8_migration.contains("params![STORE_SCHEMA_VERSION]"),
            "schema-v7 migration used the moving active-version alias"
        );
        let reservation_confirmation = store_source
            .split_once("fn confirm_native_validation_job_v0(")
            .expect("durable reservation commit confirmation")
            .1
            .split_once("pub(super) fn open(")
            .expect("durable reservation commit confirmation end")
            .0;
        let confirmation_binding_offset = reservation_confirmation
            .find("validate_native_validation_job_bindings_v0(&connection, self)")
            .expect("commit confirmation binding validation");
        let confirmation_load_offset = reservation_confirmation
            .find("load_native_validation_job_v0(&connection, facts.validation_id)")
            .expect("commit confirmation exact-row lookup");
        assert!(confirmation_binding_offset < confirmation_load_offset);
        let existing_impl = store_source
            .split_once("impl DurableNativeValidationJobV0 {")
            .expect("durable existing job implementation")
            .1
            .split_once("/// Whether this call created")
            .expect("durable existing job implementation end")
            .0;
        for forbidden_existing_surface in
            ["token", "retry", "takeover", "into_parts", "into_reserved"]
        {
            assert!(
                !existing_impl.contains(forbidden_existing_surface),
                "existing durable job gained evaluation surface: {forbidden_existing_surface}"
            );
        }
        for capability in [
            "NativeValidationReservationFactsV0",
            "NativeValidationReservationTokenV0",
            "DurableNativeValidationJobV0",
            "FailedNativeValidationReservationV0",
        ] {
            let declaration = format!("pub(super) struct {capability} {{");
            let attributes = item_attribute_source(store_source, &declaration);
            assert!(
                !["derive(", "serde::", "#[serde", "borsh::", "Borsh"]
                    .iter()
                    .any(|forbidden| attributes.contains(forbidden)),
                "durable reservation carrier gained reconstruction attributes: {capability}"
            );
            for forbidden in [
                format!("impl Clone for {capability}"),
                format!("impl Serialize for {capability}"),
                format!("impl serde::Serialize for {capability}"),
                format!("impl Deserialize for {capability}"),
                format!("impl serde::Deserialize for {capability}"),
                format!("impl BorshSerialize for {capability}"),
                format!("impl BorshDeserialize for {capability}"),
                format!("impl Drop for {capability}"),
                format!("impl From<{capability}"),
                format!("impl TryFrom<{capability}"),
            ] {
                assert!(
                    !store_source.contains(&forbidden),
                    "durable reservation carrier gained forbidden surface: {forbidden}"
                );
            }
        }

        let auth_tree_source = include_str!("auth_tree.rs");
        let plan_seal_declaration = "struct PlannedAuthUpdateSealV0([u8; 32]);";
        let plan_seal_attributes = item_attribute_source(auth_tree_source, plan_seal_declaration);
        assert!(!["derive(", "serde::", "#[serde", "borsh::", "Borsh"]
            .iter()
            .any(|forbidden| plan_seal_attributes.contains(forbidden)));
        assert!(!auth_tree_source.contains("pub struct PlannedAuthUpdateSealV0"));
        for forbidden_surface in [
            "impl Clone for PlannedAuthUpdateSealV0",
            "impl Serialize for PlannedAuthUpdateSealV0",
            "impl serde::Serialize for PlannedAuthUpdateSealV0",
            "impl Deserialize for PlannedAuthUpdateSealV0",
            "impl serde::Deserialize for PlannedAuthUpdateSealV0",
            "impl BorshSerialize for PlannedAuthUpdateSealV0",
            "impl BorshDeserialize for PlannedAuthUpdateSealV0",
            "impl From<PlannedAuthUpdateSealV0",
            "impl TryFrom<PlannedAuthUpdateSealV0",
            "fn as_bytes(&self)",
            "fn into_bytes(self)",
        ] {
            assert!(
                !auth_tree_source.contains(forbidden_surface),
                "complete JMT plan seal gained forbidden surface: {forbidden_surface}"
            );
        }

        for capability in [
            "DecodedCoreAuthorizedRegularPayloadV0",
            "PreparedCoreAuthorizedRegularPayloadV0",
            "CoreAuthorizedRegularReservationV0",
            "ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            "ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0",
            "CoreAuthorizedRegularValidationSessionAdmissionV0",
            "CoreIssuedRegularValidationReservationCauseV0",
            "CoreRegularValidationEffectIntakeV0",
            "DispatchedCoreAuthorizedNonRuntimePayloadV0",
            "FailedCoreAuthorizedNonRuntimeSemanticDecodeV0",
            "ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0",
            "DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0",
            "AppliedCoreAuthorizedNonRuntimePayloadV0",
            "AuthorizedCoreNonRuntimeFamilyAttemptV0",
            "FailedCoreAuthorizedNonRuntimeFamilyAttemptV0",
            "ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0",
            "OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0",
            "FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0",
            "ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0",
            "FinishedCoreAuthorizedRegularPocoWriteSourceV0",
        ] {
            let declaration = format!("enum {capability} {{");
            let attributes = item_attribute_source(implementation_source, &declaration);
            assert!(
                !["derive(", "serde::", "#[serde", "borsh::", "Borsh"]
                    .iter()
                    .any(|forbidden| attributes.contains(forbidden)),
                "authenticated payload capability gained a reconstruction attribute: {capability}"
            );
            assert!(
                !implementation_source.contains(&format!("pub enum {capability}")),
                "authenticated payload capability became public: {capability}"
            );
            for forbidden in [
                format!("impl Clone for {capability}"),
                format!("impl Serialize for {capability}"),
                format!("impl serde::Serialize for {capability}"),
                format!("impl Deserialize for {capability}"),
                format!("impl serde::Deserialize for {capability}"),
                format!("impl BorshSerialize for {capability}"),
                format!("impl BorshDeserialize for {capability}"),
                format!("impl Drop for {capability}"),
                format!("impl From<{capability}"),
                format!("impl TryFrom<{capability}"),
                "fn into_parts(self)".to_string(),
            ] {
                assert!(!implementation_source.contains(&forbidden));
            }
        }
        for cause in [
            "CoreAuthorizedRegularCompleteBodyPlanCauseV0",
            "ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0",
        ] {
            for forbidden in [
                format!("impl Clone for {cause}"),
                format!("impl Serialize for {cause}"),
                format!("impl serde::Serialize for {cause}"),
                format!("impl Deserialize for {cause}"),
                format!("impl serde::Deserialize for {cause}"),
                format!("impl BorshSerialize for {cause}"),
                format!("impl BorshDeserialize for {cause}"),
                format!("impl Drop for {cause}"),
                format!("impl From<{cause}"),
                format!("impl TryFrom<{cause}"),
            ] {
                assert!(
                    !implementation_source.contains(&forbidden),
                    "complete-body cause gained a reconstructing conversion: {forbidden}"
                );
            }
        }
        for (kind, capability) in [
            ("struct", "CoreAuthorizedRegularPocoPrefixV0"),
            ("struct", "CoreAuthorizedRegularValidatorPrefixV0"),
            (
                "struct",
                "OwnerBoundCoreAuthorizedPocoApplicationWriteSealV0",
            ),
            (
                "struct",
                "OwnerBoundCoreAuthorizedValidatorTransitionWriteSealV0",
            ),
            ("enum", "AppliedCoreAuthorizedNonRuntimePayloadV0"),
            (
                "enum",
                "OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0",
            ),
            ("enum", "FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0"),
            ("enum", "FinishedCoreAuthorizedRegularPocoWriteSourceV0"),
            ("enum", "CoreAuthorizedRegularCompleteBodyPlanCauseV0"),
            ("enum", "ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0"),
            (
                "struct",
                "FinishedPlannedCoreAuthorizedRegularCompleteBodyV0",
            ),
            (
                "struct",
                "MatchedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            ),
            (
                "struct",
                "FailedCoreAuthorizedRegularCompleteBodyCommitmentComparisonV0",
            ),
            (
                "struct",
                "DeterministicallyInvalidCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            ),
            ("struct", "FailedPrepareDurableInvalidV0"),
            (
                "enum",
                "ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0",
            ),
            (
                "struct",
                "ClosedFailedCoreAuthorizedRegularCompleteBodyPlanV0",
            ),
        ] {
            for visibility in ["pub ", "pub(crate) ", "pub(super) "] {
                assert!(
                    !implementation_source
                        .contains(&format!("{visibility}{kind} {capability}")),
                    "staged non-runtime capability gained visibility: {visibility}{kind} {capability}"
                );
            }
        }

        let session_admission = implementation_source
            .split_once("enum CoreAuthorizedRegularValidationSessionAdmissionV0 {")
            .expect("one-shot request admission enum")
            .1
            .split_once("}\n")
            .expect("one-shot request admission enum end")
            .0;
        assert!(session_admission.contains("Duplicate("));
        for forbidden in [
            "Unavailable",
            "DeterministicallyInvalid",
            "InvariantFault",
            "PayloadValidationResult",
            "ExecutionOutcomeV0",
        ] {
            assert!(
                !session_admission.contains(forbidden),
                "duplicate request admission became a validation outcome: {forbidden}"
            );
        }

        let route_intake = implementation_source
            .split_once("enum CoreRegularValidationEffectIntakeV0 {")
            .expect("route-aware Core effect intake enum")
            .1
            .split_once("}\n")
            .expect("route-aware Core effect intake enum end")
            .0;
        assert!(route_intake.contains("Job(Box<CoreIssuedRegularValidationJobV0>)"));
        assert!(route_intake
            .contains("RouteInvariant(Box<CoreRegularValidationEffectRouteInvariantV0>)"));
        assert!(route_intake.contains("Other(Box<Effect>)"));
        for forbidden in [
            "Unavailable",
            "DeterministicallyInvalid",
            "InvariantFault",
            "PayloadValidationResult",
            "ExecutionOutcomeV0",
        ] {
            assert!(
                !route_intake.contains(forbidden),
                "effect-route intake became terminal taxonomy: {forbidden}"
            );
        }
        assert!(!implementation_source.contains("synced: bool"));
        let callback_conversion = implementation_source
            .split_once("fn into_core_input(self) -> Input {")
            .expect("consuming route-bound Core callback conversion")
            .1
            .split_once("\n    }\n")
            .expect("Core callback conversion body")
            .0;
        assert!(callback_conversion.contains("Input::PayloadValidated { id, result }"));
        assert!(callback_conversion.contains("Input::SyncedPayloadValidated { id, result }"));
        assert!(callback_conversion.contains("self.outcome"));
        assert!(!callback_conversion.contains("core.step("));
        assert!(!callback_conversion.contains("persist_transition("));

        for capability in [
            "FinishedPlannedTestRegularRuntimeExecutionV0",
            "MatchedTestRegularRuntimeCommitmentsV0",
        ] {
            let declaration = format!("#[cfg(test)]\nstruct {capability} {{");
            let declaration_offset = source
                .find(&declaration)
                .unwrap_or_else(|| panic!("missing narrow test-only declaration: {capability}"));
            let attribute_window =
                &source[declaration_offset.saturating_sub(160)..declaration_offset];
            assert!(
                !attribute_window.contains("#[derive"),
                "test-only capability gained a derive surface: {capability}"
            );
            for forbidden in [
                format!("impl Clone for {capability}"),
                format!("impl Serialize for {capability}"),
                format!("impl serde::Serialize for {capability}"),
                format!("impl Deserialize for {capability}"),
                format!("impl serde::Deserialize for {capability}"),
                format!("impl BorshSerialize for {capability}"),
                format!("impl BorshDeserialize for {capability}"),
                format!("impl From<{capability}"),
                format!("impl TryFrom<{capability}"),
                format!(" for {capability} {{"),
            ] {
                assert!(
                    !source.contains(&forbidden),
                    "test-only capability gained a forbidden trait surface: {forbidden}"
                );
            }
        }
        let into_parts = ["fn into_", "parts("].concat();
        assert!(!implementation_source.contains(&into_parts));
        for authority_fragments in [
            ["Execution", "OutcomeV0"],
            ["PayloadValidation", "Result"],
            ["AuthenticatedExecution", "InputsV0"],
            ["AppliedRuntime", "AttemptV0"],
            ["NativeBlock", "ExecutionV0"],
            ["AuthorizedNativeCheckpoint", "ExecutionV0"],
            ["CoreAuthorizedValidation", "RequestV0"],
            ["RequestProcess", "Proposal"],
            ["ResponseProcess", "Proposal"],
            ["RequestFinalize", "Block"],
            ["ResponseFinalize", "Block"],
            ["Proposal", "Status"],
        ] {
            let authority = authority_fragments.concat();
            for capability in [
                "CoreAuthorizedExactRegularBodyV0",
                "NativeValidationHostV0",
                "NativeSignerPolicyBindingV0",
                "SnapshotAuthenticatedRegularContextV0",
                "OpenCoreAuthorizedRegularValidationV0",
                "ClaimedCoreIssuedRegularValidationOwnerV0",
                "CoreIssuedRegularValidationOwnerV0",
                "DurablyExistingCoreIssuedRegularValidationOwnerV0",
                "FailedCoreIssuedRegularValidationReservationV0",
                "CoreIssuedRegularValidationReservationCauseV0",
                "CoreAuthorizedRegularReservationV0",
                "FailedCoreIssuedRegularValidationOpenV0",
                "PendingCoreIssuedRegularValidationOpenFailureV0",
                "FinishedCoreAuthorizedRegularValidationV0",
                "ClosedFailedCoreAuthorizedRegularValidationV0",
                "OpenCoreAuthorizedRegularTransactionCursorV0",
                "ExactRuntimeExecutionContextV0",
                "DecodedCoreAuthorizedRuntimeTransactionV0",
                "DecodedCoreAuthorizedNonRuntimePayloadV0",
                "DecodedCoreAuthorizedRegularPayloadV0",
                "PreparedCoreAuthorizedRuntimeTransactionV0",
                "PreparedCoreAuthorizedRegularPayloadV0",
                "CoreAuthorizedNonRuntimePayloadRoutingV0",
                "AppliedCoreAuthorizedRuntimeTransactionV0",
                "FinishedPlannedCoreAuthorizedRegularRuntimeExecutionV0",
                "MatchedCoreAuthorizedRegularRuntimeCommitmentsV0",
                "FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0",
                "ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0",
                "CoreAuthorizedRegularCommitmentComparisonCauseV0",
                "CoreAuthorizedRegularComputedRootMismatchV0",
                "CoreAuthorizedRegularCommitmentInvariantV0",
                "CoreAuthorizedRegularPostStatePlanCauseV0",
                "ClosedCoreAuthorizedRegularPostStatePlanCauseV0",
                "ClosedFailedCoreAuthorizedRegularPostStatePlanV0",
                "CoreAuthorizedRegularRuntimeStateViewV0",
                "CoreAuthorizedExactRegularBodyFailureClassV0",
                "CoreAuthorizedExactRegularBodyFailureV0",
                "OpenCoreAuthorizedRegularValidationFailureV0",
                "FailedCoreAuthorizedRegularTransactionDecodeV0",
                "ClosedCoreAuthorizedRegularTransactionDecodeCauseV0",
                "ClosedFailedCoreAuthorizedRegularTransactionDecodeV0",
                "FailedCoreAuthorizedRegularRuntimeAttemptV0",
                "ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0",
                "ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0",
                "FinishedPlannedTestRegularRuntimeExecutionV0",
                "MatchedTestRegularRuntimeCommitmentsV0",
            ] {
                for forbidden_conversion in [
                    format!("impl From<{capability}> for {authority}"),
                    format!("impl TryFrom<{capability}> for {authority}"),
                    format!("impl From<{authority}> for {capability}"),
                    format!("impl TryFrom<{authority}> for {capability}"),
                ] {
                    assert!(
                        !source.contains(&forbidden_conversion),
                        "test-only post-state capability gained a forbidden authority conversion: {forbidden_conversion}"
                    );
                }
            }
            for forbidden_return in [
                format!(") -> {authority}"),
                format!(") -> Result<{authority}"),
            ] {
                assert!(
                    !source.contains(&forbidden_return),
                    "test-only module gained a forbidden authority return: {forbidden_return}"
                );
            }
        }

        let store_source = include_str!("store.rs");
        assert!(store_source.contains(
            "fn begin_authenticated_runtime_read_snapshot_for_core_parent_v0(\n        &self,\n        parent: &PayloadValidationParentV0,"
        ));
        assert!(store_source.contains(
            "fn load_production_poco_projection_from_connection_v0(\n    connection: &Connection,"
        ));
        assert!(store_source
            .contains("fn load_authenticated_production_poco_projection_v0(\n        &self,"));
        assert!(store_source.contains(
            "fn plan_exact_next_auth_update_v0(\n        &self,\n        writes: impl IntoIterator<Item = AuthWrite>,\n    )"
        ));
        assert!(!store_source
            .contains("fn plan_exact_next_auth_update_v0(\n        &self,\n        target"));
    }

    #[test]
    fn snapshot_finish_failure_outranks_second_runtime_rejection() {
        let test_store = test_store();
        let profile = fixture_profile_with_second_runtime_reject(test_store.parent_state_root);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact owning runtime session");
        let open = execute_next_exact_runtime_transaction_for_test_v0(open)
            .expect("execute prior credit before rejected transaction");
        let open = inject_test_runtime_snapshot_finish_failure_for_test_v0(open);
        let failed = execute_next_exact_runtime_transaction_for_test_v0(open)
            .err()
            .expect("second transaction must deterministically reject");
        assert!(matches!(
            finish_failed_test_regular_runtime_execution_for_test_v0(failed),
            Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                ..
            })
        ));
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn reversing_exact_transaction_order_rejects_without_seek_or_future_delta() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions.reverse();
        let profile = replace_profile_transactions(profile, transactions);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open reversed exact owning runtime session");
        let failed = execute_next_exact_runtime_transaction_for_test_v0(open)
            .err()
            .expect("task creation cannot read a future credit delta");
        let finished = finish_failed_test_regular_runtime_execution_for_test_v0(failed)
            .expect("finish exact reversed runtime rejection");
        assert_eq!(
            finished_runtime_reject_code(&finished),
            "insufficient_balance"
        );
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn mutation_staging_is_atomic_when_a_later_mutation_breaks_version_successorship() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open exact owning runtime session");
        let valid_first = RuntimeMutation {
            object_key_hex: account_key("did:staged:1"),
            object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
            expected_version: None,
            next_version: 1,
            value_bytes: serde_json::to_vec(&AccountV1 {
                account: "did:staged:1".to_string(),
                balance: 1,
                nonce: 0,
            })
            .expect("encode staged account"),
        };
        let invalid_second = RuntimeMutation {
            object_key_hex: task_key("staged-task"),
            object_type: TASK_OBJECT_TYPE_V1.to_string(),
            expected_version: None,
            next_version: 2,
            value_bytes: vec![1],
        };
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[valid_first, invalid_second]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation next version is not the exact successor"
            ))
        );
        assert!(open.changes.is_empty());
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::IncompleteBody {
                executed: 0,
                expected: 2,
            })
        ));
        assert_runtime_fixture_objects_absent(&test_store.store);
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn mutation_staging_accepts_all_canonical_runtime_object_families() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open runtime session for canonical mutation families");
        let account = AccountV1 {
            account: "did:canonical:account".to_string(),
            balance: 7,
            nonce: 1,
        };
        let task = open_task("canonical-task");
        let policy = FeePolicyV1::default();
        let monetary = MonetaryStateV1 { total_issued: 7 };
        let mutations = vec![
            runtime_mutation(
                account_key(&account.account),
                ACCOUNT_OBJECT_TYPE_V1,
                None,
                1,
                &account,
            ),
            runtime_mutation(task_key(&task.task_id), TASK_OBJECT_TYPE_V1, None, 1, &task),
            runtime_mutation(
                fee_policy_key(),
                FEE_POLICY_OBJECT_TYPE_V1,
                None,
                1,
                &policy,
            ),
            runtime_mutation(
                monetary_state_key(),
                MONETARY_STATE_OBJECT_TYPE_V1,
                None,
                1,
                &monetary,
            ),
        ];
        let staged = stage_runtime_mutations_for_test_v0(&open, &mutations)
            .expect("all canonical runtime object families must stage");
        assert_eq!(staged.len(), 4);
        assert!(staged.contains_key(&account_key(&account.account)));
        assert!(staged.contains_key(&task_key(&task.task_id)));
        assert!(staged.contains_key(&fee_policy_key()));
        assert!(staged.contains_key(&monetary_state_key()));
        assert!(open.changes.is_empty());
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::IncompleteBody {
                executed: 0,
                expected: 2,
            })
        ));
    }

    #[test]
    fn task_mutation_staging_reuses_runtime_state_machine_version_and_height_rules() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let mut open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open runtime session for task-state mutation validation");

        let mut contradictory = open_task("contradictory-task");
        contradictory.worker = Some("did:worker:1".to_string());
        let contradictory = runtime_mutation(
            task_key(&contradictory.task_id),
            TASK_OBJECT_TYPE_V1,
            None,
            1,
            &contradictory,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[contradictory]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime task mutation state is not reachable"
            ))
        );

        let versioned = open_task("versioned-task");
        let initial = runtime_mutation(
            task_key(&versioned.task_id),
            TASK_OBJECT_TYPE_V1,
            None,
            1,
            &versioned,
        );
        open.changes = stage_runtime_mutations_for_test_v0(&open, &[initial])
            .expect("stage reachable version-1 open task");
        let wrong_status_version = runtime_mutation(
            task_key(&versioned.task_id),
            TASK_OBJECT_TYPE_V1,
            Some(1),
            2,
            &versioned,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[wrong_status_version]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime task mutation state is not reachable"
            ))
        );

        let result_hash_hex = "11".repeat(32);
        let reveal_salt_hex = "22".repeat(32);
        let commitment_hex = trnm_protocol::result_commitment_hex(
            "future-task",
            "did:worker:1",
            &result_hash_hex,
            &reveal_salt_hex,
        )
        .expect("derive canonical future-task commitment");
        let future = TaskV1 {
            task_id: "future-task".to_string(),
            client: "did:client:1".to_string(),
            worker: Some("did:worker:1".to_string()),
            reward: 1_000,
            worker_stake: 500,
            result_deadline_height: 20,
            challenge_window_blocks: 10,
            status: TaskStatusV1::Revealed,
            commitment_hex: Some(commitment_hex),
            result_hash_hex: Some(result_hash_hex),
            reveal_salt_hex: Some(reveal_salt_hex),
            challenge_deadline_height: Some(15),
            consumer: None,
            consumed_units: 0,
            consumption_payment: 0,
            receipt_hash_hex: None,
            challenger: None,
            challenge_bond: 0,
            evidence_hash_hex: None,
        };
        let future_key = task_key(&future.task_id);
        let prior = NodeObjectMutation {
            object_key_hex: future_key.clone(),
            object_type: TASK_OBJECT_TYPE_V1.to_string(),
            expected_version: Some(2),
            next_version: 3,
            value_bytes: serde_json::to_vec(&future).expect("encode prior future task"),
        }
        .into_stored();
        open.changes.clear();
        open.changes.insert(future_key.clone(), prior);
        let future_reveal = runtime_mutation(future_key, TASK_OBJECT_TYPE_V1, Some(3), 4, &future);
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[future_reveal]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime task mutation state is not reachable"
            ))
        );

        open.changes.clear();
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::IncompleteBody { .. })
        ));
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn mutation_staging_rejects_duplicate_reserved_unknown_and_key_value_splices() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open runtime session for key/type/value mutation negatives");
        let account = AccountV1 {
            account: "did:canonical:account".to_string(),
            balance: 7,
            nonce: 1,
        };
        let canonical = runtime_mutation(
            account_key(&account.account),
            ACCOUNT_OBJECT_TYPE_V1,
            None,
            1,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[canonical.clone(), canonical.clone()],),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime receipt repeats an object key"
            ))
        );

        let reserved = runtime_mutation(
            crate::poco_authority_object_key(),
            ACCOUNT_OBJECT_TYPE_V1,
            None,
            1,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[reserved]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime receipt targets the immutable PoCO authority object"
            ))
        );

        let unknown = runtime_mutation(
            account_key(&account.account),
            "trnm.runtime.unknown.v0",
            None,
            1,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[unknown]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation uses an unknown object type"
            ))
        );

        let key_splice = runtime_mutation(
            account_key("did:foreign:key"),
            ACCOUNT_OBJECT_TYPE_V1,
            None,
            1,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[key_splice]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation key differs from its canonical typed value"
            ))
        );

        let mut noncanonical = canonical;
        noncanonical.value_bytes.push(b' ');
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[noncanonical]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime account mutation value is not canonical"
            ))
        );
        assert!(open.changes.is_empty());
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::IncompleteBody { .. })
        ));
    }

    #[test]
    fn mutation_staging_rejects_existing_type_and_version_splices() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let mut open = open_test_regular_runtime_execution_for_test_v0(
            &test_store.store,
            authenticate(profile),
        )
        .expect("open runtime session for type/version mutation negatives");
        let account = AccountV1 {
            account: "did:versioned:account".to_string(),
            balance: 7,
            nonce: 1,
        };
        let account_key_hex = account_key(&account.account);
        let initial = runtime_mutation(
            account_key_hex.clone(),
            ACCOUNT_OBJECT_TYPE_V1,
            None,
            1,
            &account,
        );
        open.changes = stage_runtime_mutations_for_test_v0(&open, &[initial])
            .expect("seed private version-1 change");

        let task = open_task("foreign-type-task");
        let type_splice = runtime_mutation(
            account_key_hex.clone(),
            TASK_OBJECT_TYPE_V1,
            Some(1),
            2,
            &task,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[type_splice]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation changes an authenticated object type"
            ))
        );

        let expected_splice = runtime_mutation(
            account_key_hex.clone(),
            ACCOUNT_OBJECT_TYPE_V1,
            None,
            2,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[expected_splice]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation expected version differs from the session view"
            ))
        );

        let successor_splice = runtime_mutation(
            account_key_hex.clone(),
            ACCOUNT_OBJECT_TYPE_V1,
            Some(1),
            3,
            &account,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[successor_splice]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation next version is not the exact successor"
            ))
        );

        let exhausted_key = account_key("did:exhausted:account");
        let exhausted_value = AccountV1 {
            account: "did:exhausted:account".to_string(),
            balance: 1,
            nonce: 1,
        };
        let mut exhausted = BTreeMap::new();
        let exhausted_object = NodeObjectMutation {
            object_key_hex: exhausted_key.clone(),
            object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
            expected_version: Some(u64::MAX - 1),
            next_version: u64::MAX,
            value_bytes: serde_json::to_vec(&exhausted_value).expect("encode exhausted account"),
        }
        .into_stored();
        exhausted.insert(exhausted_key.clone(), exhausted_object);
        open.changes = exhausted;
        let overflow = runtime_mutation(
            exhausted_key,
            ACCOUNT_OBJECT_TYPE_V1,
            Some(u64::MAX),
            u64::MAX,
            &exhausted_value,
        );
        assert_eq!(
            stage_runtime_mutations_for_test_v0(&open, &[overflow]),
            Err(TestRegularRuntimeMutationStageFailureV0::Invariant(
                "runtime mutation advances an exhausted object version"
            ))
        );
        assert_eq!(open.changes.len(), 1);
        open.changes.clear();
        assert!(matches!(
            finish_and_plan_test_regular_runtime_execution_for_test_v0(open),
            Err(TestRegularRuntimeFinishFailureV0::IncompleteBody { .. })
        ));
    }

    #[test]
    fn foreign_validator_set_fails_authenticated_snapshot_lifecycle_join() {
        let store = test_store();
        let foreign = fixture_profile(store.parent_state_root, 1);
        let error =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(foreign))
                .err()
                .expect("foreign native validator set must fail authenticated lifecycle join");
        assert_eq!(
            error,
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "retained validator set differs from authenticated parent lifecycle",
            }
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn fixture_consistent_foreign_signer_policy_is_rejected_by_store_binding() {
        let store = test_store();
        let mut profile = fixture_profile(store.parent_state_root, 0);
        profile.authorized_signers[0].public_key_hex =
            hex::encode(test_signing_key(99).verifying_key().to_bytes());
        let error =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .err()
                .expect("fixture-consistent foreign signer policy must fail store binding");
        assert_eq!(
            error,
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
                sqlite: None,
                reason: "joined signer policy differs from local application-store configuration",
            }
        );
    }

    #[test]
    fn exact_envelope_policy_and_canonical_transaction_failures_consume_the_traversal() {
        let store = test_store();

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions[0] = b"{".to_vec();
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidEnvelope
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let mut envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&transactions[0]).expect("decode signed envelope to corrupt");
        let mut signature = hex::decode(&envelope.signature_hex).expect("decode test signature");
        signature[0] ^= 1;
        envelope.signature_hex = hex::encode(signature);
        transactions[0] = serde_json::to_vec(&envelope).expect("encode corrupted signature");
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidOrUnauthorizedEnvelope
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&transactions[0]).expect("decode signed envelope for chain");
        let payload = envelope
            .payload_bytes()
            .expect("decode exact first payload");
        transactions[0] = signed_envelope_bytes(
            "trnm-foreign-chain",
            "native-input-wrong-chain".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidOrUnauthorizedEnvelope
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&transactions[0]).expect("decode signed envelope for expiry");
        let payload = envelope
            .payload_bytes()
            .expect("decode exact first payload");
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-expired".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_699_999_000_000,
            1_699_999_500_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidOrUnauthorizedEnvelope
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&transactions[0]).expect("decode signed envelope for payload");
        let payload = envelope
            .payload_bytes()
            .expect("decode exact first payload");
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-foreign-key".to_string(),
            99,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &payload,
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidOrUnauthorizedEnvelope
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        let envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&transactions[0]).expect("decode signed envelope for type");
        let payload = envelope
            .payload_bytes()
            .expect("decode exact first payload");
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-wrong-type".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            "opaque_fixture_v1",
            &payload,
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::UnsupportedPayloadType
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-invalid-inner".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            b"{}",
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::InvalidCanonicalTransaction
        );

        let sender_mismatch = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:client:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 1,
            },
        };
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-sender-mismatch".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &serde_json::to_vec(&sender_mismatch).expect("encode sender mismatch transaction"),
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::SenderMismatch
        );

        let nonce_mismatch = CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "did:operator:1".to_string(),
            nonce: 1,
            max_gas: 100_000,
            fee_limit: 100_000,
            command: CanonicalCommandV1::CreditAccount {
                account: "did:client:1".to_string(),
                amount: 1,
            },
        };
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions[0] = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-input-nonce-mismatch".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            CANONICAL_TX_PAYLOAD_TYPE_V1,
            &serde_json::to_vec(&nonce_mismatch).expect("encode nonce mismatch transaction"),
        );
        let profile = replace_profile_transactions(profile, transactions);
        assert_eq!(
            first_cursor_error(&store.store, profile),
            InertRegularBodyCursorFailureV0::NonceMismatch
        );

        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn regular_context_accepts_handoff_parent_but_rejects_epoch_terminal_parents() {
        let store = test_store();
        let handoff = replace_profile_parent_kind(
            fixture_profile(store.parent_state_root, 0),
            BlockKind::EpochHandoff,
        );
        validate_snapshot_authenticated_regular_context_v0(
            &handoff.header,
            &handoff.parent,
            &handoff.validator_set,
            &handoff.parameters,
            &store.validator_lifecycle,
        )
        .expect("first regular block may follow the matching new-context handoff");

        for parent_kind in [
            BlockKind::EpochCheckpoint,
            BlockKind::EpochSeal1,
            BlockKind::EpochSeal2,
        ] {
            let terminal = replace_profile_parent_kind(
                fixture_profile(store.parent_state_root, 0),
                parent_kind,
            );
            assert!(matches!(
                validate_snapshot_authenticated_regular_context_v0(
                    &terminal.header,
                    &terminal.parent,
                    &terminal.validator_set,
                    &terminal.parameters,
                    &store.validator_lifecycle,
                ),
                Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                        reason:
                            "Core-authenticated parent consensus context differs from target header",
                        ..
                    }
                )
            ));
        }
    }

    #[test]
    fn production_cursor_prepares_only_internal_index_and_exact_derived_context() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let expected_outer = profile.body.application_payload().transactions()[0].clone();
        let expected_envelope: SignedCommandEnvelopeV1 =
            serde_json::from_slice(&expected_outer).expect("decode expected exact envelope");
        let expected_inner = expected_envelope
            .payload_bytes()
            .expect("decode expected exact inner bytes");
        let expected_transaction: CanonicalTxV1 =
            serde_json::from_slice(&expected_inner).expect("decode expected canonical tx");
        let request = core_validation_request(&profile);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open production transaction cursor");
        assert_eq!(open.next_transaction_index, 0);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        let prepared = expect_prepared_runtime_transaction(
            prepare_next_core_authorized_regular_payload_v0(open)
                .expect("prepare exact first runtime transaction"),
        );
        assert_eq!(prepared.index, 0);
        assert_eq!(prepared.next_transaction_index, 1);
        assert_eq!(prepared.open.next_transaction_index, 0);
        assert_eq!(prepared.exact_outer_bytes, expected_outer);
        assert_eq!(prepared.exact_inner_bytes, expected_inner);
        assert_eq!(prepared.transaction, expected_transaction);
        assert_eq!(
            prepared.context.target_height,
            profile.header.height().get()
        );
        assert_eq!(prepared.context.target_block_id, profile.header.id());
        assert_eq!(
            prepared.context.validation_timestamp_ms,
            profile.header.timestamp_ms()
        );
        assert_eq!(prepared.context.signer_id, "did:operator:1");
        assert_eq!(prepared.context.signer_role, "operator");
        assert_eq!(
            prepared.context.payload_len,
            prepared.exact_inner_bytes.len()
        );
        assert_eq!(
            prepared
                .open
                .open
                .authorized
                .context
                .signer_policy
                .commitment,
            crate::signer_policy_commitment(&store.authorized_signers)
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(prepared);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_runtime_cursor_advances_only_after_real_success_and_reads_prior_delta() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before production runtime attempts");
        assert_runtime_fixture_objects_absent(&store.store);
        let profile = fixture_profile(store.parent_state_root, 0);
        let expected_block_id = profile.header.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open production runtime cursor");

        let open = attempt_next_production_runtime_transaction(open)
            .expect("first exact runtime transaction succeeds");
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied.len(), 1);
        assert_eq!(open.applied[0].index, 0);
        assert_eq!(open.applied[0].context.target_block_id, expected_block_id);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        let open = attempt_next_production_runtime_transaction(open)
            .expect("second exact runtime transaction observes the first private delta");
        assert_eq!(open.next_transaction_index, 2);
        assert_eq!(open.applied.len(), 2);
        assert_eq!(open.applied[1].index, 1);
        assert_eq!(open.applied[1].transaction.sender, "did:client:1");
        assert_eq!(
            open.applied[1].exact_outer_bytes,
            profile.body.application_payload().transactions()[1]
        );
        assert_eq!(
            open.applied[1].context.payload_len,
            open.applied[1].exact_inner_bytes.len()
        );
        assert_eq!(
            NativeTransactionReceiptFactsV0::try_from_runtime_receipt(
                &open.applied[1].runtime_receipt,
            )
            .expect("rebuild exact native receipt facts"),
            open.applied[1].native_receipt
        );

        let client_key = account_key("did:client:1");
        let client = open
            .changes
            .get(&client_key)
            .expect("second transaction retains the updated prior delta");
        assert_eq!(client.version, 2);
        assert!(open.changes.contains_key(&task_key("native-task-0")));
        assert_runtime_fixture_objects_absent(&store.store);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(open);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after production runtime attempts");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);

        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&test_authorized_signers()));
        let reopened = ApplicationStore::open(
            &store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("reopen store after inert production runtime attempts");
        let reopened_state = reopened
            .load_or_migrate()
            .expect("reload committed state after inert production runtime attempts");
        assert_eq!(reopened_state.height, committed_before.height);
        assert_eq!(reopened_state.app_hash, committed_before.app_hash);
        assert_runtime_fixture_objects_absent(&reopened);
    }

    #[test]
    fn production_complete_body_plans_exact_next_state_without_persistence() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before production planning");
        let profile = honest_runtime_profile(&store);
        let expected_block_id = profile.header.id();
        let expected_state_root = profile.header.state_root();
        let expected_height = profile.header.height().get();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open production post-state cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first exact production transaction");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute second exact production transaction");

        let finished = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .expect("plan exact production post-state on the original snapshot");
        assert_eq!(
            finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(
            finished.authorized.route,
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(finished.post_state_update.version, expected_height);
        assert_eq!(
            StateRoot::new(finished.post_state_update.root_hash.into()),
            expected_state_root
        );
        assert_eq!(finished.applied.len(), 2);
        assert_eq!(finished.applied[0].index, 0);
        assert_eq!(finished.applied[1].index, 1);
        assert!(finished.changes.contains_key(&task_key("native-task-0")));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);

        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after inert production planning");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);

        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&test_authorized_signers()));
        let reopened = ApplicationStore::open(
            &store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("reopen store after inert production post-state planning");
        let reopened_state = reopened
            .load_or_migrate()
            .expect("reload committed state after inert production post-state planning");
        assert_eq!(reopened_state.height, committed_before.height);
        assert_eq!(reopened_state.app_hash, committed_before.app_hash);
        assert_runtime_fixture_objects_absent(&reopened);
    }

    #[test]
    fn production_post_state_plan_replays_versioned_receipts_into_the_only_final_delta() {
        let store = test_store();
        let profile = honest_runtime_profile(&store);
        let open = complete_production_runtime_cursor(&store, &profile);
        let client_key = account_key("did:client:1");
        let first_client = open.applied[0]
            .runtime_receipt
            .mutations
            .iter()
            .find(|mutation| mutation.object_key_hex == client_key)
            .expect("first receipt creates the client account");
        let second_client = open.applied[1]
            .runtime_receipt
            .mutations
            .iter()
            .find(|mutation| mutation.object_key_hex == client_key)
            .expect("second receipt updates the same client account");
        assert_eq!(first_client.expected_version, None);
        assert_eq!(first_client.next_version, 1);
        assert_eq!(second_client.expected_version, Some(1));
        assert_eq!(second_client.next_version, 2);

        let mut receipt_only_changes = BTreeMap::new();
        for applied in &open.applied {
            for mutation in &applied.runtime_receipt.mutations {
                let stored = NodeObjectMutation {
                    object_key_hex: mutation.object_key_hex.clone(),
                    object_type: mutation.object_type.clone(),
                    expected_version: mutation.expected_version,
                    next_version: mutation.next_version,
                    value_bytes: mutation.value_bytes.clone(),
                }
                .into_stored();
                receipt_only_changes.insert(stored.object_key_hex.clone(), stored);
            }
        }
        let expected_writes = receipt_only_changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("encode independent receipt-only final writes");
        let expected_plan = store
            .authenticated_parent
            .plan_put_value_set(2, expected_writes)
            .expect("independently plan the receipt-only final delta");

        let finished = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .expect("replay exact retained receipts before planning");
        assert_eq!(finished.changes, receipt_only_changes);
        assert_eq!(
            finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_empty_body_plans_empty_exact_next_version_without_persistence() {
        let store = test_store();
        let profile =
            replace_profile_transactions(fixture_profile(store.parent_state_root, 0), Vec::new());
        let expected_plan = store
            .authenticated_parent
            .plan_put_value_set(2, Vec::new())
            .expect("independently plan empty exact-next state");
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open empty production cursor");
        let finished = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .expect("plan empty exact-next state on the authenticated snapshot");
        assert_eq!(finished.post_state_update.version, 2);
        assert_eq!(
            finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        assert!(finished.applied.is_empty());
        assert!(finished.changes.is_empty());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_post_state_plan_requires_the_complete_runtime_body() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open incomplete production cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute only the first exact production transaction");
        let failed = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("incomplete body must retain the exact closed cursor");
        assert_eq!(failed.authorized.validation_id, expected_id);
        assert_eq!(failed.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(failed.next_transaction_index, 1);
        assert_eq!(failed.applied.len(), 1);
        assert!(!failed.changes.is_empty());
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::IncompleteBody {
                    executed: 1,
                    expected: 2,
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_snapshot_finish_failure_outranks_successful_post_state_plan() {
        let store = test_store();
        let profile = honest_runtime_profile(&store);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open production finish-precedence cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first exact production transaction");
        let mut open = attempt_next_production_runtime_transaction(open)
            .expect("execute second exact production transaction");
        open.open.snapshot.inject_finish_failure_for_test_v0();
        let failed = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("finish failure must retain the exact completed cursor");
        assert_eq!(failed.authorized.validation_id, expected_id);
        assert_eq!(failed.next_transaction_index, 2);
        assert_eq!(failed.applied.len(), 2);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_snapshot_finish_failure_outranks_incomplete_post_state_plan() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open incomplete production finish-precedence cursor");
        let mut open = attempt_next_production_runtime_transaction(open)
            .expect("execute only the first exact production transaction");
        open.open.snapshot.inject_finish_failure_for_test_v0();
        let failed = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("finish failure must retain the exact incomplete cursor");
        assert_eq!(failed.authorized.validation_id, expected_id);
        assert_eq!(failed.next_transaction_index, 1);
        assert_eq!(failed.applied.len(), 1);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_post_state_plan_rejects_internal_runtime_and_delta_provenance_drift() {
        let store = test_store();

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.applied[0].index = 1;
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::RuntimeProvenanceInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        let (key, object) = open
            .changes
            .iter()
            .next()
            .map(|(key, object)| (key.clone(), object.clone()))
            .expect("complete cursor has a staged object");
        open.changes.remove(&key);
        open.changes.insert(format!("foreign-{key}"), object);
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::StateDeltaProvenanceInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.changes
            .values_mut()
            .next()
            .expect("complete cursor has a staged value")
            .value_hash_hex = hex::encode([0xa7; 32]);
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::StateDeltaProvenanceInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        let client = open
            .changes
            .get_mut(&account_key("did:client:1"))
            .expect("complete cursor retains the final client account");
        let mut account: AccountV1 =
            serde_json::from_slice(&client.value_bytes).expect("decode final client account");
        account.balance = account
            .balance
            .checked_add(1)
            .expect("test balance increment");
        client.value_bytes =
            serde_json::to_vec(&account).expect("encode canonical foreign account");
        client.value_hash_hex = hex::encode(trnm_finality_types::hash_domain(
            "trnm.state.object.value.v1",
            &[&client.value_bytes],
        ));
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.applied[0].runtime_receipt.mutations[0]
            .value_bytes
            .push(b' ');
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.applied[1]
            .runtime_receipt
            .mutations
            .iter_mut()
            .find(|mutation| mutation.object_key_hex == account_key("did:client:1"))
            .expect("second receipt updates the client account")
            .expected_version = None;
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        let duplicate = open.applied[0].runtime_receipt.mutations[0].clone();
        open.applied[0].runtime_receipt.mutations.push(duplicate);
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_snapshot_finish_failure_outranks_delta_and_write_preparation_drift() {
        let store = test_store();

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.changes
            .values_mut()
            .next()
            .expect("complete cursor has a staged value")
            .value_hash_hex = hex::encode([0xa8; 32]);
        open.open.snapshot.inject_finish_failure_for_test_v0();
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        open.applied[0].runtime_receipt.mutations[0]
            .value_bytes
            .push(b' ');
        open.open.snapshot.inject_finish_failure_for_test_v0();
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));

        let profile = honest_runtime_profile(&store);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        let invalid_write = NodeObjectMutation {
            object_key_hex: String::new(),
            object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
            expected_version: None,
            next_version: 1,
            value_bytes: Vec::new(),
        }
        .into_stored();
        open.changes.insert(String::new(), invalid_write);
        let failed = closed_production_post_state_failure(open);
        assert!(matches!(
            failed.cause,
            ClosedCoreAuthorizedRegularPostStatePlanCauseV0::Plan(
                CoreAuthorizedRegularPostStatePlanCauseV0::ReceiptMutationDeltaInvariant
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_post_state_plan_remains_pinned_across_a_sibling_writer() {
        let store = test_store();
        let profile = honest_runtime_profile(&store);
        let expected_state_root = profile.header.state_root();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open production cursor before sibling commit");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first production transaction before sibling commit");

        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&test_authorized_signers()));
        let writer = ApplicationStore::open(
            &store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("open independent production-planning sibling writer");
        let current = writer
            .load_or_migrate()
            .expect("load production-planning sibling parent");
        let sibling_update = writer
            .plan_auth_update(2, Vec::new())
            .expect("plan legitimate empty production-planning sibling");
        let sibling_app_hash: [u8; 32] = sibling_update.root_hash.into();
        assert_ne!(StateRoot::new(sibling_app_hash), expected_state_root);
        let sibling = PendingBlock {
            height: 2,
            app_hash: sibling_app_hash,
            tx_results: Vec::new(),
            native_execution: crate::test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                2,
                sibling_app_hash,
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update: sibling_update,
            poco_checkpoint_execution: None,
        };
        writer
            .persist_transition(&current, &sibling, 0)
            .expect("commit legitimate production-planning sibling");

        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute second production transaction against the old parent snapshot");
        let finished = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .expect("plan exact production state from the still-pinned old parent");
        assert_eq!(
            StateRoot::new(finished.post_state_update.root_hash.into()),
            expected_state_root
        );
        assert_eq!(finished.applied.len(), 2);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let visible_head = store
            .store
            .load_or_migrate()
            .expect("observe sibling only after production snapshot finish");
        assert_eq!(visible_head.height, 2);
        assert_eq!(visible_head.app_hash, sibling_app_hash);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_four_root_comparator_matches_real_runtime_and_independent_roots() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before production root comparison");
        let profile = honest_runtime_profile(&store);
        let expected_block_id = profile.header.id();
        let expected_state_root = profile.header.state_root();
        let expected_receipts_root = profile.header.receipts_root();
        let finished = finish_production_runtime_plan(&store, &profile);
        let matched = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .expect("match four roots from one exact production runtime plan");
        assert_eq!(
            matched.finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(
            matched.finished.authorized.route,
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(matched.validated_commitments.block_id(), expected_block_id);
        assert_eq!(
            StateRoot::new(matched.finished.post_state_update.root_hash.into()),
            expected_state_root
        );
        assert_eq!(
            matched
                .native_execution
                .execution_receipts()
                .receipts_root()
                .expect("derive matched production receipts root"),
            expected_receipts_root
        );
        assert_eq!(
            matched.native_execution.application_payload(),
            matched.finished.authorized.body.application_payload()
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after production root comparison");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn production_four_root_comparator_accepts_independently_authored_empty_body() {
        let store = test_store();
        let profile =
            replace_profile_transactions(fixture_profile(store.parent_state_root, 0), Vec::new());
        let independent_plan = store
            .authenticated_parent
            .plan_put_value_set(2, Vec::new())
            .expect("independently plan empty comparator state");
        let state_root = StateRoot::new(independent_plan.root_hash.into());
        let receipts_root = NativeBlockExecutionV0::empty()
            .execution_receipts()
            .receipts_root()
            .expect("derive independent empty comparator receipts root");
        let profile = replace_profile_execution_roots(profile, state_root, receipts_root);
        let expected_block_id = profile.header.id();
        let finished = finish_and_plan_core_authorized_regular_post_state_v0(
            open_core_authorized_regular_transaction_cursor_v0(
                &test_native_validation_host(&store),
                core_validation_request(&profile),
            )
            .expect("open empty production comparator cursor"),
        )
        .expect("finish empty production comparator plan");
        let matched = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .expect("match independently authored empty roots");
        assert_eq!(matched.validated_commitments.block_id(), expected_block_id);
        assert!(matched.finished.applied.is_empty());
        assert!(matched
            .native_execution
            .execution_receipts()
            .receipts()
            .is_empty());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_comparator_disposition_retains_valid_owner_without_persistence() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before process-local disposition");
        let profile = honest_runtime_profile(&store);
        let expected_block_id = profile.header.id();
        let classified = classify_core_authorized_regular_runtime_commitment_comparison_v0(
            match_finished_core_authorized_regular_runtime_commitments_v0(
                finish_production_runtime_plan(&store, &profile),
            ),
        );
        assert_eq!(
            format!("{classified:?}"),
            "ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 { disposition: \"valid\", retains_exact_owner: true, .. }"
        );
        let matched = match classified {
            ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::Valid(matched) => matched,
            other => panic!("honest production comparison misclassified: {other:?}"),
        };
        assert_eq!(
            matched.finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(
            matched.finished.authorized.route,
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(matched.validated_commitments.block_id(), expected_block_id);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after process-local disposition");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn production_valid_outcome_consumes_the_only_matched_owner_and_derives_generation() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before production outcome promotion");
        let profile = honest_runtime_profile(&store);
        let expected_block_id = profile.header.id();
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_production_runtime_plan(&store, &profile),
                ),
            ),
        );
        assert_eq!(
            format!("{promoted:?}"),
            "CoreAuthorizedRegularExecutionOutcomeV0 { disposition: \"valid\", retains_exact_owner: true, .. }"
        );
        let outcome = match promoted {
            CoreAuthorizedRegularExecutionOutcomeV0::Valid(outcome) => outcome,
            other => panic!("honest production match did not promote to Valid: {other:?}"),
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(crate::execution_outcome::TerminalExecutionDispositionV0::Valid)
        );
        let matched = outcome
            .successful_execution()
            .expect("Valid retains the exact matched owner");
        assert_eq!(
            matched.finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(
            matched.finished.authorized.validation_id.generation(),
            outcome.generation().get()
        );
        assert_eq!(matched.validated_commitments.block_id(), expected_block_id);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after production outcome promotion");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn production_invalid_and_invariant_comparisons_cannot_promote_to_valid() {
        let store = test_store();
        let honest = honest_runtime_profile(&store);
        let honest_receipts_root = honest.header.receipts_root();
        let mismatched = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xa7; 32]),
            honest_receipts_root,
        );
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_production_runtime_plan(&store, &mismatched),
                ),
            ),
        );
        let retained = match promoted {
            CoreAuthorizedRegularExecutionOutcomeV0::DeterministicallyInvalid(retained) => retained,
            other => panic!("state-root mismatch crossed the Valid boundary: {other:?}"),
        };
        assert_eq!(
            retained.outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(retained.outcome.code(), "computed_state_root_mismatch");
        assert_eq!(
            retained.failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.applied[0].native_receipt = NativeTransactionReceiptFactsV0::internal_operation();
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(finished),
            ),
        );
        let retained = match promoted {
            CoreAuthorizedRegularExecutionOutcomeV0::InvariantFault(retained) => retained,
            other => panic!("comparator invariant crossed the Valid boundary: {other:?}"),
        };
        assert_eq!(retained.outcome.terminal_disposition(), None);
        assert_eq!(
            retained.outcome.code(),
            "native_regular_commitment_comparison_invariant"
        );
        assert_eq!(
            retained.failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);

        let source = include_str!("native_payload_validation.rs");
        let promotion = source
            .split_once("fn promote_core_authorized_regular_execution_outcome_v0(")
            .expect("owning production outcome promotion")
            .1
            .split_once("\n}\n")
            .expect("promotion body")
            .0;
        assert!(!promotion.contains("generation:"));
        assert!(!promotion.contains("header:"));
        assert!(!promotion.contains("state_root:"));
        assert!(!promotion.contains("receipts_root:"));
        assert!(!promotion.contains("successful_execution:"));
    }

    #[test]
    fn terminal_production_outcomes_authorize_only_the_retained_core_route_and_id() {
        let store = test_store();
        let profile = honest_runtime_profile(&store);
        let expected_id = core_validation_request(&profile).id();
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_production_runtime_plan(&store, &profile),
                ),
            ),
        );
        let callback = match authorize_core_regular_payload_validation_callback_v0(promoted) {
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::Ready(callback) => callback,
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::InvariantFault(_) => {
                panic!("honest production outcome did not authorize its Core callback")
            }
        };
        match callback.into_core_input() {
            Input::PayloadValidated { id, result } => {
                assert_eq!(id, expected_id);
                assert_eq!(
                    result
                        .commitments()
                        .expect("Valid callback commitments")
                        .block_id(),
                    expected_id.block_id()
                );
            }
            other => panic!("proposal route changed during callback authorization: {other:?}"),
        }

        let profile = honest_runtime_profile(&store);
        let job = match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("synced fixture did not produce a validation job"),
        };
        let expected_id = job.request.id();
        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("synced validation did not open: {other:?}"),
        };
        let open = open_core_authorized_regular_transaction_cursor_from_open_v0(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first synced transaction");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute second synced transaction");
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_and_plan_core_authorized_regular_post_state_v0(open)
                        .expect("finish synced state plan"),
                ),
            ),
        );
        let callback = match authorize_core_regular_payload_validation_callback_v0(promoted) {
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::Ready(callback) => callback,
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::InvariantFault(_) => {
                panic!("synced production outcome did not authorize its Core callback")
            }
        };
        match callback.into_core_input() {
            Input::SyncedPayloadValidated { id, result } => {
                assert_eq!(id, expected_id);
                assert_eq!(
                    result
                        .commitments()
                        .expect("synced Valid commitments")
                        .block_id(),
                    expected_id.block_id()
                );
            }
            other => panic!("synced route changed during callback authorization: {other:?}"),
        }
    }

    #[test]
    fn deterministic_invalid_can_callback_but_invariant_fault_cannot() {
        let store = test_store();
        let honest = honest_runtime_profile(&store);
        let honest_receipts_root = honest.header.receipts_root();
        let mismatched = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xb7; 32]),
            honest_receipts_root,
        );
        let expected_id = core_validation_request(&mismatched).id();
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_production_runtime_plan(&store, &mismatched),
                ),
            ),
        );
        let callback = match authorize_core_regular_payload_validation_callback_v0(promoted) {
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::Ready(callback) => callback,
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::InvariantFault(_) => {
                panic!("computed state mismatch incorrectly became fail-stop")
            }
        };
        assert_eq!(
            callback.into_core_input(),
            Input::PayloadValidated {
                id: expected_id,
                result: PayloadValidationResult::DeterministicallyInvalid,
            }
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.applied[0].native_receipt = NativeTransactionReceiptFactsV0::internal_operation();
        let promoted = promote_core_authorized_regular_execution_outcome_v0(
            classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(finished),
            ),
        );
        match authorize_core_regular_payload_validation_callback_v0(promoted) {
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::InvariantFault(outcome) => {
                assert!(matches!(
                    outcome,
                    CoreAuthorizedRegularExecutionOutcomeV0::InvariantFault(_)
                ));
            }
            CoreAuthorizedRegularPayloadValidationCallbackAdmissionV0::Ready(_) => {
                panic!("comparator invariant manufactured a Core callback")
            }
        }

        let source = include_str!("native_payload_validation.rs");
        let callback_authorizer = source
            .split_once("fn authorize_core_regular_payload_validation_callback_v0(")
            .expect("callback authorizer")
            .1
            .split_once("\n}\n")
            .expect("callback authorizer body")
            .0;
        assert!(!callback_authorizer.contains("route:"));
        assert!(!callback_authorizer.contains("id:"));
        assert!(!callback_authorizer.contains("result:"));
        assert!(!callback_authorizer.contains("commitments:"));
    }

    #[test]
    fn synced_core_target_route_survives_open_runtime_plan_comparator_and_disposition() {
        let store = test_store();
        let committed_before = store
            .store
            .load_or_migrate()
            .expect("read committed state before synced production validation");
        let profile = honest_runtime_profile(&store);
        let job = match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("real synced target did not enter its route-bound job"),
        };
        let expected_id = job.request.id();
        assert_eq!(job.request.route(), PayloadValidationRouteV0::Synced);

        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("real synced target did not open exact validation: {other:?}"),
        };
        assert_eq!(open.authorized.validation_id, expected_id);
        assert_eq!(open.authorized.route, PayloadValidationRouteV0::Synced);

        let open = open_core_authorized_regular_transaction_cursor_from_open_v0(open);
        assert_eq!(open.open.authorized.validation_id, expected_id);
        assert_eq!(open.open.authorized.route, PayloadValidationRouteV0::Synced);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute first synced production transaction");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute second synced production transaction");
        let finished = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .expect("finish synced production post-state plan");
        assert_eq!(finished.authorized.validation_id, expected_id);
        assert_eq!(finished.authorized.route, PayloadValidationRouteV0::Synced);

        let comparison = match_finished_core_authorized_regular_runtime_commitments_v0(finished);
        let matched = comparison
            .as_ref()
            .expect("synced production commitments match the exact Core target");
        assert_eq!(matched.finished.authorized.validation_id, expected_id);
        assert_eq!(
            matched.finished.authorized.route,
            PayloadValidationRouteV0::Synced
        );
        let classified =
            classify_core_authorized_regular_runtime_commitment_comparison_v0(comparison);
        let matched = match classified {
            ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::Valid(matched) => matched,
            other => panic!("honest synced production target misclassified: {other:?}"),
        };
        assert_eq!(matched.finished.authorized.validation_id, expected_id);
        assert_eq!(
            matched.finished.authorized.route,
            PayloadValidationRouteV0::Synced
        );
        assert_eq!(
            matched.validated_commitments.block_id(),
            expected_id.block_id()
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
        let committed_after = store
            .store
            .load_or_migrate()
            .expect("read committed state after synced process-local disposition");
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn production_comparator_disposition_terminalizes_only_state_and_receipts_mismatch() {
        let store = test_store();

        for (state_root, receipts_root, expected) in [
            (
                Some(StateRoot::new([0xd1; 32])),
                None,
                CoreAuthorizedRegularComputedRootMismatchV0::State,
            ),
            (
                None,
                Some(ReceiptsRoot::new([0xd2; 32])),
                CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
            ),
            (
                Some(StateRoot::new([0xd3; 32])),
                Some(ReceiptsRoot::new([0xd4; 32])),
                CoreAuthorizedRegularComputedRootMismatchV0::State,
            ),
        ] {
            let honest = honest_runtime_profile(&store);
            let honest_state_root = honest.header.state_root();
            let honest_receipts_root = honest.header.receipts_root();
            let profile = replace_profile_execution_roots(
                honest,
                state_root.unwrap_or(honest_state_root),
                receipts_root.unwrap_or(honest_receipts_root),
            );
            let expected_block_id = profile.header.id();
            let classified = classify_core_authorized_regular_runtime_commitment_comparison_v0(
                match_finished_core_authorized_regular_runtime_commitments_v0(
                    finish_production_runtime_plan(&store, &profile),
                ),
            );
            let failed = match classified {
                ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::DeterministicallyInvalid(
                    failed,
                ) => failed,
                other => panic!("computed root mismatch misclassified: {other:?}"),
            };
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(expected)
            );
            assert_eq!(
                failed.finished.authorized.validation_id.block_id(),
                expected_block_id
            );
            assert_eq!(
                failed.finished.authorized.route,
                PayloadValidationRouteV0::Proposal
            );
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_comparator_disposition_keeps_internal_drift_fail_stop() {
        let store = test_store();
        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.applied[0].native_receipt = NativeTransactionReceiptFactsV0::internal_operation();
        let classified = classify_core_authorized_regular_runtime_commitment_comparison_v0(
            match_finished_core_authorized_regular_runtime_commitments_v0(finished),
        );
        assert_eq!(
            format!("{classified:?}"),
            "ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0 { disposition: \"invariant_fault\", retains_exact_owner: true, .. }"
        );
        let failed = match classified {
            ClassifiedCoreAuthorizedRegularRuntimeCommitmentsV0::InvariantFault(failed) => failed,
            other => panic!("internal comparator drift misclassified: {other:?}"),
        };
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            )
        );
        assert_eq!(
            failed.finished.authorized.route,
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_four_root_comparator_retains_exact_plan_on_state_and_receipt_mismatch() {
        let store = test_store();

        let honest = honest_runtime_profile(&store);
        let honest_receipts_root = honest.header.receipts_root();
        let profile = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xe3; 32]),
            honest_receipts_root,
        );
        let expected_block_id = profile.header.id();
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(
            finish_production_runtime_plan(&store, &profile),
        )
        .err()
        .expect("state-root substitution must retain an owning comparison failure");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State,
            )
        );
        assert_eq!(
            failed.finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(
            format!("{failed:?}"),
            "FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0 { retains_exact_finished_plan: true, .. }"
        );

        let honest = honest_runtime_profile(&store);
        let honest_state_root = honest.header.state_root();
        let profile = replace_profile_execution_roots(
            honest,
            honest_state_root,
            ReceiptsRoot::new([0xe4; 32]),
        );
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(
            finish_production_runtime_plan(&store, &profile),
        )
        .err()
        .expect("receipts-root substitution must retain an owning comparison failure");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
            )
        );

        let honest = honest_runtime_profile(&store);
        let profile = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xe5; 32]),
            ReceiptsRoot::new([0xe6; 32]),
        );
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(
            finish_production_runtime_plan(&store, &profile),
        )
        .err()
        .expect("state plus receipts substitutions retain one deterministic priority");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State,
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_four_root_comparator_treats_late_static_root_drift_as_invariant() {
        let store = test_store();

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let header = finished.authorized.header.clone();
        replace_finished_header_roots(
            &mut finished,
            PayloadDigest::new([0xe7; 32]),
            header.state_root(),
            header.receipts_root(),
            header.evidence_root(),
        );
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("late payload-root drift is an internal source invariant");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedPayloadRootDrift,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let header = finished.authorized.header.clone();
        replace_finished_header_roots(
            &mut finished,
            header.payload_root(),
            header.state_root(),
            header.receipts_root(),
            EvidenceRoot::new([0xe8; 32]),
        );
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("late evidence-root drift is an internal source invariant");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedEvidenceRootDrift,
            )
        );
        assert_ne!(
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PayloadRootComputation,
            ),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedPayloadRootDrift,
            )
        );
        assert_ne!(
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::ReceiptsRootComputation,
            ),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::Receipts,
            )
        );
        assert_ne!(
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::EvidenceRootComputation,
            ),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::AuthorizedEvidenceRootDrift,
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_four_root_comparator_prioritizes_invariants_over_root_mismatch() {
        let store = test_store();

        let honest = honest_runtime_profile(&store);
        let honest_receipts_root = honest.header.receipts_root();
        let profile = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xe9; 32]),
            honest_receipts_root,
        );
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let header = finished.authorized.header.clone();
        let foreign_proposer = finished
            .authorized
            .context
            .validator_set
            .validators()
            .iter()
            .map(Validator::id)
            .find(|id| *id != header.proposer_id())
            .expect("fixture has another authenticated proposer");
        finished.authorized.header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            foreign_proposer,
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            header.payload_root(),
            header.state_root(),
            header.receipts_root(),
            header.evidence_root(),
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .expect("replace the retained proposer after authorization");
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("late BlockId drift must outrank the state-root mismatch");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            )
        );

        let honest = honest_runtime_profile(&store);
        let honest_receipts_root = honest.header.receipts_root();
        let profile = replace_profile_execution_roots(
            honest,
            StateRoot::new([0xea; 32]),
            honest_receipts_root,
        );
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let mut parameter_fields = finished.authorized.context.parameters.fields();
        parameter_fields.max_block_bytes = parameter_fields
            .max_block_bytes
            .checked_sub(1)
            .expect("fixture maximum is positive");
        finished.authorized.context.parameters = ConsensusParametersV0::new(parameter_fields)
            .expect("construct a valid foreign static parameter value");
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("late static context drift must outrank the state-root mismatch");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::StaticCommitmentRevalidation,
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_four_root_comparator_rejects_internal_receipt_and_plan_drift() {
        let store = test_store();

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.applied[0].runtime_receipt.mutations[0]
            .value_bytes
            .push(b' ');
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("post-plan receipt mutation drift must retain an owning failure");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let mutation = finished.applied[1]
            .runtime_receipt
            .mutations
            .iter_mut()
            .find(|mutation| mutation.object_key_hex == account_key("did:client:1"))
            .expect("last receipt retains the final client-account mutation");
        let mut account: AccountV1 =
            serde_json::from_slice(&mutation.value_bytes).expect("decode final receipt account");
        account.balance = account
            .balance
            .checked_add(1)
            .expect("test balance increment");
        mutation.value_bytes =
            serde_json::to_vec(&account).expect("encode canonical post-plan receipt drift");
        let stored = NodeObjectMutation {
            object_key_hex: mutation.object_key_hex.clone(),
            object_type: mutation.object_type.clone(),
            expected_version: mutation.expected_version,
            next_version: mutation.next_version,
            value_bytes: mutation.value_bytes.clone(),
        }
        .into_stored();
        finished
            .changes
            .insert(stored.object_key_hex.clone(), stored);
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("post-plan receipt plus delta drift must not detach the JMT plan");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateDelta,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.applied[0].native_receipt = NativeTransactionReceiptFactsV0::internal_operation();
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("native receipt drift must retain an owning comparison failure");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.post_state_update.version = 3;
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("plan-version drift must retain an owning comparison failure");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        finished.post_state_update.root_hash = [0xdb; 32].into();
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("plan-root drift must fail the complete plan seal");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        assert!(!finished
            .post_state_update
            .tree_update_batch
            .node_batch
            .nodes()
            .is_empty());
        finished
            .post_state_update
            .tree_update_batch
            .node_batch
            .clear();
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("plan-node drift must fail the complete plan seal");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
            )
        );

        let profile = honest_runtime_profile(&store);
        let mut finished = finish_production_runtime_plan(&store, &profile);
        let stale_index = finished
            .post_state_update
            .tree_update_batch
            .stale_node_index_batch
            .iter()
            .next()
            .cloned()
            .expect("runtime plan contains a stale-node index");
        assert!(finished
            .post_state_update
            .tree_update_batch
            .stale_node_index_batch
            .remove(&stale_index));
        let failed = match_finished_core_authorized_regular_runtime_commitments_v0(finished)
            .err()
            .expect("plan stale-index drift must fail the complete plan seal");
        assert_eq!(
            failed.cause,
            CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_runtime_failure_destroys_prior_delta_and_retains_one_exact_failed_attempt() {
        let store = test_store();
        let profile = fixture_profile_with_second_runtime_reject(store.parent_state_root);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let expected_outer = profile.body.application_payload().transactions()[1].clone();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open production rejection cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("first exact runtime transaction succeeds before rejection");
        assert_eq!(open.next_transaction_index, 1);
        assert!(!open.changes.is_empty());
        let failed = attempt_next_production_runtime_transaction(open)
            .err()
            .expect("second exact runtime transaction deterministically rejects");
        assert_eq!(
            format!("{failed:?}"),
            "FailedCoreAuthorizedRegularRuntimeAttemptV0 { pending_explicit_snapshot_finish: true, .. }"
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        let finished = finish_failed_core_authorized_regular_runtime_attempt_v0(failed);
        assert_eq!(finished.failed_transaction_index, 1);
        assert_eq!(finished.authorized.validation_id, expected_id);
        assert_eq!(finished.exact_outer_bytes, expected_outer);
        assert_eq!(finished.context.target_block_id, expected_id.block_id());
        assert_eq!(finished.transaction.sender, "did:client:1");
        match &finished.cause {
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(
                CoreAuthorizedRegularRuntimeStepFailureV0::Runtime(attempt),
            ) => assert_eq!(
                attempt
                    .deterministic_failure_v0()
                    .expect("deterministic runtime rejection")
                    .code(),
                "insufficient_balance"
            ),
            _ => panic!("expected deterministic real runtime failure after clean close"),
        }
        assert_runtime_fixture_objects_absent(&store.store);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        let promoted = promote_closed_core_authorized_regular_runtime_failure_v0(finished);
        assert_eq!(
            promoted.outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(promoted.outcome.code(), "runtime_transaction_reject");
        assert_eq!(promoted.outcome.successful_execution(), None);
        assert_eq!(promoted.failed.authorized.validation_id, expected_id);
        assert_eq!(promoted.failed.failed_transaction_index, 1);
    }

    #[test]
    fn production_snapshot_finish_failure_outranks_real_runtime_rejection() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions.reverse();
        let profile = replace_profile_transactions(profile, transactions);
        let expected_outer = profile.body.application_payload().transactions()[0].clone();
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open reversed production runtime cursor");
        let mut prepared = expect_prepared_runtime_transaction(
            prepare_next_core_authorized_regular_payload_v0(open)
                .expect("prepare reversed exact runtime transaction"),
        );
        prepared
            .open
            .open
            .snapshot
            .inject_finish_failure_for_test_v0();
        let failed = attempt_prepared_core_authorized_runtime_transaction_v0(prepared)
            .err()
            .expect("reversed first transaction must reject");
        let closed = finish_failed_core_authorized_regular_runtime_attempt_v0(failed);
        assert!(matches!(
            closed.cause,
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(closed.authorized.validation_id, expected_id);
        assert_eq!(closed.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(closed.failed_transaction_index, 0);
        assert_eq!(closed.exact_outer_bytes, expected_outer);
        assert!(!closed.exact_inner_bytes.is_empty());
        assert_eq!(closed.context.target_block_id, profile.header.id());
        assert_eq!(closed.transaction.sender, "did:client:1");
        assert_runtime_fixture_objects_absent(&store.store);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        let promoted = promote_closed_core_authorized_regular_runtime_failure_v0(closed);
        assert_eq!(promoted.outcome.terminal_disposition(), None);
        assert_eq!(
            promoted.outcome.code(),
            "native_regular_runtime_attempt_invariant"
        );
        assert_eq!(promoted.failed.authorized.validation_id, expected_id);
        assert_eq!(promoted.failed.failed_transaction_index, 0);

        let source = include_str!("native_payload_validation.rs");
        let typed_mapping = source
            .split_once("fn authenticated_runtime_read_outcome_facts_v0(")
            .expect("typed authenticated runtime failure mapping")
            .1
            .split_once("\n}\n")
            .expect("typed authenticated runtime failure mapping body")
            .0;
        for required in [
            "AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable",
            "AuthenticatedRuntimeReadFailureV0::StorageUnavailable",
            "AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable",
            "AuthenticatedRuntimeReadFailureV0::Pruned",
            "AuthenticatedRuntimeReadFailureV0::SourceMismatch",
            "AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant",
            "AuthenticatedRuntimeReadFailureV0::HostInvariant",
        ] {
            assert!(typed_mapping.contains(required));
        }
        assert!(!typed_mapping.contains("format!("));
        assert!(!typed_mapping.contains("to_string("));
    }

    #[test]
    fn production_host_policy_is_order_independent_but_cannot_be_spliced() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut reversed_signers = store.authorized_signers.clone();
        reversed_signers.reverse();
        let reordered_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: TEST_CHAIN.as_str(),
            authorized_signers: &reversed_signers,
        };
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &reordered_host,
            core_validation_request(&profile),
        )
        .expect("canonical signer commitment is independent of input order");
        let prepared = expect_prepared_runtime_transaction(
            prepare_next_core_authorized_regular_payload_v0(open)
                .expect("reordered canonical policy still verifies exact signer"),
        );
        assert_eq!(prepared.context.signer_id, "did:operator:1");
        drop(prepared);

        let mut foreign_signers = store.authorized_signers.clone();
        foreign_signers[0].signer_role = "hepta".to_string();
        let foreign_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: TEST_CHAIN.as_str(),
            authorized_signers: &foreign_signers,
        };
        let expected_id = core_validation_request(&profile).id();
        let failure = open_core_authorized_regular_transaction_cursor_v0(
            &foreign_host,
            core_validation_request(&profile),
        )
        .err()
        .expect("foreign host policy must retain the exact Core request");
        assert_eq!(failure.owner.request.id(), expected_id);
        assert!(matches!(
            failure.cause,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "native validation host signer policy differs from application store",
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_decode_failures_remain_owned_until_snapshot_finish() {
        let store = test_store();

        let empty =
            replace_profile_transactions(fixture_profile(store.parent_state_root, 0), Vec::new());
        let empty_failure = first_production_decode_failure(&store, &empty);
        assert_eq!(
            empty_failure.authorized.validation_id.block_id(),
            empty.header.id()
        );
        assert_eq!(empty_failure.next_transaction_index, 0);
        assert!(empty_failure.changes.is_empty());
        assert!(empty_failure.applied.is_empty());
        assert!(matches!(
            empty_failure.cause,
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(
                CoreAuthorizedRegularTransactionDecodeCauseV0::Exhausted,
            )
        ));

        let malformed = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![b"{".to_vec()],
        );
        let malformed_failure = first_production_decode_failure(&store, &malformed);
        assert_eq!(
            malformed_failure.authorized.validation_id.block_id(),
            malformed.header.id()
        );
        assert!(matches!(
            malformed_failure.cause,
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(
                CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope,
            )
        ));

        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-production-non-runtime".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            "trnm.poco.application-operation.v0",
            b"{}",
        );
        let non_runtime = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&non_runtime),
        )
        .expect("open exact non-runtime routing cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("strictly verified non-runtime payload must remain routable")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("non-runtime payload must not enter the runtime carrier")
            }
        };
        assert_eq!(routed.index, 0);
        assert_eq!(routed.next_transaction_index, 1);
        assert_eq!(routed.open.next_transaction_index, 0);
        assert_eq!(routed.exact_outer_bytes, exact_outer);
        assert_eq!(routed.exact_inner_bytes, b"{}");
        assert_eq!(
            routed.envelope.payload_type,
            "trnm.poco.application-operation.v0"
        );
        assert_eq!(routed.context.target_block_id, non_runtime.header.id());
        assert_eq!(routed.context.signer_id, "did:operator:1");
        assert_eq!(routed.context.payload_len, 2);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(routed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_non_runtime_dispatch_consumes_the_exact_owner_into_a_closed_family() {
        let cases = [
            (
                crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                "poco",
            ),
            (
                crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
                "validator",
            ),
            ("trnm.unsupported.native-family.v0", "unsupported"),
        ];

        for (case, expected_family) in cases {
            let store = test_store();
            let exact_outer = signed_envelope_bytes(
                TEST_CHAIN.as_str(),
                format!("native-production-dispatch-{expected_family}"),
                81,
                "did:operator:1",
                "operator",
                1,
                1_700_000_000_000,
                1_700_000_100_000,
                case,
                b"{}",
            );
            let profile = replace_profile_transactions(
                fixture_profile(store.parent_state_root, 0),
                vec![exact_outer.clone()],
            );
            let expected_id = profile.header.id();
            let open = open_core_authorized_regular_transaction_cursor_v0(
                &test_native_validation_host(&store),
                core_validation_request(&profile),
            )
            .expect("open exact non-runtime dispatch cursor");
            let prepared = match prepare_next_core_authorized_regular_payload_v0(open) {
                Ok(prepared) => prepared,
                Err(failed) => {
                    let closed =
                        finish_failed_core_authorized_regular_transaction_decode_v0(failed);
                    panic!(
                        "strict non-runtime dispatch failed for {case}: {:?}",
                        closed.cause
                    );
                }
            };
            let routed = match prepared {
                PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
                PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                    panic!("non-runtime family entered runtime")
                }
            };
            let (actual_family, routed) =
                match dispatch_core_authorized_non_runtime_payload_v0(routed) {
                    DispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(owner) => {
                        ("poco", owner.routed)
                    }
                    DispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(owner) => {
                        ("validator", owner.routed)
                    }
                    DispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(owner) => {
                        ("unsupported", owner.routed)
                    }
                };
            assert_eq!(actual_family, expected_family);
            assert_eq!(routed.envelope.payload_type, case);
            assert_eq!(routed.exact_outer_bytes, exact_outer);
            assert_eq!(routed.context.target_block_id, expected_id);
            assert_eq!(routed.open.next_transaction_index, 0);
            assert_eq!(routed.next_transaction_index, 1);
            drop(routed);
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }
    }

    #[test]
    fn production_non_runtime_semantic_decode_retains_exact_family_owners() {
        let cases = [
            (
                crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                "native-semantic-poco",
                br#"{"schema":"trnm_poco_application_operation_v0","target_height":2,"expected_state_revision":0,"body":{"kind":"register_future_candidate","validator_id_hex":"00","target_epoch":1,"previous_registration_nonce":null,"predecessor_history_head_hex":"00","proof_cev0_hex":"","registration_decision_id_hex":"00"},"semantic_changes":[],"nullifier_non_membership_checks":[],"nullifier_insertions":[]}"#.as_slice(),
                "poco",
            ),
            (
                crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
                "native-semantic-validator",
                br#"{"schema":"trnm_validator_set_transition_v1","chain_id":"trnm-native-input-session-test","transition_id":"native-semantic-validator","base_validator_set_hash_hex":"00","activation_height":4,"target_validators":[],"new_validator_proofs":[]}"#.as_slice(),
                "validator",
            ),
            (
                "trnm.unsupported.native-family.v0",
                "native-semantic-unsupported",
                b"{}".as_slice(),
                "unsupported",
            ),
        ];

        for (payload_type, command_id, payload, expected_family) in cases {
            let store = test_store();
            let exact_outer = signed_envelope_bytes(
                TEST_CHAIN.as_str(),
                command_id.to_string(),
                81,
                "did:operator:1",
                "operator",
                1,
                1_700_000_000_000,
                1_700_000_100_000,
                payload_type,
                payload,
            );
            let profile = replace_profile_transactions(
                fixture_profile(store.parent_state_root, 0),
                vec![exact_outer.clone()],
            );
            let expected_id = profile.header.id();
            let open = open_core_authorized_regular_transaction_cursor_v0(
                &test_native_validation_host(&store),
                core_validation_request(&profile),
            )
            .expect("open semantic-decode cursor");
            let routed = match prepare_next_core_authorized_regular_payload_v0(open)
                .expect("prepare semantic-decode payload")
            {
                PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
                PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                    panic!("non-runtime semantic payload entered runtime")
                }
            };
            let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
                dispatch_core_authorized_non_runtime_payload_v0(routed),
            )
            .unwrap_or_else(|_| panic!("semantic decode failed for {expected_family}"));
            let (actual_family, routed) = match decoded {
                DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(decoded) => {
                    assert_eq!(decoded.operation.target_height(), 2);
                    ("poco", decoded.owner.routed)
                }
                DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(
                    decoded,
                ) => {
                    assert_eq!(decoded.transition.transition_id, command_id);
                    ("validator", decoded.owner.routed)
                }
                DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(owner) => {
                    ("unsupported", owner.routed)
                }
            };
            assert_eq!(actual_family, expected_family);
            assert_eq!(routed.exact_outer_bytes, exact_outer);
            assert_eq!(routed.exact_inner_bytes, payload);
            assert_eq!(routed.context.target_block_id, expected_id);
            assert_eq!(routed.open.next_transaction_index, 0);
            drop(routed);
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }
    }

    #[test]
    fn production_non_runtime_semantic_decode_failure_retains_exact_owner() {
        let store = test_store();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-semantic-invalid-poco".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            b"{}",
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open invalid semantic-decode cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare invalid semantic-decode payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("invalid non-runtime semantic payload entered runtime")
            }
        };
        let failed = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .err()
        .expect("invalid PoCO semantics must retain the family owner");
        let closed = finish_failed_core_authorized_non_runtime_semantic_decode_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("malformed PoCO semantics did not become terminal invalid")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            outcome.code(),
            "native_regular_poco_operation_decode_invalid"
        );
        assert_eq!(
            outcome.generation().get(),
            core_validation_request(&profile).id().generation()
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                owner,
                cause,
            } => {
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Decode(
                        CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::InvalidPocoApplicationOperation,
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                ..
            } => {
                panic!("PoCO semantic failure changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, b"{}");
        assert_eq!(owner.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(owner.context.target_block_id, expected_id);
        assert_eq!(owner.index, 0);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn non_runtime_terminal_failure_retains_prior_runtime_evidence_without_artifacts() {
        let store = test_store();
        let base = fixture_profile(store.parent_state_root, 0);
        let first_runtime = base.body.application_payload().transactions()[0].clone();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-semantic-after-runtime".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            b"{}",
        );
        let profile = replace_profile_transactions(base, vec![first_runtime, exact_outer.clone()]);
        let expected_validation_id = core_validation_request(&profile).id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open mixed runtime/non-runtime cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("first runtime transaction succeeds before non-runtime failure");
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied.len(), 1);
        assert!(!open.changes.is_empty());
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare second non-runtime payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("second mixed-body payload entered runtime")
            }
        };
        let failed = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .err()
        .expect("malformed second PoCO operation must retain the mixed-body owner");
        let closed = finish_failed_core_authorized_non_runtime_semantic_decode_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("mixed-body semantic failure changed terminal class")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                owner,
                cause,
            } => {
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Decode(
                        CoreAuthorizedNonRuntimeSemanticDecodeCauseV0::InvalidPocoApplicationOperation,
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                ..
            } => panic!("mixed-body PoCO failure changed family"),
        };
        assert_eq!(owner.authorized.validation_id, expected_validation_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.cursor_next_transaction_index, 1);
        assert_eq!(owner.decoded_next_transaction_index, 2);
        assert_eq!(owner.applied.len(), 1);
        assert!(!owner.changes.is_empty());
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn synced_non_runtime_terminal_mapping_derives_route_and_generation_from_owner() {
        let store = test_store();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "synced-native-semantic-invalid-poco".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            b"{}",
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let job = match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("synced non-runtime fixture did not produce a route-bound job"),
        };
        let expected_validation_id = job.request.id();
        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            _ => panic!("synced non-runtime validation did not open"),
        };
        let open = open_core_authorized_regular_transaction_cursor_from_open_v0(open);
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare synced non-runtime payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("synced non-runtime payload entered runtime")
            }
        };
        let failed = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .err()
        .expect("malformed synced PoCO operation must retain its owner");
        let closed = finish_failed_core_authorized_non_runtime_semantic_decode_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("synced semantic failure changed terminal class")
            }
        };
        assert_eq!(
            outcome.generation().get(),
            expected_validation_id.generation()
        );
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                owner, ..
            } => owner,
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                ..
            } => panic!("synced PoCO failure changed family"),
        };
        assert_eq!(owner.authorized.validation_id, expected_validation_id);
        assert_eq!(owner.authorized.route, PayloadValidationRouteV0::Synced);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_semantic_decode_finish_failure_outranks_pending_decode_cause() {
        let store = test_store();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-semantic-finish-failure".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            b"{}",
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open semantic finish-failure cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare semantic finish-failure payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("semantic finish-failure payload entered runtime")
            }
        };
        let mut failed = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .err()
        .expect("invalid PoCO operation must retain pending semantic failure");
        match failed.as_mut() {
            super::FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                owner,
                ..
            } => owner
                .routed
                .open
                .open
                .snapshot
                .inject_finish_failure_for_test_v0(),
            super::FailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                ..
            } => panic!("semantic finish-failure fixture changed family"),
        }
        let closed = finish_failed_core_authorized_non_runtime_semantic_decode_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("snapshot finish invariant was downgraded during terminal mapping"),
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_semantic_snapshot_host_invariant"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::PocoApplication {
                owner,
                cause,
            } => {
                assert!(matches!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeSemanticDecodeCauseV0::Snapshot(
                        AuthenticatedRuntimeReadFailureV0::HostInvariant {
                            stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                            ..
                        },
                    )
                ));
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeSemanticDecodeV0::ValidatorTransition {
                ..
            } => {
                panic!("closed semantic finish failure changed family")
            }
        };
        assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_poco_family_attempt_uses_exact_parent_projection_without_publishing_mutation() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-attempt".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let decoded = decode_only_non_runtime_family(&store, &profile);
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .expect("authorize PoCO family attempt against retained projection");
        let attempted = match attempted {
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted) => attempted,
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(_) => {
                panic!("PoCO family attempt changed family")
            }
        };
        assert_eq!(attempted.overlay.target_height(), Height::new(2));
        assert_eq!(attempted.overlay.source_version(), 1);
        assert_eq!(attempted.overlay.source_root(), store.parent_state_root);
        assert_eq!(attempted.overlay.operation_count(), 1);
        assert_eq!(attempted.decoded.operation.target_height(), 2);
        assert_eq!(
            attempted.decoded.owner.routed.exact_outer_bytes,
            exact_outer
        );
        assert_eq!(
            attempted.decoded.owner.routed.exact_inner_bytes,
            exact_inner
        );
        assert_eq!(
            attempted.decoded.owner.routed.context.target_block_id,
            expected_id
        );
        assert_eq!(attempted.decoded.owner.routed.index, 0);
        assert_eq!(
            attempted.decoded.owner.routed.open.next_transaction_index,
            0
        );
        assert_eq!(attempted.decoded.owner.routed.next_transaction_index, 1);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(attempted);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection,
            "authorized in-memory overlay must not publish a parent-state mutation"
        );
    }

    #[test]
    fn production_poco_family_write_seal_retains_owner_without_planning_or_advance() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-write-seal".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .expect("authorize PoCO family write-seal attempt");
        let sealed = seal_core_authorized_non_runtime_family_writes_v0(attempted)
            .expect("seal owner-bound PoCO family writes");
        let sealed = match sealed {
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication(sealed) => {
                sealed
            }
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition(_) => {
                panic!("PoCO family write seal changed family")
            }
        };
        assert_eq!(sealed.plan.source_version(), 1);
        assert_eq!(sealed.plan.source_root(), store.parent_state_root);
        assert_eq!(sealed.plan.target_height(), Height::new(2));
        assert_eq!(sealed.plan.operation_count(), 1);
        assert!(sealed
            .plan
            .binds_exact_operations_v0(std::slice::from_ref(&exact_inner)));
        let expected_writes =
            crate::poco_transition::auth_writes_from_sealed_poco_application_v0(&sealed.plan)
                .expect("rederive sealed PoCO writes");
        assert_eq!(sealed.writes, expected_writes);
        assert!(!sealed.writes.is_empty());
        let inert_plan = sealed
            .attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .snapshot
            .plan_exact_next_auth_update_v0(sealed.writes.clone())
            .expect("independently plan sealed PoCO writes without persistence");
        assert_eq!(inert_plan.version, 2);
        assert_ne!(
            <[u8; 32]>::from(inert_plan.root_hash),
            store.parent_state_root
        );
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .open
                .next_transaction_index,
            0
        );
        assert_eq!(
            sealed.attempted.decoded.owner.routed.next_transaction_index,
            1
        );
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .open
                .open
                .authorized
                .route,
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .context
                .target_block_id,
            expected_id
        );
        assert!(sealed
            .attempted
            .decoded
            .owner
            .routed
            .open
            .changes
            .is_empty());
        assert!(sealed
            .attempted
            .decoded
            .owner
            .routed
            .open
            .applied
            .is_empty());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(inert_plan);
        drop(sealed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection,
            "family write sealing must not publish PoCO state"
        );
    }

    #[test]
    fn production_cursor_advances_two_ordered_poco_operations_on_one_evolving_prefix() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_two_valid_poco_application_operations(&store, &base);
        let exact_outer = exact_inner
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    format!("native-poco-successive-{index}"),
                    81,
                    "did:operator:1",
                    "operator",
                    u64::try_from(index + 1).unwrap(),
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    raw,
                )
            })
            .collect::<Vec<_>>();
        let profile = replace_profile_transactions(base, exact_outer.clone());
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open successive PoCO cursor");
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied_non_runtime.len(), 1);
        assert_eq!(
            open.poco_prefix.as_ref().unwrap().overlay.operation_count(),
            1
        );
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 2);
        assert_eq!(open.applied_non_runtime.len(), 2);
        assert!(open.applied.is_empty());
        assert!(open.changes.is_empty());
        let prefix = open.poco_prefix.as_ref().expect("retain final PoCO prefix");
        assert_eq!(prefix.overlay.operation_count(), 2);
        let source_revision =
            crate::poco_application::PocoApplicationOperationV0::decode_exact(&exact_inner[0])
                .unwrap()
                .expected_state_revision();
        assert_eq!(prefix.overlay.expected_state_revision(), source_revision);
        assert!(exact_inner.iter().all(|raw| {
            crate::poco_application::PocoApplicationOperationV0::decode_exact(raw)
                .map(|operation| operation.expected_state_revision() == source_revision)
                .unwrap_or(false)
        }));
        assert_eq!(prefix.plan.operation_count(), 2);
        assert!(prefix.plan.binds_exact_operations_v0(&exact_inner));
        let expected_writes =
            crate::poco_transition::auth_writes_from_sealed_poco_application_v0(&prefix.plan)
                .expect("rederive complete PoCO prefix writes");
        assert_eq!(prefix.writes, expected_writes);
        for (expected_index, applied) in open.applied_non_runtime.iter().enumerate() {
            match applied {
                super::AppliedCoreAuthorizedNonRuntimePayloadV0::PocoApplication {
                    index,
                    exact_outer_bytes,
                    exact_inner_bytes,
                    ..
                } => {
                    assert_eq!(*index, u32::try_from(expected_index).unwrap());
                    assert_eq!(exact_outer_bytes, &exact_outer[expected_index]);
                    assert_eq!(exact_inner_bytes, &exact_inner[expected_index]);
                }
                super::AppliedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition { .. } => {
                    panic!("successive PoCO provenance changed family")
                }
            }
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
        drop(open);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_second_poco_duplicate_closes_with_first_prefix_retained() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (_, exact_inner) = author_valid_poco_application_operation(&store, &base);
        let exact_outer = (0..2)
            .map(|index| {
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    format!("native-poco-duplicate-{index}"),
                    81,
                    "did:operator:1",
                    "operator",
                    index + 1,
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    &exact_inner,
                )
            })
            .collect::<Vec<_>>();
        let profile = replace_profile_transactions(base, exact_outer);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open duplicate PoCO cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare duplicate second PoCO payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("duplicate second PoCO payload entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode duplicate second PoCO payload");
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .err()
            .expect("duplicate second PoCO operation must fail");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                cause:
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoOperation(
                                crate::poco_application::PocoApplicationDeterministicInvalidV0::DuplicateOperation,
                            ),
                        ),
                    ),
                ..
            } => owner,
            _ => panic!("duplicate second PoCO operation changed failure classification"),
        };
        assert_eq!(owner.cursor_next_transaction_index, 1);
        assert_eq!(owner.decoded_next_transaction_index, 2);
        assert_eq!(owner.applied_non_runtime.len(), 1);
        let prefix = owner
            .poco_prefix
            .as_ref()
            .expect("retain first PoCO prefix");
        assert_eq!(prefix.overlay.operation_count(), 1);
        assert_eq!(prefix.plan.operation_count(), 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_second_poco_seal_rejects_prior_prefix_write_drift_before_advance() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_two_valid_poco_application_operations(&store, &base);
        let exact_outer = exact_inner
            .iter()
            .enumerate()
            .map(|(index, raw)| {
                signed_envelope_bytes(
                    TEST_CHAIN.as_str(),
                    format!("native-poco-prefix-drift-{index}"),
                    81,
                    "did:operator:1",
                    "operator",
                    u64::try_from(index + 1).unwrap(),
                    1_700_000_000_000,
                    1_700_000_100_000,
                    crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
                    raw,
                )
            })
            .collect();
        let profile = replace_profile_transactions(base, exact_outer);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open prior-prefix-drift cursor");
        let mut open = advance_next_production_non_runtime_payload(open);
        open.poco_prefix
            .as_mut()
            .expect("first PoCO prefix")
            .writes
            .clear();
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare second PoCO after prior-prefix drift")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("second PoCO after prior-prefix drift entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode second PoCO after prior-prefix drift");
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .expect("family apply uses the still-valid unsealed PoCO prefix");
        let failed = seal_core_authorized_non_runtime_family_writes_v0(attempted)
            .err()
            .expect("prior prefix write drift must fail-stop during whole-prefix seal");
        assert!(matches!(
            failed,
            super::FailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                reason: CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding,
                ..
            }
        ));
        let closed = finish_failed_core_authorized_non_runtime_family_write_seal_v0(failed);
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                owner,
                cause:
                    ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding,
                    ),
                ..
            } => owner,
            _ => panic!("prior PoCO prefix write drift changed failure classification"),
        };
        assert_eq!(owner.cursor_next_transaction_index, 1);
        assert_eq!(owner.decoded_next_transaction_index, 2);
        assert_eq!(owner.applied_non_runtime.len(), 1);
        assert!(owner.poco_prefix.is_some());
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn production_runtime_between_poco_operations_preserves_prefix_and_runtime_delta() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let first_runtime = base.body.application_payload().transactions()[0].clone();
        let (_, exact_inner) = author_two_valid_poco_application_operations(&store, &base);
        let first_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-runtime-poco-first".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner[0],
        );
        let second_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-runtime-poco-second".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner[1],
        );
        let profile =
            replace_profile_transactions(base, vec![first_poco, first_runtime, second_poco]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open PoCO/runtime/PoCO cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute runtime item between PoCO operations");
        assert_eq!(open.next_transaction_index, 2);
        assert_eq!(open.applied.len(), 1);
        assert_eq!(open.applied_non_runtime.len(), 1);
        assert_eq!(
            open.poco_prefix.as_ref().unwrap().overlay.operation_count(),
            1
        );
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 3);
        assert_eq!(open.applied.len(), 1);
        assert_eq!(open.applied_non_runtime.len(), 2);
        assert!(!open.changes.is_empty());
        assert!(!open.applied[0].runtime_receipt.mutations.is_empty());
        let prefix = open
            .poco_prefix
            .as_ref()
            .expect("retain mixed final PoCO prefix");
        assert_eq!(prefix.overlay.operation_count(), 2);
        assert!(prefix.plan.binds_exact_operations_v0(&exact_inner));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        assert_runtime_fixture_objects_absent(&store.store);
        drop(open);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_complete_mixed_body_plans_runtime_and_final_poco_prefix_once() {
        let store = test_store_with_poco_application_authority();
        let committed_before = store.store.load_or_migrate().unwrap();
        let base = fixture_profile(store.parent_state_root, 0);
        let runtime = base.body.application_payload().transactions()[0].clone();
        let (_, poco_inner) = author_two_valid_poco_application_operations(&store, &base);
        let first_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-complete-poco-runtime-poco-first".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &poco_inner[0],
        );
        let second_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-complete-poco-runtime-poco-second".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &poco_inner[1],
        );
        let profile = replace_profile_transactions(base, vec![first_poco, runtime, second_poco]);
        let target_height = profile.header.height().get();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open complete mixed body cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute runtime item in complete mixed body");
        let open = advance_next_production_non_runtime_payload(open);
        let mut expected_writes = open
            .changes
            .values()
            .map(crate::authenticated_object_write)
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        expected_writes.extend(open.poco_prefix.as_ref().unwrap().writes.iter().cloned());
        let expected_plan = store
            .authenticated_parent
            .plan_put_value_set(target_height, expected_writes)
            .expect("independently plan complete mixed writes");

        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("finish one exact complete mixed-body plan");
        assert_eq!(finished.post_state_update.version, target_height);
        assert_eq!(
            finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        finished
            .post_state_update
            .verify_seal_v0(&finished.post_state_update_seal)
            .expect("verify complete mixed-body plan seal");
        assert_eq!(finished.applied.len(), 1);
        assert_eq!(finished.applied_non_runtime.len(), 2);
        assert!(!finished.changes.is_empty());
        match finished.final_poco.as_ref().unwrap() {
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(plan) => {
                assert_eq!(plan.operation_count(), 2);
                assert!(plan.binds_exact_operations_v0(&poco_inner));
            }
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(_) => {
                panic!("business operations became a scheduled cutoff write")
            }
        }
        assert!(finished.final_validator_lifecycle.is_none());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
        let committed_after = store.store.load_or_migrate().unwrap();
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn production_poco_validator_poco_keeps_independent_staged_prefixes() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (_, poco_inner) = author_two_valid_poco_application_operations(&store, &base);
        let validator_id = "native-poco-validator-poco";
        let validator_inner = valid_validator_transition_bytes(&store, validator_id);
        let first_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-validator-poco-first".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &poco_inner[0],
        );
        let validator = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            validator_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &validator_inner,
        );
        let second_poco = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-validator-poco-second".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &poco_inner[1],
        );
        let profile = replace_profile_transactions(base, vec![first_poco, validator, second_poco]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open PoCO/validator/PoCO cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 2);
        assert_eq!(
            open.validator_prefix
                .as_ref()
                .and_then(|prefix| prefix.lifecycle.pending_transition.as_ref())
                .map(|pending| pending.transition_id.as_str()),
            Some(validator_id)
        );
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 3);
        assert_eq!(open.applied_non_runtime.len(), 3);
        let poco_prefix = open.poco_prefix.as_ref().expect("retain final PoCO prefix");
        assert_eq!(poco_prefix.overlay.operation_count(), 2);
        assert!(poco_prefix.plan.binds_exact_operations_v0(&poco_inner));
        let validator_prefix = open
            .validator_prefix
            .as_ref()
            .expect("retain staged validator prefix");
        assert_eq!(validator_prefix.lifecycle.governance_sequence, 1);
        assert_eq!(
            validator_prefix
                .lifecycle
                .pending_transition
                .as_ref()
                .unwrap()
                .transition_id,
            validator_id
        );
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(open);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_complete_body_merges_runtime_poco_and_validator_replacements() {
        let store = test_store_with_poco_application_authority();
        let committed_before = store.store.load_or_migrate().unwrap();
        let profile = honest_all_family_complete_body_profile(&store);
        let expected_block_id = profile.header.id();
        let expected_state_root = profile.header.state_root();
        let expected_receipts_root = profile.header.receipts_root();
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
            complete_production_all_family_cursor(&store, &profile),
        )
        .expect("finish exact all-family complete-body plan for comparison");
        let classified = classify_core_authorized_regular_complete_body_commitment_comparison_v0(
            match_finished_core_authorized_regular_complete_body_commitments_v0(finished),
        );
        let matched = match classified {
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(matched) => matched,
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                _,
            )
            | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(_) => {
                panic!("honest all-family body did not match all four roots")
            }
        };
        assert_eq!(
            matched.finished.authorized.validation_id.block_id(),
            expected_block_id
        );
        assert_eq!(matched.validated_commitments.block_id(), expected_block_id);
        assert_eq!(
            StateRoot::new(matched.finished.post_state_update.root_hash.into()),
            expected_state_root
        );
        assert_eq!(matched.finished.applied.len(), 1);
        assert!(!matched.finished.changes.is_empty());
        assert_eq!(matched.finished.applied_non_runtime.len(), 3);
        match matched.finished.final_poco.as_ref().unwrap() {
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(plan) => {
                assert_eq!(plan.operation_count(), 2);
            }
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(_) => {
                panic!("business operations became a scheduled cutoff write")
            }
        }
        let lifecycle = matched
            .finished
            .final_validator_lifecycle
            .as_ref()
            .expect("retain final scheduled validator lifecycle");
        assert_eq!(lifecycle.governance_sequence, 1);
        assert_eq!(
            lifecycle
                .pending_transition
                .as_ref()
                .map(|pending| pending.transition_id.as_str()),
            Some("native-complete-poco-validator-poco")
        );
        let receipts = matched.native_execution.execution_receipts().receipts();
        assert_eq!(receipts.len(), 4);
        assert_eq!(
            receipts
                .iter()
                .map(|receipt| receipt.transaction_index())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        for index in [0usize, 2, 3] {
            assert_eq!(receipts[index].gas_used(), 0);
            assert_eq!(receipts[index].fee_charged(), 0);
            assert!(receipts[index].events().is_empty());
        }
        let runtime_receipt = &matched.finished.applied[0].runtime_receipt;
        assert_eq!(receipts[1].gas_used(), runtime_receipt.gas_used);
        assert_eq!(receipts[1].fee_charged(), runtime_receipt.fee_charged);
        assert_eq!(receipts[1].events().len(), runtime_receipt.events.len());
        assert_ne!(
            receipts[0].payload_leaf_hash(),
            receipts[2].payload_leaf_hash()
        );
        assert_eq!(
            matched
                .native_execution
                .execution_receipts()
                .receipts_root()
                .unwrap(),
            expected_receipts_root
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
        let committed_after = store.store.load_or_migrate().unwrap();
        assert_eq!(committed_after.height, committed_before.height);
        assert_eq!(committed_after.app_hash, committed_before.app_hash);
    }

    #[test]
    fn synced_complete_body_retains_its_exact_route_through_comparison() {
        let store = test_store_with_poco_application_authority();
        let profile = honest_all_family_complete_body_profile(&store);
        let job = match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("synced all-family fixture did not produce a job"),
        };
        let expected_id = job.request.id();
        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("synced all-family validation did not open: {other:?}"),
        };
        let open = open_core_authorized_regular_transaction_cursor_from_open_v0(open);
        let open = advance_next_production_non_runtime_payload(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute synced all-family runtime item");
        let open = advance_next_production_non_runtime_payload(open);
        let open = advance_next_production_non_runtime_payload(open);
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("finish synced all-family complete-body plan");
        let matched = match classify_core_authorized_regular_complete_body_commitment_comparison_v0(
            match_finished_core_authorized_regular_complete_body_commitments_v0(finished),
        ) {
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(matched) => matched,
            ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                _,
            )
            | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(_) => {
                panic!("honest synced all-family body did not match")
            }
        };
        assert_eq!(
            matched.finished.authorized.route,
            PayloadValidationRouteV0::Synced
        );
        assert_eq!(matched.finished.authorized.validation_id, expected_id);
        assert_eq!(
            matched.validated_commitments.block_id(),
            expected_id.block_id()
        );
        assert_eq!(
            matched
                .native_execution
                .execution_receipts()
                .receipts()
                .len(),
            profile.body.application_payload().transactions().len()
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn complete_body_root_mismatches_are_state_then_receipts_and_retain_owner() {
        fn classify_poisoned_roots(
            poison_state: Option<StateRoot>,
            poison_receipts: Option<ReceiptsRoot>,
        ) -> CoreAuthorizedRegularCommitmentComparisonCauseV0 {
            let store = test_store_with_poco_application_authority();
            let honest = honest_all_family_complete_body_profile(&store);
            let state_root = poison_state.unwrap_or_else(|| honest.header.state_root());
            let receipts_root = poison_receipts.unwrap_or_else(|| honest.header.receipts_root());
            let profile = replace_profile_execution_roots(honest, state_root, receipts_root);
            let expected_id = profile.header.id();
            let failed = match classify_all_family_complete_body(&store, &profile) {
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                    failed,
                ) => failed,
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(_)
                | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(_) => {
                    panic!("computed mixed root mismatch changed disposition")
                }
            };
            assert_eq!(
                failed.failed.finished.authorized.validation_id.block_id(),
                expected_id
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
            assert_runtime_fixture_objects_absent(&store.store);
            failed.failed.cause
        }

        assert!(matches!(
            classify_poisoned_roots(Some(StateRoot::new([0xd1; 32])), None),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State
            )
        ));
        assert!(matches!(
            classify_poisoned_roots(None, Some(ReceiptsRoot::new([0xd2; 32]))),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::Receipts
            )
        ));
        assert!(matches!(
            classify_poisoned_roots(
                Some(StateRoot::new([0xd3; 32])),
                Some(ReceiptsRoot::new([0xd4; 32])),
            ),
            CoreAuthorizedRegularCommitmentComparisonCauseV0::DeterministicMismatch(
                CoreAuthorizedRegularComputedRootMismatchV0::State
            )
        ));
    }

    #[test]
    fn durable_complete_body_invalid_bridge_freezes_state_and_receipts_reason_codes() {
        for (poison_state, poison_receipts, expected_reason, expected_code) in [
            (
                Some(StateRoot::new([0xe1; 32])),
                None,
                DurableDeterministicInvalidReasonV0::ComputedStateRootMismatch,
                1_u32,
            ),
            (
                None,
                Some(ReceiptsRoot::new([0xe2; 32])),
                DurableDeterministicInvalidReasonV0::ComputedReceiptsRootMismatch,
                2_u32,
            ),
        ] {
            let store = test_store_with_poco_application_authority();
            let owner = durable_invalid_all_family_complete_body_owner(
                &store,
                poison_state,
                poison_receipts,
            );
            let expected_route = owner.failed.finished.authorized.route;
            let expected_id = owner.failed.finished.authorized.validation_id;
            let prepared = match prepare_durable_invalid_complete_body_v0(owner) {
                Ok(prepared) => prepared,
                Err(failed) => panic!("durable root mismatch did not prepare: {failed:?}"),
            };
            assert_eq!(prepared.route(), expected_route);
            assert_eq!(prepared.validation_id(), expected_id);
            assert_eq!(prepared.reason(), expected_reason);
            assert_eq!(prepared.reason().code_v0(), expected_code);

            let parts = prepared.into_store_parts_v0();
            assert_eq!(parts.route(), expected_route);
            assert_eq!(parts.validation_id(), expected_id);
            assert_eq!(parts.reason(), expected_reason);
            assert_eq!(parts.reason().code_v0(), expected_code);
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }
    }

    #[test]
    fn durable_complete_body_invalid_seals_one_callback_pending_record_and_recovers_it() {
        let store = test_store_with_poco_application_authority();
        let owner = durable_invalid_all_family_complete_body_owner(
            &store,
            Some(StateRoot::new([0xe7; 32])),
            None,
        );
        let expected_route = owner.failed.finished.authorized.route;
        let expected_id = owner.failed.finished.authorized.validation_id;
        let prepared = prepare_durable_invalid_complete_body_v0(owner)
            .expect("prepare durable state-root mismatch");

        let committed_but_unconfirmed = match store
            .store
            .seal_durable_invalid_and_enqueue_callback_with_test_failpoint_v0(
                prepared,
                NativeValidationInvalidSealFailpointV0::AfterCommitBeforeReturn,
            ) {
            Ok(_) => panic!("post-commit response-loss failpoint unexpectedly returned success"),
            Err(failed) => failed,
        };
        assert!(matches!(
            committed_but_unconfirmed.cause(),
            NativeValidationInvalidSealFailureCauseV0::HostInvariant { .. }
        ));
        let prepared = committed_but_unconfirmed.into_prepared_v0();
        let sealed = match store
            .store
            .seal_durable_invalid_and_enqueue_callback_v0(prepared)
        {
            Ok(NativeValidationInvalidSealDecisionV0::Existing(job)) => job,
            Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(job)) => {
                panic!(
                    "exact durable-invalid retry duplicated callback-pending state {:?}",
                    job.state()
                )
            }
            Err(failed) => panic!("exact durable-invalid retry failed: {:?}", failed.cause()),
        };
        assert_eq!(sealed.route(), expected_route);
        assert_eq!(sealed.validation_id(), expected_id);
        assert_eq!(sealed.state(), NativeValidationJobStateV0::CallbackPending);

        let exact_reopen_profile = {
            let honest = honest_all_family_complete_body_profile(&store);
            let receipts_root = honest.header.receipts_root();
            replace_profile_execution_roots(honest, StateRoot::new([0xe7; 32]), receipts_root)
        };
        let exact_reopen = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            core_regular_validation_job_for_test_v0(core_validation_request(&exact_reopen_profile)),
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(existing) => {
                existing
            }
            other => panic!("callback-pending exact request did not reopen inertly: {other:?}"),
        };
        assert_eq!(exact_reopen.request.route(), expected_route);
        assert_eq!(exact_reopen.request.id(), expected_id);
        assert_eq!(exact_reopen.existing.route(), expected_route);
        assert_eq!(exact_reopen.existing.validation_id(), expected_id);
        assert_eq!(
            exact_reopen.existing.state(),
            NativeValidationJobStateV0::CallbackPending
        );

        let reserved_id = match store.store.reserve_or_reopen_native_validation_job_v0(
            NativeValidationReservationFactsV0::new_for_test_v0(
                PayloadValidationRouteV0::Synced,
                expected_id
                    .generation()
                    .checked_add(100)
                    .expect("advance mixed recovery generation"),
                TEST_CHAIN.as_str(),
            ),
        ) {
            Ok(NativeValidationReservationDecisionV0::Reserved(token)) => token.validation_id(),
            Ok(NativeValidationReservationDecisionV0::Existing(_)) | Err(_) => {
                panic!("reserve mixed recovery companion job")
            }
        };

        let connection = rusqlite::Connection::open(store.root.join("state.json.sqlite3"))
            .expect("open durable-invalid journal");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("count callback outbox"),
            1
        );
        let journal_shape = connection
            .query_row(
                "SELECT state, result_kind, invalid_reason_code_be,
                        length(artifact_bytes)
                 FROM validation_jobs_v0
                 WHERE state=2",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                },
            )
            .expect("read callback-pending job shape");
        assert_eq!(journal_shape, (2, 1, 1_u32.to_be_bytes().to_vec(), 120));
        assert_eq!(
            connection
                .query_row(
                    "SELECT length(payload_bytes) FROM validation_callback_outbox_v0",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .expect("read callback payload length"),
            84
        );
        let accounting = connection
            .query_row(
                "SELECT artifact_bytes_be, outbox_count_be, outbox_bytes_be
                 FROM validation_journal_accounting_v0 WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .expect("read callback-pending accounting");
        assert_eq!(accounting.0, 120_u64.to_be_bytes());
        assert_eq!(accounting.1, 1_u64.to_be_bytes());
        assert_eq!(accounting.2, 84_u64.to_be_bytes());
        drop(connection);

        let recovery = store
            .store
            .load_native_validation_recovery_work_v0()
            .expect("recover callback-pending invalid job");
        assert_eq!(recovery.len(), 2);
        assert_eq!(recovery[0].validation_id(), reserved_id);
        assert_eq!(recovery[0].state(), NativeValidationJobStateV0::Reserved);
        assert_eq!(recovery[1].validation_id(), expected_id);
        assert_eq!(
            recovery[1].state(),
            NativeValidationJobStateV0::CallbackPending
        );

        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&store.authorized_signers));
        let reopened = ApplicationStore::open(
            &store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("reopen durable-invalid store");
        reopened
            .load_or_migrate()
            .expect("restart authenticates callback-pending invalid job");
        let reopened_recovery = reopened
            .load_native_validation_recovery_work_v0()
            .expect("enumerate reopened callback-pending invalid job");
        assert_eq!(reopened_recovery.len(), 2);
        assert_eq!(reopened_recovery[0].validation_id(), reserved_id);
        assert_eq!(
            reopened_recovery[0].state(),
            NativeValidationJobStateV0::Reserved
        );
        assert_eq!(reopened_recovery[1].validation_id(), expected_id);
        assert_eq!(
            reopened_recovery[1].state(),
            NativeValidationJobStateV0::CallbackPending
        );
    }

    #[test]
    fn durable_complete_body_invalid_rejects_cross_store_owner_splice() {
        let first = test_store_with_poco_application_authority();
        let second = test_store_with_poco_application_authority();
        let poison = Some(StateRoot::new([0xe8; 32]));
        let first_owner = durable_invalid_all_family_complete_body_owner(&first, poison, None);
        let second_owner = durable_invalid_all_family_complete_body_owner(&second, poison, None);
        let first_prepared = prepare_durable_invalid_complete_body_v0(first_owner)
            .expect("prepare first-store durable invalid owner");
        let second_prepared = prepare_durable_invalid_complete_body_v0(second_owner)
            .expect("prepare second-store durable invalid owner");
        assert_eq!(
            first_prepared.validation_id(),
            second_prepared.validation_id()
        );

        let failed = match second
            .store
            .seal_durable_invalid_and_enqueue_callback_v0(first_prepared)
        {
            Ok(_) => panic!("first-store owner sealed the second store"),
            Err(failed) => failed,
        };
        assert!(matches!(
            failed.cause(),
            NativeValidationInvalidSealFailureCauseV0::Invariant(
                NativeValidationReservationInvariantV0::IssuingStoreMismatch
            )
        ));
        assert_eq!(
            failed.prepared().validation_id(),
            second_prepared.validation_id()
        );
        let recovered_first_prepared = failed.into_prepared_v0();
        match first
            .store
            .seal_durable_invalid_and_enqueue_callback_v0(recovered_first_prepared)
        {
            Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(job)) => {
                assert_eq!(job.state(), NativeValidationJobStateV0::CallbackPending)
            }
            Ok(NativeValidationInvalidSealDecisionV0::Existing(job)) => panic!(
                "recovered first-store owner unexpectedly reopened state {:?}",
                job.state()
            ),
            Err(failed) => panic!(
                "recovered first-store owner did not seal: {:?}",
                failed.cause()
            ),
        }

        match second
            .store
            .seal_durable_invalid_and_enqueue_callback_v0(second_prepared)
        {
            Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(job)) => {
                assert_eq!(job.state(), NativeValidationJobStateV0::CallbackPending)
            }
            Ok(NativeValidationInvalidSealDecisionV0::Existing(job)) => {
                panic!(
                    "second-store owner unexpectedly reopened state {:?}",
                    job.state()
                )
            }
            Err(failed) => panic!("second-store owner did not seal: {:?}", failed.cause()),
        }
    }

    #[test]
    fn durable_complete_body_invalid_precommit_failpoints_roll_back_and_return_owner() {
        let store = test_store_with_poco_application_authority();
        let owner = durable_invalid_all_family_complete_body_owner(
            &store,
            None,
            Some(ReceiptsRoot::new([0xe9; 32])),
        );
        let expected_id = owner.failed.finished.authorized.validation_id;
        let mut prepared = prepare_durable_invalid_complete_body_v0(owner)
            .expect("prepare durable receipts-root mismatch");

        for failpoint in [
            NativeValidationInvalidSealFailpointV0::AfterOutboxInsert,
            NativeValidationInvalidSealFailpointV0::AfterJobUpdate,
            NativeValidationInvalidSealFailpointV0::AfterAccountingUpdate,
            NativeValidationInvalidSealFailpointV0::BeforeCommit,
        ] {
            let failed = match store
                .store
                .seal_durable_invalid_and_enqueue_callback_with_test_failpoint_v0(
                    prepared, failpoint,
                ) {
                Ok(_) => panic!("durable-invalid failpoint {failpoint:?} committed"),
                Err(failed) => failed,
            };
            assert!(matches!(
                failed.cause(),
                NativeValidationInvalidSealFailureCauseV0::HostInvariant { .. }
            ));
            prepared = failed.into_prepared_v0();
            assert_eq!(prepared.validation_id(), expected_id);

            let connection = rusqlite::Connection::open(store.root.join("state.json.sqlite3"))
                .expect("open failpoint validation journal");
            assert_eq!(
                connection
                    .query_row("SELECT state FROM validation_jobs_v0", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("read rolled-back validation job state"),
                0
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM validation_callback_outbox_v0",
                        [],
                        |row| row.get::<_, u64>(0),
                    )
                    .expect("count rolled-back callback rows"),
                0
            );
            let accounting = connection
                .query_row(
                    "SELECT artifact_bytes_be, outbox_count_be, outbox_bytes_be
                     FROM validation_journal_accounting_v0 WHERE singleton=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .expect("read rolled-back validation accounting");
            assert_eq!(accounting.0, 0_u64.to_be_bytes());
            assert_eq!(accounting.1, 0_u64.to_be_bytes());
            assert_eq!(accounting.2, 0_u64.to_be_bytes());
            drop(connection);

            let signer_policy_hash_hex =
                hex::encode(crate::signer_policy_commitment(&store.authorized_signers));
            let reopened = ApplicationStore::open(
                &store.root.join("state.json"),
                TEST_CHAIN.as_str(),
                &signer_policy_hash_hex,
            )
            .expect("reopen failpoint validation store");
            reopened
                .load_or_migrate()
                .expect("rolled-back validation store restarts cleanly");
        }

        match store
            .store
            .seal_durable_invalid_and_enqueue_callback_v0(prepared)
        {
            Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(job)) => {
                assert_eq!(job.validation_id(), expected_id);
                assert_eq!(job.state(), NativeValidationJobStateV0::CallbackPending);
            }
            Ok(NativeValidationInvalidSealDecisionV0::Existing(job)) => panic!(
                "post-failpoint seal unexpectedly reopened state {:?}",
                job.state()
            ),
            Err(failed) => panic!("post-failpoint seal failed: {:?}", failed.cause()),
        }
    }

    #[test]
    fn durable_complete_body_invalid_restart_rejects_artifact_and_outbox_splices() {
        for target in ["artifact", "outbox"] {
            let store = test_store_with_poco_application_authority();
            let owner = durable_invalid_all_family_complete_body_owner(
                &store,
                Some(StateRoot::new([0xea; 32])),
                None,
            );
            let prepared = prepare_durable_invalid_complete_body_v0(owner)
                .expect("prepare durable-invalid tamper fixture");
            match store
                .store
                .seal_durable_invalid_and_enqueue_callback_v0(prepared)
            {
                Ok(NativeValidationInvalidSealDecisionV0::CallbackPending(_)) => {}
                Ok(NativeValidationInvalidSealDecisionV0::Existing(job)) => panic!(
                    "tamper fixture unexpectedly reopened state {:?}",
                    job.state()
                ),
                Err(failed) => panic!("tamper fixture seal failed: {:?}", failed.cause()),
            }

            let connection = rusqlite::Connection::open(store.root.join("state.json.sqlite3"))
                .expect("open durable-invalid tamper database");
            if target == "artifact" {
                let mut bytes = connection
                    .query_row("SELECT artifact_bytes FROM validation_jobs_v0", [], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })
                    .expect("read durable invalid artifact");
                bytes[0] ^= 0x01;
                connection
                    .execute(
                        "UPDATE validation_jobs_v0 SET artifact_bytes=?1",
                        rusqlite::params![bytes],
                    )
                    .expect("tamper durable invalid artifact");
            } else {
                let mut bytes = connection
                    .query_row(
                        "SELECT payload_bytes FROM validation_callback_outbox_v0",
                        [],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .expect("read durable invalid callback payload");
                bytes[0] ^= 0x01;
                connection
                    .execute(
                        "UPDATE validation_callback_outbox_v0 SET payload_bytes=?1",
                        rusqlite::params![bytes],
                    )
                    .expect("tamper durable invalid callback payload");
            }
            drop(connection);

            let signer_policy_hash_hex =
                hex::encode(crate::signer_policy_commitment(&store.authorized_signers));
            let reopened = ApplicationStore::open(
                &store.root.join("state.json"),
                TEST_CHAIN.as_str(),
                &signer_policy_hash_hex,
            )
            .expect("reopen tampered durable-invalid store");
            assert!(
                reopened.load_or_migrate().is_err(),
                "restart accepted tampered {target} bytes"
            );
        }
    }

    #[test]
    fn durable_complete_body_invalid_bridge_rejects_test_only_and_retained_invariant() {
        {
            let store = test_store_with_poco_application_authority();
            let honest = honest_all_family_complete_body_profile(&store);
            let honest_receipts_root = honest.header.receipts_root();
            let profile = replace_profile_execution_roots(
                honest,
                StateRoot::new([0xe3; 32]),
                honest_receipts_root,
            );
            let owner = match classify_all_family_complete_body(&store, &profile) {
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                    owner,
                ) => owner,
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(_)
                | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(_) => {
                    panic!("test-only poisoned roots changed disposition")
                }
            };
            let failed = match prepare_durable_invalid_complete_body_v0(owner) {
                Ok(_) => panic!("test-only reservation minted durable invalid authority"),
                Err(failed) => failed,
            };
            assert_eq!(
                failed.cause,
                PrepareDurableInvalidFailureCauseV0::TestOnlyReservation
            );
            assert!(matches!(
                failed.owner.failed.finished.authorized.reservation,
                CoreAuthorizedRegularReservationV0::TestOnly
            ));
        }

        {
            let store = test_store_with_poco_application_authority();
            let mut owner = durable_invalid_all_family_complete_body_owner(
                &store,
                Some(StateRoot::new([0xe4; 32])),
                None,
            );
            let expected_id = owner.failed.finished.authorized.validation_id;
            owner.failed.cause = CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity,
            );
            let failed = match prepare_durable_invalid_complete_body_v0(owner) {
                Ok(_) => panic!("retained invariant minted durable invalid authority"),
                Err(failed) => failed,
            };
            assert_eq!(
                failed.cause,
                PrepareDurableInvalidFailureCauseV0::RetainedCauseInvariant
            );
            assert_eq!(
                failed.owner.failed.finished.authorized.validation_id,
                expected_id
            );
            assert!(matches!(
                failed.owner.failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::BlockIdentity
                )
            ));
        }
    }

    #[test]
    fn durable_complete_body_invalid_bridge_rejects_route_and_full_id_splices() {
        {
            let store = test_store_with_poco_application_authority();
            let mut owner = durable_invalid_all_family_complete_body_owner(
                &store,
                Some(StateRoot::new([0xe5; 32])),
                None,
            );
            owner.failed.finished.authorized.route = PayloadValidationRouteV0::Synced;
            let failed = match prepare_durable_invalid_complete_body_v0(owner) {
                Ok(_) => panic!("route splice minted durable invalid authority"),
                Err(failed) => failed,
            };
            assert_eq!(
                failed.cause,
                PrepareDurableInvalidFailureCauseV0::ReservationRouteInvariant
            );
            assert_eq!(
                failed.owner.failed.finished.authorized.route,
                PayloadValidationRouteV0::Synced
            );
        }

        {
            let store = test_store_with_poco_application_authority();
            let mut owner = durable_invalid_all_family_complete_body_owner(
                &store,
                None,
                Some(ReceiptsRoot::new([0xe6; 32])),
            );
            let retained_id = owner.failed.finished.authorized.validation_id;
            let spliced_id = ValidationId::new(
                retained_id.block_id(),
                retained_id.view(),
                retained_id
                    .generation()
                    .checked_add(1)
                    .expect("advance test validation generation"),
            );
            owner.failed.finished.authorized.validation_id = spliced_id;
            let failed = match prepare_durable_invalid_complete_body_v0(owner) {
                Ok(_) => panic!("full ValidationId splice minted durable invalid authority"),
                Err(failed) => failed,
            };
            assert_eq!(
                failed.cause,
                PrepareDurableInvalidFailureCauseV0::ReservationValidationIdInvariant
            );
            assert_eq!(
                failed.owner.failed.finished.authorized.validation_id,
                spliced_id
            );
        }
    }

    #[test]
    fn complete_body_provenance_and_plan_invariants_precede_receipt_drift() {
        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish reorder-collision mixed body");
            finished.applied_non_runtime.swap(0, 1);
            finished.applied[0].native_receipt =
                NativeTransactionReceiptFactsV0::internal_operation();
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("reordered mixed provenance must retain the exact owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyProvenance,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish plan-collision mixed body");
            finished.post_state_update.version = finished
                .post_state_update
                .version
                .checked_add(1)
                .expect("test plan version advance");
            finished.applied[0].native_receipt =
                NativeTransactionReceiptFactsV0::internal_operation();
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("plan seal drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateSeal,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish native-receipt-drift mixed body");
            finished.applied[0].native_receipt =
                NativeTransactionReceiptFactsV0::internal_operation();
            let failed = match classify_core_authorized_regular_complete_body_commitment_comparison_v0(
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished),
            ) {
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::InvariantFault(failed) => {
                    failed
                }
                ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::Valid(_)
                | ClassifiedCoreAuthorizedRegularCompleteBodyCommitmentsV0::DeterministicallyInvalid(
                    _,
                ) => panic!("native receipt drift did not stay fail-stop"),
            };
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::NativeReceiptRebuild,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish PoCO-source-drift mixed body");
            finished.final_poco = None;
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("PoCO source drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyPocoWrites,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish validator-source-drift mixed body");
            finished.final_validator_lifecycle = None;
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("validator source drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyValidatorWrite,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish runtime-delta-drift mixed body");
            finished.changes.clear();
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("runtime delta drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::ReceiptMutationDelta,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish write-set-drift mixed body");
            let wrong_write =
                AuthWrite::put(b"complete-body-wrong-plan".to_vec(), b"wrong".to_vec())
                    .expect("construct alternate complete-body write");
            let wrong_plan = store
                .authenticated_parent
                .plan_put_value_set(profile.header.height().get(), [wrong_write])
                .expect("plan alternate sealed complete-body write");
            let wrong_seal = wrong_plan
                .seal_v0()
                .expect("seal alternate complete-body plan");
            finished.post_state_update = wrong_plan;
            finished.post_state_update_seal = wrong_seal;
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("resealed write-set drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::CompleteBodyMergedWrites,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }

        {
            let store = test_store_with_poco_application_authority();
            let profile = honest_all_family_complete_body_profile(&store);
            let mut finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(
                complete_production_all_family_cursor(&store, &profile),
            )
            .expect("finish resealed-version-drift mixed body");
            finished.post_state_update.version = finished
                .post_state_update
                .version
                .checked_add(1)
                .expect("advance alternate plan version");
            finished.post_state_update_seal = finished
                .post_state_update
                .seal_v0()
                .expect("reseal alternate plan version");
            let failed =
                match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
                    .err()
                    .expect("resealed version drift must retain the exact mixed owner");
            assert_eq!(
                failed.cause,
                CoreAuthorizedRegularCommitmentComparisonCauseV0::Invariant(
                    CoreAuthorizedRegularCommitmentInvariantV0::PlannedStateVersion,
                )
            );
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        }
    }

    #[test]
    fn complete_empty_body_plans_due_validator_activation_write() {
        let store = test_store_with_pending_validator_activation_at_height_three();
        let profile = replace_profile_transactions(
            fixture_profile_at_height(
                store.parent_state_root,
                2,
                ConsensusParametersV0::reference_shadow_v0(),
                0,
            ),
            Vec::new(),
        );
        let mut expected_lifecycle = store.validator_lifecycle.clone();
        expected_lifecycle.prepare_height(3).unwrap();
        let expected_write = crate::authenticated_lifecycle_write(3, &expected_lifecycle).unwrap();
        let expected_plan = store
            .authenticated_parent
            .plan_put_value_set(3, [expected_write])
            .expect("independently plan due validator activation");
        let receipts_root = NativeBlockExecutionV0::empty()
            .execution_receipts()
            .receipts_root()
            .expect("derive empty implicit-activation receipt root");
        let profile = replace_profile_execution_roots(
            profile,
            StateRoot::new(expected_plan.root_hash.into()),
            receipts_root,
        );
        let open = open_exact_test_authorized_regular_cursor(&store, &profile);

        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("plan mandatory due validator lifecycle write");
        let matched = match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
            .expect("match empty body with implicit validator activation");
        assert_eq!(
            matched.finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        assert!(matched.finished.applied.is_empty());
        assert!(matched.finished.applied_non_runtime.is_empty());
        assert!(matched.finished.final_poco.is_none());
        assert!(matched
            .native_execution
            .execution_receipts()
            .receipts()
            .is_empty());
        let final_lifecycle = matched
            .finished
            .final_validator_lifecycle
            .expect("retain implicitly prepared validator lifecycle");
        assert!(final_lifecycle.pending_transition.is_none());
        assert_eq!(
            final_lifecycle.last_applied_transition_id.as_deref(),
            Some("native-implicit-height-three")
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert!(store.validator_lifecycle.pending_transition.is_some());
    }

    #[test]
    fn production_complete_cutoff_body_refreshes_only_without_poco_operations() {
        let parameters = compact_cutoff_at_two_parameters();
        let store = build_test_store_with_parameters_at_height(true, parameters, 1);
        let profile = replace_profile_transactions(
            fixture_profile_at_height(store.parent_state_root, 1, parameters, 0),
            Vec::new(),
        );
        let source_projection = load_test_authenticated_poco_projection(&store);
        let refresh = crate::poco_transition::scheduled_cutoff_manifest_refresh_write_v0(
            Height::new(2),
            &source_projection,
        )
        .unwrap();
        let expected_plan = store
            .authenticated_parent
            .plan_put_value_set(2, [refresh])
            .expect("independently plan scheduled cutoff refresh");
        let receipts_root = NativeBlockExecutionV0::empty()
            .execution_receipts()
            .receipts_root()
            .expect("derive empty scheduled-cutoff receipt root");
        let profile = replace_profile_execution_roots(
            profile,
            StateRoot::new(expected_plan.root_hash.into()),
            receipts_root,
        );
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open scheduled cutoff empty cursor");
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("plan mandatory empty cutoff refresh");
        let matched = match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
            .expect("match empty cutoff refresh without a synthetic receipt");
        assert_eq!(
            matched.finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        assert!(matched
            .native_execution
            .execution_receipts()
            .receipts()
            .is_empty());
        match matched.finished.final_poco.as_ref().unwrap() {
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(projection) => {
                assert_eq!(projection, &source_projection);
            }
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(_) => {
                panic!("empty cutoff became a business-operation seal")
            }
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let operation_store = build_test_store_with_parameters_at_height(true, parameters, 1);
        let base = fixture_profile_at_height(operation_store.parent_state_root, 1, parameters, 0);
        let (_, inner) = author_valid_poco_application_operation(&operation_store, &base);
        let outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-cutoff-business-operation".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &inner,
        );
        let profile = replace_profile_transactions(base, vec![outer]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&operation_store),
            core_validation_request(&profile),
        )
        .expect("open cutoff business-operation cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let expected_writes = open.poco_prefix.as_ref().unwrap().writes.clone();
        let expected_plan = operation_store
            .authenticated_parent
            .plan_put_value_set(2, expected_writes)
            .expect("independently plan cutoff business-operation writes");
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("plan cutoff operation without duplicate refresh");
        assert_eq!(
            finished.post_state_update.root_hash,
            expected_plan.root_hash
        );
        drop(finished);
        let transaction_bytes = profile
            .body
            .application_payload()
            .transactions()
            .iter()
            .map(|transaction| Bytes::copy_from_slice(transaction))
            .collect::<Vec<_>>();
        let receipts_root = NativeBlockExecutionV0::try_new(
            &transaction_bytes,
            vec![NativeTransactionReceiptFactsV0::internal_operation()],
        )
        .expect("independently construct cutoff-operation receipt")
        .execution_receipts()
        .receipts_root()
        .expect("derive cutoff-operation receipt root");
        let profile = replace_profile_execution_roots(
            profile,
            StateRoot::new(expected_plan.root_hash.into()),
            receipts_root,
        );
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&operation_store),
            core_validation_request(&profile),
        )
        .expect("reopen authored cutoff business-operation cursor");
        let open = advance_next_production_non_runtime_payload(open);
        let finished = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .expect("finish authored cutoff operation without duplicate refresh");
        let matched = match_finished_core_authorized_regular_complete_body_commitments_v0(finished)
            .expect("match cutoff business operation with one body receipt");
        match matched.finished.final_poco.as_ref().unwrap() {
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::Operations(plan) => {
                assert_eq!(plan.operation_count(), 1);
                assert!(plan.binds_exact_operations_v0(&[inner]));
            }
            super::FinishedCoreAuthorizedRegularPocoWriteSourceV0::ScheduledCutoff(_) => {
                panic!("business operation was double-planned as cutoff refresh")
            }
        }
        assert_eq!(
            matched
                .native_execution
                .execution_receipts()
                .receipts()
                .len(),
            1
        );
        assert_eq!(
            matched.native_execution.execution_receipts().receipts()[0].gas_used(),
            0
        );
        assert_eq!(
            operation_store
                .store
                .active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn complete_body_write_merge_rejects_duplicate_raw_keys_without_deduplication() {
        let first = AuthWrite::put(b"complete-body-duplicate".to_vec(), b"first".to_vec())
            .expect("construct first duplicate-key write");
        let second = AuthWrite::put(b"complete-body-duplicate".to_vec(), b"second".to_vec())
            .expect("construct second duplicate-key write");
        assert_eq!(
            super::validate_unique_complete_body_auth_writes_v0(&[first, second]),
            Err(
                super::CoreAuthorizedRegularCompleteBodyPlanCauseV0::MergedWriteKeyConflictInvariant
            )
        );
    }

    #[test]
    fn production_complete_body_rebinds_runtime_receipt_owner_before_planning() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut open = complete_production_runtime_cursor(&store, &profile);
        let empty_internal_receipt = NativeTransactionReceiptFactsV0::internal_operation();
        assert_ne!(open.applied[0].native_receipt, empty_internal_receipt);
        open.applied[0].native_receipt = empty_internal_receipt;

        let failed = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("runtime receipt-owner drift must fail before complete-body planning");
        assert_eq!(failed.next_transaction_index, 2);
        assert_eq!(failed.applied.len(), 2);
        assert!(matches!(
            failed.cause,
            super::ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0::Plan(
                super::CoreAuthorizedRegularCompleteBodyPlanCauseV0::CompleteBodyProvenanceInvariant
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_complete_body_finish_failure_outranks_successful_mixed_plan() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let runtime = base.body.application_payload().transactions()[0].clone();
        let (_, inner) = author_two_valid_poco_application_operations(&store, &base);
        let first = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-complete-finish-override-first".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &inner[0],
        );
        let second = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-complete-finish-override-second".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &inner[1],
        );
        let profile = replace_profile_transactions(base, vec![first, runtime, second]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .unwrap();
        let open = advance_next_production_non_runtime_payload(open);
        let open = attempt_next_production_runtime_transaction(open)
            .expect("execute runtime item before finish override");
        let mut open = advance_next_production_non_runtime_payload(open);
        open.open.snapshot.inject_finish_failure_for_test_v0();
        let failed = finish_and_plan_complete_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("snapshot finish must replace successful mixed planning");
        assert_eq!(failed.next_transaction_index, 3);
        assert_eq!(failed.applied.len(), 1);
        assert_eq!(failed.applied_non_runtime.len(), 2);
        assert!(!failed.changes.is_empty());
        assert!(failed.poco_prefix.is_some());
        assert!(matches!(
            failed.cause,
            super::ClosedCoreAuthorizedRegularCompleteBodyPlanCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_runtime_failure_retains_prior_poco_prefix_but_destroys_runtime_delta() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (_, exact_inner) = author_valid_poco_application_operation(&store, &base);
        let poco_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-before-runtime-reject".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let reject_profile = fixture_profile_with_second_runtime_reject(store.parent_state_root);
        let rejected_runtime = reject_profile.body.application_payload().transactions()[1].clone();
        let profile = replace_profile_transactions(base, vec![poco_outer, rejected_runtime]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open PoCO/runtime-reject cursor");
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied_non_runtime.len(), 1);
        let failed = attempt_next_production_runtime_transaction(open)
            .err()
            .expect("runtime after PoCO must reject without enough balance");
        let closed = finish_failed_core_authorized_regular_runtime_attempt_v0(failed);
        assert_eq!(closed.failed_transaction_index, 1);
        assert_eq!(closed.applied_non_runtime.len(), 1);
        let prefix = closed
            .poco_prefix
            .as_ref()
            .expect("closed runtime failure retains prior PoCO prefix");
        assert_eq!(prefix.overlay.operation_count(), 1);
        assert_eq!(prefix.plan.operation_count(), 1);
        assert!(prefix
            .plan
            .binds_exact_operations_v0(std::slice::from_ref(&exact_inner)));
        assert!(closed.validator_prefix.is_none());
        assert!(matches!(
            closed.cause,
            ClosedCoreAuthorizedRegularRuntimeAttemptCauseV0::Attempt(
                CoreAuthorizedRegularRuntimeStepFailureV0::Runtime(_)
            )
        ));
        drop(closed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_mixed_runtime_then_poco_write_seal_retains_prior_private_evidence() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let first_runtime = base.body.application_payload().transactions()[0].clone();
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-write-seal-after-runtime".to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![first_runtime, exact_outer.clone()]);
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open mixed runtime/PoCO write-seal cursor");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("first runtime transaction succeeds before PoCO sealing");
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied.len(), 1);
        assert!(!open.changes.is_empty());
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare second mixed PoCO payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("mixed PoCO payload entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode mixed PoCO payload");
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .expect("authorize mixed PoCO family attempt");
        let sealed = seal_core_authorized_non_runtime_family_writes_v0(attempted)
            .expect("seal mixed PoCO family writes");
        let sealed = match sealed {
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication(sealed) => {
                sealed
            }
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition(_) => {
                panic!("mixed PoCO write seal changed family")
            }
        };
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .open
                .next_transaction_index,
            1
        );
        assert_eq!(
            sealed.attempted.decoded.owner.routed.next_transaction_index,
            2
        );
        assert_eq!(sealed.attempted.decoded.owner.routed.open.applied.len(), 1);
        assert!(!sealed
            .attempted
            .decoded
            .owner
            .routed
            .open
            .changes
            .is_empty());
        assert!(sealed.plan.binds_exact_operations_v0(&[exact_inner]));
        assert!(!sealed.writes.is_empty());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(sealed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn poco_write_seal_source_drift_is_fail_stop_and_retains_the_exact_attempt() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-write-seal-source-drift".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .expect("authorize PoCO source-drift seal attempt");
        let mut attempted = match attempted {
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted) => attempted,
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(_) => {
                panic!("PoCO source-drift attempt changed family")
            }
        };
        attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .authorized
            .context
            .parent_header = profile.header.clone();
        let failed = seal_core_authorized_non_runtime_family_writes_v0(
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted),
        )
        .err()
        .expect("PoCO source drift must retain a write-seal failure");
        let closed = finish_failed_core_authorized_non_runtime_family_write_seal_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("PoCO write-seal source drift did not fail stop"),
        };
        assert_eq!(
            outcome.code(),
            "native_regular_poco_write_seal_source_binding_invariant"
        );
        assert_eq!(outcome.terminal_disposition(), None);
        assert!(outcome.successful_execution().is_none());
        match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                owner,
                operation,
                overlay,
                cause,
            } => {
                assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
                assert_eq!(owner.exact_outer_bytes, exact_outer);
                assert_eq!(owner.cursor_next_transaction_index, 0);
                assert_eq!(owner.decoded_next_transaction_index, 1);
                assert_eq!(operation.target_height(), 2);
                assert_eq!(overlay.operation_count(), 1);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::PocoSourceBinding,
                    )
                );
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                ..
            } => panic!("PoCO write-seal failure changed family"),
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn poco_write_seal_finish_failure_outranks_source_binding_drift() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-write-seal-finish-override".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .expect("authorize PoCO finish-override seal attempt");
        let mut attempted = match attempted {
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted) => attempted,
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(_) => {
                panic!("PoCO finish-override attempt changed family")
            }
        };
        attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .authorized
            .context
            .parent_header = profile.header.clone();
        attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .snapshot
            .inject_finish_failure_for_test_v0();
        let failed = seal_core_authorized_non_runtime_family_writes_v0(
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(attempted),
        )
        .err()
        .expect("PoCO source drift must retain a pending write-seal failure");
        let closed = finish_failed_core_authorized_non_runtime_family_write_seal_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("PoCO finish override changed disposition"),
        };
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_write_seal_snapshot_host_invariant"
        );
        assert_eq!(outcome.terminal_disposition(), None);
        match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                owner,
                operation,
                overlay,
                cause,
            } => {
                assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
                assert_eq!(owner.exact_outer_bytes, exact_outer);
                assert_eq!(operation.target_height(), 2);
                assert_eq!(overlay.operation_count(), 1);
                assert!(matches!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Snapshot(
                        AuthenticatedRuntimeReadFailureV0::HostInvariant {
                            stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                            ..
                        },
                    )
                ));
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                ..
            } => {
                panic!("PoCO finish override changed family")
            }
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn production_poco_governance_rejection_closes_without_cursor_or_state_mutation() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, exact_inner) =
            author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-unauthorized".to_string(),
            82,
            "did:client:1",
            "hepta",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("foreign PoCO signer must retain a pending family failure");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("PoCO governance rejection changed terminal class")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            outcome.code(),
            "native_regular_poco_governance_authorization_invalid"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                operation,
                cause,
            } => {
                assert_eq!(operation.target_height(), 2);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoGovernanceAuthorization,
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("PoCO governance failure changed family")
            }
        };
        assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.envelope.signer_id, "did:client:1");
        assert_eq!(owner.index, 0);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        assert!(owner.changes.is_empty());
        assert!(owner.applied.is_empty());
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn production_family_authenticated_source_failure_closes_with_exact_owner() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (_, exact_inner) = author_valid_poco_application_operation(&store, &base);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-source-unavailable".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let decoded = decode_only_non_runtime_family(&store, &profile);
        let decoded = match decoded {
            DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(decoded) => decoded,
            DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(_)
            | DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(_) => {
                panic!("PoCO source-failure fixture changed family")
            }
        };
        // Production obtains this variant only from the retained snapshot's
        // typed loader. The test constructs the pending carrier directly so
        // no caller-supplied projection/source seam exists in production.
        let failed = Box::new(
            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                decoded,
                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(
                    AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                        stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                        sqlite: None,
                        reason: "test-only typed projection source failure",
                    },
                ),
            },
        );
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("typed family source loss did not remain retryable")
            }
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(outcome.code(), "host_resource_unavailable");
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                operation,
                cause,
            } => {
                assert_eq!(operation.target_height(), 2);
                assert!(matches!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(
                            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                                stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                                ..
                            },
                        ),
                    )
                ));
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("PoCO source failure changed family")
            }
        };
        assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let decoded = match decode_only_non_runtime_family(&store, &profile) {
            DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::PocoApplication(decoded) => decoded,
            DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::ValidatorTransition(_)
            | DecodedDispatchedCoreAuthorizedNonRuntimePayloadV0::Unsupported(_) => {
                panic!("PoCO authenticated-source invariant fixture changed family")
            }
        };
        let failed = Box::new(
            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                decoded,
                cause: CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                        sqlite: None,
                        reason: "test-only authenticated projection invariant",
                    },
                ),
            },
        );
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("authenticated source corruption was downgraded during terminal mapping"),
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_authenticated_source_state_invariant"
        );
        assert!(outcome.successful_execution().is_none());
        match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                cause,
                ..
            } => {
                assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
                assert!(matches!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::AuthenticatedSource(
                            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. },
                        ),
                    )
                ));
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("authenticated source invariant changed family")
            }
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_family_finish_failure_outranks_pending_deterministic_rejection() {
        let store = test_store();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-unsupported-family-finish".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            "trnm.unsupported.native-family.v0",
            b"{}",
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let mut failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("unsupported family must retain a pending deterministic failure");
        match failed.as_mut() {
            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { owner, cause } => {
                assert_eq!(
                    *cause,
                    CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                        CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::UnsupportedFamily,
                    )
                );
                owner
                    .routed
                    .open
                    .open
                    .snapshot
                    .inject_finish_failure_for_test_v0();
            }
            FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | FailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. } => {
                panic!("unsupported finish fixture changed family")
            }
        }
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("family snapshot invariant was downgraded during terminal mapping"),
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_family_snapshot_host_invariant"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { owner, cause } => {
                assert!(matches!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Snapshot(
                        AuthenticatedRuntimeReadFailureV0::HostInvariant {
                            stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                            ..
                        },
                    )
                ));
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. } => {
                panic!("closed unsupported finish failure changed family")
            }
        };
        assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_unsupported_family_promotes_only_after_snapshot_close() {
        let store = test_store();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-unsupported-family-terminal".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            "trnm.unsupported.native-family.v0",
            b"{}",
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_validation_id = core_validation_request(&profile).id();
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("unsupported family must retain a pending deterministic failure");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("unsupported family changed terminal class")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_family_unsupported"
        );
        assert_eq!(
            outcome.generation().get(),
            expected_validation_id.generation()
        );
        assert!(outcome.successful_execution().is_none());
        match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { owner, cause } => {
                assert_eq!(owner.authorized.validation_id, expected_validation_id);
                assert_eq!(owner.exact_outer_bytes, exact_outer);
                assert_eq!(owner.cursor_next_transaction_index, 0);
                assert_eq!(owner.decoded_next_transaction_index, 1);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::UnsupportedFamily,
                        ),
                    )
                );
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. } => {
                panic!("unsupported terminal owner changed family")
            }
        }
    }

    #[test]
    fn production_validator_family_attempt_uses_authenticated_lifecycle_and_retains_owner() {
        let store = test_store();
        let command_id = "native-validator-family-attempt";
        let exact_inner = valid_validator_transition_bytes(&store, command_id);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open validator family-attempt cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare validator family-attempt payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("validator family attempt entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .unwrap_or_else(|_| panic!("strict-decode validator family attempt"));
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .unwrap_or_else(|_| {
                panic!("authorize validator family attempt against retained lifecycle")
            });
        let attempted = match attempted {
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted) => {
                attempted
            }
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(_) => {
                panic!("validator family attempt changed family")
            }
        };
        assert_eq!(
            attempted
                .scheduled_lifecycle
                .pending_transition
                .as_ref()
                .expect("transition must be scheduled")
                .transition_id,
            command_id
        );
        assert_eq!(attempted.scheduled_lifecycle.governance_sequence, 1);
        assert_eq!(attempted.decoded.transition.transition_id, command_id);
        assert_eq!(
            attempted.decoded.owner.routed.exact_outer_bytes,
            exact_outer
        );
        assert_eq!(
            attempted.decoded.owner.routed.exact_inner_bytes,
            exact_inner
        );
        assert_eq!(
            attempted.decoded.owner.routed.context.target_block_id,
            expected_id
        );
        assert_eq!(
            attempted.decoded.owner.routed.open.next_transaction_index,
            0
        );
        assert_eq!(attempted.decoded.owner.routed.next_transaction_index, 1);
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(attempted);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_validator_family_write_seal_is_canonical_and_owner_bound() {
        let store = test_store();
        let command_id = "native-validator-family-write-seal";
        let exact_inner = valid_validator_transition_bytes(&store, command_id);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .expect("authorize validator family write-seal attempt");
        let sealed = seal_core_authorized_non_runtime_family_writes_v0(attempted)
            .expect("seal owner-bound validator lifecycle write");
        let sealed = match sealed {
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition(
                sealed,
            ) => sealed,
            super::OwnerBoundCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication(_) => {
                panic!("validator family write seal changed family")
            }
        };
        assert_eq!(sealed.write.key(), validator_state_key().unwrap());
        let record = AuthenticatedObjectRecord::decode(
            sealed
                .write
                .value()
                .expect("validator family write cannot delete lifecycle"),
        )
        .expect("decode sealed validator lifecycle record");
        assert_eq!(record.object_type, VALIDATOR_LIFECYCLE_SCHEMA_V1);
        assert_eq!(record.object_version, 2);
        assert_eq!(
            record.value,
            serde_json::to_vec(&sealed.attempted.scheduled_lifecycle).unwrap()
        );
        let inert_plan = sealed
            .attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .snapshot
            .plan_exact_next_auth_update_v0([sealed.write.clone()])
            .expect("independently plan sealed validator write without persistence");
        assert_eq!(inert_plan.version, 2);
        assert_ne!(
            <[u8; 32]>::from(inert_plan.root_hash),
            store.parent_state_root
        );
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .open
                .next_transaction_index,
            0
        );
        assert_eq!(
            sealed.attempted.decoded.owner.routed.next_transaction_index,
            1
        );
        assert_eq!(
            sealed
                .attempted
                .decoded
                .owner
                .routed
                .open
                .open
                .authorized
                .validation_id
                .block_id(),
            expected_id
        );
        assert_eq!(
            sealed.attempted.decoded.owner.routed.exact_outer_bytes,
            exact_outer
        );
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(inert_plan);
        drop(sealed);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
    }

    #[test]
    fn production_second_validator_transition_uses_staged_pending_lifecycle() {
        let store = test_store();
        let first_id = "native-validator-successive-first";
        let second_id = "native-validator-successive-second";
        let first_inner = valid_validator_transition_bytes(&store, first_id);
        let mut second_transition: crate::validator_lifecycle::ValidatorSetTransitionV1 =
            serde_json::from_slice(&valid_validator_transition_bytes(&store, second_id)).unwrap();
        second_transition.new_validator_proofs[0].signature_hex = "00".repeat(64);
        let second_inner = serde_json::to_vec(&second_transition).unwrap();
        let first_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            first_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &first_inner,
        );
        let second_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            second_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &second_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![first_outer, second_outer],
        );
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open successive validator cursor");
        let open = advance_next_production_non_runtime_payload(open);
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied_non_runtime.len(), 1);
        let prefix = open
            .validator_prefix
            .as_ref()
            .expect("retain first staged validator lifecycle");
        assert_eq!(prefix.lifecycle.governance_sequence, 1);
        assert_eq!(
            prefix
                .lifecycle
                .pending_transition
                .as_ref()
                .expect("first transition is pending")
                .transition_id,
            first_id
        );

        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare second validator payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("second validator payload entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .expect("strict-decode second validator payload");
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .err()
            .expect("second validator transition must observe staged pending state");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                owner,
                cause:
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::ValidatorTransition(
                                crate::validator_lifecycle::ValidatorTransitionDeterministicInvalidV1::PendingTransitionExists,
                            ),
                        ),
                    ),
                ..
            } => owner,
            _ => panic!("second validator transition did not freeze staged pending priority"),
        };
        assert_eq!(owner.cursor_next_transaction_index, 1);
        assert_eq!(owner.decoded_next_transaction_index, 2);
        assert_eq!(owner.applied_non_runtime.len(), 1);
        let prefix = owner
            .validator_prefix
            .as_ref()
            .expect("closed owner retains first validator prefix");
        assert_eq!(prefix.lifecycle.governance_sequence, 1);
        assert_eq!(
            prefix
                .lifecycle
                .pending_transition
                .as_ref()
                .unwrap()
                .transition_id,
            first_id
        );
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn validator_write_seal_failure_retains_owner_and_finish_failure_outranks_it() {
        for inject_finish_failure in [false, true] {
            let store = test_store();
            let command_id = if inject_finish_failure {
                "native-validator-write-seal-finish-override"
            } else {
                "native-validator-write-seal-successor-drift"
            };
            let exact_inner = valid_validator_transition_bytes(&store, command_id);
            let exact_outer = signed_envelope_bytes(
                TEST_CHAIN.as_str(),
                command_id.to_string(),
                81,
                "did:operator:1",
                "operator",
                1,
                1_700_000_000_000,
                1_700_000_100_000,
                crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
                &exact_inner,
            );
            let profile = replace_profile_transactions(
                fixture_profile(store.parent_state_root, 0),
                vec![exact_outer.clone()],
            );
            let expected_id = profile.header.id();
            let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
                decode_only_non_runtime_family(&store, &profile),
            )
            .expect("authorize validator write-seal failure fixture");
            let mut attempted = match attempted {
                super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted) => {
                    attempted
                }
                super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(_) => {
                    panic!("validator write-seal failure fixture changed family")
                }
            };
            attempted.scheduled_lifecycle.governance_sequence += 1;
            if inject_finish_failure {
                attempted
                    .decoded
                    .owner
                    .routed
                    .open
                    .open
                    .snapshot
                    .inject_finish_failure_for_test_v0();
            }
            let failed = seal_core_authorized_non_runtime_family_writes_v0(
                super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted),
            )
            .err()
            .expect("validator successor drift must retain a seal failure");
            let closed = finish_failed_core_authorized_non_runtime_family_write_seal_v0(failed);
            let promoted =
                promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(closed);
            let (outcome, closed) = match promoted {
                RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                    outcome,
                    failed,
                } => (outcome, failed),
                RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
                | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                    ..
                } => panic!("validator write-seal invariant changed disposition"),
            };
            assert_eq!(outcome.terminal_disposition(), None);
            assert!(outcome.successful_execution().is_none());
            assert_eq!(
                outcome.code(),
                if inject_finish_failure {
                    "native_regular_non_runtime_write_seal_snapshot_host_invariant"
                } else {
                    "native_regular_validator_write_seal_schedule_rebind_invariant"
                }
            );
            match *closed {
                ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                    owner,
                    transition,
                    scheduled_lifecycle,
                    cause,
                } => {
                    assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
                    assert_eq!(owner.exact_outer_bytes, exact_outer);
                    assert_eq!(owner.cursor_next_transaction_index, 0);
                    assert_eq!(owner.decoded_next_transaction_index, 1);
                    assert_eq!(transition.transition_id, command_id);
                    assert_eq!(scheduled_lifecycle.governance_sequence, 2);
                    if inject_finish_failure {
                        assert!(matches!(
                            cause,
                            ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Snapshot(
                                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                                    stage:
                                        crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                                    ..
                                },
                            )
                        ));
                    } else {
                        assert_eq!(
                            cause,
                            ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(
                                CoreAuthorizedNonRuntimeWriteSealInvariantV0::ValidatorScheduleRebind,
                            )
                        );
                    }
                }
                ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication {
                    ..
                } => panic!("validator write-seal failure changed family"),
            }
            assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
            assert_eq!(store.validator_lifecycle.governance_sequence, 0);
            assert!(store.validator_lifecycle.pending_transition.is_none());
        }
    }

    #[test]
    fn validator_write_seal_rejects_raw_owner_and_scheduled_successor_splice() {
        let store = test_store();
        let command_id = "native-validator-write-seal-owner-splice";
        let exact_inner = valid_validator_transition_bytes(&store, command_id);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let attempted = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .expect("authorize validator owner-splice fixture");
        let mut attempted = match attempted {
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted) => {
                attempted
            }
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::PocoApplication(_) => {
                panic!("validator owner-splice fixture changed family")
            }
        };

        // Poison the retained envelope and authenticated lifecycle together,
        // then rebuild a matching successor. A sealer that trusted those
        // sibling fields instead of the exact raw body could emit this write.
        attempted.decoded.owner.routed.envelope.nonce = 2;
        attempted
            .decoded
            .owner
            .routed
            .open
            .open
            .authorized
            .context
            .validator_lifecycle
            .governance_sequence = 1;
        let routed = &attempted.decoded.owner.routed;
        let mut poisoned_successor = routed
            .open
            .open
            .authorized
            .context
            .validator_lifecycle
            .clone();
        let authorization = crate::validator_lifecycle::ValidatorTransitionAuthorization {
            command_id: &routed.envelope.command_id,
            signer_id: &routed.context.signer_id,
            signer_role: &routed.context.signer_role,
            nonce: routed.envelope.nonce,
            chain_id: routed.envelope.chain_id.as_str(),
            accepted_height: routed.context.target_height,
        };
        poisoned_successor
            .schedule(attempted.decoded.transition.clone(), authorization)
            .expect("construct internally consistent poisoned successor");
        attempted.scheduled_lifecycle = poisoned_successor;

        let failed = seal_core_authorized_non_runtime_family_writes_v0(
            super::AuthorizedCoreNonRuntimeFamilyAttemptV0::ValidatorTransition(attempted),
        )
        .err()
        .expect("exact raw owner must reject the poisoned sibling fields");
        let closed = finish_failed_core_authorized_non_runtime_family_write_seal_v0(failed);
        let promoted =
            promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("validator owner splice changed disposition"),
        };
        assert_eq!(
            outcome.code(),
            "native_regular_non_runtime_write_seal_owner_binding_invariant"
        );
        assert_eq!(outcome.terminal_disposition(), None);
        match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::ValidatorTransition {
                owner,
                transition,
                scheduled_lifecycle,
                cause,
            } => {
                assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
                assert_eq!(owner.exact_outer_bytes, exact_outer);
                assert_eq!(owner.exact_inner_bytes, exact_inner);
                assert_eq!(owner.envelope.nonce, 2);
                assert_eq!(
                    owner
                        .authorized
                        .context
                        .validator_lifecycle
                        .governance_sequence,
                    1
                );
                assert_eq!(transition.transition_id, command_id);
                assert_eq!(scheduled_lifecycle.governance_sequence, 2);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyWriteSealCauseV0::Seal(
                        CoreAuthorizedNonRuntimeWriteSealInvariantV0::OwnerBinding,
                    )
                );
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyWriteSealV0::PocoApplication { .. } => {
                panic!("validator owner splice changed family")
            }
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(store.validator_lifecycle.governance_sequence, 0);
        assert!(store.validator_lifecycle.pending_transition.is_none());
    }

    #[test]
    fn production_validator_nonce_rejection_closes_without_mutating_authenticated_lifecycle() {
        let store = test_store();
        let source_lifecycle = store.validator_lifecycle.clone();
        let command_id = "native-validator-family-nonce-gap";
        let exact_inner = valid_validator_transition_bytes(&store, command_id);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            2,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("validator nonce gap must retain a pending family failure");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("validator nonce rejection changed terminal class")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            outcome.code(),
            "native_regular_validator_governance_sequence_mismatch"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                owner,
                transition,
                cause,
            } => {
                assert_eq!(transition.transition_id, command_id);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::ValidatorTransition(
                                crate::validator_lifecycle::ValidatorTransitionDeterministicInvalidV1::GovernanceSequenceMismatch,
                            ),
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("validator nonce failure changed family")
            }
        };
        assert_eq!(owner.authorized.validation_id.block_id(), expected_id);
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.envelope.nonce, 2);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        assert!(owner.changes.is_empty());
        assert!(owner.applied.is_empty());
        drop(owner);
        assert_eq!(store.validator_lifecycle, source_lifecycle);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_validator_nonce_exhaustion_is_invariant_and_retains_owner() {
        let store = test_store_with_governance_sequence(u64::MAX);
        let source_lifecycle = store.validator_lifecycle.clone();
        let command_id = "native-validator-family-nonce-exhausted";
        let exact_inner = valid_validator_transition_bytes(&store, command_id);
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            u64::MAX,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("exhausted validator nonce must retain a pending family failure");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("validator counter invariant changed terminal class"),
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(
            outcome.code(),
            "native_regular_validator_governance_sequence_exhausted_invariant"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                owner,
                transition,
                cause,
            } => {
                assert_eq!(transition.transition_id, command_id);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                            CoreAuthorizedNonRuntimeFamilyInvariantV0::ValidatorTransition(
                                crate::validator_lifecycle::ValidatorTransitionInvariantV1::GovernanceSequenceExhausted,
                            ),
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("validator nonce-exhaustion failure changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.envelope.nonce, u64::MAX);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        assert!(owner.changes.is_empty());
        assert!(owner.applied.is_empty());
        drop(owner);
        assert_eq!(store.validator_lifecycle, source_lifecycle);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_validator_bad_proof_is_deterministic_and_retains_owner() {
        let store = test_store();
        let source_lifecycle = store.validator_lifecycle.clone();
        let command_id = "native-validator-family-bad-proof";
        let mut transition: crate::validator_lifecycle::ValidatorSetTransitionV1 =
            serde_json::from_slice(&valid_validator_transition_bytes(&store, command_id))
                .expect("decode authored validator transition");
        transition.new_validator_proofs[0].signature_hex = "00".to_string();
        let exact_inner = serde_json::to_vec(&transition).expect("encode bad-proof transition");
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            command_id.to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::validator_lifecycle::VALIDATOR_TRANSITION_PAYLOAD_TYPE_V1,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("bad validator proof must retain a pending family failure");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition {
                owner,
                transition,
                cause,
            } => {
                assert_eq!(transition.transition_id, command_id);
                assert_eq!(transition.new_validator_proofs[0].signature_hex, "00");
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::ValidatorTransition(
                                crate::validator_lifecycle::ValidatorTransitionDeterministicInvalidV1::NewValidatorProof,
                            ),
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("validator bad-proof rejection changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.validator_lifecycle, source_lifecycle);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_poco_family_failure_retains_exact_authenticated_owner() {
        let store = test_store();
        let exact_inner = br#"{"schema":"trnm_poco_application_operation_v0","target_height":2,"expected_state_revision":0,"body":{"kind":"register_future_candidate","validator_id_hex":"00","target_epoch":1,"previous_registration_nonce":null,"predecessor_history_head_hex":"00","proof_cev0_hex":"","registration_decision_id_hex":"00"},"semantic_changes":[],"nullifier_non_membership_checks":[],"nullifier_insertions":[]}"#;
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-invalid".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let expected_id = profile.header.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open invalid PoCO family-attempt cursor");
        let routed = match prepare_next_core_authorized_regular_payload_v0(open)
            .expect("prepare invalid PoCO family-attempt payload")
        {
            PreparedCoreAuthorizedRegularPayloadV0::NonRuntime(routed) => routed,
            PreparedCoreAuthorizedRegularPayloadV0::Runtime(_) => {
                panic!("PoCO family attempt entered runtime")
            }
        };
        let decoded = decode_dispatched_core_authorized_non_runtime_payload_v0(
            dispatch_core_authorized_non_runtime_payload_v0(routed),
        )
        .unwrap_or_else(|_| panic!("strict-decode intrinsically valid PoCO operation"));
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(decoded)
            .err()
            .expect("invalid PoCO state transition must retain its family owner");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                ..
            } => panic!("authenticated PoCO projection invariant changed terminal class"),
        };
        assert_eq!(outcome.terminal_disposition(), None);
        assert_eq!(outcome.code(), "native_regular_poco_projection_invariant");
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                operation,
                cause,
            } => {
                assert_eq!(operation.target_height(), 2);
                assert!(
                    matches!(
                        cause,
                        ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                            CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Invariant(
                                CoreAuthorizedNonRuntimeFamilyInvariantV0::PocoProjection,
                            ),
                        )
                    ),
                    "unexpected PoCO family cause: {cause:?}"
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("PoCO family failure changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.context.target_block_id, expected_id);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_poco_revision_rejection_is_typed_and_retains_exact_owner() {
        let store = test_store_with_poco_application_authority();
        let base = fixture_profile(store.parent_state_root, 0);
        let (source_projection, valid_inner) =
            author_valid_poco_application_operation(&store, &base);
        let valid_inner = String::from_utf8(valid_inner).expect("authored PoCO operation UTF-8");
        assert_eq!(
            valid_inner.matches("\"expected_state_revision\":1").count(),
            1
        );
        let exact_inner = valid_inner
            .replacen(
                "\"expected_state_revision\":1",
                "\"expected_state_revision\":0",
                1,
            )
            .into_bytes();
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-stale-revision".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(base, vec![exact_outer.clone()]);
        let expected_id = profile.header.id();
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("stale PoCO revision must retain a family failure");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let promoted = promote_closed_core_authorized_non_runtime_family_failure_v0(closed);
        let (outcome, closed) = match promoted {
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::DeterministicallyInvalid {
                outcome,
                failed,
            } => (outcome, failed),
            RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::Unavailable { .. }
            | RetainedCoreAuthorizedRegularNonRuntimeFailureOutcomeV0::InvariantFault { .. } => {
                panic!("stale PoCO revision changed terminal class")
            }
        };
        assert_eq!(
            outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            outcome.code(),
            "native_regular_poco_authority_revision_mismatch"
        );
        assert!(outcome.successful_execution().is_none());
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                operation,
                cause,
            } => {
                assert_eq!(operation.expected_state_revision(), 0);
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoOperation(
                                crate::poco_application::PocoApplicationDeterministicInvalidV0::AuthorityRevisionMismatch,
                            ),
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("PoCO revision rejection changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.context.target_block_id, expected_id);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        assert!(owner.changes.is_empty());
        assert!(owner.applied.is_empty());
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn production_poco_bad_future_candidate_proof_is_deterministically_invalid() {
        let store = test_store_with_poco_application_authority();
        let source_projection = load_test_authenticated_poco_projection(&store);
        let exact_inner = format!(
            concat!(
                "{{\"schema\":\"trnm_poco_application_operation_v0\",",
                "\"target_height\":2,\"expected_state_revision\":1,",
                "\"body\":{{\"kind\":\"register_future_candidate\",",
                "\"validator_id_hex\":\"{}\",\"target_epoch\":1,",
                "\"previous_registration_nonce\":null,",
                "\"predecessor_history_head_hex\":\"{}\",",
                "\"proof_cev0_hex\":\"\",\"registration_decision_id_hex\":\"{}\"}},",
                "\"semantic_changes\":[],\"nullifier_non_membership_checks\":[],",
                "\"nullifier_insertions\":[]}}"
            ),
            hex::encode(b"validator-a"),
            "00".repeat(32),
            "11".repeat(32),
        )
        .into_bytes();
        crate::poco_application::PocoApplicationOperationV0::decode_exact(&exact_inner)
            .expect("bad proof remains a canonically encoded operation");
        let exact_outer = signed_envelope_bytes(
            TEST_CHAIN.as_str(),
            "native-poco-family-bad-future-proof".to_string(),
            81,
            "did:operator:1",
            "operator",
            1,
            1_700_000_000_000,
            1_700_000_100_000,
            crate::poco_application::POCO_APPLICATION_OPERATION_PAYLOAD_TYPE_V0,
            &exact_inner,
        );
        let profile = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![exact_outer.clone()],
        );
        let failed = authorize_and_execute_decoded_core_non_runtime_family_v0(
            decode_only_non_runtime_family(&store, &profile),
        )
        .err()
        .expect("bad future-candidate proof must retain a family failure");
        let closed = finish_failed_core_authorized_non_runtime_family_attempt_v0(failed);
        let owner = match *closed {
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::PocoApplication {
                owner,
                cause,
                ..
            } => {
                assert_eq!(
                    cause,
                    ClosedCoreAuthorizedNonRuntimeFamilyAttemptCauseV0::Attempt(
                        CoreAuthorizedNonRuntimeFamilyAttemptCauseV0::DeterministicallyInvalid(
                            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0::PocoOperation(
                                crate::poco_application::PocoApplicationDeterministicInvalidV0::CryptographicProof,
                            ),
                        ),
                    )
                );
                owner
            }
            ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::ValidatorTransition { .. }
            | ClosedFailedCoreAuthorizedNonRuntimeFamilyAttemptV0::Unsupported { .. } => {
                panic!("PoCO bad-proof rejection changed family")
            }
        };
        assert_eq!(owner.exact_outer_bytes, exact_outer);
        assert_eq!(owner.exact_inner_bytes, exact_inner);
        assert_eq!(owner.cursor_next_transaction_index, 0);
        assert_eq!(owner.decoded_next_transaction_index, 1);
        drop(owner);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_eq!(
            load_test_authenticated_poco_projection(&store),
            source_projection
        );
    }

    #[test]
    fn non_runtime_failure_reason_codes_are_exhaustive_static_and_unique() {
        use super::{
            CoreAuthorizedNonRuntimeFamilyDeterministicInvalidV0 as FamilyInvalid,
            CoreAuthorizedNonRuntimeFamilyInvariantV0 as FamilyInvariant,
            CoreAuthorizedNonRuntimeSemanticDecodeCauseV0 as Semantic,
            CoreAuthorizedNonRuntimeWriteSealInvariantV0 as WriteSeal,
            CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0 as Invalid,
            CoreAuthorizedRegularNonRuntimeInvariantV0 as Invariant,
            CoreAuthorizedRegularNonRuntimeSourceInvariantV0 as SourceInvariant,
        };
        use crate::poco_application::{
            PocoApplicationDeterministicInvalidV0 as PocoInvalid,
            PocoApplicationInvariantV0 as PocoInvariant,
        };
        use crate::validator_lifecycle::{
            ValidatorTransitionDeterministicInvalidV1 as ValidatorInvalid,
            ValidatorTransitionInvariantV1 as ValidatorInvariant,
        };

        let assert_unique = |codes: Vec<&'static str>| {
            let unique = codes
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(unique.len(), codes.len(), "failure reason codes collided");
            assert!(codes.iter().all(|code| {
                code.starts_with("native_regular_")
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            }));
        };

        let semantic = [
            Semantic::InvalidPocoApplicationOperation,
            Semantic::PocoTargetHeightMismatch,
            Semantic::InvalidValidatorTransition,
            Semantic::NonCanonicalValidatorTransition,
            Semantic::ValidatorTransitionSchemaMismatch,
            Semantic::ValidatorTransitionChainMismatch,
            Semantic::ValidatorTransitionCommandMismatch,
            Semantic::ValidatorTransitionSignerRoleMismatch,
        ];
        assert_unique(
            semantic
                .into_iter()
                .map(|reason| Invalid::SemanticDecode(reason).code())
                .collect(),
        );

        let poco_invalid = [
            PocoInvalid::PerBlockCapacity,
            PocoInvalid::TargetHeightMismatch,
            PocoInvalid::AuthorityRevisionMismatch,
            PocoInvalid::DuplicateOperation,
            PocoInvalid::SemanticTransition,
            PocoInvalid::MissingRequiredAuthorityFact,
            PocoInvalid::ProtocolWindowOrCap,
            PocoInvalid::NullifierProof,
            PocoInvalid::CryptographicProof,
            PocoInvalid::GovernanceRule,
            PocoInvalid::ValidatorRule,
            PocoInvalid::ChallengeNotPending,
            PocoInvalid::GovernanceApprovalMissing,
            PocoInvalid::ValidatorConsensusKeyAlreadyActive,
            PocoInvalid::NullifierNonMembershipRootMismatch,
        ];
        assert_unique(
            poco_invalid
                .into_iter()
                .map(|reason| Invalid::Family(FamilyInvalid::PocoOperation(reason)).code())
                .collect(),
        );

        let validator_invalid = [
            ValidatorInvalid::Schema,
            ValidatorInvalid::TransitionChainId,
            ValidatorInvalid::TransitionId,
            ValidatorInvalid::GovernanceAuthorization,
            ValidatorInvalid::GovernanceSequenceMismatch,
            ValidatorInvalid::PendingTransitionExists,
            ValidatorInvalid::BaseValidatorSetHash,
            ValidatorInvalid::ActivationHeight,
            ValidatorInvalid::TargetValidatorSet,
            ValidatorInvalid::ValidatorSetOverlap,
            ValidatorInvalid::NewValidatorProof,
            ValidatorInvalid::NoActiveSetChange,
        ];
        assert_unique(
            validator_invalid
                .into_iter()
                .map(|reason| Invalid::Family(FamilyInvalid::ValidatorTransition(reason)).code())
                .collect(),
        );
        assert_unique(vec![
            Invalid::Family(FamilyInvalid::PocoGovernanceAuthorization).code(),
            Invalid::Family(FamilyInvalid::UnsupportedFamily).code(),
        ]);

        let poco_invariant = [
            PocoInvariant::RawOwnerBounds,
            PocoInvariant::DecodedRawOwnerMismatch,
            PocoInvariant::OperationReencode,
            PocoInvariant::AuthenticatedOverlay,
            PocoInvariant::PlannerArithmetic,
            PocoInvariant::ProtocolCounterExhausted,
            PocoInvariant::DerivedMutationPostcondition,
        ];
        assert_unique(
            poco_invariant
                .into_iter()
                .map(|reason| Invariant::Family(FamilyInvariant::PocoOperation(reason)).code())
                .collect(),
        );

        let validator_invariant = [
            ValidatorInvariant::AuthenticatedLifecycle,
            ValidatorInvariant::LifecycleContextBinding,
            ValidatorInvariant::GovernanceSequenceExhausted,
            ValidatorInvariant::ActivationDelayOverflow,
            ValidatorInvariant::ActiveSetHash,
            ValidatorInvariant::ScheduledLifecyclePostcondition,
        ];
        assert_unique(
            validator_invariant
                .into_iter()
                .map(|reason| {
                    Invariant::Family(FamilyInvariant::ValidatorTransition(reason)).code()
                })
                .collect(),
        );
        assert_unique(vec![
            Invariant::SemanticDecodeSnapshot(SourceInvariant::AuthenticatedState).code(),
            Invariant::SemanticDecodeSnapshot(SourceInvariant::Host).code(),
            Invariant::FamilySnapshot(SourceInvariant::AuthenticatedState).code(),
            Invariant::FamilySnapshot(SourceInvariant::Host).code(),
            Invariant::WriteSealSnapshot(SourceInvariant::AuthenticatedState).code(),
            Invariant::WriteSealSnapshot(SourceInvariant::Host).code(),
            Invariant::FamilyAuthenticatedSource(SourceInvariant::AuthenticatedState).code(),
            Invariant::FamilyAuthenticatedSource(SourceInvariant::Host).code(),
            Invariant::Family(FamilyInvariant::PocoExecutionContext).code(),
            Invariant::Family(FamilyInvariant::PocoProjection).code(),
            Invariant::WriteSeal(WriteSeal::OwnerBinding).code(),
            Invariant::WriteSeal(WriteSeal::PocoSourceBinding).code(),
            Invariant::WriteSeal(WriteSeal::PocoSeal).code(),
            Invariant::WriteSeal(WriteSeal::PocoSealedPostcondition).code(),
            Invariant::WriteSeal(WriteSeal::PocoWriteEncoding).code(),
            Invariant::WriteSeal(WriteSeal::ValidatorScheduleRebind).code(),
            Invariant::WriteSeal(WriteSeal::ValidatorWriteEncoding).code(),
            Invariant::WriteSeal(WriteSeal::ValidatorWritePostcondition).code(),
        ]);

        assert_eq!(
            Invalid::SemanticDecode(Semantic::PocoTargetHeightMismatch).code(),
            Invalid::Family(FamilyInvalid::PocoOperation(
                PocoInvalid::TargetHeightMismatch
            ))
            .code(),
            "semantic and apply target-height rejection must share one canonical code",
        );

        let source = include_str!("native_payload_validation.rs");
        let facts_fields = source
            .split_once("pub(super) struct CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0 {")
            .expect("opaque non-runtime outcome token exists")
            .1
            .split_once("\n}")
            .expect("opaque non-runtime outcome token fields")
            .0;
        assert!(facts_fields.contains("generation: u64"));
        assert!(facts_fields
            .contains("disposition: CoreAuthorizedRegularNonRuntimeFailureDispositionV0"));
        assert!(
            !facts_fields.contains("pub"),
            "detached outcome authority escaped through a public token field",
        );
        let retain_signature = source
            .split_once("fn retain_non_runtime_failure_outcome_v0<")
            .expect("single-owner non-runtime retention exists")
            .1
            .split_once('{')
            .expect("single-owner non-runtime retention signature")
            .0;
        assert!(retain_signature.contains("failed: Box<Owner>"));
        assert!(retain_signature.contains("ClosedCoreAuthorizedRegularNonRuntimeFailureV0"));
        assert!(
            !retain_signature.contains("facts:"),
            "non-runtime retention accepted facts detached from its owner",
        );
        for function in [
            "fn promote_closed_core_authorized_non_runtime_semantic_decode_failure_v0(",
            "fn promote_closed_core_authorized_non_runtime_family_failure_v0(",
            "fn promote_closed_core_authorized_non_runtime_family_write_seal_failure_v0(",
        ] {
            let body = source
                .split_once(function)
                .expect("owning non-runtime promotion exists")
                .1
                .split_once("\n}\n")
                .expect("owning non-runtime promotion body")
                .0;
            for forbidden in [
                "generation:",
                "route:",
                "validation_id:",
                "Input::",
                "into_core_input",
                "Core::step",
                "format!(",
                "to_string(",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "non-runtime promotion accepted detached authority: {forbidden}",
                );
            }
        }
        let outcome_source = include_str!("execution_outcome.rs");
        let mapper_tail = outcome_source
            .split_once("fn failure_from_core_authorized_regular_non_runtime_v0(")
            .expect("typed non-runtime outcome mapper exists")
            .1;
        let mapper_signature = mapper_tail
            .split_once('{')
            .expect("typed non-runtime outcome mapper signature")
            .0;
        assert!(mapper_signature
            .contains("facts: CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0"));
        assert!(!mapper_signature.contains("generation:"));
        assert!(!mapper_signature.contains("reason:"));
        let mapper = mapper_tail
            .split_once("\n}\n")
            .expect("typed non-runtime outcome mapper body")
            .0;
        assert!(!mapper.contains("format!("));
        assert!(!mapper.contains("to_string("));
        assert!(!mapper.contains("Input::"));
    }

    #[test]
    fn pre_execution_failure_promotion_retains_each_real_owner_and_typed_disposition() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let expected_id = core_validation_request(&profile).id();
        let invalid_signers = Vec::new();
        let invalid_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: TEST_CHAIN.as_str(),
            authorized_signers: &invalid_signers,
        };
        let failed_open = open_core_authorized_regular_validation_for_test_v0(
            &invalid_host,
            core_validation_request(&profile),
        )
        .err()
        .expect("host binding drift must retain the open owner");
        let promoted_open = promote_failed_core_issued_regular_validation_open_v0(failed_open);
        assert_eq!(promoted_open.outcome.terminal_disposition(), None);
        assert_eq!(
            promoted_open.outcome.code(),
            "native_regular_open_invariant"
        );
        assert_eq!(promoted_open.failed.owner.request.id(), expected_id);

        let malformed = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![b"{".to_vec()],
        );
        let expected_decode_id = core_validation_request(&malformed).id();
        let failed_decode = first_production_decode_failure(&store, &malformed);
        let promoted_decode =
            promote_closed_core_authorized_regular_transaction_decode_failure_v0(failed_decode);
        assert_eq!(
            promoted_decode.outcome.terminal_disposition(),
            Some(
                crate::execution_outcome::TerminalExecutionDispositionV0::DeterministicallyInvalid
            )
        );
        assert_eq!(
            promoted_decode.outcome.code(),
            "native_regular_transaction_encoding_or_authorization_invalid"
        );
        assert_eq!(
            promoted_decode.failed.authorized.validation_id,
            expected_decode_id
        );

        let incomplete = fixture_profile(store.parent_state_root, 0);
        let expected_plan_id = core_validation_request(&incomplete).id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&incomplete),
        )
        .expect("open incomplete post-state owner");
        let failed_plan = finish_and_plan_core_authorized_regular_post_state_v0(open)
            .err()
            .expect("unexecuted body must fail post-state planning");
        let promoted_plan =
            promote_closed_core_authorized_regular_post_state_plan_failure_v0(failed_plan);
        assert_eq!(promoted_plan.outcome.terminal_disposition(), None);
        assert_eq!(
            promoted_plan.outcome.code(),
            "native_regular_post_state_plan_invariant"
        );
        assert_eq!(
            promoted_plan.failed.authorized.validation_id,
            expected_plan_id
        );

        let source = include_str!("native_payload_validation.rs");
        let reservation_mapping = source
            .split_once("impl FailedCoreIssuedRegularValidationReservationV0 {")
            .expect("typed reservation failure mapping")
            .1
            .split_once("\n}\n")
            .expect("typed reservation failure mapping body")
            .0;
        for required in [
            "DatabaseUnavailable",
            "StorageUnavailable",
            "HostResourceUnavailable",
            "Capacity",
            "Invariant",
            "HostInvariant",
        ] {
            assert!(reservation_mapping.contains(required));
        }
        assert!(!reservation_mapping.contains("format!("));
        assert!(!reservation_mapping.contains("to_string("));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn production_decode_failure_retains_prior_cursor_progress_and_exact_generation() {
        let store = test_store();
        let base = fixture_profile(store.parent_state_root, 0);
        let mut transactions = base.body.application_payload().transactions().to_vec();
        transactions[1] = b"{".to_vec();
        let profile = replace_profile_transactions(base, transactions);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            request,
        )
        .expect("open exact cursor with malformed second transaction");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("first exact transaction succeeds before second decode failure");
        assert_eq!(open.next_transaction_index, 1);
        assert_eq!(open.applied.len(), 1);
        assert!(!open.changes.is_empty());

        let failed = prepare_next_core_authorized_regular_payload_v0(open)
            .err()
            .expect("malformed second envelope must retain the owning cursor");
        let closed = finish_failed_core_authorized_regular_transaction_decode_v0(failed);
        assert_eq!(closed.authorized.validation_id, expected_id);
        assert_eq!(closed.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(closed.next_transaction_index, 1);
        assert_eq!(closed.applied.len(), 1);
        assert!(!closed.changes.is_empty());
        assert!(matches!(
            closed.cause,
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Decode(
                CoreAuthorizedRegularTransactionDecodeCauseV0::InvalidEnvelope,
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("reopen exact cursor for decode close precedence");
        let open = attempt_next_production_runtime_transaction(open)
            .expect("repeat first exact transaction before decode close failure");
        let mut failed = prepare_next_core_authorized_regular_payload_v0(open)
            .err()
            .expect("repeat malformed second envelope failure");
        failed
            .open
            .open
            .snapshot
            .inject_finish_failure_for_test_v0();
        let closed = finish_failed_core_authorized_regular_transaction_decode_v0(failed);
        assert_eq!(closed.authorized.validation_id, expected_id);
        assert_eq!(closed.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(closed.next_transaction_index, 1);
        assert_eq!(closed.applied.len(), 1);
        assert!(!closed.changes.is_empty());
        assert!(matches!(
            closed.cause,
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn production_snapshot_finish_failure_outranks_pending_decode_cause() {
        let store = test_store();
        let malformed = replace_profile_transactions(
            fixture_profile(store.parent_state_root, 0),
            vec![b"{".to_vec()],
        );
        let open = open_core_authorized_regular_transaction_cursor_v0(
            &test_native_validation_host(&store),
            core_validation_request(&malformed),
        )
        .expect("open malformed exact transaction cursor");
        let mut failed = prepare_next_core_authorized_regular_payload_v0(open)
            .err()
            .expect("malformed exact envelope must remain an owning failure");
        failed
            .open
            .open
            .snapshot
            .inject_finish_failure_for_test_v0();
        let closed = finish_failed_core_authorized_regular_transaction_decode_v0(failed);
        assert_eq!(
            closed.authorized.validation_id.block_id(),
            malformed.header.id()
        );
        assert_eq!(closed.next_transaction_index, 0);
        assert!(matches!(
            closed.cause,
            ClosedCoreAuthorizedRegularTransactionDecodeCauseV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_effect_intake_accepts_bound_routes_and_returns_other_effects_intact() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);

        let direct = match take_core_regular_validation_job_v0(core_validation_effect(&profile)) {
            CoreRegularValidationEffectIntakeV0::Job(job) => job,
            _ => panic!("real direct Core effect lost its route-bound job"),
        };
        assert_eq!(direct.request.route(), PayloadValidationRouteV0::Proposal);

        let synced =
            match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile)) {
                CoreRegularValidationEffectIntakeV0::Job(job) => job,
                _ => panic!("real synced Core effect lost its route-bound job"),
            };
        assert_eq!(synced.request.route(), PayloadValidationRouteV0::Synced);
        let CoreIssuedRegularValidationJobV0 {
            request: synced_request,
        } = *synced;
        let correct_synced_clone = synced_request.clone();
        assert!(matches!(
            take_core_regular_validation_job_v0(Effect::ValidatePayload(synced_request)),
            CoreRegularValidationEffectIntakeV0::RouteInvariant(_)
        ));
        let correct_synced = match take_core_regular_validation_job_v0(
            Effect::ValidateSyncedPayload(correct_synced_clone),
        ) {
            CoreRegularValidationEffectIntakeV0::Job(job) => job,
            _ => panic!("synced route mismatch consumed the correct request clone"),
        };
        assert!(correct_synced.request.try_claim().is_ok());

        let epoch = profile.header.epoch();
        let view = profile.header.view();
        let other = Effect::ArmViewTimer { epoch, view };
        match take_core_regular_validation_job_v0(other) {
            CoreRegularValidationEffectIntakeV0::Other(other) => match *other {
                Effect::ArmViewTimer {
                    epoch: retained_epoch,
                    view: retained_view,
                } => {
                    assert_eq!(retained_epoch, epoch);
                    assert_eq!(retained_view, view);
                }
                _ => panic!("non-validation Core effect changed variant"),
            },
            _ => panic!("non-validation Core effect was consumed or rewritten"),
        }
    }

    #[test]
    fn durable_reservation_fingerprint_is_stable_across_independent_core_request_graphs() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let first = core_validation_request(&profile);
        let second = core_validation_request(&profile);
        assert_eq!(first.id(), second.id());
        assert_eq!(first.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(second.route(), PayloadValidationRouteV0::Proposal);

        let first = first
            .try_claim()
            .unwrap_or_else(|_| panic!("first independent Core request has its own claim family"));
        let second = second
            .try_claim()
            .unwrap_or_else(|_| panic!("second independent Core request has its own claim family"));
        let first_fingerprint = native_validation_reservation_fingerprint_v0(&first)
            .expect("fingerprint first exact Core request");
        assert_eq!(
            first_fingerprint,
            native_validation_reservation_fingerprint_v0(&second)
                .expect("fingerprint second exact Core request")
        );
        assert_eq!(
            hex::encode(first_fingerprint),
            "b15611aabc72eec20cc86263ebbcb5d40e08b599161a1b67ee0ddf3db45e7693"
        );

        let synced = match core_synced_validation_effect(&profile) {
            Effect::ValidateSyncedPayload(request) => request,
            _ => panic!("Core synced validation fixture changed effect route"),
        };
        assert_eq!(synced.id(), first.id());
        let synced = synced
            .try_claim()
            .unwrap_or_else(|_| panic!("independent synced request has its own claim family"));
        assert_ne!(
            native_validation_reservation_fingerprint_v0(&first).expect("fingerprint direct route"),
            native_validation_reservation_fingerprint_v0(&synced)
                .expect("fingerprint synced route")
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn independent_core_request_graphs_reopen_durable_state_before_invalid_host_reads() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let first_job = match take_core_regular_validation_job_v0(core_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("first independent Core request lost its route-bound job"),
        };
        let second_job = match take_core_regular_validation_job_v0(core_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("second independent Core request lost its route-bound job"),
        };
        let expected_id = first_job.request.id();
        assert_eq!(second_job.request.id(), expected_id);

        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            first_job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("first independent Core request did not reserve: {other:?}"),
        };
        assert!(matches!(
            &open.authorized.reservation,
            CoreAuthorizedRegularReservationV0::Durable(_)
        ));
        finish_core_authorized_regular_validation_v0(open)
            .expect("fresh durable reservation closes its parent snapshot");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let invalid_signers = Vec::new();
        let invalid_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: "not-the-configured-chain",
            authorized_signers: &invalid_signers,
        };
        let existing =
            match begin_core_authorized_regular_validation_session_v0(&invalid_host, second_job) {
                CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(existing) => {
                    existing
                }
                other => {
                    panic!("exact independent request did not reopen durable state: {other:?}")
                }
            };
        assert_eq!(existing.request.id(), expected_id);
        assert_eq!(existing.request.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(existing.existing.validation_id(), expected_id);
        assert_eq!(
            existing.existing.route(),
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        assert_runtime_fixture_objects_absent(&store.store);
    }

    #[test]
    fn durable_reservation_rejects_cross_instance_route_splice_before_host_reads() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let direct_job = match take_core_regular_validation_job_v0(core_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("direct Core request lost its route-bound job"),
        };
        let synced_job =
            match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile)) {
                CoreRegularValidationEffectIntakeV0::Job(job) => *job,
                _ => panic!("synced Core request lost its route-bound job"),
            };
        let expected_id = direct_job.request.id();
        assert_eq!(synced_job.request.id(), expected_id);

        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            direct_job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("direct request did not reserve: {other:?}"),
        };
        finish_core_authorized_regular_validation_v0(open)
            .expect("direct reservation closes its parent snapshot");

        let invalid_signers = Vec::new();
        let invalid_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: "not-the-configured-chain",
            authorized_signers: &invalid_signers,
        };
        let failed =
            match begin_core_authorized_regular_validation_session_v0(&invalid_host, synced_job) {
                CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(failed) => {
                    failed
                }
                other => panic!("opposite route did not fail durable congruence: {other:?}"),
            };
        assert_eq!(failed.owner.request.id(), expected_id);
        assert_eq!(
            failed.owner.request.route(),
            PayloadValidationRouteV0::Synced
        );
        assert!(matches!(
            failed.cause,
            CoreIssuedRegularValidationReservationCauseV0::Store(ref store_failure)
                if matches!(
                    store_failure.cause(),
                    NativeValidationReservationFailureCauseV0::Invariant {
                        kind: NativeValidationReservationInvariantV0::RouteMismatch,
                        ..
                    }
                )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_effect_route_splice_is_invariant_before_claim_and_correct_clone_still_opens() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let spoofed = Effect::ValidateSyncedPayload(request.clone());

        let invariant = match take_core_regular_validation_job_v0(spoofed) {
            CoreRegularValidationEffectIntakeV0::RouteInvariant(invariant) => invariant,
            _ => panic!("opposite public wrapper did not fail as a route invariant"),
        };
        match &invariant._effect {
            Effect::ValidateSyncedPayload(retained) => {
                assert_eq!(retained.id(), expected_id);
                assert_eq!(retained.route(), PayloadValidationRouteV0::Proposal);
            }
            _ => panic!("route invariant did not retain the exact spoofed effect"),
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let job = match take_core_regular_validation_job_v0(Effect::ValidatePayload(request)) {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("correct direct wrapper failed after an inert route mismatch"),
        };
        let open = match begin_core_authorized_regular_validation_session_v0(
            &test_native_validation_host(&store),
            job,
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("correct route must retain the sole claim: {other:?}"),
        };
        assert_eq!(open.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(open.authorized.validation_id, expected_id);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        finish_core_authorized_regular_validation_v0(open)
            .expect("route-bound owner closes exact parent snapshot");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn synced_core_target_open_failure_retains_exact_route_and_generation() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let job = match take_core_regular_validation_job_v0(core_synced_validation_effect(&profile))
        {
            CoreRegularValidationEffectIntakeV0::Job(job) => *job,
            _ => panic!("real synced target did not enter its route-bound job"),
        };
        let expected_id = job.request.id();
        let authorized_signers = test_authorized_signers();
        let invalid_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: "not-the-configured-chain",
            authorized_signers: &authorized_signers,
        };

        let failed = match begin_core_authorized_regular_validation_session_v0(&invalid_host, job) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(failed) => failed,
            other => panic!("synced host mismatch did not retain an owning failure: {other:?}"),
        };
        assert_eq!(failed.owner.request.id(), expected_id);
        assert_eq!(
            failed.owner.request.route(),
            PayloadValidationRouteV0::Synced
        );
        assert_eq!(failed.owner.request.block().id(), expected_id.block_id());
        assert_eq!(
            failed.owner.request.parent().exact_header(),
            Some(&profile.parent)
        );
        assert!(matches!(
            failed.cause,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn duplicate_core_request_is_suppressed_before_host_or_snapshot_reads() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let first = claim_core_validation_request_for_test_v0(request.clone());
        let invalid_signers = Vec::new();
        let invalid_host = NativeValidationHostV0 {
            store: &store.store,
            chain_id: "not-the-configured-chain",
            authorized_signers: &invalid_signers,
        };

        let duplicate = match begin_core_authorized_regular_validation_session_v0(
            &invalid_host,
            core_regular_validation_job_for_test_v0(request),
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate(duplicate) => duplicate,
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(_) => {
                panic!("a duplicate request reopened validation")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(_) => {
                panic!("a duplicate request reached host validation")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(_) => {
                panic!("a volatile duplicate reached durable reservation")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(_) => {
                panic!("a volatile duplicate was rewritten as durable coalescing")
            }
        };
        assert_eq!(duplicate.request.id(), expected_id);
        assert_eq!(
            duplicate.request.route(),
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(duplicate.request.block().id(), expected_id.block_id());
        assert_eq!(
            duplicate.request.parent().exact_header(),
            Some(&profile.parent)
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        drop(first);
    }

    #[test]
    fn duplicate_core_request_cannot_reopen_an_active_owner() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let host = test_native_validation_host(&store);

        let open = match begin_core_authorized_regular_validation_session_v0(
            &host,
            core_regular_validation_job_for_test_v0(request.clone()),
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => *open,
            other => panic!("fresh Core request must own the session: {other:?}"),
        };
        assert_eq!(open.authorized.validation_id, expected_id);
        assert_eq!(open.authorized.route, PayloadValidationRouteV0::Proposal);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        let duplicate = match begin_core_authorized_regular_validation_session_v0(
            &host,
            core_regular_validation_job_for_test_v0(request),
        ) {
            CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate(duplicate) => duplicate,
            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(_) => {
                panic!("a clone reopened an active validation owner")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(_) => {
                panic!("a clone reached host validation instead of suppression")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(_) => {
                panic!("a clone reached durable reservation instead of volatile suppression")
            }
            CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(_) => {
                panic!("a clone was rewritten as durable coalescing")
            }
        };
        assert_eq!(duplicate.request.id(), expected_id);
        assert_eq!(
            duplicate.request.route(),
            PayloadValidationRouteV0::Proposal
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        finish_core_authorized_regular_validation_v0(open)
            .expect("the sole active owner closes cleanly");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn concurrent_core_request_clones_open_exactly_one_validation_session() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let requests = (0..16).map(|_| request.clone()).collect::<Vec<_>>();
        let host = test_native_validation_host(&store);

        let opened = std::thread::scope(|scope| {
            let host = &host;
            let workers = requests
                .into_iter()
                .map(|request| {
                    scope.spawn(move || {
                        match begin_core_authorized_regular_validation_session_v0(
                            host,
                            core_regular_validation_job_for_test_v0(request),
                        ) {
                            CoreAuthorizedRegularValidationSessionAdmissionV0::Open(open) => {
                                assert_eq!(open.authorized.validation_id, expected_id);
                                finish_core_authorized_regular_validation_v0(*open)
                                    .expect("the sole admitted clone closes its snapshot");
                                1_u32
                            }
                            CoreAuthorizedRegularValidationSessionAdmissionV0::Duplicate(
                                duplicate,
                            ) => {
                                assert_eq!(duplicate.request.id(), expected_id);
                                0_u32
                            }
                            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedOpen(
                                failed,
                            ) => panic!("the sole admitted fixture request failed: {failed:?}"),
                            CoreAuthorizedRegularValidationSessionAdmissionV0::FailedReservation(
                                _,
                            ) => panic!("the sole admitted fixture request was not reserved"),
                            CoreAuthorizedRegularValidationSessionAdmissionV0::DurablyExisting(
                                _,
                            ) => panic!("an in-family clone became an existing durable job"),
                        }
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("claim worker must not panic"))
                .sum::<u32>()
        });

        assert_eq!(opened, 1);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_request_opens_one_same_snapshot_parent_configuration_carrier() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        assert_eq!(
            request.parent().exact_header(),
            Some(&profile.parent),
            "Core capability must retain the exact native parent"
        );

        let host = test_native_validation_host(&store);
        let open = open_core_authorized_regular_validation_for_test_v0(&host, request)
            .expect("open exact Core parent/configuration carrier");
        assert_eq!(
            open.authorized.validation_id.block_id(),
            profile.header.id()
        );
        assert_eq!(open.authorized.header, profile.header);
        assert_eq!(open.authorized.body, profile.body);
        assert_eq!(open.authorized.context.parent_header, profile.parent);
        assert_eq!(open.authorized.context.validator_set, profile.validator_set);
        assert_eq!(open.authorized.context.parameters, profile.parameters);
        assert_eq!(
            open.authorized.context.validator_lifecycle,
            store.validator_lifecycle
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        let finished = finish_core_authorized_regular_validation_v0(open)
            .expect("finish exact Core parent/configuration carrier");
        assert_eq!(finished.authorized.header.id(), profile.header.id());
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn authorized_body_close_failure_retains_the_exact_core_owner() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let mut open = open_core_authorized_regular_validation_for_test_v0(
            &test_native_validation_host(&store),
            core_validation_request(&profile),
        )
        .expect("open exact authorized body before injected close failure");
        let expected_id = open.authorized.validation_id;
        open.snapshot.inject_finish_failure_for_test_v0();

        let closed = finish_core_authorized_regular_validation_v0(open)
            .err()
            .expect("close failure must retain the exact authorized body");
        assert_eq!(closed.authorized.validation_id, expected_id);
        assert_eq!(closed.authorized.route, PayloadValidationRouteV0::Proposal);
        assert!(matches!(
            closed.cause,
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                ..
            }
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_request_rejects_authenticated_configuration_source_splice() {
        let store = test_store();
        let foreign = fixture_profile(store.parent_state_root, 1);
        let request = core_validation_request(&foreign);
        let expected_id = request.id();
        let failure = open_core_authorized_regular_validation_for_test_v0(
            &test_native_validation_host(&store),
            request,
        )
        .err()
        .expect("configuration splice must retain the exact Core request");
        assert_eq!(failure.owner.request.id(), expected_id);
        assert_eq!(
            failure.owner.request.route(),
            PayloadValidationRouteV0::Proposal
        );
        assert!(matches!(
            failure.cause,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::VerifyPocoProjection,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_request_does_not_fall_back_from_a_foreign_parent_root_to_committed_head() {
        let store = test_store();
        let profile = replace_profile_parent_state_root(
            fixture_profile(store.parent_state_root, 0),
            StateRoot::new([0xa6; 32]),
        );
        let request = core_validation_request(&profile);
        let expected_id = request.id();
        let failure = open_core_authorized_regular_validation_for_test_v0(
            &test_native_validation_host(&store),
            request,
        )
        .err()
        .expect("foreign parent root must retain the exact Core request");
        assert_eq!(failure.owner.request.id(), expected_id);
        assert!(matches!(
            failure.cause,
            OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_request_keeps_root_inconsistent_retained_body_source_retryable() {
        let store = test_store();
        let mut spliced = fixture_profile(store.parent_state_root, 0);
        spliced.body = fixture_profile(store.parent_state_root, 1).body;

        let failure = open_core_authorized_regular_validation_for_test_v0(
            &test_native_validation_host(&store),
            core_validation_request(&spliced),
        )
        .err()
        .expect("retained body that does not match the signed root must be unavailable");
        assert_eq!(failure.owner.request.id().block_id(), spliced.header.id());
        assert_eq!(failure.owner.request.block().id(), spliced.header.id());
        assert_eq!(
            failure.owner.request.parent().exact_header(),
            Some(&spliced.parent)
        );
        assert!(matches!(
            failure.cause,
            OpenCoreAuthorizedRegularValidationFailureV0::SourceUnavailable(
                super::CoreAuthorizedExactRegularBodyFailureV0 {
                    reason: "retained payload root differs from header commitment",
                    ..
                }
            )
        ));
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn snapshot_finish_failure_outranks_every_exact_body_failure_class() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let pending = [
            OpenCoreAuthorizedRegularValidationFailureV0::SourceUnavailable(
                CoreAuthorizedExactRegularBodyFailureV0::source_unavailable("source"),
            ),
            OpenCoreAuthorizedRegularValidationFailureV0::DeterministicallyInvalid(
                CoreAuthorizedExactRegularBodyFailureV0::deterministically_invalid("invalid"),
            ),
            OpenCoreAuthorizedRegularValidationFailureV0::Invariant(
                CoreAuthorizedExactRegularBodyFailureV0::invariant("invariant"),
            ),
        ];

        for failure in pending {
            let request = core_validation_request(&profile);
            let expected_id = request.id();
            let mut snapshot = store
                .store
                .begin_authenticated_runtime_read_snapshot_for_core_parent_v0(request.parent())
                .expect("open exact parent snapshot for finish precedence");
            snapshot.inject_finish_failure_for_test_v0();
            let closed = finish_open_regular_validation_failure_v0(Box::new(
                super::PendingCoreIssuedRegularValidationOpenFailureV0 {
                    snapshot,
                    owner: CoreIssuedRegularValidationOwnerV0 {
                        request: claim_core_validation_request_for_test_v0(request),
                        reservation: super::CoreAuthorizedRegularReservationV0::TestOnly,
                    },
                    pending_cause: failure,
                },
            ));
            assert_eq!(closed.owner.request.id(), expected_id);
            assert!(matches!(
                closed.cause,
                OpenCoreAuthorizedRegularValidationFailureV0::AuthenticatedSource(
                    AuthenticatedRuntimeReadFailureV0::HostInvariant {
                        stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                        ..
                    }
                )
            ));
        }
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn sibling_writer_cannot_move_an_open_parent_configuration_snapshot() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let request = core_validation_request(&profile);
        let snapshot = store
            .store
            .begin_authenticated_runtime_read_snapshot_for_core_parent_v0(request.parent())
            .expect("open exact parent configuration snapshot before sibling writer");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);

        let signer_policy_hash_hex =
            hex::encode(crate::signer_policy_commitment(&test_authorized_signers()));
        let writer = ApplicationStore::open(
            &store.root.join("state.json"),
            TEST_CHAIN.as_str(),
            &signer_policy_hash_hex,
        )
        .expect("open independent configuration sibling writer");
        let current = writer
            .load_or_migrate()
            .expect("load configuration sibling parent state");
        assert_eq!(current.height, 1);
        assert_eq!(current.app_hash, store.parent_state_root);
        let sibling_update = writer
            .plan_auth_update(2, Vec::new())
            .expect("plan legitimate empty configuration sibling transition");
        let sibling_app_hash: [u8; 32] = sibling_update.root_hash.into();
        let sibling = PendingBlock {
            height: 2,
            app_hash: sibling_app_hash,
            tx_results: Vec::new(),
            native_execution: crate::test_authorized_empty_native_execution(
                current.height,
                current.app_hash,
                2,
                sibling_app_hash,
            ),
            validator_updates: Vec::new(),
            delta: BlockDelta::default(),
            auth_update: sibling_update,
            poco_checkpoint_execution: None,
        };
        writer
            .persist_transition(&current, &sibling, 0)
            .expect("commit configuration sibling through existing writer seam");
        let sibling_head = writer
            .load_or_migrate()
            .expect("reload committed configuration sibling head");
        assert_eq!(sibling_head.height, 2);
        assert_eq!(sibling_head.app_hash, sibling_app_hash);

        let projection = snapshot
            .load_authenticated_production_poco_projection_v0()
            .expect("load configuration from still-open exact parent snapshot");
        let (validator_set, parameters) =
            crate::poco_checkpoint::active_consensus_configuration(&projection)
                .expect("decode exact parent active configuration");
        let lifecycle = snapshot
            .load_authenticated_validator_lifecycle_v0()
            .expect("load lifecycle from still-open exact parent snapshot");
        assert_eq!(validator_set, profile.validator_set);
        assert_eq!(parameters, profile.parameters);
        assert_eq!(lifecycle, store.validator_lifecycle);

        snapshot
            .finish()
            .expect("finish exact parent configuration snapshot");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn core_validation_body_carrier_decodes_only_the_retained_exact_transport() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let block = exact_transport_block(&profile);
        let validation_id = ValidationId::new(block.id(), block.header().view(), 7);

        let authorized = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .expect("authorize exact retained Core transport");

        assert_eq!(authorized.validation_id, validation_id);
        assert_eq!(authorized.header, profile.header);
        assert_eq!(authorized.body, profile.body);
    }

    #[test]
    fn core_validation_body_carrier_rejects_generation_splice_and_inexact_payload() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let block = exact_transport_block(&profile);
        let wrong_id = ValidationId::new(BlockId::new([0xEE; 32]), block.header().view(), 7);
        let failure = authorize_exact_regular_body_parts_v0(
            wrong_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .err()
        .expect("wrong Core validation identity must fail");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::Invariant
        );
        assert_eq!(
            failure.reason,
            "Core validation identity differs from retained block"
        );

        let mut payload = profile
            .body
            .application_payload()
            .try_cev0_bytes()
            .expect("encode exact fixture application payload");
        payload.push(0);
        let block = Block::new(profile.header.clone(), payload, Vec::new())
            .expect("transport holder retains inexact bytes for host rejection");
        let validation_id = ValidationId::new(block.id(), block.header().view(), 8);
        let failure = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .err()
        .expect("trailing application payload byte must fail");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::SourceUnavailable
        );
        assert_eq!(
            failure.reason,
            "retained application payload is not exact canonical CEV0"
        );
    }

    #[test]
    fn core_validation_body_carrier_rejects_body_source_substitution() {
        let store = test_store();
        let committed = fixture_profile(store.parent_state_root, 0);
        let substituted = fixture_profile(store.parent_state_root, 1);
        let block = Block::new(
            committed.header.clone(),
            substituted
                .body
                .application_payload()
                .try_cev0_bytes()
                .expect("encode substituted exact payload"),
            Vec::new(),
        )
        .expect("construct root-inconsistent retained transport");
        let validation_id = ValidationId::new(block.id(), block.header().view(), 9);

        let failure = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&committed, &store.validator_lifecycle),
        )
        .err()
        .expect("body source substitution must fail");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::SourceUnavailable
        );
        assert_eq!(
            failure.reason,
            "retained payload root differs from header commitment"
        );
    }

    #[test]
    fn core_validation_body_carrier_classifies_actual_size_excess_as_deterministic() {
        let store = test_store();
        let mut profile = fixture_profile(store.parent_state_root, 0);
        let mut parameter_fields = profile.parameters.fields();
        parameter_fields.max_block_bytes = u32::try_from(
            profile
                .body
                .application_payload()
                .try_cev0_bytes()
                .expect("encode the exact application payload for the narrow size bound")
                .len(),
        )
        .expect("fixture application payload length fits u32");
        profile.parameters = ConsensusParametersV0::new(parameter_fields)
            .expect("construct a valid but deliberately tiny block-size bound");
        profile.validator_set = ValidatorSet::new(
            profile.validator_set.genesis_hash(),
            profile.validator_set.chain_id(),
            profile.validator_set.protocol_version(),
            profile.validator_set.epoch(),
            profile.parameters.hash(),
            profile.validator_set.validators().to_vec(),
        )
        .expect("bind the tiny parameter hash into the exact validator set");
        let header = profile.header.clone();
        profile.header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            profile.validator_set.id(),
            profile.parameters.hash(),
            header.payload_root(),
            header.state_root(),
            header.receipts_root(),
            header.evidence_root(),
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .expect("bind the tiny authenticated parameter hash into the exact header");
        let block = exact_transport_block(&profile);
        let validation_id = ValidationId::new(block.id(), block.header().view(), 10);

        let failure = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .err()
        .expect("canonical body above the authenticated maximum must be invalid");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid
        );
        assert_eq!(
            failure.reason,
            "retained header/body exceed committed block-size bound"
        );
    }

    #[test]
    fn core_validation_body_carrier_classifies_root_bound_payload_alone_excess_as_deterministic() {
        let store = test_store();
        let mut profile = fixture_profile(store.parent_state_root, 0);
        let payload_length = profile
            .body
            .application_payload()
            .try_cev0_bytes()
            .expect("encode exact application payload for staged root binding")
            .len();
        let mut parameter_fields = profile.parameters.fields();
        parameter_fields.max_block_bytes = u32::try_from(
            payload_length
                .checked_sub(1)
                .expect("fixture payload is non-empty"),
        )
        .expect("fixture payload length fits u32");
        assert!(
            u64::try_from(payload_length).expect("fixture payload length fits u64")
                > u64::from(parameter_fields.max_block_bytes)
        );
        profile.parameters = ConsensusParametersV0::new(parameter_fields)
            .expect("construct active bound below the canonical payload alone");
        profile.validator_set = ValidatorSet::new(
            profile.validator_set.genesis_hash(),
            profile.validator_set.chain_id(),
            profile.validator_set.protocol_version(),
            profile.validator_set.epoch(),
            profile.parameters.hash(),
            profile.validator_set.validators().to_vec(),
        )
        .expect("bind the staged-decode parameter hash into the validator set");
        let header = profile.header.clone();
        profile.header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            profile.validator_set.id(),
            profile.parameters.hash(),
            profile
                .body
                .payload_root()
                .expect("bind exact oversize payload root"),
            header.state_root(),
            header.receipts_root(),
            header.evidence_root(),
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .expect("bind staged-decode configuration into exact header");
        let block = exact_transport_block(&profile);
        let validation_id = ValidationId::new(block.id(), block.header().view(), 12);

        let failure = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .err()
        .expect("root-bound canonical payload above its active limit must be invalid");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid
        );
        assert_eq!(
            failure.reason,
            "retained header/body exceed committed block-size bound"
        );
    }

    #[test]
    fn core_validation_body_carrier_classifies_root_bound_bad_evidence_as_deterministic() {
        let store = test_store();
        let mut profile = fixture_profile(store.parent_state_root, 0);
        let author = profile.validator_set.validators()[0].id();
        let first = Vote::new(
            TEST_CHAIN,
            ProtocolVersion::V0,
            profile.validator_set.epoch(),
            View::new(19),
            Height::new(19),
            BlockId::new([0x91; 32]),
            profile.validator_set.id(),
            author,
            SignatureBytes::from_array([0x31; SIGNATURE_BYTES]),
            &profile.validator_set,
        )
        .expect("construct canonical first double-vote record");
        let second = Vote::new(
            TEST_CHAIN,
            ProtocolVersion::V0,
            profile.validator_set.epoch(),
            View::new(19),
            Height::new(19),
            BlockId::new([0x92; 32]),
            profile.validator_set.id(),
            author,
            SignatureBytes::from_array([0x32; SIGNATURE_BYTES]),
            &profile.validator_set,
        )
        .expect("construct canonical second double-vote record");
        let evidence = DoubleVoteEvidenceV0::from_votes(&first, &second)
            .expect("construct exact root-bound double-vote evidence");
        profile.body = BlockBodyV0::new(profile.body.application_payload().clone(), vec![evidence])
            .expect("construct canonical body with deliberately bad signatures");
        let header = profile.header.clone();
        profile.header = BlockHeader::new(
            header.genesis_hash(),
            header.chain_id(),
            header.protocol_version(),
            header.epoch(),
            header.view(),
            header.height(),
            header.block_kind(),
            header.parent_id(),
            header.proposer_id(),
            header.validator_set_id(),
            header.consensus_parameters_hash(),
            profile
                .body
                .payload_root()
                .expect("derive exact payload root"),
            header.state_root(),
            header.receipts_root(),
            profile
                .body
                .evidence_root()
                .expect("derive exact evidence root"),
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )
        .expect("bind the canonical evidence root into the signed header");
        let block = exact_transport_block(&profile);
        let validation_id = ValidationId::new(block.id(), block.header().view(), 11);

        let failure = authorize_exact_regular_body_parts_v0(
            validation_id,
            block,
            snapshot_context(&profile, &store.validator_lifecycle),
        )
        .err()
        .expect("root-bound evidence with bad strict signatures must be invalid");
        assert_eq!(
            failure.class,
            CoreAuthorizedExactRegularBodyFailureClassV0::DeterministicallyInvalid
        );
        assert_eq!(
            failure.reason,
            "retained evidence fails strict Ed25519 verification"
        );
    }

    #[test]
    fn same_height_and_root_foreign_parent_block_id_is_rejected() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let foreign = fixture_profile(store.parent_state_root, 1);
        assert_eq!(profile.parent.height(), foreign.parent.height());
        assert_eq!(profile.parent.state_root(), foreign.parent.state_root());
        assert_ne!(profile.parent.id(), foreign.parent.id());
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            profile.body,
            foreign.parent,
            profile.validator_set,
            profile.parameters,
            profile.authorized_signers,
        )
        .err()
        .expect("foreign parent BlockId must fail exact join");
        assert_eq!(
            error.reason,
            "exact parent BlockId differs from header parent_id"
        );
    }

    #[test]
    fn header_body_and_configuration_splices_are_rejected() {
        let store = test_store();

        let profile = fixture_profile(store.parent_state_root, 0);
        let foreign = fixture_profile(store.parent_state_root, 1);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            foreign.header,
            profile.body,
            foreign.parent,
            foreign.validator_set,
            foreign.parameters,
            profile.authorized_signers,
        )
        .err()
        .expect("foreign exact header must fail request BlockId join");
        assert_eq!(
            error.reason,
            "authorized request BlockId differs from exact header"
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let foreign = fixture_profile(store.parent_state_root, 1);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            foreign.body,
            profile.parent,
            profile.validator_set,
            profile.parameters,
            profile.authorized_signers,
        )
        .err()
        .expect("foreign exact body must fail payload-root join");
        assert_eq!(
            error.reason,
            "exact body payload root differs from header commitment"
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let foreign = fixture_profile(store.parent_state_root, 1);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            profile.body,
            profile.parent,
            foreign.validator_set,
            profile.parameters,
            profile.authorized_signers,
        )
        .err()
        .expect("foreign validator configuration must fail exact join");
        assert_eq!(
            error.reason,
            "exact validator-set context differs from header chain context"
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            profile.body,
            profile.parent,
            profile.validator_set,
            profile.parameters,
            vec![AuthorizedSignerV1 {
                signer_id: "did:operator:foreign".to_string(),
                signer_role: "operator".to_string(),
                public_key_hex: hex::encode(test_signing_key(99).verifying_key().to_bytes()),
            }],
        )
        .err()
        .expect("foreign signer policy must fail exact join");
        assert_eq!(
            error.reason,
            "authorized signer policy differs from fixture comparison value"
        );

        let profile = fixture_profile(store.parent_state_root, 0);
        let request = TestAuthorizedRegularRuntimeRequestV0::from_exact_header_for_test_v0(
            &profile.header,
            fixture_signer_policy_commitment(&profile),
        );
        let mut foreign_parameter_fields = profile.parameters.fields();
        foreign_parameter_fields.max_block_bytes -= 1;
        let foreign_parameters = ConsensusParametersV0::new(foreign_parameter_fields)
            .expect("construct safe foreign parameter profile");
        let error = authenticate_regular_runtime_inputs_for_test_v0(
            request,
            profile.header,
            profile.body,
            profile.parent,
            profile.validator_set,
            foreign_parameters,
            profile.authorized_signers,
        )
        .err()
        .expect("foreign consensus parameters must fail exact join");
        assert_eq!(
            error.reason,
            "exact consensus parameters differ from header commitments"
        );
    }

    #[test]
    fn dropping_open_traversal_cannot_return_a_finished_capability() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        let open =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .expect("open inert traversal for Drop-only boundary");
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 1);
        drop(open);
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
        // The only finished constructor consumes the open value and calls the
        // snapshot's explicit `finish`; Drop produces no marker or capability.
    }

    #[test]
    fn snapshot_finish_failure_outranks_incomplete_body_and_releases_the_pin() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let inputs = authenticate(profile);
        let open = open_inert_regular_body_traversal_for_test_v0(&test_store.store, inputs)
            .expect("open inert regular body traversal");
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            1
        );

        let open = inject_snapshot_finish_failure_for_test_v0(open);
        assert!(matches!(
            finish_inert_regular_body_traversal_for_test_v0(open),
            Err(InertRegularBodyFinishFailureV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            ))
        ));
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn snapshot_finish_failure_outranks_cursor_rejection_and_releases_the_pin() {
        let test_store = test_store();
        let profile = fixture_profile(test_store.parent_state_root, 0);
        let mut transactions = profile.body.application_payload().transactions().to_vec();
        transactions[0] = b"{".to_vec();
        let profile = replace_profile_transactions(profile, transactions);
        let open =
            open_inert_regular_body_traversal_for_test_v0(&test_store.store, authenticate(profile))
                .expect("open inert traversal with invalid envelope");
        let open = inject_snapshot_finish_failure_for_test_v0(open);
        let failed = observe_next_exact_body_transaction_for_test_v0(open)
            .err()
            .expect("invalid envelope must consume the open traversal");

        assert!(matches!(
            finish_failed_inert_regular_body_traversal_for_test_v0(failed),
            FinishedInertRegularBodyCursorFailureV0::Snapshot(
                AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: crate::store::AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    ..
                }
            )
        ));
        assert_eq!(
            test_store.store.active_runtime_snapshot_pins_for_test_v0(),
            0
        );
    }

    #[test]
    fn finish_requires_the_internal_cursor_to_consume_the_exact_body_in_order() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let open =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .expect("open incomplete inert traversal");
        let error = finish_inert_regular_body_traversal_for_test_v0(open)
            .err()
            .expect("unobserved body must not yield a finished capability");
        assert_eq!(
            error,
            InertRegularBodyFinishFailureV0::IncompleteBody {
                observed: 0,
                expected: 2,
            }
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);

        let profile = fixture_profile(store.parent_state_root, 0);
        let open =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .expect("open partially observed inert traversal");
        let open = observe_next_exact_body_transaction_for_test_v0(open)
            .expect("observe only first exact body transaction");
        let error = finish_inert_regular_body_traversal_for_test_v0(open)
            .err()
            .expect("partially observed body must not yield a finished capability");
        assert_eq!(
            error,
            InertRegularBodyFinishFailureV0::IncompleteBody {
                observed: 1,
                expected: 2,
            }
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }

    #[test]
    fn exhausted_internal_cursor_has_no_repeat_or_seek_path() {
        let store = test_store();
        let profile = fixture_profile(store.parent_state_root, 0);
        let open =
            open_inert_regular_body_traversal_for_test_v0(&store.store, authenticate(profile))
                .expect("open traversal for exhausted cursor boundary");
        let open = observe_next_exact_body_transaction_for_test_v0(open)
            .expect("observe first exact body transaction");
        let open = observe_next_exact_body_transaction_for_test_v0(open)
            .expect("observe second exact body transaction");
        let error = observe_next_exact_body_transaction_for_test_v0(open)
            .err()
            .expect("cursor beyond exact body must be consumed and rejected");
        assert_eq!(
            finish_failed_inert_regular_body_traversal_for_test_v0(error),
            FinishedInertRegularBodyCursorFailureV0::Cursor(
                InertRegularBodyCursorFailureV0::Exhausted
            )
        );
        assert_eq!(store.store.active_runtime_snapshot_pins_for_test_v0(), 0);
    }
}
