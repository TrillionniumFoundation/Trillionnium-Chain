use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use trnm_consensus_types::{
    Block, BlockHeader, BlockId, CanonicalSignIntentV0, CertificateId, ChainId,
    ConsensusParametersV0, Epoch, EquivocationEvidence, FinalityProofV0, GenesisQcV0, Height,
    ProtocolVersion, QcRef, QcReferenceV0, QuorumCertificate, SignatureBytes, SignedProposalV0,
    SigningRoot, TimeoutCertificateV0, TimeoutVote, ValidatedBlockCommitmentsV0, ValidatorId,
    ValidatorSet, ValidatorSetId, View, Vote,
};

use crate::{CoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    trusted_genesis_timestamp_ms: u64,
    max_blocks: usize,
    max_observed_messages: usize,
}

impl CoreConfig {
    pub fn new(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        trusted_genesis_timestamp_ms: u64,
        max_blocks: usize,
        max_observed_messages: usize,
    ) -> Result<Self> {
        let value = Self {
            local_validator,
            validator_set,
            consensus_parameters,
            trusted_genesis_timestamp_ms,
            max_blocks,
            max_observed_messages,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn genesis_block_id(&self) -> BlockId {
        BlockId::new(*self.validator_set.genesis_hash().as_bytes())
    }

    pub const fn consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub const fn trusted_genesis_timestamp_ms(&self) -> u64 {
        self.trusted_genesis_timestamp_ms
    }

    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }

    pub const fn max_observed_messages(&self) -> usize {
        self.max_observed_messages
    }

    pub const fn max_block_bytes(&self) -> usize {
        self.consensus_parameters.max_block_bytes() as usize
    }

    pub const fn max_block_time_step_ms(&self) -> u64 {
        self.consensus_parameters.max_block_time_step_ms()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validator_set
            .validate_against_parameters(&self.consensus_parameters)?;
        if self.validator_set.validator(self.local_validator).is_none() {
            return Err(CoreError::LocalValidatorMissing(Box::new(
                self.local_validator,
            )));
        }
        self.consensus_parameters.validate_safety_invariants()?;
        if self.consensus_parameters.hash() != self.validator_set.consensus_parameters_hash() {
            return Err(CoreError::InvalidConfig(
                "consensus parameter preimage does not match the validator set commitment",
            ));
        }
        if self.consensus_parameters.protocol_version()
            != self.validator_set.protocol_version().get()
        {
            return Err(CoreError::InvalidConfig(
                "consensus parameters do not match the validator-set protocol version",
            ));
        }
        if self.max_blocks < 4 {
            return Err(CoreError::InvalidConfig("max_blocks must be at least four"));
        }
        if self.max_observed_messages < self.validator_set.validators().len() {
            return Err(CoreError::InvalidConfig(
                "observed-message bound must cover the validator set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BarrierId(u64);

impl BarrierId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidationId {
    block_id: BlockId,
    view: View,
    generation: u64,
}

impl ValidationId {
    pub const fn new(block_id: BlockId, view: View, generation: u64) -> Self {
        Self {
            block_id,
            view,
            generation,
        }
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn view(self) -> View {
        self.view
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignId(SigningRoot);

impl SignId {
    pub const fn new(root: SigningRoot) -> Self {
        Self(root)
    }

    pub const fn signing_root(self) -> SigningRoot {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKind {
    Vote,
    TimeoutVote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignIntent {
    Vote {
        authorizing_safety_revision: u64,
        view: View,
        height: Height,
        block_id: BlockId,
        signing_root: SigningRoot,
    },
    TimeoutVote {
        authorizing_safety_revision: u64,
        view: View,
        high_qc: QcRef,
        signing_root: SigningRoot,
    },
}

impl SignIntent {
    /// SafetyState revision which first made this signing authorization
    /// durable. Unrelated exact callback persistence may advance the enclosing
    /// state revision while this outbox remains pending, but it must never
    /// change the signer authorization or its canonical fingerprint.
    pub const fn authorizing_safety_revision(&self) -> u64 {
        match self {
            Self::Vote {
                authorizing_safety_revision,
                ..
            }
            | Self::TimeoutVote {
                authorizing_safety_revision,
                ..
            } => *authorizing_safety_revision,
        }
    }

    pub const fn view(&self) -> View {
        match self {
            Self::Vote { view, .. } | Self::TimeoutVote { view, .. } => *view,
        }
    }

    pub const fn signing_root(&self) -> SigningRoot {
        match self {
            Self::Vote { signing_root, .. } | Self::TimeoutVote { signing_root, .. } => {
                *signing_root
            }
        }
    }

    pub const fn id(&self) -> SignId {
        SignId::new(self.signing_root())
    }

    pub const fn kind(&self) -> SignKind {
        match self {
            Self::Vote { .. } => SignKind::Vote,
            Self::TimeoutVote { .. } => SignKind::TimeoutVote,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedTip {
    height: Height,
    view: View,
    block_id: BlockId,
    timestamp_ms: u64,
}

/// Exact Core-authenticated parent context retained by one payload request.
///
/// A positive-height parent carries its complete native header, including the
/// state root needed to bind an application snapshot. The trusted synthetic
/// genesis anchor has no native network header or state root, so it remains an
/// explicit header-less case which downstream hosts must classify as
/// unavailable until a canonical genesis-state carrier exists.
///
/// All fields and constructors are crate-private. External hosts may inspect
/// a value only after receiving it inside a Core-issued
/// [`PayloadValidationRequest`]; they cannot manufacture a parent authority
/// from caller-supplied height/root coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadValidationParentV0 {
    tip: FinalizedTip,
    exact_header: Option<BlockHeader>,
}

impl PayloadValidationParentV0 {
    pub(crate) fn from_exact_header(header: BlockHeader) -> Self {
        let tip = FinalizedTip::new(
            header.height(),
            header.view(),
            header.id(),
            header.timestamp_ms(),
        );
        Self {
            tip,
            exact_header: Some(header),
        }
    }

    pub(crate) const fn trusted_genesis(tip: FinalizedTip) -> Self {
        Self {
            tip,
            exact_header: None,
        }
    }

    pub const fn tip(&self) -> FinalizedTip {
        self.tip
    }

    pub const fn exact_header(&self) -> Option<&BlockHeader> {
        self.exact_header.as_ref()
    }
}

impl FinalizedTip {
    pub const fn new(height: Height, view: View, block_id: BlockId, timestamp_ms: u64) -> Self {
        Self {
            height,
            view,
            block_id,
            timestamp_ms,
        }
    }

    pub const fn height(self) -> Height {
        self.height
    }

    pub const fn view(self) -> View {
        self.view
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn timestamp_ms(self) -> u64 {
        self.timestamp_ms
    }
}

/// Current durable safety-state schema. Version five added bounded, canonical
/// payload-validation obligations so persistence cannot silently forget a
/// Core-issued validation route, generation, proposal, or exact parent.
/// Version six added route-scoped completion tombstones. Version seven keeps
/// those tombstones while replacing their process-local validation-capability
/// value with an inert, durable result snapshot. A decoded snapshot can prove
/// equality with a newly supplied live result, but can never reconstruct a
/// [`ValidatedBlockCommitmentsV0`] capability. Version eight freezes the
/// authorizing SafetyState revision inside each pending signing intent so an
/// unrelated callback revision cannot change its canonical signer contract.
///
/// Version-five records omit completion tombstones, version-six records retain
/// opaque live validation capabilities, and version-seven records do not bind
/// the first durable signing barrier. All older schemas must fail closed in
/// `Core::recover`; there is deliberately no implicit migration in this model
/// layer.
pub const SAFETY_STATE_SCHEMA_VERSION: u16 = 8;

/// A verified timeout certificate whose selected high QC cannot yet be
/// adopted because its block, ancestry, or payload is unavailable locally.
///
/// The complete certificate is retained so recovery can re-verify the
/// authorization for the exact immutable target. Every ordinary QC referenced
/// by the TC receives complete QC processing before this state is cleared.
/// `selected_high_qc` is the canonical pacemaker maximum; the driver-facing
/// sync coordinate is the first not-yet-ready reference in deterministic QC
/// order. Construction always derives the selected value from the certificate
/// so the two cannot diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTcHighQcSync {
    timeout_certificate: TimeoutCertificateV0,
    selected_high_qc: QcReferenceV0,
}

impl PendingTcHighQcSync {
    /// Reconstructs the canonical durable target selected by a decoded TC.
    /// `Core::recover` re-verifies the complete certificate before accepting
    /// this value as durable safety state.
    pub fn from_timeout_certificate(timeout_certificate: TimeoutCertificateV0) -> Result<Self> {
        let selected_high_qc = timeout_certificate
            .referenced_qcs()
            .iter()
            .find(|reference| reference.id() == timeout_certificate.selected_high_qc_digest())
            .cloned()
            .ok_or(CoreError::InvalidRecovery(
                "pending TC does not contain its selected high QC",
            ))?;
        Ok(Self {
            timeout_certificate,
            selected_high_qc,
        })
    }

    pub const fn timeout_certificate(&self) -> &TimeoutCertificateV0 {
        &self.timeout_certificate
    }

    pub const fn selected_high_qc(&self) -> &QcReferenceV0 {
        &self.selected_high_qc
    }

    pub fn certificate_id(&self) -> CertificateId {
        self.timeout_certificate.id()
    }

    pub const fn timed_out_view(&self) -> View {
        self.timeout_certificate.timed_out_view()
    }
}

/// A verified standalone QC whose certified block, ancestry, body, or parent
/// execution context is not yet ready locally.
///
/// `active` is immutable until it is adopted, durably subsumed, or causes a
/// safety halt. Later non-conflicting QCs are retained in canonical `backlog`
/// order rather than silently preempting an in-flight sync target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStandaloneQcSync {
    active: QuorumCertificate,
    backlog: Vec<QuorumCertificate>,
}

impl PendingStandaloneQcSync {
    pub fn new(active: QuorumCertificate) -> Self {
        Self {
            active,
            backlog: Vec::new(),
        }
    }

    /// Reconstructs decoded durable parts for validation by `Core::recover`.
    pub fn from_persisted_parts(
        active: QuorumCertificate,
        backlog: Vec<QuorumCertificate>,
    ) -> Self {
        Self { active, backlog }
    }

    pub const fn active(&self) -> &QuorumCertificate {
        &self.active
    }

    pub fn backlog(&self) -> &[QuorumCertificate] {
        &self.backlog
    }

    pub(crate) fn set_backlog(&mut self, backlog: Vec<QuorumCertificate>) {
        self.backlog = backlog;
    }
}

/// A finality proof plus the authenticated direct parent of its first header.
///
/// The parent is represented with `FinalizedTip`'s compact coordinates, but it
/// may have become finalized atomically with the proof rather than having been
/// the previously persisted finalized tip. Keeping this exact timestamp and
/// identity permanently is required to verify `FinalityProofV0` after pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableFinalizationV0 {
    authenticated_parent: FinalizedTip,
    proof: FinalityProofV0,
}

impl DurableFinalizationV0 {
    pub fn new(authenticated_parent: FinalizedTip, proof: FinalityProofV0) -> Result<Self> {
        let first = proof.finalized_block();
        let header = first.header();
        let justify = first.justify_qc().qc_ref();
        if header.parent_id() != authenticated_parent.block_id()
            || header.height() != authenticated_parent.height().checked_next()?
            || justify.block_id() != authenticated_parent.block_id()
            || justify.height() != authenticated_parent.height()
            || justify.view() != authenticated_parent.view()
        {
            return Err(CoreError::InvalidRecovery(
                "finality proof does not bind its authenticated direct parent",
            ));
        }
        Ok(Self {
            authenticated_parent,
            proof,
        })
    }

    pub const fn authenticated_parent(&self) -> FinalizedTip {
        self.authenticated_parent
    }

    pub const fn proof(&self) -> &FinalityProofV0 {
        &self.proof
    }

    pub fn proof_id(&self) -> CertificateId {
        self.proof.id()
    }
}

/// Terminal host payload-validation facts. `Unavailable` is deliberately
/// absent because it is a retryable dependency/source failure, not a fact
/// about the signed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadTerminalResult {
    Valid,
    DeterministicallyInvalid,
}

/// One durable terminal result for the exact signed block identifier.
///
/// The block identifier commits the complete current-v0 header, including its
/// body/state/receipt/evidence roots, parent ID, protocol version, validator
/// set and parameter hash. It is only the prototype validation-context key:
/// the release schema must be bumped again if the canonical body or frozen
/// runtime context is not uniquely recoverable from those commitments.
/// `Unavailable` is never represented here because it is a source/dependency
/// failure and remains retryable. `SafetyState` keeps these entries in strictly
/// increasing block-ID order so decoding, bounded eviction, and trace hashing
/// are deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadTerminalFact {
    block_id: BlockId,
    result: PayloadTerminalResult,
    first_recorded_revision: u64,
}

impl PayloadTerminalFact {
    pub const fn new(
        block_id: BlockId,
        result: PayloadTerminalResult,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            block_id,
            result,
            first_recorded_revision,
        }
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn result(self) -> PayloadTerminalResult {
        self.result
    }

    pub const fn first_recorded_revision(self) -> u64 {
        self.first_recorded_revision
    }
}

/// The independently authenticatable safety reference which collided with a
/// terminally invalid payload result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPayloadReference {
    /// A verified QC, including a QC carried only in a verified TC. Keeping
    /// the complete certificate makes a halt independently recoverable even
    /// when that QC was never adopted as the durable high/locked QC.
    QuorumCertificate(Box<QuorumCertificate>),
    /// A verified TC whose referenced-QC table names the invalid block. The
    /// complete carrier independently explains any durable view advancement
    /// which preceded the fail-stop.
    TimeoutCertificate(Box<TimeoutCertificateV0>),
    /// A persist-before-sign vote outbox which names the invalid block.
    PendingVote(Box<SignIntent>),
}

/// A durable diagnostic fail-stop. Payload-validation conflicts are not
/// slash evidence; they record a broken execution/integration assumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyHalt {
    ConflictingQuorumCertificates {
        first: Box<QuorumCertificate>,
        second: Box<QuorumCertificate>,
    },
    ConflictingPayloadValidation {
        block_id: BlockId,
        first: PayloadTerminalResult,
        second: PayloadTerminalResult,
    },
    DeterministicallyInvalidPayload {
        block_id: BlockId,
        reference: InvalidPayloadReference,
    },
}

impl SafetyHalt {
    pub fn from_conflicting_qcs(
        mut first: QuorumCertificate,
        mut second: QuorumCertificate,
    ) -> Result<Self> {
        if first.chain_id() != second.chain_id()
            || first.protocol_version() != second.protocol_version()
            || first.epoch() != second.epoch()
            || first.validator_set_id() != second.validator_set_id()
            || first.view() != second.view()
            || first.block_id() == second.block_id()
        {
            return Err(CoreError::ConflictingCertificate);
        }
        if (first.block_id(), first.id()) > (second.block_id(), second.id()) {
            core::mem::swap(&mut first, &mut second);
        }
        Ok(Self::ConflictingQuorumCertificates {
            first: Box::new(first),
            second: Box::new(second),
        })
    }

    pub fn conflicting_qcs(&self) -> Option<(&QuorumCertificate, &QuorumCertificate)> {
        match self {
            Self::ConflictingQuorumCertificates { first, second } => {
                Some((first.as_ref(), second.as_ref()))
            }
            Self::ConflictingPayloadValidation { .. }
            | Self::DeterministicallyInvalidPayload { .. } => None,
        }
    }

    pub const fn conflicting_payload_validation(block_id: BlockId) -> Self {
        Self::ConflictingPayloadValidation {
            block_id,
            first: PayloadTerminalResult::Valid,
            second: PayloadTerminalResult::DeterministicallyInvalid,
        }
    }

    pub fn deterministically_invalid_payload(
        block_id: BlockId,
        reference: InvalidPayloadReference,
    ) -> Result<Self> {
        let referenced_block = match &reference {
            InvalidPayloadReference::QuorumCertificate(certificate) => certificate.block_id(),
            InvalidPayloadReference::TimeoutCertificate(certificate) => certificate
                .referenced_qcs()
                .iter()
                .filter_map(QcReferenceV0::as_ordinary)
                .find(|referenced| referenced.block_id() == block_id)
                .map(QuorumCertificate::block_id)
                .ok_or(CoreError::InvalidRecovery(
                    "invalid-payload TC witness does not reference the block",
                ))?,
            InvalidPayloadReference::PendingVote(intent) => match intent.as_ref() {
                SignIntent::Vote { block_id, .. } => *block_id,
                SignIntent::TimeoutVote { .. } => {
                    return Err(CoreError::InvalidRecovery(
                        "an invalid-payload halt cannot cite a timeout-vote intent",
                    ));
                }
            },
        };
        if referenced_block != block_id {
            return Err(CoreError::InvalidRecovery(
                "invalid-payload halt witness names a different block",
            ));
        }
        Ok(Self::DeterministicallyInvalidPayload {
            block_id,
            reference,
        })
    }

    pub const fn payload_block_id(&self) -> Option<BlockId> {
        match self {
            Self::ConflictingQuorumCertificates { .. } => None,
            Self::ConflictingPayloadValidation { block_id, .. }
            | Self::DeterministicallyInvalidPayload { block_id, .. } => Some(*block_id),
        }
    }

    pub const fn invalid_payload_reference(&self) -> Option<&InvalidPayloadReference> {
        match self {
            Self::DeterministicallyInvalidPayload { reference, .. } => Some(reference),
            Self::ConflictingQuorumCertificates { .. }
            | Self::ConflictingPayloadValidation { .. } => None,
        }
    }
}

/// One durable, Core-issued payload-validation obligation.
///
/// This is a persistence fact from which the safety core reconstructs the
/// exact route, generation, signed proposal, and authenticated parent after
/// the registration persistence acknowledgement in the same process. Crash
/// recovery validates the record but deliberately fails closed while any
/// obligation remains; authenticated replay-ticket support is required before
/// cross-crash reissue. It is not a host callback capability: possession of
/// this cloneable record does not authorize construction of
/// [`Input::PayloadValidated`] or [`Input::SyncedPayloadValidated`], and only
/// `Core` may decide whether the obligation is live and when it is resolved.
///
/// Construction is crate-private so external drivers may persist and inspect
/// the exact value supplied inside [`SafetyState`] but cannot mint a durable
/// obligation from caller-selected parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePayloadValidationObligationV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
    proposal: SignedProposalV0,
    parent: PayloadValidationParentV0,
    first_recorded_revision: u64,
}

impl DurablePayloadValidationObligationV0 {
    pub(crate) fn new(
        route: PayloadValidationRouteV0,
        id: ValidationId,
        proposal: SignedProposalV0,
        parent: PayloadValidationParentV0,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            route,
            id,
            proposal,
            parent,
            first_recorded_revision,
        }
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn id(&self) -> ValidationId {
        self.id
    }

    pub const fn proposal(&self) -> &SignedProposalV0 {
        &self.proposal
    }

    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        &self.parent
    }

    pub const fn first_recorded_revision(&self) -> u64 {
        self.first_recorded_revision
    }
}

/// Inert comparison data retained from one live valid-payload capability.
///
/// This value deliberately contains only the four stable facts exposed by
/// [`ValidatedBlockCommitmentsV0`]. It is cloneable persistence data, not a
/// validation capability, and has no conversion back into the live token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableValidatedBlockCommitmentsV1 {
    block_id: BlockId,
    logical_block_size: u64,
    transaction_count: u32,
    evidence_count: u32,
}

impl DurableValidatedBlockCommitmentsV1 {
    pub(crate) const fn from_live(commitments: ValidatedBlockCommitmentsV0) -> Self {
        Self {
            block_id: commitments.block_id(),
            logical_block_size: commitments.logical_block_size(),
            transaction_count: commitments.transaction_count(),
            evidence_count: commitments.evidence_count(),
        }
    }

    /// Reconstructs one decoded inert commitment snapshot for validation as
    /// part of a durable [`SafetyState`] record.
    ///
    /// This crate-private boundary deliberately has no counterpart that can
    /// mint a live [`ValidatedBlockCommitmentsV0`]. Persisted bytes remain
    /// comparison data and must never become payload-validation authority.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn from_persisted_parts(
        block_id: BlockId,
        logical_block_size: u64,
        transaction_count: u32,
        evidence_count: u32,
    ) -> Self {
        Self {
            block_id,
            logical_block_size,
            transaction_count,
            evidence_count,
        }
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn logical_block_size(self) -> u64 {
        self.logical_block_size
    }

    pub const fn transaction_count(self) -> u32 {
        self.transaction_count
    }

    pub const fn evidence_count(self) -> u32 {
        self.evidence_count
    }
}

/// Durable, non-authoritative projection of a live payload-validation result.
///
/// `Valid` stores only inert comparison data. `matches_live` projects a newly
/// supplied live callback result in the same direction; no API performs the
/// reverse conversion or grants callback, voting, or application authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurablePayloadValidationResultV1 {
    Valid {
        commitments: DurableValidatedBlockCommitmentsV1,
    },
    Unavailable,
    DeterministicallyInvalid,
}

impl DurablePayloadValidationResultV1 {
    pub(crate) const fn from_live(result: PayloadValidationResult) -> Self {
        match result {
            PayloadValidationResult::Valid { commitments } => Self::Valid {
                commitments: DurableValidatedBlockCommitmentsV1::from_live(commitments),
            },
            PayloadValidationResult::Unavailable => Self::Unavailable,
            PayloadValidationResult::DeterministicallyInvalid => Self::DeterministicallyInvalid,
        }
    }

    pub fn matches_live(self, result: PayloadValidationResult) -> bool {
        self == Self::from_live(result)
    }

    pub const fn commitments(self) -> Option<DurableValidatedBlockCommitmentsV1> {
        match self {
            Self::Valid { commitments } => Some(commitments),
            Self::Unavailable | Self::DeterministicallyInvalid => None,
        }
    }

    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub const fn is_deterministically_invalid(self) -> bool {
        matches!(self, Self::DeterministicallyInvalid)
    }
}

/// One durable, route-scoped payload-validation completion tombstone.
///
/// This cloneable persistence fact records the exact inert projection of the
/// result accepted for one Core-selected route and full [`ValidationId`]. It
/// is distinct from the block-scoped [`PayloadTerminalFact`]: all three
/// durable result variants, including
/// [`DurablePayloadValidationResultV1::Unavailable`], close only this exact
/// generation and route. Possession of this read-only record does not grant
/// callback, terminal, or application-state authority.
///
/// Construction is crate-private so external drivers may persist and inspect
/// the exact value supplied inside [`SafetyState`] but cannot mint completion
/// tombstones from caller-selected identifiers or results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurablePayloadValidationCompletionV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
    result: DurablePayloadValidationResultV1,
    first_recorded_revision: u64,
}

impl DurablePayloadValidationCompletionV0 {
    pub(crate) const fn new(
        route: PayloadValidationRouteV0,
        id: ValidationId,
        result: DurablePayloadValidationResultV1,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            route,
            id,
            result,
            first_recorded_revision,
        }
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn id(&self) -> ValidationId {
        self.id
    }

    pub const fn key(&self) -> (PayloadValidationRouteV0, ValidationId) {
        (self.route, self.id)
    }

    pub const fn result(&self) -> DurablePayloadValidationResultV1 {
        self.result
    }

    pub const fn first_recorded_revision(&self) -> u64 {
        self.first_recorded_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyState {
    schema_version: u16,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    genesis_block_id: BlockId,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    high_qc: QcReferenceV0,
    locked_qc: QcReferenceV0,
    finalized: FinalizedTip,
    revision: u64,
    payload_terminal_facts: Vec<PayloadTerminalFact>,
    payload_validation_obligations: Vec<DurablePayloadValidationObligationV0>,
    payload_validation_completions: Vec<DurablePayloadValidationCompletionV0>,
    pending_tc_high_qc_sync: Option<PendingTcHighQcSync>,
    pending_standalone_qc_sync: Option<PendingStandaloneQcSync>,
    pending_sign: Option<SignIntent>,
    last_finalization: Option<DurableFinalizationV0>,
    pending_finalize: Option<CertificateId>,
    safety_halt: Option<SafetyHalt>,
}

impl SafetyState {
    /// Reconstructs a decoded durable state for read-only validation by
    /// [`crate::Core::validate_persisted_state_v0`].
    ///
    /// This constructor intentionally performs no cryptographic work. Callers
    /// must authenticate the stored record and pass the result through that
    /// persisted-state validator. Only a state with no unresolved validation
    /// obligations may subsequently enter [`crate::Core::recover`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts(
        schema_version: u16,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_id: ValidatorSetId,
        genesis_block_id: BlockId,
        current_view: View,
        last_voted_view: Option<View>,
        last_timeout_view: Option<View>,
        high_qc: QcReferenceV0,
        locked_qc: QcReferenceV0,
        finalized: FinalizedTip,
        revision: u64,
        payload_terminal_facts: Vec<PayloadTerminalFact>,
        payload_validation_obligations: Vec<DurablePayloadValidationObligationV0>,
        payload_validation_completions: Vec<DurablePayloadValidationCompletionV0>,
        pending_tc_high_qc_sync: Option<PendingTcHighQcSync>,
        pending_standalone_qc_sync: Option<PendingStandaloneQcSync>,
        pending_sign: Option<SignIntent>,
        last_finalization: Option<DurableFinalizationV0>,
        pending_finalize: Option<CertificateId>,
        safety_halt: Option<SafetyHalt>,
    ) -> Self {
        Self {
            schema_version,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            genesis_block_id,
            current_view,
            last_voted_view,
            last_timeout_view,
            high_qc,
            locked_qc,
            finalized,
            revision,
            payload_terminal_facts,
            payload_validation_obligations,
            payload_validation_completions,
            pending_tc_high_qc_sync,
            pending_standalone_qc_sync,
            pending_sign,
            last_finalization,
            pending_finalize,
            safety_halt,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn genesis_block_id(&self) -> BlockId {
        self.genesis_block_id
    }

    pub const fn current_view(&self) -> View {
        self.current_view
    }

    pub const fn last_voted_view(&self) -> Option<View> {
        self.last_voted_view
    }

    pub const fn last_timeout_view(&self) -> Option<View> {
        self.last_timeout_view
    }

    pub const fn high_qc(&self) -> &QcReferenceV0 {
        &self.high_qc
    }

    pub const fn locked_qc(&self) -> &QcReferenceV0 {
        &self.locked_qc
    }

    pub const fn finalized(&self) -> FinalizedTip {
        self.finalized
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn payload_terminal_facts(&self) -> &[PayloadTerminalFact] {
        &self.payload_terminal_facts
    }

    /// Durable validation obligations in strictly increasing full
    /// [`ValidationId`] order.
    ///
    /// The decoder-facing constructor preserves the supplied sequence;
    /// `Core::recover` is responsible for rejecting duplicates, disorder, or
    /// inconsistent route/proposal/parent facts rather than normalizing them.
    pub fn payload_validation_obligations(&self) -> &[DurablePayloadValidationObligationV0] {
        &self.payload_validation_obligations
    }

    /// Durable validation completions in strictly increasing
    /// ([`PayloadValidationRouteV0`], [`ValidationId`]) key order.
    ///
    /// The decoder-facing constructor preserves the supplied sequence;
    /// `Core::recover` is responsible for rejecting duplicates, disorder, or
    /// inconsistent result/revision facts rather than normalizing them.
    pub fn payload_validation_completions(&self) -> &[DurablePayloadValidationCompletionV0] {
        &self.payload_validation_completions
    }

    pub fn payload_terminal_result(&self, block_id: BlockId) -> Option<PayloadTerminalResult> {
        self.payload_terminal_facts
            .binary_search_by_key(&block_id, |fact| fact.block_id())
            .ok()
            .map(|index| self.payload_terminal_facts[index].result())
    }

    pub const fn pending_tc_high_qc_sync(&self) -> Option<&PendingTcHighQcSync> {
        self.pending_tc_high_qc_sync.as_ref()
    }

    pub const fn pending_standalone_qc_sync(&self) -> Option<&PendingStandaloneQcSync> {
        self.pending_standalone_qc_sync.as_ref()
    }

    pub const fn pending_sign(&self) -> Option<&SignIntent> {
        self.pending_sign.as_ref()
    }

    pub const fn last_finalization(&self) -> Option<&DurableFinalizationV0> {
        self.last_finalization.as_ref()
    }

    pub fn last_finalization_proof(&self) -> Option<&FinalityProofV0> {
        self.last_finalization
            .as_ref()
            .map(DurableFinalizationV0::proof)
    }

    pub const fn pending_finalize(&self) -> Option<CertificateId> {
        self.pending_finalize
    }

    pub const fn safety_halt(&self) -> Option<&SafetyHalt> {
        self.safety_halt.as_ref()
    }

    pub(crate) fn from_genesis(
        validator_set: &ValidatorSet,
        genesis_qc: GenesisQcV0,
        trusted_genesis_timestamp_ms: u64,
    ) -> Result<Self> {
        genesis_qc.matches_trusted_set(validator_set)?;
        let genesis_reference = QcReferenceV0::genesis_anchor(genesis_qc.clone());
        Ok(Self {
            schema_version: SAFETY_STATE_SCHEMA_VERSION,
            chain_id: validator_set.chain_id(),
            protocol_version: validator_set.protocol_version(),
            epoch: validator_set.epoch(),
            validator_set_id: validator_set.id(),
            genesis_block_id: genesis_qc.block_id(),
            current_view: View::new(1),
            last_voted_view: None,
            last_timeout_view: None,
            finalized: FinalizedTip::new(
                genesis_qc.height(),
                genesis_qc.view(),
                genesis_qc.block_id(),
                trusted_genesis_timestamp_ms,
            ),
            locked_qc: genesis_reference.clone(),
            high_qc: genesis_reference,
            revision: 0,
            payload_terminal_facts: Vec::new(),
            payload_validation_obligations: Vec::new(),
            payload_validation_completions: Vec::new(),
            pending_tc_high_qc_sync: None,
            pending_standalone_qc_sync: None,
            pending_sign: None,
            last_finalization: None,
            pending_finalize: None,
            safety_halt: None,
        })
    }

    pub(crate) fn set_current_view(&mut self, view: View) {
        if view > self.current_view {
            self.current_view = view;
        }
    }

    pub(crate) fn set_last_voted(&mut self, view: View) {
        self.last_voted_view = Some(view);
    }

    pub(crate) fn set_last_timeout(&mut self, view: View) {
        self.last_timeout_view = Some(view);
    }

    pub(crate) fn set_high_qc(&mut self, certificate: QcReferenceV0) {
        self.high_qc = certificate;
    }

    pub(crate) fn set_locked_qc(&mut self, certificate: QcReferenceV0) {
        self.locked_qc = certificate;
    }

    pub(crate) fn set_finalized(&mut self, finalized: FinalizedTip) {
        self.finalized = finalized;
    }

    pub(crate) fn next_revision(&mut self) -> Result<BarrierId> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow("safety-state revision"))?;
        Ok(BarrierId::new(self.revision))
    }

    pub(crate) fn set_pending_sign(&mut self, intent: Option<SignIntent>) {
        self.pending_sign = intent;
    }

    pub(crate) fn set_payload_terminal_facts(&mut self, facts: Vec<PayloadTerminalFact>) {
        self.payload_terminal_facts = facts;
    }

    pub(crate) fn set_payload_validation_obligations(
        &mut self,
        obligations: Vec<DurablePayloadValidationObligationV0>,
    ) {
        self.payload_validation_obligations = obligations;
    }

    pub(crate) fn set_payload_validation_completions(
        &mut self,
        completions: Vec<DurablePayloadValidationCompletionV0>,
    ) {
        self.payload_validation_completions = completions;
    }

    pub(crate) fn set_pending_tc_high_qc_sync(&mut self, pending: Option<PendingTcHighQcSync>) {
        self.pending_tc_high_qc_sync = pending;
    }

    pub(crate) fn set_pending_standalone_qc_sync(
        &mut self,
        pending: Option<PendingStandaloneQcSync>,
    ) {
        self.pending_standalone_qc_sync = pending;
    }

    pub(crate) fn set_last_finalization(&mut self, finalization: DurableFinalizationV0) {
        self.last_finalization = Some(finalization);
    }

    pub(crate) fn set_pending_finalize(&mut self, proof_id: Option<CertificateId>) {
        self.pending_finalize = proof_id;
    }

    pub(crate) fn set_safety_halt(&mut self, halt: Option<SafetyHalt>) {
        self.safety_halt = halt;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Resume,
    Proposal(Box<SignedProposalV0>),
    SyncedProposal(Box<SignedProposalV0>),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(QuorumCertificate),
    TimeoutCertificate(TimeoutCertificateV0),
    LocalTimeout {
        epoch: Epoch,
        view: View,
    },
    PayloadValidated {
        id: ValidationId,
        result: PayloadValidationResult,
    },
    SyncedPayloadValidated {
        id: ValidationId,
        result: PayloadValidationResult,
    },
    /// Cancels one exact volatile sync-validation request after the local
    /// driver replaces the replay generation which issued it.
    ///
    /// This is a local lifecycle input, never a peer message. It records no
    /// payload result and cannot consume a different validation generation.
    CancelSyncedPayloadValidation {
        id: ValidationId,
    },
    StorageAck {
        barrier: BarrierId,
    },
    FinalizationApplied {
        proof_id: CertificateId,
    },
    SafetyReplayComplete,
    SignatureReady {
        id: SignId,
        signature: SignatureBytes,
    },
}

/// Result of validating one exact host-issued validation request.
///
/// The driver may return `DeterministicallyInvalid` only after it has the
/// complete canonical body matching the signed payload root, authenticated
/// parent state, and the epoch-authorized runtime and parameters. Missing or
/// mismatched source data and transient execution/storage failures are
/// `Unavailable` and must remain retryable under a new request generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadValidationResult {
    Valid {
        commitments: ValidatedBlockCommitmentsV0,
    },
    Unavailable,
    DeterministicallyInvalid,
}

impl PayloadValidationResult {
    pub const fn commitments(self) -> Option<ValidatedBlockCommitmentsV0> {
        match self {
            Self::Valid { commitments } => Some(commitments),
            Self::Unavailable | Self::DeterministicallyInvalid => None,
        }
    }

    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub const fn is_unavailable(self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub const fn is_deterministically_invalid(self) -> bool {
        matches!(self, Self::DeterministicallyInvalid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundMessage {
    Vote(Vote),
    TimeoutVote(TimeoutVote),
}

/// The Core-owned input route which issued one payload-validation capability.
///
/// Route is process-local authorization context. It is not part of
/// [`ValidationId`], any signed block field, or a wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadValidationRouteV0 {
    Proposal,
    Synced,
}

/// Opaque Core-issued request to validate one exact native block payload.
///
/// Only the safety core can construct this capability. A host may inspect or
/// consume the retained validation identity and block, but cannot synthesize a
/// request from caller-supplied values that merely have the same shape.
pub struct PayloadValidationRequest {
    route: PayloadValidationRouteV0,
    id: ValidationId,
    block: Block,
    parent: PayloadValidationParentV0,
    claimed: Arc<AtomicBool>,
}

impl PayloadValidationRequest {
    pub(crate) fn new(
        route: PayloadValidationRouteV0,
        id: ValidationId,
        block: Block,
        parent: PayloadValidationParentV0,
    ) -> Self {
        Self {
            route,
            id,
            block,
            parent,
            claimed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn id(&self) -> ValidationId {
        self.id
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        &self.parent
    }

    /// Atomically claims this exact process-local request object graph.
    ///
    /// Every clone of this request shares one claim gate. Exactly one caller
    /// may obtain the consuming carrier; all later callers retain only
    /// read-only duplicate facts and cannot retry or recover the capability
    /// from that carrier. Independently materialized requests, including
    /// requests issued by distinct `Core` instances recovered from the same
    /// durable state, do not share this volatile gate. A route-aware host
    /// journal keyed by the complete [`ValidationId`] remains required before
    /// terminal persistence or callback wiring.
    pub fn try_claim(
        self,
    ) -> core::result::Result<
        ClaimedPayloadValidationRequestV0,
        Box<DuplicatePayloadValidationRequestV0>,
    > {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Ok(ClaimedPayloadValidationRequestV0 { request: self })
        } else {
            Err(Box::new(DuplicatePayloadValidationRequestV0 {
                request: self,
            }))
        }
    }
}

impl fmt::Debug for PayloadValidationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayloadValidationRequest")
            .field("route", &self.route)
            .field("id", &self.id)
            .field("block", &self.block)
            .field("parent", &self.parent)
            .finish()
    }
}

impl Clone for PayloadValidationRequest {
    fn clone(&self) -> Self {
        Self {
            route: self.route,
            id: self.id,
            block: self.block.clone(),
            parent: self.parent.clone(),
            claimed: Arc::clone(&self.claimed),
        }
    }
}

impl PartialEq for PayloadValidationRequest {
    fn eq(&self, other: &Self) -> bool {
        self.route == other.route
            && self.id == other.id
            && self.block == other.block
            && self.parent == other.parent
    }
}

impl Eq for PayloadValidationRequest {}

/// The unique consumer within one Core-issued request object graph.
///
/// This carrier is deliberately non-cloneable and non-serializable. It can be
/// obtained only by winning [`PayloadValidationRequest::try_claim`].
#[must_use = "a claimed payload-validation request owns its object graph's one consumer"]
pub struct ClaimedPayloadValidationRequestV0 {
    request: PayloadValidationRequest,
}

impl ClaimedPayloadValidationRequestV0 {
    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.request.route()
    }

    pub const fn id(&self) -> ValidationId {
        self.request.id()
    }

    pub const fn block(&self) -> &Block {
        self.request.block()
    }

    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        self.request.parent()
    }

    pub fn into_parts(
        self,
    ) -> (
        PayloadValidationRouteV0,
        ValidationId,
        Block,
        PayloadValidationParentV0,
    ) {
        let PayloadValidationRequest {
            route,
            id,
            block,
            parent,
            claimed: _,
        } = self.request;
        (route, id, block, parent)
    }
}

/// Read-only facts from a request generation already claimed in this process.
///
/// No consuming extraction or reclaim operation is exposed, so a losing clone
/// cannot be converted back into validation authority.
#[must_use = "a duplicate payload-validation request must be suppressed, not retried"]
pub struct DuplicatePayloadValidationRequestV0 {
    request: PayloadValidationRequest,
}

impl DuplicatePayloadValidationRequestV0 {
    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.request.route()
    }

    pub const fn id(&self) -> ValidationId {
        self.request.id()
    }

    pub const fn block(&self) -> &Block {
        self.request.block()
    }

    pub const fn parent(&self) -> &PayloadValidationParentV0 {
        self.request.parent()
    }
}

#[derive(Debug, Clone)]
pub struct SafetyStatePersistenceV0 {
    barrier: BarrierId,
    state: Box<SafetyState>,
    affinity: Arc<()>,
}

impl PartialEq for SafetyStatePersistenceV0 {
    fn eq(&self, other: &Self) -> bool {
        self.barrier == other.barrier && self.state == other.state
    }
}

impl Eq for SafetyStatePersistenceV0 {}

impl SafetyStatePersistenceV0 {
    pub(crate) fn new(
        barrier: BarrierId,
        state: Box<SafetyState>,
        affinity: Arc<()>,
        _seal: crate::core::CorePersistenceSealV0,
    ) -> Self {
        Self {
            barrier,
            state,
            affinity,
        }
    }

    pub const fn barrier(&self) -> BarrierId {
        self.barrier
    }

    pub fn state(&self) -> &SafetyState {
        &self.state
    }
}

/// Process-local binding for one host-designated Core instance.
///
/// Publicly cloning a [`crate::Core`] deliberately creates a different
/// binding. The Core's private transactional snapshots preserve it, so a host
/// can reject persistence effects emitted by a throwaway public clone without
/// gaining access to the underlying identity token.
#[derive(Debug, Clone)]
pub struct SafetyStatePersistenceBindingV0 {
    affinity: Arc<()>,
}

impl SafetyStatePersistenceBindingV0 {
    pub(crate) fn new(affinity: Arc<()>, _seal: crate::core::CorePersistenceSealV0) -> Self {
        Self { affinity }
    }

    pub fn accepts(&self, request: &SafetyStatePersistenceV0) -> bool {
        Arc::ptr_eq(&self.affinity, &request.affinity)
    }
}

/// Effects are the Core's only boundary for nondeterministic host work.
///
/// A [`SafetyStatePersistenceV0`] is opaque outside this crate: only the Core
/// can bind an exact barrier to the state that it advanced. Cloning the effect
/// permits an idempotent retry of those exact bytes, but cannot forge another
/// persistence request. Hosts additionally bind it to their designated Core
/// through [`SafetyStatePersistenceBindingV0`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    PersistSafetyState(SafetyStatePersistenceV0),
    ValidatePayload(PayloadValidationRequest),
    ValidateSyncedPayload(PayloadValidationRequest),
    RequestSignature {
        intent: CanonicalSignIntentV0,
    },
    Broadcast(OutboundMessage),
    ArmViewTimer {
        epoch: Epoch,
        view: View,
    },
    RequestSafetyReplay {
        finalized: FinalizedTip,
        high_qc: QcRef,
        locked_qc: QcRef,
    },
    RequestTcHighQcSync {
        certificate_id: CertificateId,
        timed_out_view: View,
        target: QcRef,
        finalized: FinalizedTip,
    },
    RequestStandaloneQcSync {
        certificate_id: CertificateId,
        target: QcRef,
        finalized: FinalizedTip,
    },
    SafetyHalted(Box<SafetyHalt>),
    Finalize(Box<FinalityProofV0>),
    Evidence(EquivocationEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeferredEffect {
    RequestSignature,
    ArmViewTimer,
    ValidatePayload(ValidationId),
    ValidateSyncedPayload(ValidationId),
    RequestTcHighQcSync,
    RequestStandaloneQcSync,
    SafetyHalted,
    Finalize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingPersistence {
    pub(crate) barrier: BarrierId,
    pub(crate) deferred: Vec<DeferredEffect>,
}
