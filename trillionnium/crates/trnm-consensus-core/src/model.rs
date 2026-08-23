use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    ops::Deref,
    sync::atomic::{AtomicBool, Ordering},
};

use sha2::{Digest, Sha256};
use trnm_consensus_safety_rules::InertSafetyTransitionV1;
use trnm_consensus_types::{
    Block, BlockHeader, BlockId, CanonicalSignIntentV0, CertificateId, ChainId,
    ConsensusParametersV0, Epoch, EquivocationEvidence, FinalityProofV0, GenesisQcV0, Height,
    ProtocolVersion, QcRef, QcReferenceV0, QuorumCertificate, SignatureBytes, SignedProposalV0,
    SigningRoot, StateRoot, TimeoutCertificateV0, TimeoutVote, ValidatedBlockCommitmentsV0,
    ValidatorId, ValidatorSet, ValidatorSetId, View, Vote,
};

use crate::{CoreError, Result, CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    trusted_genesis_timestamp_ms: u64,
    authenticated_genesis_application_parent: Option<AuthenticatedGenesisApplicationParentV0>,
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
            authenticated_genesis_application_parent: None,
            max_blocks,
            max_observed_messages,
        };
        value.validate()?;
        Ok(value)
    }

    /// Constructs a development-only Core configuration whose synthetic
    /// genesis consensus tip is additionally bound to one exact application
    /// state parent.
    ///
    /// This is an operator/config-pinned trust root. The current GenesisQC and
    /// genesis hash do **not** commit this carrier. Supplying it therefore
    /// does not make peer-provided genesis state self-authenticating and must
    /// not be represented as a height-zero [`BlockHeader`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_authenticated_genesis_application_parent_v0(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        trusted_genesis_timestamp_ms: u64,
        authenticated_genesis_application_parent: AuthenticatedGenesisApplicationParentV0,
        max_blocks: usize,
        max_observed_messages: usize,
    ) -> Result<Self> {
        let value = Self {
            local_validator,
            validator_set,
            consensus_parameters,
            trusted_genesis_timestamp_ms,
            authenticated_genesis_application_parent: Some(
                authenticated_genesis_application_parent,
            ),
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

    /// Exact operator-pinned application state parent for synthetic genesis,
    /// when this Core is configured for authenticated ordinary h1 execution.
    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> Option<&AuthenticatedGenesisApplicationParentV0> {
        self.authenticated_genesis_application_parent.as_ref()
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
        if let Some(parent) = self.authenticated_genesis_application_parent_v0() {
            self.consensus_parameters
                .validate_reference_shadow_profile()?;
            parent.validate_shape_v0()?;
            if parent.genesis_block_id() != self.genesis_block_id() {
                return Err(CoreError::InvalidConfig(
                    "authenticated genesis application parent names a foreign genesis block",
                ));
            }
            if parent.timestamp_ms() != self.trusted_genesis_timestamp_ms {
                return Err(CoreError::InvalidConfig(
                    "authenticated genesis application parent timestamp differs from the trusted genesis timestamp",
                ));
            }
        }
        if self.max_blocks < 4 {
            return Err(CoreError::InvalidConfig("max_blocks must be at least four"));
        }
        if self.consensus_parameters.max_consensus_message_bytes() as usize
            > CORE_MAX_RETAINED_VALIDATED_PROPOSAL_RESOURCE_BYTES_V1
        {
            return Err(CoreError::InvalidConfig(
                "one consensus message may exceed the retained-proposal hard cap",
            ));
        }
        if self.max_observed_messages < self.validator_set.validators().len() {
            return Err(CoreError::InvalidConfig(
                "observed-message bound must cover the validator set",
            ));
        }
        Ok(())
    }
}

/// Operator/config-pinned application state parent for synthetic genesis.
///
/// This is fixed-size inert comparison data. It is deliberately distinct from
/// [`BlockHeader`]: network headers require positive height and view, while
/// this carrier names application state version zero under the synthetic
/// GenesisQC tip. The current genesis hash does not commit these fields. Its
/// trust therefore comes only from an exact [`CoreConfig`] preimage selected
/// by the operator in this development-only slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedGenesisApplicationParentV0 {
    genesis_block_id: BlockId,
    timestamp_ms: u64,
    state_root: StateRoot,
    descriptor_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
}

pub const AUTHENTICATED_GENESIS_APPLICATION_PARENT_BINDING_DOMAIN_V0: &str =
    "trnm.consensus-core.authenticated-genesis-application-parent.v0";

impl AuthenticatedGenesisApplicationParentV0 {
    /// Builds the exact fixed carrier. `state_version` is accepted explicitly
    /// so callers cannot silently reinterpret a positive-height snapshot as
    /// genesis application state.
    pub fn new(
        genesis_block_id: BlockId,
        timestamp_ms: u64,
        state_version: u64,
        state_root: StateRoot,
        descriptor_ref: [u8; 32],
        projection_profile_ref: [u8; 32],
    ) -> Result<Self> {
        if state_version != 0 {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application parent state version must be zero",
            ));
        }
        let value = Self {
            genesis_block_id,
            timestamp_ms,
            state_root,
            descriptor_ref,
            projection_profile_ref,
        };
        value.validate_shape_v0()?;
        Ok(value)
    }

    pub const fn genesis_block_id(self) -> BlockId {
        self.genesis_block_id
    }

    pub const fn timestamp_ms(self) -> u64 {
        self.timestamp_ms
    }

    pub const fn state_version(self) -> u64 {
        0
    }

    pub const fn state_root(self) -> StateRoot {
        self.state_root
    }

    pub const fn descriptor_ref(self) -> [u8; 32] {
        self.descriptor_ref
    }

    pub const fn projection_profile_ref(self) -> [u8; 32] {
        self.projection_profile_ref
    }

    /// Canonical request/persistence comparison reference for the complete
    /// tagged carrier. This checksum is not authentication authority.
    pub fn binding_ref_v0(self) -> [u8; 32] {
        let timestamp = self.timestamp_ms.to_be_bytes();
        let state_version = self.state_version().to_be_bytes();
        let parts: [&[u8]; 6] = [
            self.genesis_block_id.as_bytes(),
            &timestamp,
            &state_version,
            self.state_root.as_bytes(),
            &self.descriptor_ref,
            &self.projection_profile_ref,
        ];
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        hasher.update(
            (AUTHENTICATED_GENESIS_APPLICATION_PARENT_BINDING_DOMAIN_V0.len() as u64).to_be_bytes(),
        );
        hasher.update(AUTHENTICATED_GENESIS_APPLICATION_PARENT_BINDING_DOMAIN_V0.as_bytes());
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    pub(crate) fn validate_shape_v0(self) -> Result<()> {
        if self.genesis_block_id.is_zero() {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application parent block ID must be nonzero",
            ));
        }
        if self.state_root.is_zero() {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application parent state root must be nonzero",
            ));
        }
        if self.descriptor_ref == [0; 32] {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application parent descriptor reference must be nonzero",
            ));
        }
        if self.projection_profile_ref == [0; 32] {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application parent projection profile must be nonzero",
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

/// Stable identity of one application-owned speculative overlay.
///
/// Unlike a validation request, this reference deliberately contains no
/// route, view, or generation. Revalidating the same signed block through the
/// Proposal and Synced routes must therefore name the same BlockId-keyed
/// overlay. The checksum is inert comparison data; only the node's unique
/// application adapter may establish that the referenced overlay was sealed
/// and read back before returning a live payload result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockIdOverlayRefV0 {
    block_id: BlockId,
    parent_block_id: BlockId,
    overlay_checksum: [u8; 32],
}

impl BlockIdOverlayRefV0 {
    pub const fn new(
        block_id: BlockId,
        parent_block_id: BlockId,
        overlay_checksum: [u8; 32],
    ) -> Self {
        Self {
            block_id,
            parent_block_id,
            overlay_checksum,
        }
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn parent_block_id(self) -> BlockId {
        self.parent_block_id
    }

    pub const fn overlay_checksum(self) -> [u8; 32] {
        self.overlay_checksum
    }
}

/// Exact application artifact accepted for one live Valid callback.
///
/// `overlay` is stable across callback routes and generations. The source
/// artifact checksum is retained separately because the application journal
/// may bind an otherwise equivalent sealed overlay to a route-scoped durable
/// validation job. This remains inert comparison data and cannot mint an
/// application or validation capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPayloadArtifactRefV0 {
    overlay: BlockIdOverlayRefV0,
    source_artifact_checksum: [u8; 32],
}

impl ValidatedPayloadArtifactRefV0 {
    pub const fn new(overlay: BlockIdOverlayRefV0, source_artifact_checksum: [u8; 32]) -> Self {
        Self {
            overlay,
            source_artifact_checksum,
        }
    }

    pub const fn overlay(self) -> BlockIdOverlayRefV0 {
        self.overlay
    }

    pub const fn source_artifact_checksum(self) -> [u8; 32] {
        self.source_artifact_checksum
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

/// Core-authenticated provenance of one exact payload-validation parent.
///
/// A finalized parent is backed by the Core's durable finalized tip (and, for
/// positive heights, its exact finalization header). A speculative parent is
/// backed by the exact BlockId-keyed application overlay which the Core
/// previously accepted as `Valid`. The overlay reference is inert comparison
/// data: it cannot mint application read or apply authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadValidationParentProvenanceV0 {
    Finalized,
    Speculative(BlockIdOverlayRefV0),
}

pub const PAYLOAD_VALIDATION_PARENT_BINDING_DOMAIN_V0: &str =
    "trnm.consensus-core.payload-validation-parent.v0";

/// Closed carrier kind for an exact Core-authenticated payload parent.
///
/// The enum is private so callers cannot construct a Core request from inert
/// comparison fields. Public accessors on [`PayloadValidationParentV0`] expose
/// the selected facts without erasing the distinction between synthetic
/// genesis and a real positive-height network header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PayloadValidationParentCarrierV0 {
    LegacyTrustedGenesis,
    AuthenticatedGenesisApplication(AuthenticatedGenesisApplicationParentV0),
    ExactHeader(Box<BlockHeader>),
}

/// Exact Core-authenticated parent context retained by one payload request.
///
/// A positive-height parent carries its complete native header, including the
/// state root needed to bind an application snapshot. Synthetic genesis is a
/// closed tagged choice: either the legacy header-less Core-only anchor, or a
/// separate operator/config-pinned application-state carrier. Neither case is
/// represented as a fabricated height-zero [`BlockHeader`].
///
/// All fields and constructors are crate-private. External hosts may inspect
/// a value only after receiving it inside a Core-issued
/// [`PayloadValidationRequest`]; they cannot manufacture a parent authority
/// from caller-supplied height/root coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadValidationParentV0 {
    tip: FinalizedTip,
    carrier: PayloadValidationParentCarrierV0,
    provenance: PayloadValidationParentProvenanceV0,
}

impl PayloadValidationParentV0 {
    pub(crate) fn from_finalized_exact_header(header: BlockHeader) -> Self {
        let tip = FinalizedTip::new(
            header.height(),
            header.view(),
            header.id(),
            header.timestamp_ms(),
        );
        Self {
            tip,
            carrier: PayloadValidationParentCarrierV0::ExactHeader(Box::new(header)),
            provenance: PayloadValidationParentProvenanceV0::Finalized,
        }
    }

    pub(crate) fn from_speculative_exact_header(
        header: BlockHeader,
        overlay: BlockIdOverlayRefV0,
    ) -> Self {
        let tip = FinalizedTip::new(
            header.height(),
            header.view(),
            header.id(),
            header.timestamp_ms(),
        );
        Self {
            tip,
            carrier: PayloadValidationParentCarrierV0::ExactHeader(Box::new(header)),
            provenance: PayloadValidationParentProvenanceV0::Speculative(overlay),
        }
    }

    pub(crate) const fn trusted_genesis(tip: FinalizedTip) -> Self {
        Self {
            tip,
            carrier: PayloadValidationParentCarrierV0::LegacyTrustedGenesis,
            provenance: PayloadValidationParentProvenanceV0::Finalized,
        }
    }

    pub(crate) fn authenticated_genesis_application(
        tip: FinalizedTip,
        parent: AuthenticatedGenesisApplicationParentV0,
    ) -> Result<Self> {
        parent.validate_shape_v0()?;
        if tip.height().get() != 0
            || tip.view().get() != 0
            || tip.block_id() != parent.genesis_block_id()
            || tip.timestamp_ms() != parent.timestamp_ms()
        {
            return Err(CoreError::InvalidRecovery(
                "authenticated genesis application parent differs from the synthetic genesis tip",
            ));
        }
        Ok(Self {
            tip,
            carrier: PayloadValidationParentCarrierV0::AuthenticatedGenesisApplication(parent),
            provenance: PayloadValidationParentProvenanceV0::Finalized,
        })
    }

    pub const fn tip(&self) -> FinalizedTip {
        self.tip
    }

    pub fn exact_header(&self) -> Option<&BlockHeader> {
        match &self.carrier {
            PayloadValidationParentCarrierV0::ExactHeader(header) => Some(header.as_ref()),
            PayloadValidationParentCarrierV0::LegacyTrustedGenesis
            | PayloadValidationParentCarrierV0::AuthenticatedGenesisApplication(_) => None,
        }
    }

    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> Option<AuthenticatedGenesisApplicationParentV0> {
        match &self.carrier {
            PayloadValidationParentCarrierV0::AuthenticatedGenesisApplication(parent) => {
                Some(*parent)
            }
            PayloadValidationParentCarrierV0::LegacyTrustedGenesis
            | PayloadValidationParentCarrierV0::ExactHeader(_) => None,
        }
    }

    pub const fn is_legacy_trusted_genesis_v0(&self) -> bool {
        matches!(
            &self.carrier,
            PayloadValidationParentCarrierV0::LegacyTrustedGenesis
        )
    }

    pub const fn provenance(&self) -> PayloadValidationParentProvenanceV0 {
        self.provenance
    }

    /// Canonical comparison reference for the complete tagged parent.
    ///
    /// Application request fingerprints must include this value (or the exact
    /// equivalent preimage) so an h1 request cannot be replayed under a
    /// different operator-pinned genesis descriptor or state root. The digest
    /// is inert and does not grant payload-validation authority.
    pub fn binding_ref_v0(&self) -> Result<[u8; 32]> {
        let height = self.tip.height().get().to_be_bytes();
        let view = self.tip.view().get().to_be_bytes();
        let timestamp = self.tip.timestamp_ms().to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        hasher.update((PAYLOAD_VALIDATION_PARENT_BINDING_DOMAIN_V0.len() as u64).to_be_bytes());
        hasher.update(PAYLOAD_VALIDATION_PARENT_BINDING_DOMAIN_V0.as_bytes());
        for part in [
            height.as_slice(),
            view.as_slice(),
            self.tip.block_id().as_bytes().as_slice(),
            timestamp.as_slice(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        match self.provenance {
            PayloadValidationParentProvenanceV0::Finalized => {
                hasher.update(1u64.to_be_bytes());
                hasher.update([0]);
            }
            PayloadValidationParentProvenanceV0::Speculative(overlay) => {
                let mut bytes = [0u8; 97];
                bytes[0] = 1;
                bytes[1..33].copy_from_slice(overlay.block_id().as_bytes());
                bytes[33..65].copy_from_slice(overlay.parent_block_id().as_bytes());
                bytes[65..97].copy_from_slice(&overlay.overlay_checksum());
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
        }
        match &self.carrier {
            PayloadValidationParentCarrierV0::LegacyTrustedGenesis => {
                hasher.update(1u64.to_be_bytes());
                hasher.update([0]);
            }
            PayloadValidationParentCarrierV0::AuthenticatedGenesisApplication(parent) => {
                let binding = parent.binding_ref_v0();
                let mut bytes = [0u8; 33];
                bytes[0] = 1;
                bytes[1..].copy_from_slice(&binding);
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
            PayloadValidationParentCarrierV0::ExactHeader(header) => {
                let header = header.try_cev0_bytes()?;
                hasher.update(((header.len() + 1) as u64).to_be_bytes());
                hasher.update([2]);
                hasher.update(header);
            }
        }
        Ok(hasher.finalize().into())
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
/// Version nine makes every durable Valid result name both the exact sealed
/// application artifact and its route-stable BlockId overlay; the block-scoped
/// terminal fact retains the stable overlay identity after route completions.
/// Version ten separates the consensus-finalized tip from the
/// application-applied watermark and replaces the lossy single pending proof
/// slot with a bounded, ancestor-ordered queue of unapplied finalizations.
/// Version eleven adds one immutable, genesis-anchored h1 state-sync proof.
/// The anchor authenticates an already-installed application base without
/// inventing a local payload-validation completion, terminal fact, speculative
/// overlay, or finalization-apply job for h1.
/// Version twelve adds one optional, immutable, operator/config-pinned genesis
/// application parent. It is a separate state-version-zero carrier and never
/// a fabricated network block header. The complete carrier is bound by both
/// CoreConfig and every h1 validation obligation issued from synthetic
/// genesis.
///
/// Version-five records omit completion tombstones, version-six records retain
/// opaque live validation capabilities, and version-seven records do not bind
/// the first durable signing barrier. Version-eight records can mark a payload
/// Valid without proving that a sealed speculative overlay exists. All older
/// schemas must fail closed in
/// `Core::recover`; there is deliberately no implicit migration in this model
/// layer.
pub const SAFETY_STATE_SCHEMA_VERSION: u16 = 12;

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

/// A finality proof plus the authenticated direct parent and exact application
/// overlay of its first header.
///
/// The parent is represented with `FinalizedTip`'s compact coordinates, but it
/// may have become finalized atomically with the proof rather than having been
/// the previously persisted finalized tip. Keeping this exact timestamp and
/// identity permanently is required to verify `FinalityProofV0` after pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableFinalizationV0 {
    authenticated_parent: FinalizedTip,
    proof: FinalityProofV0,
    target_overlay_ref: BlockIdOverlayRefV0,
}

/// Permanent proof of one exact h1 application state-sync base.
///
/// This carrier is deliberately distinct from [`DurableFinalizationV0`]. It
/// contains no application overlay and can never enter the application
/// finalization queue: h1 was authenticated and installed as a trusted base,
/// not speculatively executed by this node. Core accepts the carrier only when
/// its authenticated parent is the exact configured epoch-zero genesis tip and
/// its proof finalizes the regular height-one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableStateSyncAnchorV0 {
    authenticated_parent: FinalizedTip,
    proof: FinalityProofV0,
}

impl DurableStateSyncAnchorV0 {
    /// Reconstructs inert anchor parts for later Core validation.
    ///
    /// This checks only the proof's exact direct-parent geometry. Signature,
    /// epoch, configured-genesis, h1, and fresh-bootstrap checks belong to the
    /// Core preparation/recovery boundary.
    pub fn new(authenticated_parent: FinalizedTip, proof: FinalityProofV0) -> Result<Self> {
        if !finality_proof_binds_authenticated_parent_v0(&proof, authenticated_parent)? {
            return Err(CoreError::InvalidRecovery(
                "state-sync proof does not bind its authenticated direct parent",
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

fn finality_proof_binds_authenticated_parent_v0(
    proof: &FinalityProofV0,
    authenticated_parent: FinalizedTip,
) -> Result<bool> {
    let first = proof.finalized_block();
    let header = first.header();
    let justify = first.justify_qc().qc_ref();
    Ok(header.parent_id() == authenticated_parent.block_id()
        && header.height() == authenticated_parent.height().checked_next()?
        && justify.block_id() == authenticated_parent.block_id()
        && justify.height() == authenticated_parent.height()
        && justify.view() == authenticated_parent.view())
}

impl DurableFinalizationV0 {
    pub fn new(
        authenticated_parent: FinalizedTip,
        proof: FinalityProofV0,
        target_overlay_ref: BlockIdOverlayRefV0,
    ) -> Result<Self> {
        let header = proof.finalized_block().header();
        if !finality_proof_binds_authenticated_parent_v0(&proof, authenticated_parent)?
            || target_overlay_ref.block_id() != header.id()
            || target_overlay_ref.parent_block_id() != header.parent_id()
        {
            return Err(CoreError::InvalidRecovery(
                "finality proof does not bind its authenticated direct parent and target overlay",
            ));
        }
        Ok(Self {
            authenticated_parent,
            proof,
            target_overlay_ref,
        })
    }

    pub const fn authenticated_parent(&self) -> FinalizedTip {
        self.authenticated_parent
    }

    pub const fn proof(&self) -> &FinalityProofV0 {
        &self.proof
    }

    /// Exact inert BlockId-keyed overlay which the application must consume.
    ///
    /// This reference is comparison data, not apply authority. Core accepts a
    /// queue pop only through an opaque [`ApplicationFinalizationReceiptV0`]
    /// minted by the installed application authority after consuming the
    /// exact queue-front permit.
    pub const fn target_overlay_ref(&self) -> BlockIdOverlayRefV0 {
        self.target_overlay_ref
    }

    pub fn proof_id(&self) -> CertificateId {
        self.proof.id()
    }
}

/// Preserve the proof's read-only inspection surface on the inert
/// finalization carrier while retaining the exact overlay alongside it.
impl Deref for DurableFinalizationV0 {
    type Target = FinalityProofV0;

    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}

/// Linear Core-issued permit for one exact durable finalization queue front.
///
/// The permit is process-local, non-cloneable, non-serializable, and has no
/// public constructor.  It can be issued only once for the current queue
/// front by [`crate::Core::issue_application_finalization_permit_v0`].  The
/// inert [`DurableFinalizationV0`] carried by [`Effect::Finalize`] is therefore
/// insufficient to acknowledge or pop the queue.
///
/// ```compile_fail
/// use trnm_consensus_core::CoreIssuedApplicationFinalizationPermitV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<CoreIssuedApplicationFinalizationPermitV0>();
/// }
/// ```
#[must_use = "the exact queue-front permit must remain with its application apply owner"]
pub struct CoreIssuedApplicationFinalizationPermitV0 {
    finalization: DurableFinalizationV0,
    front_affinity: Arc<()>,
    application_apply_affinity: Arc<()>,
}

pub const NATIVE_FINALIZATION_APPLIED_CHECKSUM_DOMAIN_V0: &str =
    "trnm.consensus-core.application-finalization.applied.v0";

/// Canonical inert checksum of one exact durable finalization carrier.
///
/// The checksum covers the authenticated predecessor, complete CEV0 finality
/// proof, and exact BlockId-keyed target overlay. It is comparison data only
/// and cannot acknowledge or apply the carrier.
pub fn native_finalization_applied_checksum_v0(
    finalization: &DurableFinalizationV0,
) -> Result<[u8; 32]> {
    let parent = finalization.authenticated_parent();
    let proof_bytes = finalization.proof().try_cev0_bytes()?;
    let overlay = finalization.target_overlay_ref();
    let parent_height = parent.height().get().to_be_bytes();
    let parent_view = parent.view().get().to_be_bytes();
    let parent_timestamp = parent.timestamp_ms().to_be_bytes();
    let parent_block_id = parent.block_id();
    let overlay_block_id = overlay.block_id();
    let overlay_parent_block_id = overlay.parent_block_id();
    let overlay_checksum = overlay.overlay_checksum();
    let parts: [&[u8]; 8] = [
        &parent_height,
        &parent_view,
        parent_block_id.as_bytes(),
        &parent_timestamp,
        proof_bytes.as_slice(),
        overlay_block_id.as_bytes(),
        overlay_parent_block_id.as_bytes(),
        &overlay_checksum,
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((NATIVE_FINALIZATION_APPLIED_CHECKSUM_DOMAIN_V0.len() as u64).to_be_bytes());
    hasher.update(NATIVE_FINALIZATION_APPLIED_CHECKSUM_DOMAIN_V0.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Ok(hasher.finalize().into())
}

/// Inert projection reconstructed from one exact ApplicationStore apply
/// receipt after commit/readback.
///
/// Fields are private and construction is available only through the live
/// Core-issued apply authority while borrowing its exact queue-front permit.
/// The value is cloneable comparison material; it is not apply, receipt, or
/// persistence authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationFinalizationApplyReadbackV0 {
    source_route: PayloadValidationRouteV0,
    source_validation_id: ValidationId,
    ordinal: u64,
    application_host_config_ref: [u8; 32],
    finalization_checksum: [u8; 32],
    prior_head_checksum: [u8; 32],
    new_head_checksum: [u8; 32],
    source_artifact_checksum: [u8; 32],
    accepted_source_checksum: [u8; 32],
    applied_job_row_checksum: [u8; 32],
    receipt_row_checksum: [u8; 32],
}

impl ApplicationFinalizationApplyReadbackV0 {
    pub(crate) fn from_native_finalization_applied_recovery_transition_v0(
        transition: &NativeFinalizationAppliedRecoveryTransitionV0,
    ) -> Self {
        Self {
            source_route: transition.source_route(),
            source_validation_id: transition.source_validation_id(),
            ordinal: transition.ordinal(),
            application_host_config_ref: transition.application_host_config_ref(),
            finalization_checksum: transition.finalization_checksum(),
            prior_head_checksum: transition.prior_head_checksum(),
            new_head_checksum: transition.new_head_checksum(),
            source_artifact_checksum: transition.source_artifact_checksum(),
            accepted_source_checksum: transition.accepted_source_checksum(),
            applied_job_row_checksum: transition.applied_job_row_checksum(),
            receipt_row_checksum: transition.application_receipt_row_checksum(),
        }
    }

    pub const fn source_route(&self) -> PayloadValidationRouteV0 {
        self.source_route
    }

    pub const fn source_validation_id(&self) -> ValidationId {
        self.source_validation_id
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn application_host_config_ref(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn finalization_checksum(&self) -> [u8; 32] {
        self.finalization_checksum
    }

    pub const fn prior_head_checksum(&self) -> [u8; 32] {
        self.prior_head_checksum
    }

    pub const fn new_head_checksum(&self) -> [u8; 32] {
        self.new_head_checksum
    }

    pub const fn source_artifact_checksum(&self) -> [u8; 32] {
        self.source_artifact_checksum
    }

    pub const fn accepted_source_checksum(&self) -> [u8; 32] {
        self.accepted_source_checksum
    }

    pub const fn applied_job_row_checksum(&self) -> [u8; 32] {
        self.applied_job_row_checksum
    }

    pub const fn receipt_row_checksum(&self) -> [u8; 32] {
        self.receipt_row_checksum
    }
}

impl fmt::Debug for CoreIssuedApplicationFinalizationPermitV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreIssuedApplicationFinalizationPermitV0")
            .field("finalization", &self.finalization)
            .finish_non_exhaustive()
    }
}

impl CoreIssuedApplicationFinalizationPermitV0 {
    pub(crate) fn new(
        finalization: DurableFinalizationV0,
        front_affinity: Arc<()>,
        application_apply_affinity: Arc<()>,
    ) -> Self {
        Self {
            finalization,
            front_affinity,
            application_apply_affinity,
        }
    }

    pub const fn finalization(&self) -> &DurableFinalizationV0 {
        &self.finalization
    }
}

/// The one process-local application-finalization apply authority issued by a
/// live Core instance.
///
/// A trusted node host moves this non-cloneable value into one private
/// ApplicationStore.  The store may mint a receipt only after it has consumed
/// the matching single-use queue-front permit and durably applied/read back
/// that exact carrier.  Possession is trusted host authority; this value must
/// never cross RPC, network, or durable boundaries.
///
/// This Core slice defines the capability boundary only.  No current
/// production ApplicationStore or node host installs this authority yet, so
/// the callback remains deliberately unreachable in production until that
/// downstream exact-apply/readback wiring exists.
///
/// ```compile_fail
/// use trnm_consensus_core::CoreIssuedApplicationFinalizationApplyAuthorityV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<CoreIssuedApplicationFinalizationApplyAuthorityV0>();
/// }
/// ```
#[must_use = "the Core-issued finalization apply authority must be installed into one private store"]
pub struct CoreIssuedApplicationFinalizationApplyAuthorityV0 {
    affinity: Arc<()>,
    application_host_affinity: Arc<()>,
    chain_id: ChainId,
}

impl fmt::Debug for CoreIssuedApplicationFinalizationApplyAuthorityV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreIssuedApplicationFinalizationApplyAuthorityV0")
            .finish_non_exhaustive()
    }
}

impl CoreIssuedApplicationFinalizationApplyAuthorityV0 {
    pub(crate) fn new(
        affinity: Arc<()>,
        application_host_affinity: Arc<()>,
        chain_id: ChainId,
    ) -> Self {
        Self {
            affinity,
            application_host_affinity,
            chain_id,
        }
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Checks that `permit` was issued by the exact live Core which installed
    /// this application apply authority.
    ///
    /// This borrow-only matcher is the mandatory pre-write gate for a trusted
    /// ApplicationStore.  It neither consumes nor duplicates the linear
    /// permit, so a mismatch can be rejected before `BEGIN IMMEDIATE` without
    /// losing its sole owner.  Matching this process-local affinity is
    /// necessary but does not replace exact queue-front, carrier, or durable
    /// store validation.
    pub fn matches_application_finalization_permit_v0(
        &self,
        permit: &CoreIssuedApplicationFinalizationPermitV0,
    ) -> bool {
        Arc::ptr_eq(&self.affinity, &permit.application_apply_affinity)
    }

    /// Constructs inert comparison facts from a fresh exact ApplicationStore
    /// readback while borrowing the still-live queue-front permit.
    ///
    /// This is the only constructor for the projection. A mismatch consumes
    /// neither the permit nor any authority, so the store can fail before
    /// acknowledging a write. The trusted store remains responsible for
    /// deriving every supplied checksum from its canonical committed rows.
    #[allow(clippy::too_many_arguments)]
    pub fn application_store_apply_readback_v0(
        &self,
        permit: &CoreIssuedApplicationFinalizationPermitV0,
        source_route: PayloadValidationRouteV0,
        source_validation_id: ValidationId,
        ordinal: u64,
        application_host_config_ref: [u8; 32],
        prior_head_checksum: [u8; 32],
        new_head_checksum: [u8; 32],
        source_artifact_checksum: [u8; 32],
        accepted_source_checksum: [u8; 32],
        applied_job_row_checksum: [u8; 32],
        receipt_row_checksum: [u8; 32],
    ) -> Result<ApplicationFinalizationApplyReadbackV0> {
        if !self.matches_application_finalization_permit_v0(permit) {
            return Err(CoreError::ApplicationFinalizationPermitMismatch);
        }
        let finalization = permit.finalization();
        let target = finalization.proof().finalized_block().header();
        let checksums = [
            application_host_config_ref,
            prior_head_checksum,
            new_head_checksum,
            source_artifact_checksum,
            accepted_source_checksum,
            applied_job_row_checksum,
            receipt_row_checksum,
        ];
        if source_validation_id.block_id() != target.id()
            || source_validation_id.view() != target.view()
            || ordinal != target.height().get()
            || ordinal == 0
            || checksums.contains(&[0; 32])
            || prior_head_checksum == new_head_checksum
        {
            return Err(CoreError::ApplicationFinalizationReadbackMismatch);
        }
        Ok(ApplicationFinalizationApplyReadbackV0 {
            source_route,
            source_validation_id,
            ordinal,
            application_host_config_ref,
            finalization_checksum: native_finalization_applied_checksum_v0(finalization)?,
            prior_head_checksum,
            new_head_checksum,
            source_artifact_checksum,
            accepted_source_checksum,
            applied_job_row_checksum,
            receipt_row_checksum,
        })
    }

    /// Consumes the exact Core-issued queue-front permit after the trusted
    /// ApplicationStore has atomically applied and read back that carrier.
    ///
    /// The authority remains installed for later queue fronts.  Uniqueness of
    /// each receipt comes from consuming the non-cloneable permit.
    pub fn receipt_after_application_store_apply_v0(
        &self,
        permit: CoreIssuedApplicationFinalizationPermitV0,
        readback: ApplicationFinalizationApplyReadbackV0,
    ) -> core::result::Result<
        ApplicationFinalizationReceiptV0,
        ApplicationFinalizationPermitRejectionV0,
    > {
        let exact_readback = self
            .application_store_apply_readback_v0(
                &permit,
                readback.source_route,
                readback.source_validation_id,
                readback.ordinal,
                readback.application_host_config_ref,
                readback.prior_head_checksum,
                readback.new_head_checksum,
                readback.source_artifact_checksum,
                readback.accepted_source_checksum,
                readback.applied_job_row_checksum,
                readback.receipt_row_checksum,
            )
            .is_ok_and(|exact| exact == readback);
        if !exact_readback {
            return Err(ApplicationFinalizationPermitRejectionV0::new(
                if self.matches_application_finalization_permit_v0(&permit) {
                    CoreError::ApplicationFinalizationReadbackMismatch
                } else {
                    CoreError::ApplicationFinalizationPermitMismatch
                },
                Box::new(permit),
            ));
        }
        Ok(ApplicationFinalizationReceiptV0 {
            finalization: permit.finalization,
            readback,
            front_affinity: permit.front_affinity,
            application_apply_affinity: Arc::clone(&self.affinity),
        })
    }
}

/// Owner-preserving rejection when an application apply authority receives a
/// queue-front permit issued by a different live Core.
///
/// The error is inspectable, while the sole consuming accessor returns the
/// exact non-cloneable permit.  The trusted host can therefore route it back
/// to its issuing authority without reminting or reconstructing authority
/// from durable comparison data.
#[must_use = "a rejected application finalization permit retains the sole apply owner"]
pub struct ApplicationFinalizationPermitRejectionV0 {
    error: CoreError,
    permit: Box<CoreIssuedApplicationFinalizationPermitV0>,
}

impl fmt::Debug for ApplicationFinalizationPermitRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationFinalizationPermitRejectionV0")
            .field("error", &self.error)
            .field("permit", &self.permit)
            .finish()
    }
}

impl ApplicationFinalizationPermitRejectionV0 {
    fn new(error: CoreError, permit: Box<CoreIssuedApplicationFinalizationPermitV0>) -> Self {
        Self { error, permit }
    }

    pub const fn error(&self) -> &CoreError {
        &self.error
    }

    pub fn into_permit(self) -> CoreIssuedApplicationFinalizationPermitV0 {
        *self.permit
    }

    pub fn into_parts(self) -> (CoreError, CoreIssuedApplicationFinalizationPermitV0) {
        (self.error, *self.permit)
    }
}

/// Opaque live proof of one exact, durably applied application-finalization
/// queue front.
///
/// This receipt is neither cloneable nor serializable and exposes no public
/// constructor.  It is accepted only by
/// [`crate::Core::step_application_finalization_receipt_v0`], which binds both
/// process affinities and the complete durable queue-front carrier.  On a
/// rejected callback the receipt is returned unchanged inside
/// [`ApplicationFinalizationReceiptRejectionV0`] for exact retry.
///
/// ```compile_fail
/// use trnm_consensus_core::ApplicationFinalizationReceiptV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<ApplicationFinalizationReceiptV0>();
/// }
/// ```
#[must_use = "an application finalization receipt must be submitted to its issuing Core"]
pub struct ApplicationFinalizationReceiptV0 {
    finalization: DurableFinalizationV0,
    readback: ApplicationFinalizationApplyReadbackV0,
    front_affinity: Arc<()>,
    application_apply_affinity: Arc<()>,
}

impl fmt::Debug for ApplicationFinalizationReceiptV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationFinalizationReceiptV0")
            .field("finalization", &self.finalization)
            .finish_non_exhaustive()
    }
}

impl ApplicationFinalizationReceiptV0 {
    pub const fn finalization(&self) -> &DurableFinalizationV0 {
        &self.finalization
    }

    pub const fn application_store_readback_v0(&self) -> &ApplicationFinalizationApplyReadbackV0 {
        &self.readback
    }

    pub(crate) fn matches_front_affinity_v0(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.front_affinity, expected)
    }

    pub(crate) fn matches_application_apply_affinity_v0(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.application_apply_affinity, expected)
    }
}

/// Owner-preserving rejection from an application-finalization receipt step.
///
/// The error is inspectable, while the sole consuming accessor returns the
/// exact non-cloneable receipt so a trusted host can retry without reminting.
#[must_use = "a rejected application finalization receipt retains the sole retry owner"]
pub struct ApplicationFinalizationReceiptRejectionV0 {
    error: CoreError,
    receipt: Box<ApplicationFinalizationReceiptV0>,
}

impl fmt::Debug for ApplicationFinalizationReceiptRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationFinalizationReceiptRejectionV0")
            .field("error", &self.error)
            .field("receipt", &self.receipt)
            .finish()
    }
}

impl ApplicationFinalizationReceiptRejectionV0 {
    pub(crate) fn new(error: CoreError, receipt: Box<ApplicationFinalizationReceiptV0>) -> Self {
        Self { error, receipt }
    }

    pub const fn error(&self) -> &CoreError {
        &self.error
    }

    pub fn into_receipt(self) -> ApplicationFinalizationReceiptV0 {
        *self.receipt
    }

    pub fn into_parts(self) -> (CoreError, ApplicationFinalizationReceiptV0) {
        (self.error, *self.receipt)
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
    valid_overlay: Option<BlockIdOverlayRefV0>,
    first_recorded_revision: u64,
}

impl PayloadTerminalFact {
    pub const fn new_valid(
        valid_overlay: BlockIdOverlayRefV0,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            block_id: valid_overlay.block_id(),
            result: PayloadTerminalResult::Valid,
            valid_overlay: Some(valid_overlay),
            first_recorded_revision,
        }
    }

    pub const fn new_deterministically_invalid(
        block_id: BlockId,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            block_id,
            result: PayloadTerminalResult::DeterministicallyInvalid,
            valid_overlay: None,
            first_recorded_revision,
        }
    }

    pub(crate) const fn from_persisted_parts(
        block_id: BlockId,
        result: PayloadTerminalResult,
        valid_overlay: Option<BlockIdOverlayRefV0>,
        first_recorded_revision: u64,
    ) -> Self {
        Self {
            block_id,
            result,
            valid_overlay,
            first_recorded_revision,
        }
    }

    pub const fn block_id(self) -> BlockId {
        self.block_id
    }

    pub const fn result(self) -> PayloadTerminalResult {
        self.result
    }

    pub const fn valid_overlay(self) -> Option<BlockIdOverlayRefV0> {
        self.valid_overlay
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
/// the registration persistence acknowledgement in the same process. Ordinary
/// [`Core::recover`](crate::Core::recover) deliberately fails closed while any
/// obligation remains. The separately gated V0 recovery session can restore
/// exactly one obligation only after a trusted host reconciles a pre-existing
/// deterministic-invalid application result. It is not a host callback
/// capability: possession of this cloneable record does not authorize construction of
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

    pub fn parent_binding_ref_v0(&self) -> Result<[u8; 32]> {
        self.parent.binding_ref_v0()
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
        artifact_ref: ValidatedPayloadArtifactRefV0,
    },
    Unavailable,
    DeterministicallyInvalid,
}

impl DurablePayloadValidationResultV1 {
    pub(crate) const fn from_live(result: PayloadValidationResult) -> Self {
        match result {
            PayloadValidationResult::Valid(valid) => Self::Valid {
                commitments: DurableValidatedBlockCommitmentsV1::from_live(valid.commitments()),
                artifact_ref: valid.artifact_ref(),
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
            Self::Valid { commitments, .. } => Some(commitments),
            Self::Unavailable | Self::DeterministicallyInvalid => None,
        }
    }

    pub const fn artifact_ref(self) -> Option<ValidatedPayloadArtifactRefV0> {
        match self {
            Self::Valid { artifact_ref, .. } => Some(artifact_ref),
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

pub const NATIVE_VALID_RESULT_CHECKSUM_DOMAIN_V0: &str =
    "trnm.consensus-core.payload-validation.valid-result.v0";

/// Computes Core's canonical inert checksum for one durable Valid result.
///
/// `None` means the supplied result is not Valid or its commitments and
/// overlay target disagree. SafetyStore and ApplicationStore must call this
/// helper rather than maintaining a second domain/framing implementation.
pub fn native_valid_result_checksum_v0(
    result: DurablePayloadValidationResultV1,
) -> Option<[u8; 32]> {
    let commitments = result.commitments()?;
    let artifact_ref = result.artifact_ref()?;
    let overlay = artifact_ref.overlay();
    if commitments.block_id() != overlay.block_id() {
        return None;
    }
    let logical_block_size = commitments.logical_block_size().to_be_bytes();
    let transaction_count = commitments.transaction_count().to_be_bytes();
    let evidence_count = commitments.evidence_count().to_be_bytes();
    let target_block_id = commitments.block_id();
    let overlay_block_id = overlay.block_id();
    let parent_block_id = overlay.parent_block_id();
    let overlay_checksum = overlay.overlay_checksum();
    let source_artifact_checksum = artifact_ref.source_artifact_checksum();
    let parts: [&[u8]; 8] = [
        target_block_id.as_bytes(),
        &logical_block_size,
        &transaction_count,
        &evidence_count,
        overlay_block_id.as_bytes(),
        parent_block_id.as_bytes(),
        &overlay_checksum,
        &source_artifact_checksum,
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((NATIVE_VALID_RESULT_CHECKSUM_DOMAIN_V0.len() as u64).to_be_bytes());
    hasher.update(NATIVE_VALID_RESULT_CHECKSUM_DOMAIN_V0.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Some(hasher.finalize().into())
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
    authenticated_genesis_application_parent: Option<AuthenticatedGenesisApplicationParentV0>,
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
    state_sync_anchor: Option<DurableStateSyncAnchorV0>,
    application_applied: FinalizedTip,
    finalization_queue: Vec<DurableFinalizationV0>,
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
        let (application_applied, finalization_queue) =
            match (pending_finalize, last_finalization.as_ref()) {
                (Some(_), Some(finalization)) => (
                    finalization.authenticated_parent(),
                    Vec::from([finalization.clone()]),
                ),
                _ => (finalized, Vec::new()),
            };
        Self::from_persisted_parts_v10(
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
            application_applied,
            finalization_queue,
            pending_finalize,
            safety_halt,
        )
    }

    /// Reconstructs the schema-v10 finalization shape inside a current state.
    ///
    /// Unlike [`Self::from_persisted_parts`], this constructor does not
    /// collapse the ordered queue into the historical single-proof shape. It
    /// remains as a compatibility helper for callers with no state-sync
    /// anchor; the schema-v11 canonical decoder uses
    /// [`Self::from_persisted_parts_v11`] directly.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts_v10(
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
        application_applied: FinalizedTip,
        finalization_queue: Vec<DurableFinalizationV0>,
        pending_finalize: Option<CertificateId>,
        safety_halt: Option<SafetyHalt>,
    ) -> Self {
        Self::from_persisted_parts_v11(
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
            None,
            application_applied,
            finalization_queue,
            pending_finalize,
            safety_halt,
        )
    }

    /// Compatibility constructor for schema-v11 callers which have no
    /// authenticated genesis application parent.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts_v11(
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
        state_sync_anchor: Option<DurableStateSyncAnchorV0>,
        application_applied: FinalizedTip,
        finalization_queue: Vec<DurableFinalizationV0>,
        pending_finalize: Option<CertificateId>,
        safety_halt: Option<SafetyHalt>,
    ) -> Self {
        Self::from_persisted_parts_v12(
            schema_version,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            genesis_block_id,
            None,
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
            state_sync_anchor,
            application_applied,
            finalization_queue,
            pending_finalize,
            safety_halt,
        )
    }

    /// Reconstructs the complete schema-v12 state, including optional
    /// immutable genesis-application and state-sync anchors.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts_v12(
        schema_version: u16,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_id: ValidatorSetId,
        genesis_block_id: BlockId,
        authenticated_genesis_application_parent: Option<AuthenticatedGenesisApplicationParentV0>,
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
        state_sync_anchor: Option<DurableStateSyncAnchorV0>,
        application_applied: FinalizedTip,
        finalization_queue: Vec<DurableFinalizationV0>,
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
            authenticated_genesis_application_parent,
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
            state_sync_anchor,
            application_applied,
            finalization_queue,
            pending_finalize,
            safety_halt,
        }
    }

    /// Validates the only exact fresh SafetyState shape which may be exposed
    /// as inert authenticated-genesis commissioning facts.
    ///
    /// The destructure deliberately names every field and contains no `..`.
    /// Adding durable state therefore breaks this classifier at compile time
    /// until the new field is explicitly classified as empty or rejected.
    pub(crate) fn validate_exact_authenticated_genesis_application_bootstrap_v0(
        &self,
        config: &CoreConfig,
        genesis_qc: &GenesisQcV0,
    ) -> Result<()> {
        config.validate()?;
        if config.validator_set().epoch() != Epoch::new(0) {
            return Err(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap supports genesis epoch zero only",
            ));
        }
        genesis_qc.matches_trusted_set(config.validator_set())?;
        let expected_authenticated_parent = config
            .authenticated_genesis_application_parent_v0()
            .copied()
            .ok_or(CoreError::InvalidConfig(
                "authenticated genesis application bootstrap requires its exact application parent",
            ))?;

        let SafetyState {
            schema_version,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            genesis_block_id,
            authenticated_genesis_application_parent,
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
            state_sync_anchor,
            application_applied,
            finalization_queue,
            pending_finalize,
            safety_halt,
        } = self;

        if state_sync_anchor.is_some() {
            return Err(CoreError::InvalidRecovery(
                "authenticated genesis application bootstrap and h1 state-sync bootstrap are mutually exclusive",
            ));
        }

        let genesis_reference = QcReferenceV0::genesis_anchor(genesis_qc.clone());
        let genesis_tip = FinalizedTip::new(
            Height::new(0),
            View::new(0),
            config.genesis_block_id(),
            config.trusted_genesis_timestamp_ms(),
        );
        if *schema_version != SAFETY_STATE_SCHEMA_VERSION
            || *chain_id != config.validator_set().chain_id()
            || *protocol_version != config.validator_set().protocol_version()
            || *epoch != Epoch::new(0)
            || *validator_set_id != config.validator_set().id()
            || *genesis_block_id != config.genesis_block_id()
            || authenticated_genesis_application_parent.as_ref().copied()
                != Some(expected_authenticated_parent)
            || *current_view != View::new(1)
            || last_voted_view.is_some()
            || last_timeout_view.is_some()
            || high_qc != &genesis_reference
            || locked_qc != &genesis_reference
            || *finalized != genesis_tip
            || *revision != 0
            || !payload_terminal_facts.is_empty()
            || !payload_validation_obligations.is_empty()
            || !payload_validation_completions.is_empty()
            || pending_tc_high_qc_sync.is_some()
            || pending_standalone_qc_sync.is_some()
            || pending_sign.is_some()
            || last_finalization.is_some()
            || *application_applied != genesis_tip
            || !finalization_queue.is_empty()
            || pending_finalize.is_some()
            || safety_halt.is_some()
        {
            return Err(CoreError::InvalidRecovery(
                "authenticated genesis application bootstrap must contain only exact inert revision-zero genesis facts",
            ));
        }
        Ok(())
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

    pub const fn authenticated_genesis_application_parent_v0(
        &self,
    ) -> Option<&AuthenticatedGenesisApplicationParentV0> {
        self.authenticated_genesis_application_parent.as_ref()
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
        self.payload_terminal_fact(block_id)
            .map(|fact| fact.result())
    }

    pub fn payload_terminal_fact(&self, block_id: BlockId) -> Option<PayloadTerminalFact> {
        self.payload_terminal_facts
            .binary_search_by_key(&block_id, |fact| fact.block_id())
            .ok()
            .map(|index| self.payload_terminal_facts[index])
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

    /// Returns true only when `self` is the in-memory state produced by
    /// releasing one already-durable signature request from `persisted`.
    ///
    /// `SignatureReady` is intentionally an authority-release transition: it
    /// clears `pending_sign` without creating another durable Safety revision.
    /// Consumers which freshly authenticate the persisted head therefore
    /// need an exhaustive comparison which permits exactly that one field to
    /// differ.  This is comparison-only and mints no recovery, persistence,
    /// or signing authority.
    pub fn matches_signature_released_successor_of_v0(&self, persisted: &Self) -> bool {
        let mut expected = persisted.clone();
        if expected.pending_sign.take().is_none() {
            return false;
        }
        self == &expected
    }

    pub const fn last_finalization(&self) -> Option<&DurableFinalizationV0> {
        self.last_finalization.as_ref()
    }

    pub fn last_finalization_proof(&self) -> Option<&FinalityProofV0> {
        self.last_finalization
            .as_ref()
            .map(DurableFinalizationV0::proof)
    }

    /// Permanent genesis-anchored h1 bootstrap provenance, when this namespace
    /// originated from an authenticated state-sync base.
    pub const fn state_sync_anchor(&self) -> Option<&DurableStateSyncAnchorV0> {
        self.state_sync_anchor.as_ref()
    }

    /// Highest finalization which the application has durably acknowledged.
    ///
    /// `finalized` is the independently advancing consensus tip. Every height
    /// strictly between this watermark and that tip must be represented once
    /// in [`Self::finalization_queue`].
    pub const fn application_applied(&self) -> FinalizedTip {
        self.application_applied
    }

    /// Unapplied finalizations in strict ancestor/height order.
    pub fn finalization_queue(&self) -> &[DurableFinalizationV0] {
        &self.finalization_queue
    }

    pub fn pending_finalization(&self) -> Option<&DurableFinalizationV0> {
        self.finalization_queue.first()
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
        authenticated_genesis_application_parent: Option<AuthenticatedGenesisApplicationParentV0>,
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
            authenticated_genesis_application_parent,
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
            state_sync_anchor: None,
            application_applied: FinalizedTip::new(
                genesis_qc.height(),
                genesis_qc.view(),
                genesis_qc.block_id(),
                trusted_genesis_timestamp_ms,
            ),
            finalization_queue: Vec::new(),
            pending_finalize: None,
            safety_halt: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_authenticated_genesis_application_for_test_v0(
        validator_set: &ValidatorSet,
        genesis_qc: GenesisQcV0,
        trusted_genesis_timestamp_ms: u64,
        authenticated_genesis_application_parent: AuthenticatedGenesisApplicationParentV0,
    ) -> Result<Self> {
        Self::from_genesis(
            validator_set,
            genesis_qc,
            trusted_genesis_timestamp_ms,
            Some(authenticated_genesis_application_parent),
        )
    }

    pub(crate) fn from_h1_state_sync_anchor(
        validator_set: &ValidatorSet,
        genesis_block_id: BlockId,
        authenticated_genesis_application_parent: Option<AuthenticatedGenesisApplicationParentV0>,
        anchor: DurableStateSyncAnchorV0,
    ) -> Result<Self> {
        let target = anchor.proof().finalized_block().header();
        let high_qc = QcReferenceV0::ordinary(anchor.proof().grandchild().certifying_qc().clone());
        let locked_qc = anchor.proof().grandchild().justify_qc().clone();
        let finalized = FinalizedTip::new(
            target.height(),
            target.view(),
            target.id(),
            target.timestamp_ms(),
        );
        Ok(Self {
            schema_version: SAFETY_STATE_SCHEMA_VERSION,
            chain_id: validator_set.chain_id(),
            protocol_version: validator_set.protocol_version(),
            epoch: validator_set.epoch(),
            validator_set_id: validator_set.id(),
            genesis_block_id,
            authenticated_genesis_application_parent,
            current_view: high_qc.qc_ref().view().checked_next()?,
            last_voted_view: None,
            last_timeout_view: None,
            high_qc,
            locked_qc,
            finalized,
            revision: 0,
            payload_terminal_facts: Vec::new(),
            payload_validation_obligations: Vec::new(),
            payload_validation_completions: Vec::new(),
            pending_tc_high_qc_sync: None,
            pending_standalone_qc_sync: None,
            pending_sign: None,
            last_finalization: None,
            state_sync_anchor: Some(anchor),
            application_applied: finalized,
            finalization_queue: Vec::new(),
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

    pub(crate) fn set_application_applied(&mut self, applied: FinalizedTip) {
        self.application_applied = applied;
    }

    pub(crate) fn set_finalization_queue(&mut self, queue: Vec<DurableFinalizationV0>) {
        self.finalization_queue = queue;
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
    SafetyReplayComplete,
    SignatureReady {
        id: SignId,
        signature: SignatureBytes,
    },
}

/// Core-internal projection of a Valid callback after the live request permit
/// has matched the exact pending Core slot.
///
/// The type is public only because it is carried by the public result enum;
/// every field and its sole constructor remain crate-private. Consequently an
/// external caller can inspect an already-authorized value but cannot turn
/// inert commitments or artifact references into a live Valid Core input.
///
/// ```compile_fail
/// use trnm_consensus_core::{
///     AuthorizedPayloadValidationValidV0, PayloadValidationResult,
/// };
/// use trnm_consensus_types::{
///     ValidatedBlockCommitmentsV0,
/// };
///
/// fn forge(
///     commitments: ValidatedBlockCommitmentsV0,
///     authorized: AuthorizedPayloadValidationValidV0,
/// ) -> PayloadValidationResult {
///     PayloadValidationResult::Valid(AuthorizedPayloadValidationValidV0 {
///         commitments,
///         artifact_ref: authorized.artifact_ref(),
///     })
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedPayloadValidationValidV0 {
    commitments: ValidatedBlockCommitmentsV0,
    artifact_ref: ValidatedPayloadArtifactRefV0,
}

impl AuthorizedPayloadValidationValidV0 {
    pub(crate) const fn new(
        commitments: ValidatedBlockCommitmentsV0,
        artifact_ref: ValidatedPayloadArtifactRefV0,
    ) -> Self {
        Self {
            commitments,
            artifact_ref,
        }
    }

    pub const fn commitments(self) -> ValidatedBlockCommitmentsV0 {
        self.commitments
    }

    pub const fn artifact_ref(self) -> ValidatedPayloadArtifactRefV0 {
        self.artifact_ref
    }
}

/// Result of validating one exact host-issued validation request.
///
/// The driver may return `DeterministicallyInvalid` only after it has the
/// complete canonical body matching the signed payload root, authenticated
/// parent state, and the epoch-authorized runtime and parameters. Missing or
/// mismatched source data and transient execution/storage failures are
/// `Unavailable` and must remain retryable under a new request generation.
/// A live `Valid` result cannot be constructed directly; it is created inside
/// Core only after an application-sealed callback presents an opaque
/// [`ApplicationSealedValidV0`] joining the matching request permit and the
/// separately installed Core/store seal authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadValidationResult {
    Valid(AuthorizedPayloadValidationValidV0),
    Unavailable,
    DeterministicallyInvalid,
}

impl PayloadValidationResult {
    pub(crate) const fn authorized_valid_v0(
        commitments: ValidatedBlockCommitmentsV0,
        artifact_ref: ValidatedPayloadArtifactRefV0,
    ) -> Self {
        Self::Valid(AuthorizedPayloadValidationValidV0::new(
            commitments,
            artifact_ref,
        ))
    }

    pub const fn commitments(self) -> Option<ValidatedBlockCommitmentsV0> {
        match self {
            Self::Valid(valid) => Some(valid.commitments()),
            Self::Unavailable | Self::DeterministicallyInvalid => None,
        }
    }

    pub const fn artifact_ref(self) -> Option<ValidatedPayloadArtifactRefV0> {
        match self {
            Self::Valid(valid) => Some(valid.artifact_ref()),
            Self::Unavailable | Self::DeterministicallyInvalid => None,
        }
    }

    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid(_))
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
    valid_affinity: Arc<()>,
}

impl PayloadValidationRequest {
    pub(crate) fn new(
        route: PayloadValidationRouteV0,
        id: ValidationId,
        block: Block,
        parent: PayloadValidationParentV0,
        valid_affinity: Arc<()>,
    ) -> Self {
        Self {
            route,
            id,
            block,
            parent,
            claimed: Arc::new(AtomicBool::new(false)),
            valid_affinity,
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

    pub fn parent_binding_ref_v0(&self) -> Result<[u8; 32]> {
        self.parent.binding_ref_v0()
    }

    pub(crate) fn matches_valid_affinity_v0(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.valid_affinity, expected)
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
            valid_affinity: Arc::clone(&self.valid_affinity),
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

    pub fn parent_binding_ref_v0(&self) -> Result<[u8; 32]> {
        self.request.parent_binding_ref_v0()
    }

    pub fn into_parts(
        self,
    ) -> (
        PayloadValidationRouteV0,
        ValidationId,
        Block,
        PayloadValidationParentV0,
        CoreIssuedValidPermitV0,
    ) {
        let PayloadValidationRequest {
            route,
            id,
            block,
            parent,
            claimed: _,
            valid_affinity,
        } = self.request;
        let permit = CoreIssuedValidPermitV0 {
            route,
            id,
            affinity: valid_affinity,
        };
        (route, id, block, parent, permit)
    }
}

/// Linear half of one exact Core-issued validation request.
///
/// This process-local permit is created only when the unique claimed request
/// is consumed. It is deliberately non-`Clone`, non-serializable, and has no
/// public constructor. Inert commitments or overlay references never recreate
/// it. The application adapter must retain it through execution and the
/// durable store seal, then present it together with that app-private sealed
/// owner at the live Valid delivery boundary.
///
/// ```compile_fail
/// use trnm_consensus_core::CoreIssuedValidPermitV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<CoreIssuedValidPermitV0>();
/// }
/// ```
#[must_use = "a Core-issued Valid permit must remain joined to its application validation owner"]
pub struct CoreIssuedValidPermitV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
    affinity: Arc<()>,
}

impl fmt::Debug for CoreIssuedValidPermitV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreIssuedValidPermitV0")
            .field("route", &self.route)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl CoreIssuedValidPermitV0 {
    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn id(&self) -> ValidationId {
        self.id
    }
}

/// The single process-local application-store seal authority issued by one
/// live [`crate::Core`] instance.
///
/// This capability is deliberately separate from every per-request
/// [`CoreIssuedValidPermitV0`].  A trusted node host installs it into its
/// private ApplicationStore exactly once; a caller that merely wins a request
/// claim therefore cannot turn caller-supplied commitments or artifact bytes
/// into a Core callback.  The authority is neither cloneable nor serializable
/// and a recovered Core issues a fresh process-local binding.
///
/// The proof-minting method is public only because the application store lives
/// in a downstream crate.  Possession is the authority: production code must
/// move this value directly from Core initialization into the private store
/// and must never expose it through an RPC, driver callback, or durable form.
///
/// ```compile_fail
/// use trnm_consensus_core::CoreIssuedApplicationSealAuthorityV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<CoreIssuedApplicationSealAuthorityV0>();
/// }
/// ```
#[must_use = "the Core-issued application seal authority must be installed into one private store"]
pub struct CoreIssuedApplicationSealAuthorityV0 {
    affinity: Arc<()>,
    application_host_affinity: Arc<()>,
    chain_id: ChainId,
}

impl fmt::Debug for CoreIssuedApplicationSealAuthorityV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreIssuedApplicationSealAuthorityV0")
            .finish_non_exhaustive()
    }
}

impl CoreIssuedApplicationSealAuthorityV0 {
    pub(crate) fn new(
        affinity: Arc<()>,
        application_host_affinity: Arc<()>,
        chain_id: ChainId,
    ) -> Self {
        Self {
            affinity,
            application_host_affinity,
            chain_id,
        }
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Checks that the two non-cloneable application authorities were issued
    /// by the same exact live Core instance.
    ///
    /// The trusted ApplicationStore host uses this borrow-only check before
    /// mutating either private authority slot. Public Core clones and newly
    /// recovered Core instances carry fresh host affinities even when their
    /// durable protocol state and chain ID are otherwise identical.
    pub fn matches_application_finalization_authority_v0(
        &self,
        authority: &CoreIssuedApplicationFinalizationApplyAuthorityV0,
    ) -> bool {
        Arc::ptr_eq(
            &self.application_host_affinity,
            &authority.application_host_affinity,
        )
    }

    pub(crate) fn accepts_application_host_persistence_v0(
        &self,
        persistence: &SafetyStatePersistenceV0,
    ) -> bool {
        Arc::ptr_eq(&self.application_host_affinity, &persistence.affinity)
    }

    /// Consumes one exact pending-slot permit after the application store has
    /// atomically committed and read back the corresponding Valid artifact.
    ///
    /// The authority itself remains installed so the same Core/store binding
    /// can seal later request generations.  Uniqueness per callback comes from
    /// consuming the non-cloneable request permit.
    pub fn seal_after_application_store_commit_v0(
        &self,
        permit: CoreIssuedValidPermitV0,
        commitments: ValidatedBlockCommitmentsV0,
        artifact_ref: ValidatedPayloadArtifactRefV0,
    ) -> ApplicationSealedValidV0 {
        ApplicationSealedValidV0 {
            route: permit.route,
            id: permit.id,
            valid_affinity: permit.affinity,
            application_seal_affinity: Arc::clone(&self.affinity),
            commitments,
            artifact_ref,
        }
    }
}

/// Opaque live proof that one exact Core request and one atomically committed
/// ApplicationStore seal were joined in the same process.
///
/// Core accepts Valid only through this value.  It has no public constructor,
/// exposes no constituent permit or affinity, is non-cloneable and
/// non-serializable, and is never reconstructed from a durable artifact.
/// Rejected submission borrows the proof so its owning application callback
/// can retry against the issuing Core.
///
/// ```compile_fail
/// use trnm_consensus_core::ApplicationSealedValidV0;
///
/// fn assert_clone<T: Clone>() {}
///
/// fn duplicate_is_forbidden() {
///     assert_clone::<ApplicationSealedValidV0>();
/// }
/// ```
#[must_use = "an application-sealed Valid proof must remain with its live callback owner"]
pub struct ApplicationSealedValidV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
    valid_affinity: Arc<()>,
    application_seal_affinity: Arc<()>,
    commitments: ValidatedBlockCommitmentsV0,
    artifact_ref: ValidatedPayloadArtifactRefV0,
}

impl fmt::Debug for ApplicationSealedValidV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationSealedValidV0")
            .field("route", &self.route)
            .field("id", &self.id)
            .field("commitments", &self.commitments)
            .field("artifact_ref", &self.artifact_ref)
            .finish_non_exhaustive()
    }
}

impl ApplicationSealedValidV0 {
    pub const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn id(&self) -> ValidationId {
        self.id
    }

    pub const fn commitments(&self) -> ValidatedBlockCommitmentsV0 {
        self.commitments
    }

    pub const fn artifact_ref(&self) -> ValidatedPayloadArtifactRefV0 {
        self.artifact_ref
    }

    pub(crate) fn matches_valid_affinity_v0(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.valid_affinity, expected)
    }

    pub(crate) fn matches_application_seal_affinity_v0(&self, expected: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.application_seal_affinity, expected)
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

impl fmt::Debug for DuplicatePayloadValidationRequestV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DuplicatePayloadValidationRequestV0")
            .field("route", &self.request.route())
            .field("id", &self.request.id())
            .finish_non_exhaustive()
    }
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

/// Canonical post-persistence action set reachable from a Valid payload
/// callback in schema v10.
///
/// The value is inert comparison data. Only Core can attach it to an opaque
/// [`SafetyStatePersistenceV0`], allowing a SafetyStore transition context to
/// bind exact post-ack behavior without attempting to reconstruct it through
/// `Input::Resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeValidPostAckActionV0 {
    None = 0,
    RequestSignature = 1,
    ArmViewTimer = 2,
    ArmViewTimerThenFinalize = 3,
    RequestTcHighQcSync = 4,
    RequestStandaloneQcSync = 5,
    ArmViewTimerThenRequestStandaloneQcSync = 6,
    SafetyHaltedConflict = 7,
}

impl NativeValidPostAckActionV0 {
    pub const fn code(self) -> u32 {
        self as u32
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::RequestSignature),
            2 => Some(Self::ArmViewTimer),
            3 => Some(Self::ArmViewTimerThenFinalize),
            4 => Some(Self::RequestTcHighQcSync),
            5 => Some(Self::RequestStandaloneQcSync),
            6 => Some(Self::ArmViewTimerThenRequestStandaloneQcSync),
            7 => Some(Self::SafetyHaltedConflict),
            _ => None,
        }
    }

    pub(crate) fn from_deferred_v0(deferred: &[DeferredEffect]) -> Option<Self> {
        match deferred {
            [] => Some(Self::None),
            [DeferredEffect::RequestSignature] => Some(Self::RequestSignature),
            [DeferredEffect::ArmViewTimer] => Some(Self::ArmViewTimer),
            [DeferredEffect::ArmViewTimer, DeferredEffect::Finalize] => {
                Some(Self::ArmViewTimerThenFinalize)
            }
            [DeferredEffect::RequestTcHighQcSync] => Some(Self::RequestTcHighQcSync),
            [DeferredEffect::RequestStandaloneQcSync] => Some(Self::RequestStandaloneQcSync),
            [DeferredEffect::ArmViewTimer, DeferredEffect::RequestStandaloneQcSync] => {
                Some(Self::ArmViewTimerThenRequestStandaloneQcSync)
            }
            [DeferredEffect::SafetyHalted] => Some(Self::SafetyHaltedConflict),
            _ => None,
        }
    }
}

/// Canonical post-persistence action set reachable after one exact
/// ApplicationStore finalization receipt advances the applied watermark.
///
/// This set is deliberately distinct from [`NativeValidPostAckActionV0`]: a
/// finalization acknowledgement may emit standalone `Finalize` and may stage
/// a vote with or without a preceding timer arm. Recovery must replay the
/// exact recorded shape and must not substitute `Input::Resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NativeFinalizationAppliedPostAckActionV0 {
    None = 0,
    ArmViewTimer = 1,
    RequestSignature = 2,
    ArmViewTimerThenRequestSignature = 3,
    Finalize = 4,
    ArmViewTimerThenFinalize = 5,
    RequestTcHighQcSync = 6,
    RequestStandaloneQcSync = 7,
    ArmViewTimerThenRequestStandaloneQcSync = 8,
}

impl NativeFinalizationAppliedPostAckActionV0 {
    pub const fn code(self) -> u32 {
        self as u32
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::ArmViewTimer),
            2 => Some(Self::RequestSignature),
            3 => Some(Self::ArmViewTimerThenRequestSignature),
            4 => Some(Self::Finalize),
            5 => Some(Self::ArmViewTimerThenFinalize),
            6 => Some(Self::RequestTcHighQcSync),
            7 => Some(Self::RequestStandaloneQcSync),
            8 => Some(Self::ArmViewTimerThenRequestStandaloneQcSync),
            _ => None,
        }
    }

    pub(crate) fn from_deferred_v0(deferred: &[DeferredEffect]) -> Option<Self> {
        match deferred {
            [] => Some(Self::None),
            [DeferredEffect::ArmViewTimer] => Some(Self::ArmViewTimer),
            [DeferredEffect::RequestSignature] => Some(Self::RequestSignature),
            [DeferredEffect::ArmViewTimer, DeferredEffect::RequestSignature] => {
                Some(Self::ArmViewTimerThenRequestSignature)
            }
            [DeferredEffect::Finalize] => Some(Self::Finalize),
            [DeferredEffect::ArmViewTimer, DeferredEffect::Finalize] => {
                Some(Self::ArmViewTimerThenFinalize)
            }
            [DeferredEffect::RequestTcHighQcSync] => Some(Self::RequestTcHighQcSync),
            [DeferredEffect::RequestStandaloneQcSync] => Some(Self::RequestStandaloneQcSync),
            [DeferredEffect::ArmViewTimer, DeferredEffect::RequestStandaloneQcSync] => {
                Some(Self::ArmViewTimerThenRequestStandaloneQcSync)
            }
            _ => None,
        }
    }
}

/// Inert recovery projection of one authenticated SafetyStore
/// codec-v0/tag-3 head and its consumed predecessor queue front.
///
/// The fixed tag-3 bytes carry application/source checksums while the retained
/// predecessor supplies the proof, parent, target, and overlay coordinates.
/// Combining them here does not change either persistent codec. This value
/// deliberately carries no recovery authority: a live Core is released only
/// after an exact, process-local recovery challenge binds this projection to
/// the complete current [`SafetyState`] and an independently authenticated
/// ApplicationStore apply readback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationAppliedRecoveryTransitionV0 {
    ordinal: u64,
    proof_id: CertificateId,
    parent_block_id: BlockId,
    target_block_id: BlockId,
    overlay_checksum: [u8; 32],
    source_route: PayloadValidationRouteV0,
    source_validation_id: ValidationId,
    application_host_config_ref: [u8; 32],
    finalization_checksum: [u8; 32],
    source_artifact_checksum: [u8; 32],
    accepted_source_checksum: [u8; 32],
    applied_job_row_checksum: [u8; 32],
    prior_head_checksum: [u8; 32],
    new_head_checksum: [u8; 32],
    application_receipt_row_checksum: [u8; 32],
    post_ack_action: NativeFinalizationAppliedPostAckActionV0,
    transition_revision: u64,
}

impl NativeFinalizationAppliedRecoveryTransitionV0 {
    /// Reconstructs inert decoded tag-3 fields for a trusted-host recovery
    /// comparison.  This constructor neither authenticates the journal nor
    /// creates a recovery attestation.
    #[allow(clippy::too_many_arguments)]
    pub const fn from_persisted_parts(
        ordinal: u64,
        proof_id: CertificateId,
        parent_block_id: BlockId,
        target_block_id: BlockId,
        overlay_checksum: [u8; 32],
        source_route: PayloadValidationRouteV0,
        source_validation_id: ValidationId,
        application_host_config_ref: [u8; 32],
        finalization_checksum: [u8; 32],
        source_artifact_checksum: [u8; 32],
        accepted_source_checksum: [u8; 32],
        applied_job_row_checksum: [u8; 32],
        prior_head_checksum: [u8; 32],
        new_head_checksum: [u8; 32],
        application_receipt_row_checksum: [u8; 32],
        post_ack_action: NativeFinalizationAppliedPostAckActionV0,
        transition_revision: u64,
    ) -> Self {
        Self {
            ordinal,
            proof_id,
            parent_block_id,
            target_block_id,
            overlay_checksum,
            source_route,
            source_validation_id,
            application_host_config_ref,
            finalization_checksum,
            source_artifact_checksum,
            accepted_source_checksum,
            applied_job_row_checksum,
            prior_head_checksum,
            new_head_checksum,
            application_receipt_row_checksum,
            post_ack_action,
            transition_revision,
        }
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn proof_id(&self) -> CertificateId {
        self.proof_id
    }

    pub const fn parent_block_id(&self) -> BlockId {
        self.parent_block_id
    }

    pub const fn target_block_id(&self) -> BlockId {
        self.target_block_id
    }

    pub const fn overlay_checksum(&self) -> [u8; 32] {
        self.overlay_checksum
    }

    pub const fn source_route(&self) -> PayloadValidationRouteV0 {
        self.source_route
    }

    pub const fn source_validation_id(&self) -> ValidationId {
        self.source_validation_id
    }

    pub const fn application_host_config_ref(&self) -> [u8; 32] {
        self.application_host_config_ref
    }

    pub const fn finalization_checksum(&self) -> [u8; 32] {
        self.finalization_checksum
    }

    pub const fn source_artifact_checksum(&self) -> [u8; 32] {
        self.source_artifact_checksum
    }

    pub const fn accepted_source_checksum(&self) -> [u8; 32] {
        self.accepted_source_checksum
    }

    pub const fn applied_job_row_checksum(&self) -> [u8; 32] {
        self.applied_job_row_checksum
    }

    pub const fn prior_head_checksum(&self) -> [u8; 32] {
        self.prior_head_checksum
    }

    pub const fn new_head_checksum(&self) -> [u8; 32] {
        self.new_head_checksum
    }

    pub const fn application_receipt_row_checksum(&self) -> [u8; 32] {
        self.application_receipt_row_checksum
    }

    pub const fn post_ack_action_v0(&self) -> NativeFinalizationAppliedPostAckActionV0 {
        self.post_ack_action
    }

    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

/// Exact Core-owned finalization transition manifest carried only by the
/// persistence request produced from an opaque ApplicationStore receipt.
///
/// It binds the inert App readback to both Core safety watermarks and the
/// closed post-ack action set. Decoding SafetyStore bytes never constructs
/// this value or any receipt authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinalizationAppliedPersistenceV0 {
    readback: ApplicationFinalizationApplyReadbackV0,
    predecessor: FinalizedTip,
    successor: FinalizedTip,
    post_ack_action: NativeFinalizationAppliedPostAckActionV0,
}

impl NativeFinalizationAppliedPersistenceV0 {
    pub(crate) const fn new(
        readback: ApplicationFinalizationApplyReadbackV0,
        predecessor: FinalizedTip,
        successor: FinalizedTip,
        post_ack_action: NativeFinalizationAppliedPostAckActionV0,
    ) -> Self {
        Self {
            readback,
            predecessor,
            successor,
            post_ack_action,
        }
    }

    pub const fn application_store_readback_v0(&self) -> &ApplicationFinalizationApplyReadbackV0 {
        &self.readback
    }

    pub const fn predecessor(&self) -> FinalizedTip {
        self.predecessor
    }

    pub const fn successor(&self) -> FinalizedTip {
        self.successor
    }

    pub const fn post_ack_action_v0(&self) -> NativeFinalizationAppliedPostAckActionV0 {
        self.post_ack_action
    }
}

/// Exact Core-owned marker for the sole durable h1-anchor successor replay
/// promotion cut.
///
/// The marker is minted only while the live anchored-successor owner is at
/// canonical H3Valid revision four.  Its persistence request advances to
/// revision five without changing any other SafetyState field.  SafetyStore
/// binds these facts to its typed promotion transition and the authenticated
/// revision-four predecessor before acknowledging the write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSyncAnchorOrdinaryPromotionPersistenceV0 {
    anchor_proof_id: CertificateId,
    transition_revision: u64,
}

impl StateSyncAnchorOrdinaryPromotionPersistenceV0 {
    pub(crate) const fn new(anchor_proof_id: CertificateId, transition_revision: u64) -> Self {
        Self {
            anchor_proof_id,
            transition_revision,
        }
    }

    pub const fn anchor_proof_id(&self) -> CertificateId {
        self.anchor_proof_id
    }

    pub const fn transition_revision(&self) -> u64 {
        self.transition_revision
    }
}

#[derive(Debug, Clone)]
pub struct SafetyStatePersistenceV0 {
    barrier: BarrierId,
    state: Box<SafetyState>,
    /// Exact comparison-only SafetyRules shadow transition which authorized
    /// this Core persistence request, when the request is a Vote or
    /// TimeoutVote intent.  The transition is never authority by itself;
    /// hosts may bind it to an independently durable sidecar before
    /// releasing the corresponding signer effect.
    safety_rules_shadow_transition: Option<InertSafetyTransitionV1>,
    native_valid_post_ack_action: Option<NativeValidPostAckActionV0>,
    native_finalization_applied: Option<NativeFinalizationAppliedPersistenceV0>,
    state_sync_anchor_ordinary_promotion: Option<StateSyncAnchorOrdinaryPromotionPersistenceV0>,
    affinity: Arc<()>,
}

impl PartialEq for SafetyStatePersistenceV0 {
    fn eq(&self, other: &Self) -> bool {
        self.barrier == other.barrier
            && self.state == other.state
            && self.safety_rules_shadow_transition == other.safety_rules_shadow_transition
            && self.native_valid_post_ack_action == other.native_valid_post_ack_action
            && self.native_finalization_applied == other.native_finalization_applied
            && self.state_sync_anchor_ordinary_promotion
                == other.state_sync_anchor_ordinary_promotion
    }
}

impl Eq for SafetyStatePersistenceV0 {}

impl SafetyStatePersistenceV0 {
    pub(crate) fn new(
        barrier: BarrierId,
        state: Box<SafetyState>,
        safety_rules_shadow_transition: Option<InertSafetyTransitionV1>,
        native_valid_post_ack_action: Option<NativeValidPostAckActionV0>,
        native_finalization_applied: Option<NativeFinalizationAppliedPersistenceV0>,
        affinity: Arc<()>,
        _seal: crate::core::CorePersistenceSealV0,
    ) -> Self {
        Self {
            barrier,
            state,
            safety_rules_shadow_transition,
            native_valid_post_ack_action,
            native_finalization_applied,
            state_sync_anchor_ordinary_promotion: None,
            affinity,
        }
    }

    pub const fn barrier(&self) -> BarrierId {
        self.barrier
    }

    pub fn state(&self) -> &SafetyState {
        &self.state
    }

    /// Returns the exact pure SafetyRules transition compared at Core's
    /// pre-persistence boundary, if this request authorizes a Vote or
    /// TimeoutVote.  This is comparison material only; it does not grant a
    /// signer, persistence, or Core transition capability.
    pub fn safety_rules_shadow_transition_v1(&self) -> Option<&InertSafetyTransitionV1> {
        self.safety_rules_shadow_transition.as_ref()
    }

    /// Exact Core-owned Valid-callback post-ack manifest, when this
    /// persistence transition has one of the eight schema-v10 action sets.
    pub const fn native_valid_post_ack_action_v0(&self) -> Option<NativeValidPostAckActionV0> {
        self.native_valid_post_ack_action
    }

    /// Exact ApplicationStore readback, predecessor/successor, and post-ack
    /// manifest for a finalization-applied transition.
    pub const fn native_finalization_applied_v0(
        &self,
    ) -> Option<&NativeFinalizationAppliedPersistenceV0> {
        self.native_finalization_applied.as_ref()
    }

    /// Exact Core-owned marker for a revision-four H3Valid to revision-five
    /// anchored-ordinary promotion request.
    pub const fn state_sync_anchor_ordinary_promotion_v0(
        &self,
    ) -> Option<StateSyncAnchorOrdinaryPromotionPersistenceV0> {
        self.state_sync_anchor_ordinary_promotion
    }

    pub(crate) fn bind_native_valid_post_ack_action_v0(
        &mut self,
        action: NativeValidPostAckActionV0,
    ) {
        self.native_valid_post_ack_action = Some(action);
    }

    pub(crate) fn bind_native_finalization_applied_v0(
        &mut self,
        manifest: NativeFinalizationAppliedPersistenceV0,
    ) {
        self.native_finalization_applied = Some(manifest);
    }

    pub(crate) fn bind_state_sync_anchor_ordinary_promotion_v0(
        &mut self,
        manifest: StateSyncAnchorOrdinaryPromotionPersistenceV0,
    ) {
        self.state_sync_anchor_ordinary_promotion = Some(manifest);
    }
}

/// Opaque Core authority proving one exact application-sealed Valid callback
/// advanced to the durable-delivery (`D`) boundary.
///
/// This value is minted only by
/// [`crate::Core::step_application_sealed_valid_to_delivery_v0`]. It owns the
/// exact process-affined Safety persistence request emitted by that Core step
/// and binds it to the completed validation identity and canonical Valid
/// result. It is deliberately non-`Clone`, non-serializable, and has no public
/// constructor. Persisting its inert digest is not a substitute for the
/// retained carrier or for a real SafetyStore confirmation.
///
/// ```compile_fail
/// use trnm_consensus_core::CoreAcceptedApplicationValidDV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<CoreAcceptedApplicationValidDV0>();
/// ```
#[must_use = "Core-accepted D must remain joined to exact Safety persistence"]
pub struct CoreAcceptedApplicationValidDV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    persistence: SafetyStatePersistenceV0,
    completion_revision: u64,
    valid_result_checksum: [u8; 32],
    delivery_digest: [u8; 32],
}

impl fmt::Debug for CoreAcceptedApplicationValidDV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreAcceptedApplicationValidDV0")
            .field("route", &self.route)
            .field("validation_id", &self.validation_id)
            .field("barrier", &self.persistence.barrier())
            .field("completion_revision", &self.completion_revision)
            .field("valid_result_checksum", &self.valid_result_checksum)
            .field("delivery_digest", &self.delivery_digest)
            .finish_non_exhaustive()
    }
}

impl CoreAcceptedApplicationValidDV0 {
    pub(crate) fn new(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        persistence: SafetyStatePersistenceV0,
        completion_revision: u64,
        valid_result_checksum: [u8; 32],
        delivery_digest: [u8; 32],
    ) -> Self {
        Self {
            route,
            validation_id,
            persistence,
            completion_revision,
            valid_result_checksum,
            delivery_digest,
        }
    }

    pub const fn route_v0(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub const fn validation_id_v0(&self) -> ValidationId {
        self.validation_id
    }

    pub const fn persistence_request_v0(&self) -> &SafetyStatePersistenceV0 {
        &self.persistence
    }

    pub const fn barrier_v0(&self) -> BarrierId {
        self.persistence.barrier()
    }

    pub const fn completion_revision_v0(&self) -> u64 {
        self.completion_revision
    }

    pub const fn valid_result_checksum_v0(&self) -> [u8; 32] {
        self.valid_result_checksum
    }

    /// Inert digest of the exact accepted Core carrier. Authority remains in
    /// this non-cloneable value and its affined persistence request.
    pub const fn delivery_digest_v0(&self) -> [u8; 32] {
        self.delivery_digest
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
    /// Inert exact queue-front request. The carrier includes the proof,
    /// authenticated prior tip, and target overlay, but cannot acknowledge or
    /// apply itself.
    Finalize(Box<DurableFinalizationV0>),
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
