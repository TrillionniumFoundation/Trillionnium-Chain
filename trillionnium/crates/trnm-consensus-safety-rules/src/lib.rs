#![no_std]
#![forbid(unsafe_code)]
//! Inert, pure HotStuff safety evaluation for PoCO-BFT v0.
//!
//! This crate verifies a complete typed proposal, every QC/TC carried by that
//! proposal, and a bounded finalized-to-target ancestry path before it builds
//! a canonical vote intent. A timeout intent is always rebuilt from the exact
//! complete high QC retained in the supplied state.
//!
//! The output is only a consensus-safety candidate. Application validity,
//! persistence, external anti-rollback, signing authority, authoritative Core
//! integration, runtime activation, and production use all remain explicitly
//! unavailable. Core may invoke the evaluator as a fail-closed shadow and
//! discard the returned candidate after exact comparison with its legacy
//! transition.

extern crate alloc;

mod authority;

pub use authority::{
    DurableSafetyRulesAuthorityErrorV1, DurableSafetyRulesAuthorityV1,
    DurableSafetyRulesSigningErrorV1, SafetyRulesDurableTransitionStoreV1,
    SafetyRulesSigningAdapterV1, SignedSafetyMessageV1, SignedSafetyTransitionV1,
};

use alloc::collections::BTreeSet;
use core::fmt;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    BlockHeader, BlockId, BlockKind, CanonicalSignIntentV0, ChainId, ConsensusParametersHash,
    ConsensusParametersV0, ContextAuthorizedQcV0, Epoch, GenesisHash, GenesisQcV0, Height,
    ProtocolVersion, QcRef, QcReferenceV0, SignatureVerifier, SignedProposalV0, ValidatorId,
    ValidatorSet, ValidatorSetId, View,
};

/// Frozen schema for the first inert safety-rules model.
pub const SAFETY_RULES_SCHEMA_VERSION_V1: u16 = 1;

/// Frozen state digest domain. It is not a protocol-types signing domain.
pub const SAFETY_RULES_STATE_DIGEST_DOMAIN_V1: &[u8] = b"trnm.consensus.safety-rules.state.v1";

/// Frozen transition digest domain. It is not a signing domain.
pub const SAFETY_RULES_TRANSITION_DIGEST_DOMAIN_V1: &[u8] =
    b"trnm.consensus.safety-rules.transition.v1";

/// Hard memory bound for the caller-supplied ancestry proof.
pub const MAX_SAFETY_ANCESTRY_BLOCKS_V1: u32 = 64;

/// Truth flags intentionally remain false until separate authority layers exist.
pub const APPLICATION_VALID_AUTHORITY_V1: bool = false;
pub const COMPLETE_VOTE_ADMISSION_V1: bool = false;
pub const SIGNER_AUTHORITY_V1: bool = false;
pub const STATE_SEED_AUTHORITY_V1: bool = false;
pub const FINALIZED_REFERENCE_AUTHORITY_V1: bool = false;
pub const PERSISTENCE_AUTHORITY_V1: bool = false;
pub const EXTERNAL_CAS_AUTHORITY_V1: bool = false;
pub const HSM_AUTHORITY_V1: bool = false;
pub const CORE_INTEGRATION_V1: bool = true;
pub const CORE_SHADOW_INTEGRATION_V1: bool = true;
pub const CORE_AUTHORITATIVE_INTEGRATION_V1: bool = false;
/// Recovered pending intents and tag-3 signature remints do not re-run this
/// evaluator and cannot derive recovery or cross-upgrade signer authority from it.
pub const RECOVERY_REPLAY_AUTHORITY_V1: bool = false;
pub const REMOTE_WIRE_V1: bool = false;
pub const OBSERVE_QC_V1: bool = false;
pub const OBSERVE_TC_V1: bool = false;
pub const RUNTIME_ACTIVATION_V1: bool = false;
pub const PRODUCTION_CANDIDATE_V1: bool = false;
pub const PRODUCTION_CONSENSUS_ACTIVATION_V1: bool = false;

pub type SafetyRulesResultV1<T> = core::result::Result<T, SafetyRulesErrorV1>;

/// Closed failure surface for the inert evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyRulesErrorV1 {
    InvalidContext,
    ProductionActivationUnsupported,
    InvalidAncestryBound,
    InvalidState,
    StateContextMismatch,
    StateDigestMismatch,
    UnsupportedEpochAnchor,
    UnsupportedBlockKind,
    WrongView,
    VoteWatermarkRegression,
    TimeoutWatermarkRegression,
    AncestryTooLong,
    DuplicateOrCyclicBlock,
    ParentEdgeMismatch,
    HeightEdgeMismatch,
    JustifyEdgeMismatch,
    InvalidConsensusArtifact,
    ResourceLimitExceeded,
    UnsafeLock,
    ArithmeticOverflow,
}

impl fmt::Display for SafetyRulesErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidContext => "invalid safety-rules context",
            Self::ProductionActivationUnsupported => {
                "production activation is unsupported by the inert evaluator"
            }
            Self::InvalidAncestryBound => "invalid safety ancestry bound",
            Self::InvalidState => "invalid safety-rules state",
            Self::StateContextMismatch => "safety-rules state context mismatch",
            Self::StateDigestMismatch => "safety-rules state digest mismatch",
            Self::UnsupportedEpochAnchor => "epoch anchors are unsupported",
            Self::UnsupportedBlockKind => "non-regular intra-epoch block is unsupported",
            Self::WrongView => "candidate view differs from the current safety view",
            Self::VoteWatermarkRegression => "vote watermark would regress or equivocate",
            Self::TimeoutWatermarkRegression => "timeout watermark would regress or equivocate",
            Self::AncestryTooLong => "safety ancestry exceeds its configured bound",
            Self::DuplicateOrCyclicBlock => "safety ancestry repeats a block identifier",
            Self::ParentEdgeMismatch => "safety ancestry parent edge mismatch",
            Self::HeightEdgeMismatch => "safety ancestry height edge mismatch",
            Self::JustifyEdgeMismatch => "proposal QC does not certify the exact ancestry parent",
            Self::InvalidConsensusArtifact => "typed consensus artifact failed fresh verification",
            Self::ResourceLimitExceeded => "proposal exceeds committed resource limits",
            Self::UnsafeLock => "proposal neither extends nor unlocks the retained lock",
            Self::ArithmeticOverflow => "safety-rules arithmetic overflow",
        };
        formatter.write_str(message)
    }
}

/// Complete immutable inputs shared by every state and evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRulesContextV1 {
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    author: ValidatorId,
    trusted_genesis_timestamp_ms: u64,
    max_ancestry_blocks: u32,
}

impl SafetyRulesContextV1 {
    pub fn new(
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        author: ValidatorId,
        trusted_genesis_timestamp_ms: u64,
        max_ancestry_blocks: u32,
    ) -> SafetyRulesResultV1<Self> {
        validator_set
            .validate_against_parameters(&consensus_parameters)
            .map_err(|_| SafetyRulesErrorV1::InvalidContext)?;
        if consensus_parameters.production_activation() {
            return Err(SafetyRulesErrorV1::ProductionActivationUnsupported);
        }
        if validator_set.validator(author).is_none() {
            return Err(SafetyRulesErrorV1::InvalidContext);
        }
        if max_ancestry_blocks == 0 || max_ancestry_blocks > MAX_SAFETY_ANCESTRY_BLOCKS_V1 {
            return Err(SafetyRulesErrorV1::InvalidAncestryBound);
        }
        Ok(Self {
            validator_set,
            consensus_parameters,
            author,
            trusted_genesis_timestamp_ms,
            max_ancestry_blocks,
        })
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn consensus_parameters(&self) -> &ConsensusParametersV0 {
        &self.consensus_parameters
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn trusted_genesis_timestamp_ms(&self) -> u64 {
        self.trusted_genesis_timestamp_ms
    }

    pub const fn max_ancestry_blocks(&self) -> u32 {
        self.max_ancestry_blocks
    }
}

/// Complete retained coordinate for the finalized ancestry root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBlockRefV1 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    view: View,
    height: Height,
    block_id: BlockId,
    timestamp_ms: u64,
}

impl FinalizedBlockRefV1 {
    /// Builds the exact height-zero root committed by the configured genesis.
    pub fn trusted_genesis(context: &SafetyRulesContextV1) -> Self {
        Self {
            genesis_hash: context.validator_set.genesis_hash(),
            chain_id: context.validator_set.chain_id(),
            protocol_version: context.validator_set.protocol_version(),
            epoch: context.validator_set.epoch(),
            validator_set_id: context.validator_set.id(),
            consensus_parameters_hash: context.validator_set.consensus_parameters_hash(),
            view: View::new(0),
            height: Height::new(0),
            block_id: BlockId::new(*context.validator_set.genesis_hash().as_bytes()),
            timestamp_ms: context.trusted_genesis_timestamp_ms,
        }
    }

    /// Retains the complete consensus coordinate of a caller-supplied header.
    ///
    /// Shape validation does not prove finality, ancestry, freshness, or
    /// durability. The resulting reference is data only and never constitutes
    /// finalized-reference authority.
    pub fn from_header(header: &BlockHeader) -> SafetyRulesResultV1<Self> {
        header
            .validate_shape()
            .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
        Ok(Self {
            genesis_hash: header.genesis_hash(),
            chain_id: header.chain_id(),
            protocol_version: header.protocol_version(),
            epoch: header.epoch(),
            validator_set_id: header.validator_set_id(),
            consensus_parameters_hash: header.consensus_parameters_hash(),
            view: header.view(),
            height: header.height(),
            block_id: header.id(),
            timestamp_ms: header.timestamp_ms(),
        })
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    fn matches_context(&self, context: &SafetyRulesContextV1) -> bool {
        self.genesis_hash == context.validator_set.genesis_hash()
            && self.chain_id == context.validator_set.chain_id()
            && self.protocol_version == context.validator_set.protocol_version()
            && self.epoch == context.validator_set.epoch()
            && self.validator_set_id == context.validator_set.id()
            && self.consensus_parameters_hash == context.validator_set.consensus_parameters_hash()
            && ((self.height == Height::new(0)
                && self.view == View::new(0)
                && self.block_id == BlockId::new(*context.validator_set.genesis_hash().as_bytes())
                && self.timestamp_ms == context.trusted_genesis_timestamp_ms)
                || (self.height > Height::new(0) && self.view > View::new(0)))
    }
}

/// Constructor payload for one complete immutable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRulesStateSeedV1 {
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    high_qc: QcReferenceV0,
    locked_qc: QcReferenceV0,
    finalized: FinalizedBlockRefV1,
    revision: u64,
}

impl SafetyRulesStateSeedV1 {
    /// Collects caller-supplied state data without minting safety authority.
    ///
    /// A later [`SafetyRulesStateV1::new`] call freshly verifies QC signatures,
    /// but neither constructor proves the lock/high/finalized ancestry,
    /// finality, freshness, or durability of this seed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_view: View,
        last_voted_view: Option<View>,
        last_timeout_view: Option<View>,
        high_qc: QcReferenceV0,
        locked_qc: QcReferenceV0,
        finalized: FinalizedBlockRefV1,
        revision: u64,
    ) -> Self {
        Self {
            current_view,
            last_voted_view,
            last_timeout_view,
            high_qc,
            locked_qc,
            finalized,
            revision,
        }
    }
}

/// Domain-separated digest of every safety-state field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafetyRulesStateDigestV1([u8; 32]);

impl SafetyRulesStateDigestV1 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Immutable state consumed by the pure evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRulesStateV1 {
    schema_version: u16,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    author: ValidatorId,
    trusted_genesis_timestamp_ms: u64,
    max_ancestry_blocks: u32,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    high_qc: QcReferenceV0,
    locked_qc: QcReferenceV0,
    finalized: FinalizedBlockRefV1,
    revision: u64,
    digest: SafetyRulesStateDigestV1,
}

impl SafetyRulesStateV1 {
    /// Freshly verifies complete high/locked QC signatures and state shape.
    ///
    /// This does not prove that the supplied seed is latest or durable, that
    /// its high QC and lock descend from the finalized reference, or that the
    /// reference is actually finalized. Caller-supplied data remains inert and
    /// does not become state-seed or finalized-reference authority.
    pub fn new<V: SignatureVerifier>(
        context: &SafetyRulesContextV1,
        seed: SafetyRulesStateSeedV1,
        verifier: &V,
    ) -> SafetyRulesResultV1<Self> {
        let mut value = Self {
            schema_version: SAFETY_RULES_SCHEMA_VERSION_V1,
            genesis_hash: context.validator_set.genesis_hash(),
            chain_id: context.validator_set.chain_id(),
            protocol_version: context.validator_set.protocol_version(),
            epoch: context.validator_set.epoch(),
            validator_set_id: context.validator_set.id(),
            consensus_parameters_hash: context.validator_set.consensus_parameters_hash(),
            author: context.author,
            trusted_genesis_timestamp_ms: context.trusted_genesis_timestamp_ms,
            max_ancestry_blocks: context.max_ancestry_blocks,
            current_view: seed.current_view,
            last_voted_view: seed.last_voted_view,
            last_timeout_view: seed.last_timeout_view,
            high_qc: seed.high_qc,
            locked_qc: seed.locked_qc,
            finalized: seed.finalized,
            revision: seed.revision,
            digest: SafetyRulesStateDigestV1([0; 32]),
        };
        value.validate(context, verifier)?;
        value.digest = compute_state_digest_v1(&value);
        Ok(value)
    }

    pub fn from_genesis<V: SignatureVerifier>(
        context: &SafetyRulesContextV1,
        genesis_qc: GenesisQcV0,
        verifier: &V,
    ) -> SafetyRulesResultV1<Self> {
        let reference = QcReferenceV0::genesis_anchor(genesis_qc);
        Self::new(
            context,
            SafetyRulesStateSeedV1::new(
                View::new(1),
                None,
                None,
                reference.clone(),
                reference,
                FinalizedBlockRefV1::trusted_genesis(context),
                0,
            ),
            verifier,
        )
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
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

    pub const fn finalized(&self) -> FinalizedBlockRefV1 {
        self.finalized
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn digest(&self) -> SafetyRulesStateDigestV1 {
        self.digest
    }

    fn validate<V: SignatureVerifier>(
        &self,
        context: &SafetyRulesContextV1,
        verifier: &V,
    ) -> SafetyRulesResultV1<()> {
        if !self.matches_context(context) {
            return Err(SafetyRulesErrorV1::StateContextMismatch);
        }
        if self.schema_version != SAFETY_RULES_SCHEMA_VERSION_V1
            || self.current_view == View::new(0)
            || self
                .last_voted_view
                .is_some_and(|view| view == View::new(0) || view > self.current_view)
            || self
                .last_timeout_view
                .is_some_and(|view| view == View::new(0) || view > self.current_view)
            || ((self.last_voted_view.is_some() || self.last_timeout_view.is_some())
                && self.revision == 0)
            || !self.finalized.matches_context(context)
        {
            return Err(SafetyRulesErrorV1::InvalidState);
        }

        verify_qc_reference_v1(context, &self.high_qc, verifier)?;
        verify_qc_reference_v1(context, &self.locked_qc, verifier)?;
        let high = self.high_qc.qc_ref();
        let locked = self.locked_qc.qc_ref();
        // HotStuff QC strength is ordered by view, not height. Across forks a
        // later-view high QC may certify a shallower block than the retained
        // lock. High and lock must nevertheless each remain independently
        // at/above finality in both coordinates, and an equal-height reference
        // must identify the exact finalized block.
        if high.view() >= self.current_view
            || locked.view() > high.view()
            || self.finalized.view > high.view()
            || self.finalized.height > high.height()
            || self.finalized.view > locked.view()
            || self.finalized.height > locked.height()
            || (self.finalized.height == high.height()
                && self.finalized.block_id != high.block_id())
            || (self.finalized.height == locked.height()
                && self.finalized.block_id != locked.block_id())
            || same_view_conflict(high, locked)
            || repeated_block_has_different_coordinate(high, locked)
            || qc_conflicts_with_finalized(high, self.finalized)
            || qc_conflicts_with_finalized(locked, self.finalized)
        {
            return Err(SafetyRulesErrorV1::InvalidState);
        }
        Ok(())
    }

    pub(crate) fn validate_fresh<V: SignatureVerifier>(
        &self,
        context: &SafetyRulesContextV1,
        verifier: &V,
    ) -> SafetyRulesResultV1<()> {
        self.validate(context, verifier)?;
        if self.digest != compute_state_digest_v1(self) {
            return Err(SafetyRulesErrorV1::StateDigestMismatch);
        }
        Ok(())
    }

    fn matches_context(&self, context: &SafetyRulesContextV1) -> bool {
        self.genesis_hash == context.validator_set.genesis_hash()
            && self.chain_id == context.validator_set.chain_id()
            && self.protocol_version == context.validator_set.protocol_version()
            && self.epoch == context.validator_set.epoch()
            && self.validator_set_id == context.validator_set.id()
            && self.consensus_parameters_hash == context.validator_set.consensus_parameters_hash()
            && self.author == context.author
            && self.trusted_genesis_timestamp_ms == context.trusted_genesis_timestamp_ms
            && self.max_ancestry_blocks == context.max_ancestry_blocks
    }
}

/// The only two inert state transitions implemented by this commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InertSafetyTransitionKindV1 {
    Vote = 0,
    TimeoutVote = 1,
}

/// Domain-separated digest of an exact inert transition candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafetyCandidateDigestV1([u8; 32]);

impl SafetyCandidateDigestV1 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Private-field output with no signer, store, lease, or runtime authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InertSafetyTransitionV1 {
    kind: InertSafetyTransitionKindV1,
    predecessor_state_digest: SafetyRulesStateDigestV1,
    successor_state: SafetyRulesStateV1,
    canonical_intent: CanonicalSignIntentV0,
    candidate_digest: SafetyCandidateDigestV1,
    vote_block_id: Option<BlockId>,
}

impl InertSafetyTransitionV1 {
    pub const fn kind(&self) -> InertSafetyTransitionKindV1 {
        self.kind
    }

    pub const fn predecessor_state_digest(&self) -> SafetyRulesStateDigestV1 {
        self.predecessor_state_digest
    }

    pub const fn successor_state(&self) -> &SafetyRulesStateV1 {
        &self.successor_state
    }

    pub const fn canonical_intent(&self) -> &CanonicalSignIntentV0 {
        &self.canonical_intent
    }

    pub const fn candidate_digest(&self) -> SafetyCandidateDigestV1 {
        self.candidate_digest
    }

    pub const fn vote_block_id(&self) -> Option<BlockId> {
        self.vote_block_id
    }
}

/// Stateless namespace for the two pure evaluations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PureHotStuffSafetyKernelV1;

impl PureHotStuffSafetyKernelV1 {
    /// Re-verifies a complete proposal and bounded finalized ancestry, applies
    /// the chained-HotStuff lock rule, and rebuilds the exact vote intent.
    pub fn prepare_vote<'a, V: SignatureVerifier>(
        context: &SafetyRulesContextV1,
        state: &SafetyRulesStateV1,
        ancestry: &'a [SignedProposalV0],
        target: &'a SignedProposalV0,
        verifier: &V,
    ) -> SafetyRulesResultV1<InertSafetyTransitionV1> {
        prepare_vote_v1(context, state, ancestry.iter(), target, verifier)
    }

    /// Borrowed-proposal counterpart used by Core's Arc-backed retention
    /// cache. It evaluates and hashes the exact same proposal sequence without
    /// deep-cloning retained bodies or changing any authority boundary.
    pub fn prepare_vote_from_refs<'a, V: SignatureVerifier>(
        context: &SafetyRulesContextV1,
        state: &SafetyRulesStateV1,
        ancestry: &[&'a SignedProposalV0],
        target: &'a SignedProposalV0,
        verifier: &V,
    ) -> SafetyRulesResultV1<InertSafetyTransitionV1> {
        prepare_vote_v1(context, state, ancestry.iter().copied(), target, verifier)
    }

    /// Rebuilds a timeout intent from the exact complete high QC in state. The
    /// caller cannot supply or substitute a high-QC summary.
    pub fn prepare_timeout<V: SignatureVerifier>(
        context: &SafetyRulesContextV1,
        state: &SafetyRulesStateV1,
        verifier: &V,
    ) -> SafetyRulesResultV1<InertSafetyTransitionV1> {
        state.validate_fresh(context, verifier)?;
        if state
            .last_timeout_view
            .is_some_and(|last| last >= state.current_view)
        {
            return Err(SafetyRulesErrorV1::TimeoutWatermarkRegression);
        }

        let successor_revision = state
            .revision
            .checked_add(1)
            .ok_or(SafetyRulesErrorV1::ArithmeticOverflow)?;
        let mut successor = state.clone();
        successor.last_timeout_view = Some(state.current_view);
        successor.revision = successor_revision;
        successor.digest = compute_state_digest_v1(&successor);

        let canonical_intent = CanonicalSignIntentV0::timeout_vote(
            &context.validator_set,
            context.author,
            successor_revision,
            state.current_view,
            state.high_qc.qc_ref(),
        )
        .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
        let predecessor_state_digest = state.digest;
        let candidate_digest = compute_timeout_transition_digest_v1(
            predecessor_state_digest,
            successor.digest,
            &canonical_intent,
            &state.high_qc,
        )?;
        Ok(InertSafetyTransitionV1 {
            kind: InertSafetyTransitionKindV1::TimeoutVote,
            predecessor_state_digest,
            successor_state: successor,
            canonical_intent,
            candidate_digest,
            vote_block_id: None,
        })
    }
}

fn prepare_vote_v1<'a, V, I>(
    context: &SafetyRulesContextV1,
    state: &SafetyRulesStateV1,
    ancestry: I,
    target: &'a SignedProposalV0,
    verifier: &V,
) -> SafetyRulesResultV1<InertSafetyTransitionV1>
where
    V: SignatureVerifier,
    I: Clone + ExactSizeIterator<Item = &'a SignedProposalV0>,
{
    state.validate_fresh(context, verifier)?;
    let header = target.block().header();
    if header.view() != state.current_view {
        return Err(SafetyRulesErrorV1::WrongView);
    }
    if state
        .last_voted_view
        .is_some_and(|last| last >= header.view())
    {
        return Err(SafetyRulesErrorV1::VoteWatermarkRegression);
    }

    let extends_lock = verify_ancestry_v1(context, state, ancestry.clone(), target, verifier)?;
    let justify = target.witness().justify_qc().qc_ref();
    if !extends_lock && justify.view() <= state.locked_qc.qc_ref().view() {
        return Err(SafetyRulesErrorV1::UnsafeLock);
    }

    let successor_revision = state
        .revision
        .checked_add(1)
        .ok_or(SafetyRulesErrorV1::ArithmeticOverflow)?;
    let mut successor = state.clone();
    successor.last_voted_view = Some(header.view());
    successor.revision = successor_revision;
    successor.digest = compute_state_digest_v1(&successor);

    let canonical_intent = CanonicalSignIntentV0::vote(
        &context.validator_set,
        context.author,
        successor_revision,
        header.view(),
        header.height(),
        target.block().id(),
    )
    .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
    let predecessor_state_digest = state.digest;
    let candidate_digest = compute_vote_transition_digest_v1(
        predecessor_state_digest,
        successor.digest,
        &canonical_intent,
        ancestry,
        target,
    )?;
    Ok(InertSafetyTransitionV1 {
        kind: InertSafetyTransitionKindV1::Vote,
        predecessor_state_digest,
        successor_state: successor,
        canonical_intent,
        candidate_digest,
        vote_block_id: Some(target.block().id()),
    })
}

fn verify_qc_reference_v1<V: SignatureVerifier>(
    context: &SafetyRulesContextV1,
    reference: &QcReferenceV0,
    verifier: &V,
) -> SafetyRulesResultV1<()> {
    match reference {
        QcReferenceV0::Ordinary(certificate) => certificate
            .verify(&context.validator_set, verifier)
            .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact),
        QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
            ContextAuthorizedQcV0::Genesis(anchor) => anchor
                .matches_trusted_set(&context.validator_set)
                .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact),
            ContextAuthorizedQcV0::Epoch(_) => Err(SafetyRulesErrorV1::UnsupportedEpochAnchor),
        },
    }
}

fn verify_ancestry_v1<'a, V, I>(
    context: &SafetyRulesContextV1,
    state: &SafetyRulesStateV1,
    ancestry: I,
    target: &'a SignedProposalV0,
    verifier: &V,
) -> SafetyRulesResultV1<bool>
where
    V: SignatureVerifier,
    I: ExactSizeIterator<Item = &'a SignedProposalV0>,
{
    let path_len = ancestry
        .len()
        .checked_add(1)
        .ok_or(SafetyRulesErrorV1::ArithmeticOverflow)?;
    if path_len > context.max_ancestry_blocks as usize {
        return Err(SafetyRulesErrorV1::AncestryTooLong);
    }

    let locked = state.locked_qc.qc_ref();
    let mut extends_lock = finalized_matches_qc_v1(state.finalized, locked);
    let mut previous_view = state.finalized.view;
    let mut previous_height = state.finalized.height;
    let mut previous_block_id = state.finalized.block_id;
    let mut previous_timestamp_ms = state.finalized.timestamp_ms;
    let mut seen = BTreeSet::new();
    seen.insert(previous_block_id);

    for proposal in ancestry.chain(core::iter::once(target)) {
        let block = proposal.block();
        let header = block.header();
        if header.block_kind() != BlockKind::Regular {
            return Err(SafetyRulesErrorV1::UnsupportedBlockKind);
        }
        if header.genesis_hash() != context.validator_set.genesis_hash()
            || header.chain_id() != context.validator_set.chain_id()
            || header.protocol_version() != context.validator_set.protocol_version()
            || header.epoch() != context.validator_set.epoch()
            || header.validator_set_id() != context.validator_set.id()
            || header.consensus_parameters_hash()
                != context.validator_set.consensus_parameters_hash()
        {
            return Err(SafetyRulesErrorV1::InvalidConsensusArtifact);
        }
        if !seen.insert(block.id()) {
            return Err(SafetyRulesErrorV1::DuplicateOrCyclicBlock);
        }
        if header.parent_id() != previous_block_id {
            return Err(SafetyRulesErrorV1::ParentEdgeMismatch);
        }
        if previous_height
            .checked_next()
            .map_err(|_| SafetyRulesErrorV1::ArithmeticOverflow)?
            != header.height()
        {
            return Err(SafetyRulesErrorV1::HeightEdgeMismatch);
        }
        let justify = proposal.witness().justify_qc().qc_ref();
        if justify.epoch() != context.validator_set.epoch()
            || justify.validator_set_id() != context.validator_set.id()
            || justify.view() != previous_view
            || justify.height() != previous_height
            || justify.block_id() != previous_block_id
        {
            return Err(SafetyRulesErrorV1::JustifyEdgeMismatch);
        }

        proposal
            .verify(
                &context.validator_set,
                None,
                &context.consensus_parameters,
                previous_timestamp_ms,
                verifier,
            )
            .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
        if block.logical_block_size() > context.consensus_parameters.max_block_bytes() as usize
            || proposal
                .durable_validation_resource_size_v0()
                .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?
                > context.consensus_parameters.max_consensus_message_bytes() as usize
        {
            return Err(SafetyRulesErrorV1::ResourceLimitExceeded);
        }

        if block.id() == locked.block_id() {
            if header.view() != locked.view() || header.height() != locked.height() {
                return Err(SafetyRulesErrorV1::InvalidState);
            }
            extends_lock = true;
        }
        previous_view = header.view();
        previous_height = header.height();
        previous_block_id = block.id();
        previous_timestamp_ms = header.timestamp_ms();
    }
    Ok(extends_lock)
}

fn same_view_conflict(left: QcRef, right: QcRef) -> bool {
    left.view() == right.view() && left.block_id() != right.block_id()
}

fn repeated_block_has_different_coordinate(left: QcRef, right: QcRef) -> bool {
    left.block_id() == right.block_id()
        && (left.view() != right.view() || left.height() != right.height())
}

fn qc_conflicts_with_finalized(reference: QcRef, finalized: FinalizedBlockRefV1) -> bool {
    reference.block_id() == finalized.block_id
        && (reference.view() != finalized.view || reference.height() != finalized.height)
}

fn finalized_matches_qc_v1(finalized: FinalizedBlockRefV1, reference: QcRef) -> bool {
    finalized.view == reference.view()
        && finalized.height == reference.height()
        && finalized.block_id == reference.block_id()
}

fn compute_state_digest_v1(state: &SafetyRulesStateV1) -> SafetyRulesStateDigestV1 {
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_RULES_STATE_DIGEST_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(state.schema_version.to_be_bytes());
    hasher.update(state.genesis_hash.as_bytes());
    update_len_prefixed_v1(&mut hasher, state.chain_id.as_bytes());
    hasher.update(state.protocol_version.get().to_be_bytes());
    hasher.update(state.epoch.get().to_be_bytes());
    hasher.update(state.validator_set_id.as_bytes());
    hasher.update(state.consensus_parameters_hash.as_bytes());
    update_len_prefixed_v1(&mut hasher, state.author.as_bytes());
    hasher.update(state.trusted_genesis_timestamp_ms.to_be_bytes());
    hasher.update(state.max_ancestry_blocks.to_be_bytes());
    hasher.update(state.current_view.get().to_be_bytes());
    update_optional_view_v1(&mut hasher, state.last_voted_view);
    update_optional_view_v1(&mut hasher, state.last_timeout_view);
    update_qc_reference_v1(&mut hasher, &state.high_qc);
    update_qc_reference_v1(&mut hasher, &state.locked_qc);
    update_finalized_v1(&mut hasher, state.finalized);
    hasher.update(state.revision.to_be_bytes());
    SafetyRulesStateDigestV1(hasher.finalize().into())
}

fn compute_vote_transition_digest_v1<'a, I>(
    predecessor: SafetyRulesStateDigestV1,
    successor: SafetyRulesStateDigestV1,
    intent: &CanonicalSignIntentV0,
    ancestry: I,
    target: &'a SignedProposalV0,
) -> SafetyRulesResultV1<SafetyCandidateDigestV1>
where
    I: ExactSizeIterator<Item = &'a SignedProposalV0>,
{
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_RULES_TRANSITION_DIGEST_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(SAFETY_RULES_SCHEMA_VERSION_V1.to_be_bytes());
    hasher.update([InertSafetyTransitionKindV1::Vote as u8]);
    hasher.update(predecessor.as_bytes());
    hasher.update(successor.as_bytes());
    let intent_bytes = intent
        .canonical_bytes()
        .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
    update_len_prefixed_v1(&mut hasher, &intent_bytes);
    let count = ancestry
        .len()
        .checked_add(1)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(SafetyRulesErrorV1::ArithmeticOverflow)?;
    hasher.update(count.to_be_bytes());
    for proposal in ancestry.chain(core::iter::once(target)) {
        update_proposal_identity_v1(&mut hasher, proposal);
    }
    Ok(SafetyCandidateDigestV1(hasher.finalize().into()))
}

fn compute_timeout_transition_digest_v1(
    predecessor: SafetyRulesStateDigestV1,
    successor: SafetyRulesStateDigestV1,
    intent: &CanonicalSignIntentV0,
    high_qc: &QcReferenceV0,
) -> SafetyRulesResultV1<SafetyCandidateDigestV1> {
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_RULES_TRANSITION_DIGEST_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(SAFETY_RULES_SCHEMA_VERSION_V1.to_be_bytes());
    hasher.update([InertSafetyTransitionKindV1::TimeoutVote as u8]);
    hasher.update(predecessor.as_bytes());
    hasher.update(successor.as_bytes());
    let intent_bytes = intent
        .canonical_bytes()
        .map_err(|_| SafetyRulesErrorV1::InvalidConsensusArtifact)?;
    update_len_prefixed_v1(&mut hasher, &intent_bytes);
    update_qc_reference_v1(&mut hasher, high_qc);
    Ok(SafetyCandidateDigestV1(hasher.finalize().into()))
}

fn update_optional_view_v1(hasher: &mut Sha256, view: Option<View>) {
    match view {
        Some(view) => {
            hasher.update([1]);
            hasher.update(view.get().to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

fn update_len_prefixed_v1(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("bounded consensus bytes fit u32");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn update_qc_reference_v1(hasher: &mut Sha256, reference: &QcReferenceV0) {
    let tag = match reference {
        QcReferenceV0::Ordinary(_) => 0,
        QcReferenceV0::Synthetic(synthetic) => match synthetic.as_ref() {
            ContextAuthorizedQcV0::Genesis(_) => 1,
            ContextAuthorizedQcV0::Epoch(_) => 2,
        },
    };
    hasher.update([tag]);
    hasher.update(reference.id().as_bytes());
    update_qc_ref_v1(hasher, reference.qc_ref());
}

fn update_qc_ref_v1(hasher: &mut Sha256, reference: QcRef) {
    hasher.update(reference.qc_digest().as_bytes());
    hasher.update(reference.epoch().get().to_be_bytes());
    hasher.update(reference.view().get().to_be_bytes());
    hasher.update(reference.height().get().to_be_bytes());
    hasher.update(reference.block_id().as_bytes());
    hasher.update(reference.validator_set_id().as_bytes());
}

fn update_finalized_v1(hasher: &mut Sha256, finalized: FinalizedBlockRefV1) {
    hasher.update(finalized.genesis_hash.as_bytes());
    update_len_prefixed_v1(hasher, finalized.chain_id.as_bytes());
    hasher.update(finalized.protocol_version.get().to_be_bytes());
    hasher.update(finalized.epoch.get().to_be_bytes());
    hasher.update(finalized.validator_set_id.as_bytes());
    hasher.update(finalized.consensus_parameters_hash.as_bytes());
    hasher.update(finalized.view.get().to_be_bytes());
    hasher.update(finalized.height.get().to_be_bytes());
    hasher.update(finalized.block_id.as_bytes());
    hasher.update(finalized.timestamp_ms.to_be_bytes());
}

fn update_proposal_identity_v1(hasher: &mut Sha256, proposal: &SignedProposalV0) {
    hasher.update(proposal.block().id().as_bytes());
    hasher.update(proposal.witness().justify_qc().id().as_bytes());
    match proposal.witness().timeout_certificate() {
        Some(certificate) => {
            hasher.update([1]);
            hasher.update(certificate.id().as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(proposal.proposal_signing_root().as_bytes());
    hasher.update(proposal.witness().proposer_signature().as_bytes());
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
