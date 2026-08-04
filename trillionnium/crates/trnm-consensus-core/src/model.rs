use alloc::{boxed::Box, vec::Vec};

use trnm_consensus_types::{
    Block, BlockId, CertificateId, ChainId, CommitProof, Epoch, EquivocationEvidence, Height,
    Proposal, ProtocolVersion, QcRef, QuorumCertificate, SignatureBytes, SigningRoot,
    TimeoutCertificate, TimeoutVote, ValidatorId, ValidatorSet, ValidatorSetId, View, Vote,
};

use crate::{CoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    local_validator: ValidatorId,
    validator_set: ValidatorSet,
    genesis_block_id: BlockId,
    max_blocks: usize,
    max_observed_messages: usize,
    max_block_bytes: usize,
    max_block_time_step_ms: u64,
}

impl CoreConfig {
    pub fn new(
        local_validator: ValidatorId,
        validator_set: ValidatorSet,
        genesis_block_id: BlockId,
        max_blocks: usize,
        max_observed_messages: usize,
        max_block_bytes: usize,
        max_block_time_step_ms: u64,
    ) -> Result<Self> {
        let value = Self {
            local_validator,
            validator_set,
            genesis_block_id,
            max_blocks,
            max_observed_messages,
            max_block_bytes,
            max_block_time_step_ms,
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
        self.genesis_block_id
    }

    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }

    pub const fn max_observed_messages(&self) -> usize {
        self.max_observed_messages
    }

    pub const fn max_block_bytes(&self) -> usize {
        self.max_block_bytes
    }

    pub const fn max_block_time_step_ms(&self) -> u64 {
        self.max_block_time_step_ms
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.validator_set.validate_shape()?;
        if self.validator_set.validator(self.local_validator).is_none() {
            return Err(CoreError::LocalValidatorMissing(Box::new(
                self.local_validator,
            )));
        }
        if self.genesis_block_id.is_zero() {
            return Err(CoreError::InvalidConfig(
                "trusted genesis block id must be nonzero",
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
        if self.max_block_bytes == 0 || self.max_block_bytes > u32::MAX as usize {
            return Err(CoreError::InvalidConfig(
                "max_block_bytes must fit the positive frozen u32 bound",
            ));
        }
        if self.max_block_time_step_ms == 0 {
            return Err(CoreError::InvalidConfig(
                "max_block_time_step_ms must be positive",
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
        view: View,
        height: Height,
        block_id: BlockId,
        signing_root: SigningRoot,
    },
    TimeoutVote {
        view: View,
        high_qc: QcRef,
        signing_root: SigningRoot,
    },
}

impl SignIntent {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyHalt {
    first: QuorumCertificate,
    second: QuorumCertificate,
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
        Ok(Self { first, second })
    }

    pub const fn first(&self) -> &QuorumCertificate {
        &self.first
    }

    pub const fn second(&self) -> &QuorumCertificate {
        &self.second
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyState {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    genesis_block_id: BlockId,
    current_view: View,
    last_voted_view: Option<View>,
    last_timeout_view: Option<View>,
    high_qc: QuorumCertificate,
    locked_qc: QuorumCertificate,
    finalized: FinalizedTip,
    revision: u64,
    pending_sign: Option<SignIntent>,
    last_finalization_proof: Option<CommitProof>,
    pending_finalize: Option<CommitProof>,
    safety_halt: Option<SafetyHalt>,
}

impl SafetyState {
    /// Reconstructs a decoded durable state for validation by [`crate::Core::recover`].
    ///
    /// This constructor intentionally performs no cryptographic work. Callers
    /// must authenticate the stored record and pass the result through
    /// `Core::recover`, which validates all invariants available in this state.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_parts(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_id: ValidatorSetId,
        genesis_block_id: BlockId,
        current_view: View,
        last_voted_view: Option<View>,
        last_timeout_view: Option<View>,
        high_qc: QuorumCertificate,
        locked_qc: QuorumCertificate,
        finalized: FinalizedTip,
        revision: u64,
        pending_sign: Option<SignIntent>,
        last_finalization_proof: Option<CommitProof>,
        pending_finalize: Option<CommitProof>,
        safety_halt: Option<SafetyHalt>,
    ) -> Self {
        Self {
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
            pending_sign,
            last_finalization_proof,
            pending_finalize,
            safety_halt,
        }
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

    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }

    pub const fn locked_qc(&self) -> &QuorumCertificate {
        &self.locked_qc
    }

    pub const fn finalized(&self) -> FinalizedTip {
        self.finalized
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn pending_sign(&self) -> Option<&SignIntent> {
        self.pending_sign.as_ref()
    }

    pub const fn last_finalization_proof(&self) -> Option<&CommitProof> {
        self.last_finalization_proof.as_ref()
    }

    pub const fn pending_finalize(&self) -> Option<&CommitProof> {
        self.pending_finalize.as_ref()
    }

    pub const fn safety_halt(&self) -> Option<&SafetyHalt> {
        self.safety_halt.as_ref()
    }

    pub(crate) fn from_genesis(
        validator_set: &ValidatorSet,
        genesis_qc: QuorumCertificate,
    ) -> Result<Self> {
        let current_view = genesis_qc.view().checked_next().map_err(CoreError::from)?;
        Ok(Self {
            chain_id: validator_set.chain_id(),
            protocol_version: validator_set.protocol_version(),
            epoch: validator_set.epoch(),
            validator_set_id: validator_set.id(),
            genesis_block_id: genesis_qc.block_id(),
            current_view,
            last_voted_view: None,
            last_timeout_view: None,
            finalized: FinalizedTip::new(
                genesis_qc.height(),
                genesis_qc.view(),
                genesis_qc.block_id(),
                0,
            ),
            locked_qc: genesis_qc.clone(),
            high_qc: genesis_qc,
            revision: 0,
            pending_sign: None,
            last_finalization_proof: None,
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

    pub(crate) fn set_high_qc(&mut self, certificate: QuorumCertificate) {
        self.high_qc = certificate;
    }

    pub(crate) fn set_locked_qc(&mut self, certificate: QuorumCertificate) {
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

    pub(crate) fn set_last_finalization_proof(&mut self, proof: CommitProof) {
        self.last_finalization_proof = Some(proof);
    }

    pub(crate) fn set_pending_finalize(&mut self, proof: Option<CommitProof>) {
        self.pending_finalize = proof;
    }

    pub(crate) fn set_safety_halt(&mut self, halt: Option<SafetyHalt>) {
        self.safety_halt = halt;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Resume,
    Proposal(Box<Proposal>),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(QuorumCertificate),
    TimeoutCertificate(TimeoutCertificate),
    LocalTimeout {
        epoch: Epoch,
        view: View,
    },
    PayloadValidated {
        id: ValidationId,
        valid: bool,
    },
    SyncedPayloadValidated {
        id: ValidationId,
        valid: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundMessage {
    Vote(Vote),
    TimeoutVote(TimeoutVote),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    PersistSafetyState {
        barrier: BarrierId,
        state: Box<SafetyState>,
    },
    ValidatePayload {
        id: ValidationId,
        block: Block,
    },
    ValidateSyncedPayload {
        id: ValidationId,
        block: Block,
    },
    RequestSignature {
        id: SignId,
        author: ValidatorId,
        kind: SignKind,
        signing_root: SigningRoot,
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
    SafetyHalted(Box<SafetyHalt>),
    Finalize(Box<CommitProof>),
    Evidence(EquivocationEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeferredEffect {
    RequestSignature,
    ArmViewTimer,
    ValidatePayload { id: ValidationId, block: Box<Block> },
    ValidateSyncedPayload { id: ValidationId, block: Box<Block> },
    SafetyHalted,
    Finalize(Box<CommitProof>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingPersistence {
    pub(crate) barrier: BarrierId,
    pub(crate) deferred: Vec<DeferredEffect>,
}
