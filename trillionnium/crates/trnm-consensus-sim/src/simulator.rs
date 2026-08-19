use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    leader_for, native_finalization_applied_checksum_v0, ApplicationFinalizationApplyReadbackV0,
    ApplicationFinalizationReceiptV0, ApplicationSealedValidV0, BarrierId, BlockIdOverlayRefV0,
    Core, CoreConfig, CoreError, CoreIssuedApplicationFinalizationApplyAuthorityV0,
    CoreIssuedApplicationFinalizationPermitV0, CoreIssuedApplicationSealAuthorityV0,
    CoreIssuedValidPermitV0, DurableFinalizationV0, DurablePayloadValidationCompletionV0,
    DurablePayloadValidationObligationV0, DurablePayloadValidationResultV1, Effect, FinalizedTip,
    Input, InvalidPayloadReference, OutboundMessage, PayloadValidationRequest,
    PayloadValidationResult, PayloadValidationRouteV0, SafetyHalt, SafetyState, SignId, SignIntent,
    ValidatedPayloadArtifactRefV0, ValidationId,
};
use trnm_consensus_types::{
    ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockId, BlockKind,
    BlockValidationError, CanonicalSignable, CertificateId, ChainId, ConsensusParametersV0,
    ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, FinalityProofV0,
    GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion, QcReferenceV0,
    QuorumCertificate, SignatureBytes, SignatureVerifier, SignedProposalV0, SigningRoot, StateRoot,
    TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote, ValidatedBlockCommitmentsV0,
    ValidationError, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
    SIGNATURE_BYTES,
};

use crate::{Trace, TraceDigest};

pub type NodeId = usize;

const CHAIN_ID: ChainId = ChainId::from_static("trnm-poco-bft-sim-0");
const MAX_EVENT_RETRIES: u8 = 64;
pub const GENESIS_BLOCK_ID: BlockId = BlockId::new([0xA5; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimConfig {
    validator_count: usize,
    seed: u64,
    maximum_network_delay: u64,
    timeout_ticks: u64,
    max_blocks: usize,
    epoch_length_blocks: u64,
    snapshot_lead_blocks: u64,
}

impl SimConfig {
    pub fn new(validator_count: usize, seed: u64) -> Result<Self, SimError> {
        if !(4..=100).contains(&validator_count) {
            return Err(SimError::InvalidConfig(
                "validator_count must be in the frozen 4..=100 range",
            ));
        }
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        Ok(Self {
            validator_count,
            seed,
            maximum_network_delay: 3,
            timeout_ticks: 24,
            max_blocks: 256,
            epoch_length_blocks: parameters.epoch_length_blocks(),
            snapshot_lead_blocks: parameters.snapshot_lead_blocks(),
        })
    }

    pub const fn validator_count(&self) -> usize {
        self.validator_count
    }

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub const fn maximum_network_delay(&self) -> u64 {
        self.maximum_network_delay
    }

    pub const fn timeout_ticks(&self) -> u64 {
        self.timeout_ticks
    }

    pub fn with_maximum_network_delay(mut self, ticks: u64) -> Result<Self, SimError> {
        if ticks == 0 {
            return Err(SimError::InvalidConfig(
                "maximum_network_delay must be positive",
            ));
        }
        self.maximum_network_delay = ticks;
        Ok(self)
    }

    pub fn with_timeout_ticks(mut self, ticks: u64) -> Result<Self, SimError> {
        if ticks < 2 {
            return Err(SimError::InvalidConfig(
                "timeout_ticks must be at least two",
            ));
        }
        self.timeout_ticks = ticks;
        Ok(self)
    }

    /// Replaces only the epoch geometry fields of the reference v0 parameter
    /// profile. Construction validates the complete resulting parameter
    /// preimage before any simulator node is created.
    pub fn with_epoch_layout(
        mut self,
        epoch_length_blocks: u64,
        snapshot_lead_blocks: u64,
    ) -> Result<Self, SimError> {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.epoch_length_blocks = epoch_length_blocks;
        fields.snapshot_lead_blocks = snapshot_lead_blocks;
        ConsensusParametersV0::new(fields)?;
        self.epoch_length_blocks = epoch_length_blocks;
        self.snapshot_lead_blocks = snapshot_lead_blocks;
        Ok(self)
    }
}

#[derive(Debug)]
pub enum SimError {
    InvalidConfig(&'static str),
    UnknownNode(NodeId),
    Protocol(ValidationError),
    BodyValidation(BlockValidationError),
    Core(CoreError),
    MissingProposal(BlockId),
    MissingQuorumCertificate(CertificateId),
    NoProposalJustification { node: NodeId, view: View },
    ArithmeticOverflow(&'static str),
    InvalidFinalityObservation(Box<InvalidFinalityObservation>),
    ConflictingFinality(Box<FinalityConflict>),
}

#[derive(Debug)]
pub struct InvalidFinalityObservation {
    pub node: NodeId,
    pub layer: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct FinalityConflict {
    pub left_node: NodeId,
    pub left_layer: String,
    pub right_node: NodeId,
    pub right_layer: String,
    pub height: Height,
    pub left_block: BlockId,
    pub right_block: BlockId,
}

impl fmt::Display for SimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid simulator config: {reason}"),
            Self::UnknownNode(node) => write!(formatter, "unknown simulator node {node}"),
            Self::Protocol(error) => write!(formatter, "consensus type error: {error}"),
            Self::BodyValidation(error) => {
                write!(formatter, "canonical body validation error: {error}")
            }
            Self::Core(error) => write!(formatter, "consensus core error: {error}"),
            Self::MissingProposal(block_id) => {
                write!(
                    formatter,
                    "missing replay proposal for {}",
                    hex_block(*block_id)
                )
            }
            Self::MissingQuorumCertificate(certificate_id) => write!(
                formatter,
                "missing referenced QC {}",
                hex_certificate(*certificate_id)
            ),
            Self::NoProposalJustification { node, view } => write!(
                formatter,
                "node {node} has no proposal justification for view {}",
                view.get()
            ),
            Self::ArithmeticOverflow(field) => {
                write!(formatter, "simulator arithmetic overflow in {field}")
            }
            Self::InvalidFinalityObservation(observation) => write!(
                formatter,
                "invalid finality observation at node {} layer {}: {}",
                observation.node, observation.layer, observation.reason
            ),
            Self::ConflictingFinality(conflict) => write!(
                formatter,
                "conflicting finality at height {}: node {} layer {} has {}, node {} layer {} has {}",
                conflict.height.get(),
                conflict.left_node,
                conflict.left_layer,
                hex_block(conflict.left_block),
                conflict.right_node,
                conflict.right_layer,
                hex_block(conflict.right_block)
            ),
        }
    }
}

impl std::error::Error for SimError {}

impl From<ValidationError> for SimError {
    fn from(value: ValidationError) -> Self {
        Self::Protocol(value)
    }
}

impl From<BlockValidationError> for SimError {
    fn from(value: BlockValidationError) -> Self {
        Self::BodyValidation(value)
    }
}

impl From<CoreError> for SimError {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageKind {
    Proposal,
    Vote,
    TimeoutVote,
    QuorumCertificate,
    TimeoutCertificate,
}

/// Deterministic host outcome selected by the fault simulator.
///
/// A `Valid` outcome is materialized through the real canonical body/receipt
/// kernel for the exact requested block, then crosses a development-only
/// simulated application seal boundary. `MismatchedValid` produces a
/// different-header candidate which that boundary rejects before sealing;
/// Core sees `Unavailable` and may issue a fresh request generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptedValidationOutcome {
    Valid,
    MismatchedValid,
    Unavailable,
    DeterministicallyInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeSnapshot {
    pub node: NodeId,
    pub validator: ValidatorId,
    pub online: bool,
    pub halted: bool,
    pub current_view: View,
    pub finalized_height: Height,
    pub finalized_block: BlockId,
    pub applied_height: Height,
    pub applied_block: BlockId,
    pub durable_finalized_height: Height,
    pub durably_applied_height: Height,
    pub durable_pending_finalize: bool,
    pub durable_pending_standalone_qc_sync: bool,
    pub durable_halted: bool,
    pub durable_revision: u64,
}

#[derive(Debug, Clone)]
enum WireMessage {
    Proposal(Box<SignedProposalV0>),
    Vote(Box<Vote>),
    TimeoutVote(Box<TimeoutVote>),
    QuorumCertificate(Box<QuorumCertificate>),
    TimeoutCertificate(Box<TimeoutCertificateV0>),
}

impl WireMessage {
    const fn kind(&self) -> MessageKind {
        match self {
            Self::Proposal(_) => MessageKind::Proposal,
            Self::Vote(_) => MessageKind::Vote,
            Self::TimeoutVote(_) => MessageKind::TimeoutVote,
            Self::QuorumCertificate(_) => MessageKind::QuorumCertificate,
            Self::TimeoutCertificate(_) => MessageKind::TimeoutCertificate,
        }
    }

    fn fingerprint(&self) -> String {
        match self {
            Self::Proposal(proposal) => format!(
                "proposal:view={}:height={}:block={}:justify={}:tc={}:proposer={}:root={}:signature={}",
                proposal.block().header().view().get(),
                proposal.block().header().height().get(),
                hex_block(proposal.block().id()),
                hex_certificate(proposal.witness().justify_qc().id()),
                proposal
                    .witness()
                    .timeout_certificate()
                    .map(TimeoutCertificateV0::id)
                    .map(hex_certificate)
                .unwrap_or_else(|| "none".to_owned()),
                hex_validator(proposal.proposer()),
                hex_bytes(proposal.proposal_signing_root().as_bytes()),
                hex_bytes(proposal.witness().proposer_signature().as_bytes())
            ),
            Self::Vote(vote) => format!(
                "vote:view={}:height={}:block={}:author={}:root={}:signature={}",
                vote.view().get(),
                vote.height().get(),
                hex_block(vote.block_id()),
                hex_validator(vote.author()),
                hex_bytes(vote.signing_root().as_bytes()),
                hex_bytes(vote.signature().as_bytes())
            ),
            Self::TimeoutVote(vote) => format!(
                "timeout-vote:view={}:high-qc={}:author={}:root={}:signature={}",
                vote.view().get(),
                hex_certificate(vote.high_qc().qc_digest()),
                hex_validator(vote.author()),
                hex_bytes(vote.signing_root().as_bytes()),
                hex_bytes(vote.signature().as_bytes())
            ),
            Self::QuorumCertificate(certificate) => format!(
                "qc:view={}:height={}:block={}:id={}:votes={}",
                certificate.view().get(),
                certificate.height().get(),
                hex_block(certificate.block_id()),
                hex_certificate(certificate.id()),
                certificate.votes().len()
            ),
            Self::TimeoutCertificate(certificate) => format!(
                "tc:view={}:id={}:high-qc={}:referenced-qcs={}:votes={}",
                certificate.timed_out_view().get(),
                hex_certificate(certificate.id()),
                hex_certificate(certificate.selected_high_qc_digest()),
                certificate.referenced_qcs().len(),
                certificate.entries().len()
            ),
        }
    }
}

#[derive(Debug, Clone)]
enum Event {
    Deliver {
        from: NodeId,
        to: NodeId,
        message: WireMessage,
        attempt: u8,
    },
    PersistAck {
        node: NodeId,
        incarnation: u64,
        barrier: BarrierId,
        state: Box<SafetyState>,
    },
    Validate {
        node: NodeId,
        incarnation: u64,
        id: ValidationId,
        synced: bool,
        replay_generation: Option<u64>,
    },
    RetryPayloadValidation {
        node: NodeId,
        incarnation: u64,
        block_id: BlockId,
        attempt: u8,
    },
    Signature {
        node: NodeId,
        incarnation: u64,
        id: SignId,
        root: SigningRoot,
    },
    FinalizationApplied {
        node: NodeId,
        incarnation: u64,
        proof: Box<DurableFinalizationV0>,
        attempt: u8,
    },
    LocalTimeout {
        node: NodeId,
        incarnation: u64,
        view: View,
    },
    TryPropose {
        node: NodeId,
        incarnation: u64,
    },
    Resume {
        node: NodeId,
        incarnation: u64,
    },
    ReplayNext {
        node: NodeId,
        incarnation: u64,
        replay_generation: u64,
        attempt: u8,
    },
}

#[derive(Debug, Clone, Copy)]
enum FaultAction {
    Drop,
    Duplicate(usize),
    Delay(u64),
}

#[derive(Debug, Clone, Copy)]
struct FaultRule {
    kind: MessageKind,
    from: Option<NodeId>,
    to: Option<NodeId>,
    remaining: usize,
    action: FaultAction,
}

impl FaultRule {
    fn matches(&self, kind: MessageKind, from: NodeId, to: NodeId) -> bool {
        self.remaining > 0
            && self.kind == kind
            && self.from.is_none_or(|expected| expected == from)
            && self.to.is_none_or(|expected| expected == to)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VoteCoordinate {
    view: View,
    height: Height,
    block_id: BlockId,
}

#[derive(Debug)]
struct FinalityObservation {
    node: NodeId,
    layer: String,
    chain: BTreeMap<Height, BlockId>,
}

#[derive(Debug, Clone)]
struct ValidationArtifacts {
    body: BlockBodyV0,
    receipts: ExecutionReceiptsV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SimValidationKeyV0 {
    route: PayloadValidationRouteV0,
    id: ValidationId,
}

impl SimValidationKeyV0 {
    const fn new(route: PayloadValidationRouteV0, id: ValidationId) -> Self {
        Self { route, id }
    }
}

#[derive(Debug)]
enum SimValidationCapabilityV0 {
    Permit(CoreIssuedValidPermitV0),
    ApplicationSealed(ApplicationSealedValidV0),
}

/// Development-only stand-in for the private ApplicationStore callback
/// owner. Neither the Core permit nor the application-sealed proof enters a
/// cloneable simulator event or trace.
#[derive(Debug)]
struct SimValidationCallbackV0 {
    parent_block_id: BlockId,
    outcome: Option<ScriptedValidationOutcome>,
    capability: SimValidationCapabilityV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayRequest {
    Safety {
        high: BlockId,
        locked: BlockId,
    },
    Tc {
        certificate_id: CertificateId,
        target: BlockId,
    },
    Standalone {
        certificate_id: CertificateId,
    },
}

#[derive(Debug)]
struct SimNode {
    validator: ValidatorId,
    config: CoreConfig,
    core: Option<Core>,
    application_seal_authority: Option<CoreIssuedApplicationSealAuthorityV0>,
    validation_callbacks: BTreeMap<SimValidationKeyV0, SimValidationCallbackV0>,
    application_finalization_apply_authority:
        Option<CoreIssuedApplicationFinalizationApplyAuthorityV0>,
    pending_application_finalization_readback: Option<ApplicationFinalizationApplyReadbackV0>,
    pending_application_finalization_receipt: Option<ApplicationFinalizationReceiptV0>,
    durable: SafetyState,
    incarnation: u64,
    replaying: bool,
    recovering: bool,
    replay_request: Option<ReplayRequest>,
    replay_generation: u64,
    replay_queue: VecDeque<SignedProposalV0>,
    replay_blocks: BTreeSet<BlockId>,
    scripted_validation_results: VecDeque<ScriptedValidationOutcome>,
    vote_pool: BTreeMap<VoteCoordinate, BTreeMap<ValidatorId, Vote>>,
    timeout_pool: BTreeMap<View, BTreeMap<ValidatorId, TimeoutVote>>,
    timeout_certificates: BTreeMap<View, TimeoutCertificateV0>,
    applied: BTreeMap<Height, BlockId>,
    durably_applied_height: Height,
    halted: bool,
}

impl SimNode {
    fn safety(&self) -> &SafetyState {
        self.core
            .as_ref()
            .map(Core::safety_state)
            .unwrap_or(&self.durable)
    }

    fn advance_replay_generation(&mut self) -> Result<u64, SimError> {
        self.replay_generation = self
            .replay_generation
            .checked_add(1)
            .ok_or(SimError::ArithmeticOverflow("replay generation"))?;
        Ok(self.replay_generation)
    }
}

#[derive(Debug)]
pub struct Simulator {
    config: SimConfig,
    consensus_parameters: ConsensusParametersV0,
    validator_set: ValidatorSet,
    genesis_qc: GenesisQcV0,
    nodes: Vec<SimNode>,
    queue: BTreeMap<(u64, u64), Event>,
    tick: u64,
    next_sequence: u64,
    rng_state: u64,
    block_nonce: u64,
    started: bool,
    trace: Trace,
    components: Option<Vec<usize>>,
    fault_rules: Vec<FaultRule>,
    proposals: BTreeMap<BlockId, SignedProposalV0>,
    validation_artifacts: BTreeMap<BlockId, ValidationArtifacts>,
    quorum_certificates: BTreeMap<CertificateId, QuorumCertificate>,
    timeout_certificates: BTreeMap<CertificateId, TimeoutCertificateV0>,
    formed_qcs: BTreeSet<VoteCoordinate>,
    formed_tcs: BTreeSet<View>,
    proposed_views: BTreeSet<(NodeId, View)>,
    gossip: Vec<(NodeId, WireMessage)>,
    gossip_keys: BTreeSet<(NodeId, String)>,
    evidence_count: usize,
}

impl Simulator {
    pub fn new(config: SimConfig) -> Result<Self, SimError> {
        let mut parameter_fields = ConsensusParametersV0::reference_shadow_v0().fields();
        parameter_fields.epoch_length_blocks = config.epoch_length_blocks;
        parameter_fields.snapshot_lead_blocks = config.snapshot_lead_blocks;
        let consensus_parameters = ConsensusParametersV0::new(parameter_fields)?;
        let validator_set = fixture_validator_set(config.validator_count, &consensus_parameters)?;
        let genesis_qc = fixture_genesis_qc(&validator_set)?;
        let mut nodes = Vec::with_capacity(config.validator_count);
        for validator in validator_set.validators() {
            let core_config = CoreConfig::new(
                validator.id(),
                validator_set.clone(),
                consensus_parameters,
                0,
                config.max_blocks,
                config.validator_count.saturating_mul(16),
            )?;
            let core = Core::new(core_config.clone(), genesis_qc.clone(), &MockSignatures)?;
            let application_seal_authority = core.issue_application_seal_authority_v0()?;
            let application_finalization_apply_authority =
                core.issue_application_finalization_apply_authority_v0()?;
            let durable = core.safety_state().clone();
            let mut applied = BTreeMap::new();
            applied.insert(Height::new(0), GENESIS_BLOCK_ID);
            nodes.push(SimNode {
                validator: validator.id(),
                config: core_config,
                core: Some(core),
                application_seal_authority: Some(application_seal_authority),
                validation_callbacks: BTreeMap::new(),
                application_finalization_apply_authority: Some(
                    application_finalization_apply_authority,
                ),
                pending_application_finalization_readback: None,
                pending_application_finalization_receipt: None,
                durable,
                incarnation: 0,
                replaying: false,
                recovering: false,
                replay_request: None,
                replay_generation: 0,
                replay_queue: VecDeque::new(),
                replay_blocks: BTreeSet::new(),
                scripted_validation_results: VecDeque::new(),
                vote_pool: BTreeMap::new(),
                timeout_pool: BTreeMap::new(),
                timeout_certificates: BTreeMap::new(),
                applied,
                durably_applied_height: Height::new(0),
                halted: false,
            });
        }
        let seed = config.seed;
        let mut value = Self {
            config,
            consensus_parameters,
            validator_set,
            genesis_qc,
            nodes,
            queue: BTreeMap::new(),
            tick: 0,
            next_sequence: 0,
            rng_state: seed ^ 0x9E37_79B9_7F4A_7C15,
            block_nonce: 0,
            started: false,
            trace: Trace::default(),
            components: None,
            fault_rules: Vec::new(),
            proposals: BTreeMap::new(),
            validation_artifacts: BTreeMap::new(),
            quorum_certificates: BTreeMap::new(),
            timeout_certificates: BTreeMap::new(),
            formed_qcs: BTreeSet::new(),
            formed_tcs: BTreeSet::new(),
            proposed_views: BTreeSet::new(),
            gossip: Vec::new(),
            gossip_keys: BTreeSet::new(),
            evidence_count: 0,
        };
        value.record(
            "sim-init",
            format!("nodes={} seed={seed}", value.nodes.len()),
        );
        Ok(value)
    }

    pub const fn seed(&self) -> u64 {
        self.config.seed
    }

    pub const fn tick(&self) -> u64 {
        self.tick
    }

    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub const fn genesis_qc(&self) -> &GenesisQcV0 {
        &self.genesis_qc
    }

    pub const fn trace(&self) -> &Trace {
        &self.trace
    }

    pub fn trace_digest(&self) -> TraceDigest {
        self.trace.digest()
    }

    pub const fn evidence_count(&self) -> usize {
        self.evidence_count
    }

    pub fn halted_count(&self) -> usize {
        self.nodes.iter().filter(|node| node.halted).count()
    }

    /// Queues deterministic host callback results for one node.
    ///
    /// Every scripted `Valid` is materialized from the proposal's canonical
    /// payload, deterministic receipt commitments, and ordinary B2-D body
    /// kernel. Runtime execution and authenticated parent-state acquisition
    /// remain outside this simulator. Once the queue is empty, validation
    /// defaults to [`ScriptedValidationOutcome::Valid`].
    pub fn queue_payload_validation_results<I>(
        &mut self,
        node: NodeId,
        results: I,
    ) -> Result<(), SimError>
    where
        I: IntoIterator<Item = ScriptedValidationOutcome>,
    {
        let scripted: Vec<_> = results.into_iter().collect();
        let state = self
            .nodes
            .get_mut(node)
            .ok_or(SimError::UnknownNode(node))?;
        state
            .scripted_validation_results
            .extend(scripted.iter().copied());
        self.record(
            "validation-script",
            format!(
                "node={node} queued={}",
                scripted
                    .iter()
                    .map(|result| scripted_validation_label(*result))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
        Ok(())
    }

    /// Checks every finality representation the simulator can currently
    /// observe, including in-core state, durable state, queued persistence
    /// effects, queued/durable finalization outboxes, and application state.
    ///
    /// The check is intentionally stronger than comparing applied tips: every
    /// pair of observed chains must be prefix-comparable. A malformed or
    /// incomplete observation is also rejected because silently dropping that
    /// layer could hide a safety failure.
    pub fn check_finality_safety(&self) -> Result<(), SimError> {
        let observations = self.finality_observations()?;
        for (left_index, left) in observations.iter().enumerate() {
            for right in observations.iter().skip(left_index + 1) {
                if let Some((height, left_block, right_block)) =
                    first_chain_conflict(&left.chain, &right.chain)
                {
                    return Err(SimError::ConflictingFinality(Box::new(FinalityConflict {
                        left_node: left.node,
                        left_layer: left.layer.clone(),
                        right_node: right.node,
                        right_layer: right.layer.clone(),
                        height,
                        left_block,
                        right_block,
                    })));
                }
            }
        }
        Ok(())
    }

    pub fn has_conflicting_finality(&self) -> bool {
        self.check_finality_safety().is_err()
    }

    fn finality_observations(&self) -> Result<Vec<FinalityObservation>, SimError> {
        let mut observations = Vec::new();
        for (node_id, node) in self.nodes.iter().enumerate() {
            if let Some(core) = &node.core {
                self.push_safety_observations(
                    &mut observations,
                    node_id,
                    "volatile-core".to_owned(),
                    core.safety_state(),
                )?;
            }
            self.push_safety_observations(
                &mut observations,
                node_id,
                "durable-storage".to_owned(),
                &node.durable,
            )?;

            let applied = self.validate_application_chain(
                node_id,
                "application-acknowledged",
                &node.applied,
            )?;
            observations.push(FinalityObservation {
                node: node_id,
                layer: "application-acknowledged".to_owned(),
                chain: applied.clone(),
            });

            if !applied.contains_key(&node.durably_applied_height) {
                return Err(SimError::InvalidFinalityObservation(Box::new(
                    InvalidFinalityObservation {
                        node: node_id,
                        layer: "durable-application-ack".to_owned(),
                        reason: format!(
                            "durable applied height {} is absent from the acknowledged chain",
                            node.durably_applied_height.get()
                        ),
                    },
                )));
            }
            let durably_applied = applied
                .into_iter()
                .take_while(|(height, _)| *height <= node.durably_applied_height)
                .collect();
            observations.push(FinalityObservation {
                node: node_id,
                layer: "durable-application-ack".to_owned(),
                chain: durably_applied,
            });
        }

        for event in self.queue.values() {
            match event {
                Event::PersistAck {
                    node,
                    incarnation,
                    barrier,
                    state,
                } if self.incarnation_is_current(*node, *incarnation) => {
                    self.push_safety_observations(
                        &mut observations,
                        *node,
                        format!("pending-persist:{}", barrier.get()),
                        state,
                    )?;
                }
                Event::FinalizationApplied {
                    node,
                    incarnation,
                    proof,
                    ..
                } if self.incarnation_is_current(*node, *incarnation) => {
                    self.push_proof_observation(
                        &mut observations,
                        *node,
                        format!("pending-finalize:{}", hex_certificate(proof.id())),
                        proof,
                    )?;
                }
                _ => {}
            }
        }

        Ok(observations)
    }

    fn push_safety_observations(
        &self,
        observations: &mut Vec<FinalityObservation>,
        node: NodeId,
        layer: String,
        state: &SafetyState,
    ) -> Result<(), SimError> {
        observations.push(FinalityObservation {
            node,
            layer: layer.clone(),
            chain: self.chain_for_finalized_tip(node, &layer, state.finalized())?,
        });

        let Some(proof_id) = state.pending_finalize() else {
            return Ok(());
        };
        let finalization = state.pending_finalization().ok_or_else(|| {
            SimError::InvalidFinalityObservation(Box::new(InvalidFinalityObservation {
                node,
                layer: format!("{layer}/finalize-proof"),
                reason: "pending finalization has no durable queue front".to_owned(),
            }))
        })?;
        let proof = finalization.proof();
        if proof.id() != proof_id {
            return Err(SimError::InvalidFinalityObservation(Box::new(
                InvalidFinalityObservation {
                    node,
                    layer: format!("{layer}/finalize-proof"),
                    reason: format!(
                        "pending proof id {} does not match durable queue-front proof {}",
                        hex_certificate(proof_id),
                        hex_certificate(proof.id())
                    ),
                },
            )));
        }
        self.push_proof_observation(observations, node, format!("{layer}/finalize-proof"), proof)
    }

    fn push_proof_observation(
        &self,
        observations: &mut Vec<FinalityObservation>,
        node: NodeId,
        layer: String,
        proof: &FinalityProofV0,
    ) -> Result<(), SimError> {
        let header = proof.finalized_block().header();
        let tip = FinalizedTip::new(
            header.height(),
            header.view(),
            header.id(),
            header.timestamp_ms(),
        );
        observations.push(FinalityObservation {
            node,
            chain: self.chain_for_finalized_tip(node, &layer, tip)?,
            layer,
        });
        Ok(())
    }

    fn chain_for_finalized_tip(
        &self,
        node: NodeId,
        layer: &str,
        tip: FinalizedTip,
    ) -> Result<BTreeMap<Height, BlockId>, SimError> {
        let invalid = |reason: String| {
            SimError::InvalidFinalityObservation(Box::new(InvalidFinalityObservation {
                node,
                layer: layer.to_owned(),
                reason,
            }))
        };
        let mut chain = BTreeMap::new();
        chain.insert(Height::new(0), GENESIS_BLOCK_ID);
        if tip.height() == Height::new(0) {
            if tip.block_id() != GENESIS_BLOCK_ID
                || tip.view() != View::new(0)
                || tip.timestamp_ms() != 0
            {
                return Err(invalid(
                    "height-zero finalized tip is not the exact trusted genesis".to_owned(),
                ));
            }
            return Ok(chain);
        }

        let mut cursor = tip.block_id();
        let mut expected_height = tip.height().get();
        while expected_height > 0 {
            let proposal = self.proposals.get(&cursor).ok_or_else(|| {
                invalid(format!(
                    "missing proposal ancestry for height {} block {}",
                    expected_height,
                    hex_block(cursor)
                ))
            })?;
            let header = proposal.block().header();
            if header.height() != Height::new(expected_height) || header.id() != cursor {
                return Err(invalid(format!(
                    "proposal ancestry coordinates do not match height {} block {}",
                    expected_height,
                    hex_block(cursor)
                )));
            }
            if cursor == tip.block_id()
                && (header.view() != tip.view() || header.timestamp_ms() != tip.timestamp_ms())
            {
                return Err(invalid(
                    "finalized tip metadata does not match its authenticated header".to_owned(),
                ));
            }
            chain.insert(Height::new(expected_height), cursor);
            cursor = header.parent_id();
            expected_height -= 1;
        }
        if cursor != GENESIS_BLOCK_ID {
            return Err(invalid(format!(
                "finalized ancestry terminates at {} instead of trusted genesis",
                hex_block(cursor)
            )));
        }
        Ok(chain)
    }

    fn validate_application_chain(
        &self,
        node: NodeId,
        layer: &str,
        chain: &BTreeMap<Height, BlockId>,
    ) -> Result<BTreeMap<Height, BlockId>, SimError> {
        if !applied_chain_is_complete(chain) {
            return Err(SimError::InvalidFinalityObservation(Box::new(
                InvalidFinalityObservation {
                    node,
                    layer: layer.to_owned(),
                    reason: "application chain is empty or has a height gap".to_owned(),
                },
            )));
        }
        if chain.get(&Height::new(0)) != Some(&GENESIS_BLOCK_ID) {
            return Err(SimError::InvalidFinalityObservation(Box::new(
                InvalidFinalityObservation {
                    node,
                    layer: layer.to_owned(),
                    reason: "application chain does not start at trusted genesis".to_owned(),
                },
            )));
        }
        Ok(chain.clone())
    }

    pub fn latest_qc(&self) -> &QuorumCertificate {
        self.quorum_certificates
            .values()
            .max_by_key(|certificate| {
                (certificate.view(), certificate.block_id(), certificate.id())
            })
            .expect("at least one ordinary QC has formed")
    }

    /// Returns the highest ordered ordinary QC known for `block_id`.
    ///
    /// This is a scenario-inspection surface, not a node lookup path. The
    /// simulator's global certificate archive deliberately models privileged
    /// test-fixture knowledge.
    pub fn quorum_certificate_for_block(&self, block_id: BlockId) -> Option<&QuorumCertificate> {
        self.quorum_certificates
            .values()
            .filter(|certificate| certificate.block_id() == block_id)
            .max_by_key(|certificate| (certificate.view(), certificate.id()))
    }

    pub fn node_snapshot(&self, node: NodeId) -> Result<NodeSnapshot, SimError> {
        let state = self.nodes.get(node).ok_or(SimError::UnknownNode(node))?;
        let safety = state.safety();
        let applied_height = state
            .applied
            .keys()
            .next_back()
            .copied()
            .unwrap_or_else(|| Height::new(0));
        let applied_block = state
            .applied
            .get(&applied_height)
            .copied()
            .unwrap_or(GENESIS_BLOCK_ID);
        Ok(NodeSnapshot {
            node,
            validator: state.validator,
            online: state.core.is_some(),
            halted: state.halted,
            current_view: safety.current_view(),
            finalized_height: safety.finalized().height(),
            finalized_block: safety.finalized().block_id(),
            applied_height,
            applied_block,
            durable_finalized_height: state.durable.finalized().height(),
            durably_applied_height: state.durably_applied_height,
            durable_pending_finalize: state.durable.pending_finalize().is_some(),
            durable_pending_standalone_qc_sync: state
                .durable
                .pending_standalone_qc_sync()
                .is_some(),
            durable_halted: state.durable.safety_halt().is_some(),
            durable_revision: state.durable.revision(),
        })
    }

    pub fn maximum_applied_height(&self, online_only: bool) -> Height {
        self.nodes
            .iter()
            .filter(|node| !online_only || node.core.is_some())
            .filter_map(|node| node.applied.keys().next_back().copied())
            .max()
            .unwrap_or_else(|| Height::new(0))
    }

    pub fn all_applied_and_durable(&self, height: Height, online_only: bool) -> bool {
        let mut selected = 0usize;
        for node in &self.nodes {
            if online_only && node.core.is_none() {
                continue;
            }
            selected += 1;
            let applied_height = node
                .applied
                .keys()
                .next_back()
                .copied()
                .unwrap_or_else(|| Height::new(0));
            if applied_height < height || node.durably_applied_height < height {
                return false;
            }
        }
        selected > 0
    }

    pub fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.record("sim-start", String::new());
        for node in 0..self.nodes.len() {
            self.arm_node(node, self.nodes[node].safety().current_view());
        }
    }

    pub fn run_events(&mut self, maximum: usize) -> Result<usize, SimError> {
        self.check_finality_safety()?;
        let mut processed = 0usize;
        while processed < maximum {
            let Some((key, event)) = self.queue.pop_first() else {
                break;
            };
            self.tick = key.0;
            self.handle_event(event)?;
            processed += 1;
        }
        Ok(processed)
    }

    pub fn run_until<F>(&mut self, maximum: usize, predicate: F) -> Result<bool, SimError>
    where
        F: Fn(&Self) -> bool,
    {
        self.check_finality_safety()?;
        if predicate(self) {
            return Ok(true);
        }
        for _ in 0..maximum {
            let Some((key, event)) = self.queue.pop_first() else {
                return Ok(predicate(self));
            };
            self.tick = key.0;
            self.handle_event(event)?;
            if predicate(self) {
                return Ok(true);
            }
        }
        Ok(predicate(self))
    }

    pub fn drop_next(
        &mut self,
        kind: MessageKind,
        from: Option<NodeId>,
        to: Option<NodeId>,
        count: usize,
    ) {
        self.fault_rules.push(FaultRule {
            kind,
            from,
            to,
            remaining: count,
            action: FaultAction::Drop,
        });
    }

    pub fn duplicate_next(
        &mut self,
        kind: MessageKind,
        from: Option<NodeId>,
        to: Option<NodeId>,
        count: usize,
        extra_copies: usize,
    ) {
        self.fault_rules.push(FaultRule {
            kind,
            from,
            to,
            remaining: count,
            action: FaultAction::Duplicate(extra_copies),
        });
    }

    pub fn delay_next(
        &mut self,
        kind: MessageKind,
        from: Option<NodeId>,
        to: Option<NodeId>,
        count: usize,
        extra_ticks: u64,
    ) {
        self.fault_rules.push(FaultRule {
            kind,
            from,
            to,
            remaining: count,
            action: FaultAction::Delay(extra_ticks),
        });
    }

    pub fn reorder_next_two_messages(&mut self) -> bool {
        let keys: Vec<_> = self
            .queue
            .iter()
            .filter_map(|(key, event)| matches!(event, Event::Deliver { .. }).then_some(*key))
            .take(2)
            .collect();
        if keys.len() != 2 {
            return false;
        }
        let first = self.queue.remove(&keys[0]).expect("selected event exists");
        let second = self.queue.remove(&keys[1]).expect("selected event exists");
        let first_message = match &first {
            Event::Deliver { message, .. } => message.fingerprint(),
            _ => unreachable!("selected event is a network delivery"),
        };
        let second_message = match &second {
            Event::Deliver { message, .. } => message.fingerprint(),
            _ => unreachable!("selected event is a network delivery"),
        };
        self.queue.insert(keys[0], second);
        self.queue.insert(keys[1], first);
        self.record(
            "fault-reorder",
            format!(
                "first-key={:?} first-message={first_message} second-key={:?} second-message={second_message}",
                keys[0], keys[1]
            ),
        );
        true
    }

    pub fn pending_fault_matches(&self) -> usize {
        self.fault_rules.iter().fold(0usize, |pending, rule| {
            pending.saturating_add(rule.remaining)
        })
    }

    pub fn partition(&mut self, groups: &[Vec<NodeId>]) -> Result<(), SimError> {
        let mut components = vec![usize::MAX; self.nodes.len()];
        for (component, group) in groups.iter().enumerate() {
            for &node in group {
                if node >= self.nodes.len() {
                    return Err(SimError::UnknownNode(node));
                }
                if components[node] != usize::MAX {
                    return Err(SimError::InvalidConfig("partition groups must be disjoint"));
                }
                components[node] = component;
            }
        }
        let mut next = groups.len();
        for component in &mut components {
            if *component == usize::MAX {
                *component = next;
                next += 1;
            }
        }
        self.components = Some(components);
        self.record("partition", format!("groups={groups:?}"));
        Ok(())
    }

    pub fn heal(&mut self) {
        self.components = None;
        self.record("heal", String::new());
        let gossip = self.gossip.clone();
        for (from, message) in gossip {
            self.broadcast_inner(from, message, None, false);
        }
    }

    pub fn crash(&mut self, node: NodeId) -> Result<(), SimError> {
        self.check_finality_safety()?;
        let revision = {
            let state = self
                .nodes
                .get_mut(node)
                .ok_or(SimError::UnknownNode(node))?;
            state.core = None;
            state.application_seal_authority = None;
            state.validation_callbacks.clear();
            state.application_finalization_apply_authority = None;
            state.pending_application_finalization_readback = None;
            state.pending_application_finalization_receipt = None;
            state.incarnation = state
                .incarnation
                .checked_add(1)
                .ok_or(SimError::ArithmeticOverflow("node incarnation"))?;
            state.replaying = false;
            state.recovering = false;
            state.replay_request = None;
            state.advance_replay_generation()?;
            state.replay_queue.clear();
            state.replay_blocks.clear();
            state.vote_pool.clear();
            state.timeout_pool.clear();
            state.timeout_certificates.clear();
            state.durable.revision()
        };
        self.record("crash", format!("node={node} durable={revision}"));
        self.check_finality_safety()
    }

    pub fn recover(&mut self, node: NodeId) -> Result<(), SimError> {
        self.check_finality_safety()?;
        let (incarnation, revision) = {
            let state = self
                .nodes
                .get_mut(node)
                .ok_or(SimError::UnknownNode(node))?;
            let core = Core::recover(state.config.clone(), state.durable.clone(), &MockSignatures)?;
            let application_seal_authority = core.issue_application_seal_authority_v0()?;
            let application_finalization_apply_authority =
                core.issue_application_finalization_apply_authority_v0()?;
            state.core = Some(core);
            state.application_seal_authority = Some(application_seal_authority);
            state.validation_callbacks.clear();
            state.application_finalization_apply_authority =
                Some(application_finalization_apply_authority);
            state.pending_application_finalization_readback = None;
            state.pending_application_finalization_receipt = None;
            state.incarnation = state
                .incarnation
                .checked_add(1)
                .ok_or(SimError::ArithmeticOverflow("node incarnation"))?;
            state.replaying = false;
            state.recovering = true;
            state.replay_request = None;
            state.advance_replay_generation()?;
            state.replay_queue.clear();
            state.replay_blocks.clear();
            state.vote_pool.clear();
            state.timeout_pool.clear();
            state.timeout_certificates.clear();
            (state.incarnation, state.durable.revision())
        };
        self.record("recover", format!("node={node} durable={revision}"));
        self.schedule_after(1, Event::Resume { node, incarnation });
        self.check_finality_safety()
    }

    pub fn inject_equivocating_votes(
        &mut self,
        author: NodeId,
        view: View,
        height: Height,
        first_block: BlockId,
        second_block: BlockId,
        targets: &[NodeId],
    ) -> Result<(), SimError> {
        self.require_node(author)?;
        if first_block == second_block {
            return Err(SimError::InvalidConfig(
                "equivocating votes require distinct block IDs",
            ));
        }
        let validator = self.nodes[author].validator;
        let first =
            privileged_forged_vote(&self.validator_set, view, height, first_block, validator)?;
        let second =
            privileged_forged_vote(&self.validator_set, view, height, second_block, validator)?;
        self.record(
            "inject-equivocation",
            format!(
                "privileged-forge=true author={author} view={} first={} second={}",
                view.get(),
                hex_block(first_block),
                hex_block(second_block)
            ),
        );
        self.broadcast_inner(
            author,
            WireMessage::Vote(Box::new(first)),
            Some(targets.to_vec()),
            true,
        );
        self.broadcast_inner(
            author,
            WireMessage::Vote(Box::new(second)),
            Some(targets.to_vec()),
            true,
        );
        Ok(())
    }

    pub fn inject_conflicting_qc(
        &mut self,
        base: &QuorumCertificate,
        conflicting_block: BlockId,
        targets: &[NodeId],
    ) -> Result<QuorumCertificate, SimError> {
        if base.block_id() == conflicting_block {
            return Err(SimError::InvalidConfig(
                "conflicting QC requires a distinct block ID",
            ));
        }
        let mut votes = Vec::new();
        let mut power = 0u128;
        for validator in self.validator_set.validators() {
            votes.push(privileged_forged_vote(
                &self.validator_set,
                base.view(),
                base.height(),
                conflicting_block,
                validator.id(),
            )?);
            power = power
                .checked_add(validator.voting_power().get() as u128)
                .ok_or(SimError::ArithmeticOverflow("injected QC power"))?;
            if power >= self.validator_set.quorum_power() {
                break;
            }
        }
        let certificate = QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            base.view(),
            base.height(),
            conflicting_block,
            self.validator_set.id(),
            votes,
            &self.validator_set,
        )?;
        self.quorum_certificates
            .insert(certificate.id(), certificate.clone());
        self.record(
            "inject-conflicting-qc",
            format!(
                "privileged-forge=true view={} base={} conflict={}",
                base.view().get(),
                hex_block(base.block_id()),
                hex_block(conflicting_block)
            ),
        );
        self.broadcast_inner(
            0,
            WireMessage::QuorumCertificate(Box::new(certificate.clone())),
            Some(targets.to_vec()),
            true,
        );
        Ok(certificate)
    }

    /// Injects and immediately delivers an out-of-model, fully signed QC for
    /// a different block and different view at `base`'s height.
    ///
    /// This narrowly supports the finalized-height historical-competition
    /// regression. It is intentionally separate from [`Self::inject_conflicting_qc`],
    /// whose same-view certificate must remain a durable safety halt.
    pub fn inject_historical_competing_qc(
        &mut self,
        base: &QuorumCertificate,
        competing_view: View,
        competing_block: BlockId,
        targets: &[NodeId],
    ) -> Result<QuorumCertificate, SimError> {
        if base.block_id() == competing_block {
            return Err(SimError::InvalidConfig(
                "historical competing QC requires a distinct block ID",
            ));
        }
        if base.view() == competing_view {
            return Err(SimError::InvalidConfig(
                "historical competing QC requires a distinct view",
            ));
        }
        let mut votes = Vec::new();
        let mut power = 0u128;
        for validator in self.validator_set.validators() {
            votes.push(privileged_forged_vote(
                &self.validator_set,
                competing_view,
                base.height(),
                competing_block,
                validator.id(),
            )?);
            power = power
                .checked_add(validator.voting_power().get() as u128)
                .ok_or(SimError::ArithmeticOverflow("injected historical QC power"))?;
            if power >= self.validator_set.quorum_power() {
                break;
            }
        }
        let certificate = QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            competing_view,
            base.height(),
            competing_block,
            self.validator_set.id(),
            votes,
            &self.validator_set,
        )?;
        self.quorum_certificates
            .insert(certificate.id(), certificate.clone());
        self.record(
            "inject-historical-competing-qc",
            format!(
                "privileged-forge=true base-view={} competing-view={} height={} base={} competing={}",
                base.view().get(),
                competing_view.get(),
                base.height().get(),
                hex_block(base.block_id()),
                hex_block(competing_block)
            ),
        );
        for &target in targets {
            self.require_node(target)?;
            self.handle_delivery(
                0,
                target,
                WireMessage::QuorumCertificate(Box::new(certificate.clone())),
                0,
            )?;
        }
        self.check_finality_safety()?;
        Ok(certificate)
    }

    fn require_node(&self, node: NodeId) -> Result<(), SimError> {
        if node < self.nodes.len() {
            Ok(())
        } else {
            Err(SimError::UnknownNode(node))
        }
    }
}

impl Simulator {
    fn handle_event(&mut self, event: Event) -> Result<(), SimError> {
        match event {
            Event::Deliver {
                from,
                to,
                message,
                attempt,
            } => self.handle_delivery(from, to, message, attempt),
            Event::PersistAck {
                node,
                incarnation,
                barrier,
                state,
            } => self.handle_persist_ack(node, incarnation, barrier, state),
            Event::Validate {
                node,
                incarnation,
                id,
                synced,
                replay_generation,
            } => self.handle_validation(node, incarnation, id, synced, replay_generation),
            Event::RetryPayloadValidation {
                node,
                incarnation,
                block_id,
                attempt,
            } => self.handle_payload_validation_retry(node, incarnation, block_id, attempt),
            Event::Signature {
                node,
                incarnation,
                id,
                root,
            } => self.handle_signature(node, incarnation, id, root),
            Event::FinalizationApplied {
                node,
                incarnation,
                proof,
                attempt,
            } => self.handle_finalization(node, incarnation, *proof, attempt),
            Event::LocalTimeout {
                node,
                incarnation,
                view,
            } => self.handle_timeout(node, incarnation, view),
            Event::TryPropose { node, incarnation } => self.handle_try_propose(node, incarnation),
            Event::Resume { node, incarnation } => self.handle_resume(node, incarnation),
            Event::ReplayNext {
                node,
                incarnation,
                replay_generation,
                attempt,
            } => self.handle_replay_next(node, incarnation, replay_generation, attempt),
        }?;
        self.check_finality_safety()
    }

    fn handle_delivery(
        &mut self,
        from: NodeId,
        to: NodeId,
        message: WireMessage,
        attempt: u8,
    ) -> Result<(), SimError> {
        if !self.connected(from, to) {
            self.record(
                "net-drop",
                format!(
                    "partition from={from} to={to} message={}",
                    message.fingerprint()
                ),
            );
            return Ok(());
        }
        if self
            .nodes
            .get(to)
            .is_some_and(|node| node.core.is_some() && node.recovering)
        {
            if attempt < MAX_EVENT_RETRIES {
                self.record(
                    "net-retry",
                    format!(
                        "from={from} to={to} attempt={attempt} error=recovery-in-progress message={}",
                        message.fingerprint()
                    ),
                );
                self.schedule_after(
                    2,
                    Event::Deliver {
                        from,
                        to,
                        message,
                        attempt: attempt + 1,
                    },
                );
            } else {
                self.record(
                    "net-reject",
                    format!(
                        "from={from} to={to} error=recovery-retry-limit message={}",
                        message.fingerprint()
                    ),
                );
            }
            return Ok(());
        }
        let Some(core) = self.nodes.get_mut(to).and_then(|node| node.core.as_mut()) else {
            self.record(
                "net-drop",
                format!(
                    "offline from={from} to={to} message={}",
                    message.fingerprint()
                ),
            );
            return Ok(());
        };
        let input = match &message {
            WireMessage::Proposal(proposal) => Input::Proposal(Box::new(proposal.as_ref().clone())),
            WireMessage::Vote(vote) => Input::Vote(vote.as_ref().clone()),
            WireMessage::TimeoutVote(vote) => Input::TimeoutVote(vote.as_ref().clone()),
            WireMessage::QuorumCertificate(certificate) => {
                Input::QuorumCertificate(certificate.as_ref().clone())
            }
            WireMessage::TimeoutCertificate(certificate) => {
                Input::TimeoutCertificate(certificate.as_ref().clone())
            }
        };
        let result = core.step(input, &MockSignatures);
        match result {
            Ok(effects) => {
                self.record(
                    "net-deliver",
                    format!("from={from} to={to} message={}", message.fingerprint()),
                );
                if let WireMessage::TimeoutCertificate(certificate) = &message {
                    self.nodes[to]
                        .timeout_certificates
                        .insert(certificate.timed_out_view(), certificate.as_ref().clone());
                }
                self.process_effects(to, effects)?;
                match message {
                    WireMessage::Vote(vote) => self.collect_vote(to, *vote)?,
                    WireMessage::TimeoutVote(vote) => self.collect_timeout_vote(to, *vote)?,
                    WireMessage::Proposal(_)
                    | WireMessage::QuorumCertificate(_)
                    | WireMessage::TimeoutCertificate(_) => {}
                }
            }
            Err(error)
                if attempt < MAX_EVENT_RETRIES
                    && matches!(error, CoreError::Busy(_) | CoreError::MissingBlock(_)) =>
            {
                self.record(
                    "net-retry",
                    format!(
                        "from={from} to={to} attempt={attempt} error={error} message={}",
                        message.fingerprint()
                    ),
                );
                self.schedule_after(
                    2,
                    Event::Deliver {
                        from,
                        to,
                        message,
                        attempt: attempt + 1,
                    },
                );
            }
            Err(error) => self.record(
                "net-reject",
                format!(
                    "from={from} to={to} error={error} message={}",
                    message.fingerprint()
                ),
            ),
        }
        Ok(())
    }

    fn handle_persist_ack(
        &mut self,
        node: NodeId,
        incarnation: u64,
        barrier: BarrierId,
        state: Box<SafetyState>,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record(
                "local-drop",
                format!("stale-persist node={node} barrier={}", barrier.get()),
            );
            return Ok(());
        }
        let effects = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(Input::StorageAck { barrier }, &MockSignatures)?;
        let state_digest = safety_state_trace_digest(&state);
        let revision = state.revision();
        self.nodes[node].durable = *state;
        if self.nodes[node].durable.pending_finalize().is_none() {
            let applied_height = self.nodes[node]
                .applied
                .keys()
                .next_back()
                .copied()
                .unwrap_or_else(|| Height::new(0));
            let durable_height = self.nodes[node].durable.finalized().height();
            let cleared_height = core::cmp::min(applied_height, durable_height);
            if cleared_height > self.nodes[node].durably_applied_height {
                self.nodes[node].durably_applied_height = cleared_height;
            }
        }
        let standalone_pending = self.nodes[node]
            .durable
            .pending_standalone_qc_sync()
            .is_some();
        self.record(
            "persist-ack",
            format!(
                "node={node} barrier={} revision={revision} standalone-pending={standalone_pending} state={}",
                barrier.get(),
                hex_bytes(&state_digest)
            ),
        );
        // A payload-validation cleanup ACK can be empty while an authenticated
        // safety replay is still in flight. `ReplayNext` owns that lifecycle;
        // injecting a concurrent `Resume` would race the next durable
        // validation registration and trip the Core busy gate.
        let resume =
            self.nodes[node].recovering && !self.nodes[node].replaying && effects.is_empty();
        self.process_effects(node, effects)?;
        if resume {
            self.schedule_after(1, Event::Resume { node, incarnation });
        }
        Ok(())
    }

    fn handle_validation(
        &mut self,
        node: NodeId,
        incarnation: u64,
        id: ValidationId,
        synced: bool,
        replay_generation: Option<u64>,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record(
                "local-drop",
                format!(
                    "stale-validation node={node} generation={}",
                    id.generation()
                ),
            );
            return Ok(());
        }
        let replay_callback_was_current = !synced
            || (self.nodes[node].replaying
                && replay_generation == Some(self.nodes[node].replay_generation));
        if !replay_callback_was_current {
            self.record(
                "stale-sync-validation-callback",
                format!(
                    "stale-sync-validation node={node} generation={} replay-generation={replay_generation:?}",
                    id.generation()
                ),
            );
            // A callback belongs to the replay generation which created it.
            // It may neither consume the deterministic fault script for a
            // newer request nor reach the core after that request replaced
            // the old generation.
            //
            // The replacement request can still require the exact same
            // block (for example, a TC whose ancestry overlaps the request it
            // superseded). First cancel the exact old volatile core request;
            // if the block remains in the current replay ancestry, replay its
            // proposal so the core issues a fresh ValidationId. The stale
            // result itself is never applied or reused.
            let current_generation = self.nodes[node].replay_generation;
            let required_by_current_replay = self.nodes[node].replaying
                && self.nodes[node].replay_blocks.contains(&id.block_id());
            let key = SimValidationKeyV0::new(PayloadValidationRouteV0::Synced, id);
            let cancellation = self.nodes[node]
                .core
                .as_mut()
                .expect("current incarnation is online")
                .step(Input::CancelSyncedPayloadValidation { id }, &MockSignatures);
            match cancellation {
                Ok(effects) => {
                    self.nodes[node].validation_callbacks.remove(&key);
                    // Cancellation removes the process-local request first,
                    // but the durable obligation cleanup must cross its
                    // persistence barrier before a replacement validation can
                    // be admitted. Keep the ACK in the normal simulator event
                    // stream so a replay retry observes the same busy fence as
                    // a real driver.
                    self.process_effects(node, effects)?;
                }
                Err(CoreError::UnknownValidation(_)) => {
                    self.nodes[node].validation_callbacks.remove(&key);
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
            if required_by_current_replay {
                if !self.nodes[node]
                    .replay_queue
                    .iter()
                    .any(|proposal| proposal.block().id() == id.block_id())
                {
                    let proposal = self
                        .proposals
                        .get(&id.block_id())
                        .cloned()
                        .ok_or(SimError::MissingProposal(id.block_id()))?;
                    self.nodes[node].replay_queue.push_front(proposal);
                }
                self.record(
                    "rebind-sync-validation-callback",
                    format!(
                        "rebind-sync-validation node={node} generation={} replay-generation={current_generation}",
                        id.generation()
                    ),
                );
                let replay_next_queued = self.queue.values().any(|event| {
                    matches!(
                        event,
                        Event::ReplayNext {
                            node: queued_node,
                            incarnation: queued_incarnation,
                            replay_generation: queued_generation,
                            ..
                        } if *queued_node == node
                            && *queued_incarnation == incarnation
                            && *queued_generation == current_generation
                    )
                });
                if !replay_next_queued {
                    self.schedule_after(
                        0,
                        Event::ReplayNext {
                            node,
                            incarnation,
                            replay_generation: current_generation,
                            attempt: 0,
                        },
                    );
                }
            }
            return Ok(());
        }
        if self.nodes[node].halted {
            let route = validation_route_v0(synced);
            self.nodes[node]
                .validation_callbacks
                .remove(&SimValidationKeyV0::new(route, id));
            self.record(
                "local-drop",
                format!(
                    "halted-validation node={node} generation={}",
                    id.generation()
                ),
            );
            return Ok(());
        }

        let route = validation_route_v0(synced);
        let key = SimValidationKeyV0::new(route, id);
        if !self.nodes[node].validation_callbacks.contains_key(&key) {
            return Err(SimError::InvalidConfig(
                "validation callback lacks its exact claimed Core request",
            ));
        }
        let (outcome, newly_selected) = match self.nodes[node]
            .validation_callbacks
            .get(&key)
            .and_then(|callback| callback.outcome)
        {
            Some(outcome) => (outcome, false),
            None => {
                let outcome = self.nodes[node]
                    .scripted_validation_results
                    .pop_front()
                    .unwrap_or(ScriptedValidationOutcome::Valid);
                self.nodes[node]
                    .validation_callbacks
                    .get_mut(&key)
                    .expect("the exact callback was checked above")
                    .outcome = Some(outcome);
                (outcome, true)
            }
        };

        if outcome == ScriptedValidationOutcome::MismatchedValid && newly_selected {
            let candidate = self.mismatched_commitments_for(id.block_id())?;
            if candidate.block_id() == id.block_id() {
                return Err(SimError::InvalidConfig(
                    "mismatched validation fixture did not change the block identity",
                ));
            }
            self.record(
                "validation-preseal-reject",
                format!(
                    "node={node} view={} generation={} block={} candidate={} disposition=unavailable",
                    id.view().get(),
                    id.generation(),
                    hex_block(id.block_id()),
                    hex_block(candidate.block_id())
                ),
            );
        }

        if outcome == ScriptedValidationOutcome::Valid
            && matches!(
                self.nodes[node]
                    .validation_callbacks
                    .get(&key)
                    .map(|callback| &callback.capability),
                Some(SimValidationCapabilityV0::Permit(_))
            )
        {
            let commitments = self.validated_commitments_for(id.block_id())?;
            if commitments.block_id() != id.block_id() {
                return Err(SimError::InvalidConfig(
                    "simulated application returned commitments for another block",
                ));
            }
            let mut callback = self.nodes[node]
                .validation_callbacks
                .remove(&key)
                .expect("the exact callback was checked above");
            let permit = match callback.capability {
                SimValidationCapabilityV0::Permit(permit) => permit,
                SimValidationCapabilityV0::ApplicationSealed(_) => {
                    return Err(SimError::InvalidConfig(
                        "simulated Valid callback was sealed more than once",
                    ));
                }
            };
            let artifact_ref =
                simulated_artifact_ref_v0(commitments.block_id(), callback.parent_block_id);
            let authority = self.nodes[node].application_seal_authority.as_ref().ok_or(
                SimError::InvalidConfig(
                    "online Core lacks its simulated application seal authority",
                ),
            )?;
            callback.capability = SimValidationCapabilityV0::ApplicationSealed(
                authority.seal_after_application_store_commit_v0(permit, commitments, artifact_ref),
            );
            self.nodes[node].validation_callbacks.insert(key, callback);
        }

        let result = {
            let state = &mut self.nodes[node];
            let core = state.core.as_mut().expect("current incarnation is online");
            match outcome {
                ScriptedValidationOutcome::Valid => {
                    let callback = state
                        .validation_callbacks
                        .get(&key)
                        .expect("the exact callback was checked above");
                    let SimValidationCapabilityV0::ApplicationSealed(proof) = &callback.capability
                    else {
                        return Err(SimError::InvalidConfig(
                            "Valid outcome lacks its application-sealed proof",
                        ));
                    };
                    core.step_application_sealed_valid_v0(proof, &MockSignatures)
                }
                ScriptedValidationOutcome::MismatchedValid
                | ScriptedValidationOutcome::Unavailable
                | ScriptedValidationOutcome::DeterministicallyInvalid => {
                    let validation_result = materialize_nonvalid_validation_outcome(outcome);
                    let input = if synced {
                        Input::SyncedPayloadValidated {
                            id,
                            result: validation_result,
                        }
                    } else {
                        Input::PayloadValidated {
                            id,
                            result: validation_result,
                        }
                    };
                    core.step(input, &MockSignatures)
                }
            }
        };
        match result {
            Ok(effects) => {
                self.nodes[node].validation_callbacks.remove(&key);
                self.record(
                    if synced {
                        "sync-validated"
                    } else {
                        "payload-validated"
                    },
                    format!(
                        "node={node} view={} generation={} block={} result={}",
                        id.view().get(),
                        id.generation(),
                        hex_block(id.block_id()),
                        effective_validation_label(outcome)
                    ),
                );
                self.process_effects(node, effects)?;
                let replay_callback_is_current = replay_callback_was_current
                    && (!synced
                        || (self.nodes[node].replaying
                            && replay_generation == Some(self.nodes[node].replay_generation)));
                if matches!(
                    outcome,
                    ScriptedValidationOutcome::MismatchedValid
                        | ScriptedValidationOutcome::Unavailable
                ) {
                    if replay_callback_is_current
                        && self.nodes[node].replaying
                        && !self.nodes[node].halted
                    {
                        let queued_position = self.nodes[node]
                            .replay_queue
                            .iter()
                            .position(|proposal| proposal.block().id() == id.block_id());
                        let proposal = match queued_position {
                            Some(position) => self.nodes[node]
                                .replay_queue
                                .remove(position)
                                .expect("selected replay proposal exists"),
                            None => self
                                .proposals
                                .get(&id.block_id())
                                .cloned()
                                .ok_or(SimError::MissingProposal(id.block_id()))?,
                        };
                        self.nodes[node].replay_queue.push_front(proposal);
                        let replay_generation = self.nodes[node].replay_generation;
                        self.schedule_after(
                            1,
                            Event::ReplayNext {
                                node,
                                incarnation,
                                replay_generation,
                                attempt: 0,
                            },
                        );
                    } else if !synced && !self.nodes[node].halted {
                        self.schedule_after(
                            0,
                            Event::RetryPayloadValidation {
                                node,
                                incarnation,
                                block_id: id.block_id(),
                                attempt: 0,
                            },
                        );
                    }
                } else if synced
                    && outcome == ScriptedValidationOutcome::Valid
                    && replay_callback_is_current
                    && self.nodes[node].replaying
                    && !self.nodes[node].halted
                {
                    let replay_generation = self.nodes[node].replay_generation;
                    self.schedule_after(
                        1,
                        Event::ReplayNext {
                            node,
                            incarnation,
                            replay_generation,
                            attempt: 0,
                        },
                    );
                }
            }
            Err(CoreError::Busy(_)) => self.schedule_after(
                1,
                Event::Validate {
                    node,
                    incarnation,
                    id,
                    synced,
                    replay_generation,
                },
            ),
            Err(
                error @ (CoreError::ValidationCapabilityMismatch { .. }
                | CoreError::ValidPayloadPermitMismatch(_)
                | CoreError::ApplicationSealedValidMismatch(_)),
            ) => {
                self.record(
                    "validation-host-capability-reject",
                    format!(
                        "node={node} view={} generation={} block={} error={error}",
                        id.view().get(),
                        id.generation(),
                        hex_block(id.block_id())
                    ),
                );
                return Err(error.into());
            }
            Err(CoreError::UnknownValidation(block_id)) if block_id == id.block_id() => {
                self.nodes[node].validation_callbacks.remove(&key);
                self.record(
                    "local-drop",
                    format!(
                        "retired-validation node={node} generation={} block={}",
                        id.generation(),
                        hex_block(id.block_id())
                    ),
                );
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn validated_commitments_for(
        &self,
        block_id: BlockId,
    ) -> Result<ValidatedBlockCommitmentsV0, SimError> {
        let proposal = self
            .proposals
            .get(&block_id)
            .ok_or(SimError::MissingProposal(block_id))?;
        let artifacts = self
            .validation_artifacts
            .get(&block_id)
            .ok_or(SimError::InvalidConfig(
                "proposal lacks canonical validation artifacts",
            ))?;
        Ok(artifacts.body.validate_ordinary_commitments(
            proposal.block().header(),
            &artifacts.receipts,
            &self.consensus_parameters,
            &self.validator_set,
            &MockSignatures,
        )?)
    }

    fn mismatched_commitments_for(
        &self,
        requested_block_id: BlockId,
    ) -> Result<ValidatedBlockCommitmentsV0, SimError> {
        let proposal = self
            .proposals
            .get(&requested_block_id)
            .ok_or(SimError::MissingProposal(requested_block_id))?;
        let artifacts =
            self.validation_artifacts
                .get(&requested_block_id)
                .ok_or(SimError::InvalidConfig(
                    "proposal lacks canonical validation artifacts",
                ))?;
        let header = proposal.block().header();
        let mut mismatched_state_root = *header.state_root().as_bytes();
        mismatched_state_root[0] ^= 0x80;
        let mismatched_header = BlockHeader::new(
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
            header.payload_digest(),
            StateRoot::new(mismatched_state_root),
            header.receipts_root(),
            header.evidence_root(),
            header.timestamp_ms(),
            header.next_epoch_commitment_hash(),
        )?;
        Ok(artifacts.body.validate_ordinary_commitments(
            &mismatched_header,
            &artifacts.receipts,
            &self.consensus_parameters,
            &self.validator_set,
            &MockSignatures,
        )?)
    }

    fn handle_payload_validation_retry(
        &mut self,
        node: NodeId,
        incarnation: u64,
        block_id: BlockId,
        attempt: u8,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record(
                "local-drop",
                format!(
                    "stale-validation-retry node={node} block={}",
                    hex_block(block_id)
                ),
            );
            return Ok(());
        }
        if self.nodes[node].halted {
            self.record(
                "local-drop",
                format!(
                    "halted-validation-retry node={node} block={}",
                    hex_block(block_id)
                ),
            );
            return Ok(());
        }
        let proposal = self
            .proposals
            .get(&block_id)
            .cloned()
            .ok_or(SimError::MissingProposal(block_id))?;
        let result = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(Input::Proposal(Box::new(proposal)), &MockSignatures);
        match result {
            Ok(effects) => {
                self.record(
                    "payload-validation-retry",
                    format!(
                        "node={node} block={} attempt={attempt}",
                        hex_block(block_id)
                    ),
                );
                self.process_effects(node, effects)?;
            }
            Err(error)
                if attempt < MAX_EVENT_RETRIES
                    && matches!(error, CoreError::Busy(_) | CoreError::MissingBlock(_)) =>
            {
                self.schedule_after(
                    1,
                    Event::RetryPayloadValidation {
                        node,
                        incarnation,
                        block_id,
                        attempt: attempt + 1,
                    },
                );
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn handle_signature(
        &mut self,
        node: NodeId,
        incarnation: u64,
        id: SignId,
        root: SigningRoot,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record("local-drop", format!("stale-signature node={node}"));
            return Ok(());
        }
        if self.nodes[node].halted || self.nodes[node].safety().safety_halt().is_some() {
            self.record("local-drop", format!("halted-signature node={node}"));
            return Ok(());
        }
        let validator_id = self.nodes[node].validator;
        let validator = self
            .validator_set
            .validator(validator_id)
            .expect("simulator node belongs to its validator set");
        let signature = mock_signature_for(validator, root);
        let effects = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(Input::SignatureReady { id, signature }, &MockSignatures)?;
        self.record(
            "signature-ready",
            format!("node={node} root={}", hex_bytes(root.as_bytes())),
        );
        self.process_effects(node, effects)?;
        if self.nodes[node].recovering {
            self.schedule_after(1, Event::Resume { node, incarnation });
        }
        Ok(())
    }

    fn handle_finalization(
        &mut self,
        node: NodeId,
        incarnation: u64,
        proof: DurableFinalizationV0,
        attempt: u8,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record("local-drop", format!("stale-finalization node={node}"));
            return Ok(());
        }
        if self.nodes[node].halted || self.nodes[node].safety().safety_halt().is_some() {
            self.nodes[node].application_finalization_apply_authority = None;
            self.nodes[node].pending_application_finalization_readback = None;
            self.nodes[node].pending_application_finalization_receipt = None;
            self.record("local-drop", format!("halted-finalization node={node}"));
            return Ok(());
        }

        if let Err(error) = self.prepare_simulated_finalization_receipt_v0(node, &proof) {
            if matches!(&error, SimError::Core(CoreError::Busy(_))) && attempt < MAX_EVENT_RETRIES {
                self.record(
                    "finalization-retry",
                    format!(
                        "node={node} proof={} attempt={attempt} phase=permit error={error}",
                        hex_certificate(proof.id())
                    ),
                );
                self.schedule_after(
                    1,
                    Event::FinalizationApplied {
                        node,
                        incarnation,
                        proof: Box::new(proof),
                        attempt: attempt + 1,
                    },
                );
                return Ok(());
            }
            return Err(error);
        }

        let receipt = self.nodes[node]
            .pending_application_finalization_receipt
            .take()
            .expect("the simulated application retained its exact receipt owner");
        let result = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step_application_finalization_receipt_v0(receipt, &MockSignatures);
        match result {
            Ok(effects) => {
                self.nodes[node].pending_application_finalization_readback = None;
                self.process_effects(node, effects)
            }
            Err(rejection) => {
                let (error, receipt) = rejection.into_parts();
                if self.nodes[node]
                    .pending_application_finalization_readback
                    .as_ref()
                    != Some(receipt.application_store_readback_v0())
                {
                    self.nodes[node].pending_application_finalization_receipt = Some(receipt);
                    return Err(SimError::InvalidConfig(
                        "rejected finalization receipt lost its exact in-memory readback projection",
                    ));
                }
                self.nodes[node].pending_application_finalization_receipt = Some(receipt);
                if matches!(&error, CoreError::Busy(_)) && attempt < MAX_EVENT_RETRIES {
                    self.record(
                        "finalization-retry",
                        format!(
                            "node={node} proof={} attempt={attempt} phase=receipt error={error}",
                            hex_certificate(proof.id())
                        ),
                    );
                    self.schedule_after(
                        1,
                        Event::FinalizationApplied {
                            node,
                            incarnation,
                            proof: Box::new(proof),
                            attempt: attempt + 1,
                        },
                    );
                    Ok(())
                } else {
                    self.record(
                        "finalization-host-capability-reject",
                        format!(
                            "node={node} proof={} attempt={attempt} error={error}",
                            hex_certificate(proof.id())
                        ),
                    );
                    Err(error.into())
                }
            }
        }
    }

    /// Development-only stand-in for an ApplicationStore exact apply/readback.
    ///
    /// The cloneable event carries only inert comparison data. The sole Core
    /// permit, once-issued application authority, and resulting receipt remain
    /// private to `SimNode`. Its deterministic inert readback projection is
    /// retained beside the receipt. A previously minted receipt is reused
    /// verbatim on retry and is never reconstructed from the event.
    fn prepare_simulated_finalization_receipt_v0(
        &mut self,
        node: NodeId,
        proof: &DurableFinalizationV0,
    ) -> Result<(), SimError> {
        if let Some(receipt) = self.nodes[node]
            .pending_application_finalization_receipt
            .as_ref()
        {
            if receipt.finalization() != proof {
                return Err(SimError::InvalidConfig(
                    "queued finalization event conflicts with the retained receipt owner",
                ));
            }
            if self.nodes[node]
                .pending_application_finalization_readback
                .as_ref()
                != Some(receipt.application_store_readback_v0())
            {
                return Err(SimError::InvalidConfig(
                    "retained finalization receipt differs from its in-memory readback projection",
                ));
            }
            return Ok(());
        }
        if self.nodes[node]
            .pending_application_finalization_readback
            .is_some()
        {
            return Err(SimError::InvalidConfig(
                "orphaned in-memory finalization readback lacks its unique receipt owner",
            ));
        }

        let exact_front = self.nodes[node]
            .core
            .as_ref()
            .expect("current incarnation is online")
            .safety_state()
            .pending_finalization();
        if exact_front != Some(proof) {
            return Err(SimError::InvalidConfig(
                "queued finalization event is not the Core's exact authenticated front",
            ));
        }
        if self.nodes[node]
            .application_finalization_apply_authority
            .is_none()
        {
            return Err(SimError::InvalidConfig(
                "online Core lacks its simulated application-finalization authority",
            ));
        }

        let newly_finalized = self.collect_newly_finalized(node, proof)?;
        let permit = self.nodes[node]
            .core
            .as_ref()
            .expect("current incarnation is online")
            .issue_application_finalization_permit_v0()?;
        if permit.finalization() != proof {
            let readback = {
                let state = &self.nodes[node];
                simulated_application_finalization_readback_v0(
                    state.safety(),
                    state
                        .application_finalization_apply_authority
                        .as_ref()
                        .expect("the authority was checked above"),
                    &permit,
                )?
            };
            let receipt = self.nodes[node]
                .application_finalization_apply_authority
                .as_ref()
                .expect("the authority was checked above")
                .receipt_after_application_store_apply_v0(permit, readback.clone())
                .expect("the permit was issued by the same simulated Core authority");
            self.nodes[node].pending_application_finalization_readback = Some(readback);
            self.nodes[node].pending_application_finalization_receipt = Some(receipt);
            return Err(SimError::InvalidConfig(
                "Core finalization permit changed after exact-front admission",
            ));
        }

        self.record_applied_finalization(node, proof, &newly_finalized);
        let readback = {
            let state = &self.nodes[node];
            simulated_application_finalization_readback_v0(
                state.safety(),
                state
                    .application_finalization_apply_authority
                    .as_ref()
                    .expect("the authority was checked above"),
                &permit,
            )?
        };
        let receipt = self.nodes[node]
            .application_finalization_apply_authority
            .as_ref()
            .expect("the authority was checked above")
            .receipt_after_application_store_apply_v0(permit, readback.clone())
            .expect("the permit was issued by the same simulated Core authority");
        self.nodes[node].pending_application_finalization_readback = Some(readback);
        self.nodes[node].pending_application_finalization_receipt = Some(receipt);
        Ok(())
    }

    fn handle_timeout(
        &mut self,
        node: NodeId,
        incarnation: u64,
        view: View,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation)
            || self.nodes[node].replaying
            || self.nodes[node].halted
        {
            return Ok(());
        }
        if self.nodes[node].safety().current_view() != view {
            return Ok(());
        }
        let result = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(
                Input::LocalTimeout {
                    epoch: Epoch::new(0),
                    view,
                },
                &MockSignatures,
            );
        match result {
            Ok(effects) => {
                self.record("local-timeout", format!("node={node} view={}", view.get()));
                self.process_effects(node, effects)?;
            }
            Err(CoreError::Busy(_)) => self.schedule_after(
                1,
                Event::LocalTimeout {
                    node,
                    incarnation,
                    view,
                },
            ),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn handle_try_propose(&mut self, node: NodeId, incarnation: u64) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation)
            || self.nodes[node].replaying
            || self.nodes[node].halted
        {
            return Ok(());
        }
        let view = self.nodes[node].safety().current_view();
        if leader_for(&self.validator_set, view) != self.nodes[node].validator
            || self.proposed_views.contains(&(node, view))
        {
            return Ok(());
        }
        let Some(proposal) = self.build_proposal(node)? else {
            self.record("proposal-wait", format!("node={node} view={}", view.get()));
            return Ok(());
        };
        self.proposed_views.insert((node, view));
        self.proposals
            .insert(proposal.block().id(), proposal.clone());
        self.record(
            "proposal-create",
            format!(
                "node={node} view={} height={} block={}",
                view.get(),
                proposal.block().header().height().get(),
                hex_block(proposal.block().id())
            ),
        );
        self.broadcast_inner(node, WireMessage::Proposal(Box::new(proposal)), None, true);
        Ok(())
    }

    fn handle_resume(&mut self, node: NodeId, incarnation: u64) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            return Ok(());
        }
        let effects = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(Input::Resume, &MockSignatures)?;
        let terminal_resume = effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::RequestSafetyReplay { .. }
                    | Effect::RequestStandaloneQcSync { .. }
                    | Effect::ArmViewTimer { .. }
                    | Effect::SafetyHalted(_)
            )
        });
        self.record("resume", format!("node={node}"));
        self.process_effects(node, effects)?;
        if terminal_resume && !self.nodes[node].replaying {
            self.nodes[node].recovering = false;
            self.gossip_to(node);
        }
        Ok(())
    }

    fn handle_replay_next(
        &mut self,
        node: NodeId,
        incarnation: u64,
        replay_generation: u64,
        attempt: u8,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation)
            || !self.nodes[node].replaying
            || self.nodes[node].replay_generation != replay_generation
        {
            return Ok(());
        }
        if let Some(proposal) = self.nodes[node].replay_queue.front().cloned() {
            let result = self.nodes[node]
                .core
                .as_mut()
                .expect("current incarnation is online")
                .step(
                    Input::SyncedProposal(Box::new(proposal.clone())),
                    &MockSignatures,
                );
            match result {
                Ok(effects) => {
                    self.nodes[node].replay_queue.pop_front();
                    let waits_for_sync_validation = effects.iter().any(|effect| {
                        matches!(
                            effect,
                            Effect::PersistSafetyState(_) | Effect::ValidateSyncedPayload(_)
                        )
                    });
                    self.record(
                        "replay-proposal",
                        format!("node={node} block={}", hex_block(proposal.block().id())),
                    );
                    self.process_effects(node, effects)?;
                    if !waits_for_sync_validation {
                        self.schedule_after(
                            1,
                            Event::ReplayNext {
                                node,
                                incarnation,
                                replay_generation,
                                attempt: 0,
                            },
                        );
                    }
                }
                Err(error)
                    if attempt < MAX_EVENT_RETRIES
                        && matches!(error, CoreError::Busy(_) | CoreError::MissingBlock(_)) =>
                {
                    self.schedule_after(
                        1,
                        Event::ReplayNext {
                            node,
                            incarnation,
                            replay_generation,
                            attempt: attempt + 1,
                        },
                    );
                }
                Err(error) => return Err(error.into()),
            }
            return Ok(());
        }

        let result = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(Input::SafetyReplayComplete, &MockSignatures);
        match result {
            Ok(effects) => {
                self.nodes[node].advance_replay_generation()?;
                self.nodes[node].replaying = false;
                self.nodes[node].recovering = false;
                self.nodes[node].replay_request = None;
                self.nodes[node].replay_blocks.clear();
                self.record("replay-complete", format!("node={node}"));
                self.process_effects(node, effects)?;
                self.gossip_to(node);
            }
            Err(CoreError::Busy(_)) if attempt < MAX_EVENT_RETRIES => self.schedule_after(
                1,
                Event::ReplayNext {
                    node,
                    incarnation,
                    replay_generation,
                    attempt: attempt + 1,
                },
            ),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

impl Simulator {
    fn schedule_simulated_validation_v0(
        &mut self,
        node: NodeId,
        request: PayloadValidationRequest,
        expected_route: PayloadValidationRouteV0,
        replay_generation: Option<u64>,
    ) -> Result<(), SimError> {
        if self.nodes[node].application_seal_authority.is_none() {
            return Err(SimError::InvalidConfig(
                "online Core lacks its simulated application seal authority",
            ));
        }

        // The event retains only copyable request identity. Claiming one clone
        // consumes the shared Core request graph, while the read-only clone is
        // used solely to prove the claimed parts were not substituted at this
        // trusted development host boundary.
        let request_facts = request.clone();
        let claimed = request.try_claim().map_err(|_| {
            SimError::InvalidConfig("simulator received an already-claimed validation request")
        })?;
        let (route, id, block, parent, permit) = claimed.into_parts();
        if route != expected_route
            || request_facts.route() != route
            || request_facts.id() != id
            || request_facts.block() != &block
            || request_facts.parent() != &parent
            || block.id() != id.block_id()
            || block.header().parent_id() != parent.tip().block_id()
        {
            return Err(SimError::InvalidConfig(
                "claimed validation request differs from its Core-issued facts",
            ));
        }

        let key = SimValidationKeyV0::new(route, id);
        if self.nodes[node].validation_callbacks.contains_key(&key) {
            return Err(SimError::InvalidConfig(
                "simulator already retains a callback for this validation request",
            ));
        }
        self.nodes[node].validation_callbacks.insert(
            key,
            SimValidationCallbackV0 {
                parent_block_id: parent.tip().block_id(),
                outcome: None,
                capability: SimValidationCapabilityV0::Permit(permit),
            },
        );
        self.schedule_after(
            1,
            Event::Validate {
                node,
                incarnation: self.nodes[node].incarnation,
                id,
                synced: route == PayloadValidationRouteV0::Synced,
                replay_generation,
            },
        );
        Ok(())
    }

    fn process_effects(&mut self, node: NodeId, effects: Vec<Effect>) -> Result<(), SimError> {
        let incarnation = self.nodes[node].incarnation;
        for effect in effects {
            match effect {
                Effect::PersistSafetyState(request) => {
                    let barrier = request.barrier();
                    let state = Box::new(request.state().clone());
                    let state_digest = safety_state_trace_digest(&state);
                    self.record(
                        "persist-request",
                        format!(
                            "node={node} barrier={} revision={} state={}",
                            barrier.get(),
                            state.revision(),
                            hex_bytes(&state_digest)
                        ),
                    );
                    self.schedule_after(
                        1,
                        Event::PersistAck {
                            node,
                            incarnation,
                            barrier,
                            state,
                        },
                    );
                }
                Effect::ValidatePayload(request) => {
                    self.schedule_simulated_validation_v0(
                        node,
                        request,
                        PayloadValidationRouteV0::Proposal,
                        None,
                    )?;
                }
                Effect::ValidateSyncedPayload(request) => {
                    let id = request.id();
                    self.nodes[node].replay_blocks.insert(id.block_id());
                    let replay_generation = self.nodes[node].replay_generation;
                    self.schedule_simulated_validation_v0(
                        node,
                        request,
                        PayloadValidationRouteV0::Synced,
                        Some(replay_generation),
                    )?;
                }
                Effect::RequestSignature { intent } => {
                    intent.validate(&self.validator_set)?;
                    if intent.author() != self.nodes[node].validator {
                        return Err(SimError::InvalidConfig(
                            "sign intent author differs from simulated node",
                        ));
                    }
                    let root = intent.signing_root();
                    self.schedule_after(
                        1,
                        Event::Signature {
                            node,
                            incarnation,
                            id: SignId::new(root),
                            root,
                        },
                    );
                }
                Effect::Broadcast(message) => {
                    let wire = match message {
                        OutboundMessage::Vote(vote) => WireMessage::Vote(Box::new(vote)),
                        OutboundMessage::TimeoutVote(vote) => {
                            WireMessage::TimeoutVote(Box::new(vote))
                        }
                    };
                    self.broadcast_inner(node, wire, None, true);
                }
                Effect::ArmViewTimer { view, .. } => {
                    if !self.nodes[node].replaying {
                        self.arm_node(node, view);
                    }
                }
                Effect::RequestSafetyReplay {
                    finalized,
                    high_qc,
                    locked_qc,
                } => {
                    let request = ReplayRequest::Safety {
                        high: high_qc.block_id(),
                        locked: locked_qc.block_id(),
                    };
                    let same_request = self.nodes[node].replaying
                        && self.nodes[node].replay_request == Some(request);
                    if !same_request {
                        let replay = self.collect_replay(
                            finalized.block_id(),
                            high_qc.block_id(),
                            locked_qc.block_id(),
                        )?;
                        self.nodes[node].advance_replay_generation()?;
                        self.nodes[node].replaying = true;
                        self.nodes[node].replay_request = Some(request);
                        self.nodes[node].replay_blocks = replay
                            .iter()
                            .map(|proposal| proposal.block().id())
                            .collect();
                        self.nodes[node].replay_queue = replay.into();
                    }
                    self.record(
                        if same_request {
                            "replay-continue"
                        } else {
                            "replay-request"
                        },
                        format!(
                            "node={node} finalized={} high={} locked={} count={}",
                            hex_block(finalized.block_id()),
                            hex_block(high_qc.block_id()),
                            hex_block(locked_qc.block_id()),
                            self.nodes[node].replay_queue.len()
                        ),
                    );
                    if !same_request {
                        let replay_generation = self.nodes[node].replay_generation;
                        self.schedule_after(
                            1,
                            Event::ReplayNext {
                                node,
                                incarnation,
                                replay_generation,
                                attempt: 0,
                            },
                        );
                    }
                }
                Effect::RequestTcHighQcSync {
                    certificate_id,
                    timed_out_view,
                    target,
                    finalized,
                } => {
                    let request = ReplayRequest::Tc {
                        certificate_id,
                        target: target.block_id(),
                    };
                    let same_request = self.nodes[node].replaying
                        && self.nodes[node].replay_request == Some(request);
                    if !same_request {
                        let replay = self.collect_replay(
                            finalized.block_id(),
                            target.block_id(),
                            target.block_id(),
                        )?;
                        self.nodes[node].advance_replay_generation()?;
                        self.nodes[node].replaying = true;
                        self.nodes[node].replay_request = Some(request);
                        self.nodes[node].replay_blocks = replay
                            .iter()
                            .map(|proposal| proposal.block().id())
                            .collect();
                        self.nodes[node].replay_queue = replay.into();
                    }
                    self.record(
                        if same_request {
                            "tc-high-qc-sync-continue"
                        } else {
                            "tc-high-qc-sync-request"
                        },
                        format!(
                            "node={node} tc={} timed-out-view={} finalized={} target={} count={}",
                            hex_certificate(certificate_id),
                            timed_out_view.get(),
                            hex_block(finalized.block_id()),
                            hex_block(target.block_id()),
                            self.nodes[node].replay_queue.len()
                        ),
                    );
                    if !same_request {
                        let replay_generation = self.nodes[node].replay_generation;
                        self.schedule_after(
                            1,
                            Event::ReplayNext {
                                node,
                                incarnation,
                                replay_generation,
                                attempt: 0,
                            },
                        );
                    }
                }
                Effect::RequestStandaloneQcSync {
                    certificate_id,
                    target,
                    finalized,
                } => {
                    let request = ReplayRequest::Standalone { certificate_id };
                    let same_request = self.nodes[node].replaying
                        && self.nodes[node].replay_request == Some(request);
                    if !same_request {
                        let replay = self.collect_replay(
                            finalized.block_id(),
                            target.block_id(),
                            target.block_id(),
                        )?;
                        self.nodes[node].advance_replay_generation()?;
                        self.nodes[node].replaying = true;
                        self.nodes[node].replay_request = Some(request);
                        self.nodes[node].replay_blocks = replay
                            .iter()
                            .map(|proposal| proposal.block().id())
                            .collect();
                        self.nodes[node].replay_queue = replay.into();
                    }
                    self.record(
                        if same_request {
                            "standalone-qc-sync-continue"
                        } else {
                            "standalone-qc-sync-request"
                        },
                        format!(
                            "node={node} qc={} finalized={} target={} count={}",
                            hex_certificate(certificate_id),
                            hex_block(finalized.block_id()),
                            hex_block(target.block_id()),
                            self.nodes[node].replay_queue.len()
                        ),
                    );
                    if !same_request {
                        let replay_generation = self.nodes[node].replay_generation;
                        self.schedule_after(
                            1,
                            Event::ReplayNext {
                                node,
                                incarnation,
                                replay_generation,
                                attempt: 0,
                            },
                        );
                    }
                }
                Effect::SafetyHalted(halt) => {
                    self.nodes[node].halted = true;
                    self.nodes[node].recovering = false;
                    self.nodes[node].replaying = false;
                    self.nodes[node].replay_request = None;
                    self.nodes[node].advance_replay_generation()?;
                    self.nodes[node].replay_queue.clear();
                    self.nodes[node].replay_blocks.clear();
                    self.nodes[node].validation_callbacks.clear();
                    self.nodes[node].application_seal_authority = None;
                    self.nodes[node].application_finalization_apply_authority = None;
                    self.nodes[node].pending_application_finalization_readback = None;
                    self.nodes[node].pending_application_finalization_receipt = None;
                    self.record(
                        "safety-halt",
                        format!(
                            "node={node} reason={}",
                            safety_halt_fingerprint(halt.as_ref())
                        ),
                    );
                }
                Effect::Finalize(proof) => {
                    self.record(
                        "finalize-request",
                        format!(
                            "node={node} height={} block={} proof={}",
                            proof.finalized_block().header().height().get(),
                            hex_block(proof.finalized_block().header().id()),
                            hex_certificate(proof.id())
                        ),
                    );
                    self.schedule_after(
                        1,
                        Event::FinalizationApplied {
                            node,
                            incarnation,
                            proof,
                            attempt: 0,
                        },
                    );
                }
                Effect::Evidence(_) => {
                    self.evidence_count = self
                        .evidence_count
                        .checked_add(1)
                        .ok_or(SimError::ArithmeticOverflow("evidence count"))?;
                    self.record("evidence", format!("node={node}"));
                }
            }
        }
        Ok(())
    }

    fn collect_vote(&mut self, receiver: NodeId, vote: Vote) -> Result<(), SimError> {
        let coordinate = VoteCoordinate {
            view: vote.view(),
            height: vote.height(),
            block_id: vote.block_id(),
        };
        self.nodes[receiver]
            .vote_pool
            .entry(coordinate)
            .or_default()
            .insert(vote.author(), vote);
        if self.formed_qcs.contains(&coordinate) {
            return Ok(());
        }
        let votes = self.nodes[receiver]
            .vote_pool
            .get(&coordinate)
            .expect("just inserted vote");
        if self.signed_power(votes.keys().copied())? < self.validator_set.quorum_power() {
            return Ok(());
        }
        let certificate = QuorumCertificate::new(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            coordinate.view,
            coordinate.height,
            coordinate.block_id,
            self.validator_set.id(),
            votes.values().cloned().collect(),
            &self.validator_set,
        )?;
        self.formed_qcs.insert(coordinate);
        self.quorum_certificates
            .insert(certificate.id(), certificate.clone());
        self.record(
            "qc-formed",
            format!(
                "receiver={receiver} view={} height={} block={} qc={}",
                coordinate.view.get(),
                coordinate.height.get(),
                hex_block(coordinate.block_id),
                hex_certificate(certificate.id())
            ),
        );
        self.broadcast_inner(
            receiver,
            WireMessage::QuorumCertificate(Box::new(certificate)),
            None,
            true,
        );
        Ok(())
    }

    fn collect_timeout_vote(
        &mut self,
        receiver: NodeId,
        vote: TimeoutVote,
    ) -> Result<(), SimError> {
        let view = vote.view();
        self.nodes[receiver]
            .timeout_pool
            .entry(view)
            .or_default()
            .insert(vote.author(), vote);
        if self.formed_tcs.contains(&view) {
            return Ok(());
        }
        let votes = self.nodes[receiver]
            .timeout_pool
            .get(&view)
            .expect("just inserted timeout vote");
        if self.signed_power(votes.keys().copied())? < self.validator_set.quorum_power() {
            return Ok(());
        }
        let mut referenced: BTreeMap<CertificateId, QcReferenceV0> = BTreeMap::new();
        for vote in votes.values() {
            let digest = vote.high_qc().qc_digest();
            let reference = if digest == self.genesis_qc.id() {
                QcReferenceV0::genesis_anchor(self.genesis_qc.clone())
            } else {
                QcReferenceV0::ordinary(
                    self.quorum_certificates
                        .get(&digest)
                        .cloned()
                        .ok_or(SimError::MissingQuorumCertificate(digest))?,
                )
            };
            referenced.insert(digest, reference);
        }
        let selected = referenced
            .values()
            .max_by_key(|reference| {
                let summary = reference.qc_ref();
                (summary.view(), summary.block_id(), reference.id())
            })
            .expect("a timeout quorum is nonempty")
            .id();
        let selected_block = referenced
            .get(&selected)
            .expect("selected QC is referenced")
            .qc_ref()
            .block_id();
        let entries = votes
            .values()
            .map(|vote| TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature()))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = TimeoutCertificateV0::new(
            view,
            entries,
            referenced.into_values().collect(),
            selected,
            &self.validator_set,
        )?;
        self.formed_tcs.insert(view);
        self.timeout_certificates
            .insert(certificate.id(), certificate.clone());
        self.record(
            "tc-formed",
            format!(
                "receiver={receiver} view={} tc={} high={}",
                view.get(),
                hex_certificate(certificate.id()),
                hex_block(selected_block)
            ),
        );
        self.broadcast_inner(
            receiver,
            WireMessage::TimeoutCertificate(Box::new(certificate)),
            None,
            true,
        );
        Ok(())
    }

    fn signed_power<I>(&self, validators: I) -> Result<u128, SimError>
    where
        I: IntoIterator<Item = ValidatorId>,
    {
        validators.into_iter().try_fold(0u128, |power, id| {
            let voting_power = self
                .validator_set
                .power_of(id)
                .ok_or(SimError::InvalidConfig(
                    "pool contains an unknown validator",
                ))?;
            power
                .checked_add(voting_power)
                .ok_or(SimError::ArithmeticOverflow("aggregated voting power"))
        })
    }

    fn build_proposal(&mut self, node: NodeId) -> Result<Option<SignedProposalV0>, SimError> {
        let safety = self.nodes[node].safety();
        let view = safety.current_view();
        let high_qc = safety.high_qc().clone();
        let high_ref = high_qc.qc_ref();
        let timeout_certificate = if high_ref.view().checked_next()? == view {
            None
        } else {
            let Some(timeout_view) = view.get().checked_sub(1).map(View::new) else {
                return Err(SimError::NoProposalJustification { node, view });
            };
            let Some(certificate) = self.nodes[node]
                .timeout_certificates
                .get(&timeout_view)
                .filter(|certificate| certificate.selected_high_qc_digest() == high_qc.id())
                .cloned()
            else {
                return Ok(None);
            };
            Some(certificate)
        };
        let parent_timestamp = if high_ref.block_id() == GENESIS_BLOCK_ID {
            0
        } else {
            self.proposals
                .get(&high_ref.block_id())
                .ok_or(SimError::MissingProposal(high_ref.block_id()))?
                .block()
                .header()
                .timestamp_ms()
        };
        let timestamp_ms = parent_timestamp
            .checked_add(1)
            .ok_or(SimError::ArithmeticOverflow("block timestamp"))?;
        self.block_nonce = self
            .block_nonce
            .checked_add(1)
            .ok_or(SimError::ArithmeticOverflow("block nonce"))?;
        let nonce = self.block_nonce;
        let transaction = format!(
            "seed={} node={node} view={} nonce={nonce}",
            self.seed(),
            view.get()
        )
        .into_bytes();
        let application_payload = ApplicationPayloadV0::new(vec![transaction.clone()])?;
        let receipt = ExecutionReceiptCommitmentV0::for_transaction(
            &application_payload,
            0,
            0,
            0,
            Vec::new(),
        )?;
        let receipts = ExecutionReceiptsV0::new(&application_payload, vec![receipt])?;
        let body = BlockBodyV0::new(application_payload.clone(), Vec::new())?;
        let payload_root = body.payload_root()?;
        let receipts_root = receipts.receipts_root()?;
        let evidence_root = body.evidence_root()?;
        let payload = application_payload.try_cev0_bytes()?;
        let evidence_objects = body
            .evidence()
            .iter()
            .map(|item| item.try_cev0_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        let proposer = self.nodes[node].validator;
        let height = high_ref.height().checked_next()?;
        let header = BlockHeader::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            height,
            BlockKind::Regular,
            high_ref.block_id(),
            proposer,
            self.validator_set.id(),
            self.validator_set.consensus_parameters_hash(),
            payload_root,
            StateRoot::new(self.derive_root(b"state", nonce, &transaction)),
            receipts_root,
            evidence_root,
            timestamp_ms,
            None,
        )?;
        let block = Block::new(header, payload, evidence_objects)?;
        let root = ProposalWitnessV0::signing_root_for(
            block.header(),
            &high_qc,
            timeout_certificate.as_ref(),
            None,
        )?;
        let proposer_validator = self
            .validator_set
            .validator(proposer)
            .expect("simulator proposer belongs to its validator set");
        let witness = ProposalWitnessV0::new(
            block.header(),
            high_qc,
            timeout_certificate,
            None,
            mock_signature_for(proposer_validator, root),
            &self.validator_set,
            None,
            &self.consensus_parameters,
            parent_timestamp,
        )?;
        let proposal = SignedProposalV0::new(
            block,
            witness,
            &self.validator_set,
            None,
            &self.consensus_parameters,
            parent_timestamp,
        )?;
        self.validation_artifacts.insert(
            proposal.block().id(),
            ValidationArtifacts { body, receipts },
        );
        Ok(Some(proposal))
    }

    fn derive_root(&self, label: &[u8], nonce: u64, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"TRNM_POCO_BFT_SIM_ROOT_V0");
        hasher.update(self.seed().to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update((payload.len() as u64).to_le_bytes());
        hasher.update(payload);
        hasher.finalize().into()
    }

    fn collect_replay(
        &self,
        finalized: BlockId,
        high: BlockId,
        locked: BlockId,
    ) -> Result<Vec<SignedProposalV0>, SimError> {
        let mut proposals = BTreeMap::new();
        for anchor in [high, locked] {
            let mut cursor = anchor;
            let mut seen = BTreeSet::new();
            while cursor != finalized {
                if !seen.insert(cursor) {
                    return Err(SimError::InvalidConfig("replay ancestry contains a cycle"));
                }
                let proposal = self
                    .proposals
                    .get(&cursor)
                    .cloned()
                    .ok_or(SimError::MissingProposal(cursor))?;
                let header = proposal.block().header();
                proposals.insert(
                    (header.height(), header.view(), proposal.block().id()),
                    proposal.clone(),
                );
                cursor = header.parent_id();
            }
        }
        Ok(proposals.into_values().collect())
    }

    fn collect_newly_finalized(
        &self,
        node: NodeId,
        proof: &FinalityProofV0,
    ) -> Result<Vec<(Height, BlockId)>, SimError> {
        let mut header = proof.finalized_block().header().clone();
        let mut newly_finalized = Vec::new();
        let applied = &self.nodes[node].applied;
        loop {
            let height = header.height();
            let block_id = header.id();
            if let Some(existing) = applied.get(&height) {
                if *existing != block_id {
                    return Err(SimError::InvalidConfig(
                        "application finality conflicts with its durable finalized prefix",
                    ));
                }
                break;
            }
            newly_finalized.push((height, block_id));
            let parent_height = height.get().checked_sub(1).ok_or(SimError::InvalidConfig(
                "network finalization cannot descend below height one",
            ))?;
            if parent_height == 0 {
                if header.parent_id() != GENESIS_BLOCK_ID {
                    return Err(SimError::InvalidConfig(
                        "height-one finalized block does not descend from genesis",
                    ));
                }
                match applied.get(&Height::new(0)) {
                    Some(existing) if *existing == GENESIS_BLOCK_ID => break,
                    _ => {
                        return Err(SimError::InvalidConfig(
                            "application finalized prefix is missing genesis",
                        ));
                    }
                }
            }
            let parent = self
                .proposals
                .get(&header.parent_id())
                .ok_or(SimError::MissingProposal(header.parent_id()))?;
            if parent.block().header().height() != Height::new(parent_height) {
                return Err(SimError::InvalidConfig(
                    "application finality ancestry has a non-consecutive height",
                ));
            }
            header = parent.block().header().clone();
        }
        Ok(newly_finalized)
    }

    fn record_applied_finalization(
        &mut self,
        node: NodeId,
        proof: &FinalityProofV0,
        newly_finalized: &[(Height, BlockId)],
    ) {
        for &(height, block_id) in newly_finalized.iter().rev() {
            self.nodes[node].applied.insert(height, block_id);
        }
        let height = proof.finalized_block().header().height();
        let block_id = proof.finalized_block().header().id();
        self.record(
            "finalization-applied",
            format!(
                "node={node} height={} block={} ancestors={}",
                height.get(),
                hex_block(block_id),
                newly_finalized.len()
            ),
        );
    }
}

impl Simulator {
    fn arm_node(&mut self, node: NodeId, view: View) {
        if self.nodes[node].core.is_none() || self.nodes[node].replaying || self.nodes[node].halted
        {
            return;
        }
        let incarnation = self.nodes[node].incarnation;
        self.schedule_after(1, Event::TryPropose { node, incarnation });
        self.schedule_after(
            self.config.timeout_ticks,
            Event::LocalTimeout {
                node,
                incarnation,
                view,
            },
        );
    }

    fn broadcast_inner(
        &mut self,
        from: NodeId,
        message: WireMessage,
        targets: Option<Vec<NodeId>>,
        remember: bool,
    ) {
        if remember {
            let key = (from, message.fingerprint());
            if self.gossip_keys.insert(key) {
                self.gossip.push((from, message.clone()));
            }
        }
        let targets = targets.unwrap_or_else(|| (0..self.nodes.len()).collect());
        for to in targets {
            if to >= self.nodes.len() {
                self.record("net-drop", format!("unknown-target from={from} to={to}"));
                continue;
            }
            self.schedule_network(from, to, message.clone());
        }
    }

    fn schedule_network(&mut self, from: NodeId, to: NodeId, message: WireMessage) {
        if !self.connected(from, to) {
            self.record(
                "net-drop",
                format!(
                    "partition-send from={from} to={to} message={}",
                    message.fingerprint()
                ),
            );
            return;
        }
        let mut dropped = false;
        let mut extra_delay = 0u64;
        let mut extra_copies = 0usize;
        for rule in &mut self.fault_rules {
            if !rule.matches(message.kind(), from, to) {
                continue;
            }
            rule.remaining -= 1;
            match rule.action {
                FaultAction::Drop => dropped = true,
                FaultAction::Duplicate(copies) => {
                    extra_copies = extra_copies.saturating_add(copies)
                }
                FaultAction::Delay(ticks) => extra_delay = extra_delay.saturating_add(ticks),
            }
        }
        if dropped {
            self.record(
                "fault-drop",
                format!("from={from} to={to} message={}", message.fingerprint()),
            );
            return;
        }
        let base_delay = if from == to {
            1
        } else {
            1 + self.next_random() % self.config.maximum_network_delay
        };
        for copy in 0..=extra_copies {
            self.schedule_after(
                base_delay
                    .saturating_add(extra_delay)
                    .saturating_add(copy as u64),
                Event::Deliver {
                    from,
                    to,
                    message: message.clone(),
                    attempt: 0,
                },
            );
        }
        if extra_copies > 0 || extra_delay > 0 {
            self.record(
                "fault-shape",
                format!(
                    "from={from} to={to} delay={extra_delay} copies={extra_copies} message={}",
                    message.fingerprint()
                ),
            );
        }
    }

    fn gossip_to(&mut self, target: NodeId) {
        let gossip = self.gossip.clone();
        for (from, message) in gossip {
            self.broadcast_inner(from, message, Some(vec![target]), false);
        }
    }

    fn connected(&self, from: NodeId, to: NodeId) -> bool {
        from == to
            || self
                .components
                .as_ref()
                .is_none_or(|components| components[from] == components[to])
    }

    fn incarnation_is_current(&self, node: NodeId, incarnation: u64) -> bool {
        self.nodes
            .get(node)
            .is_some_and(|state| state.core.is_some() && state.incarnation == incarnation)
    }

    fn schedule_after(&mut self, delay: u64, event: Event) {
        let tick = self.tick.saturating_add(delay);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.queue.insert((tick, sequence), event);
    }

    fn next_random(&mut self) -> u64 {
        if self.rng_state == 0 {
            self.rng_state = 0xD1B5_4A32_D192_ED03;
        }
        let mut value = self.rng_state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.rng_state = value;
        value
    }

    fn record(&mut self, code: &'static str, detail: String) {
        self.trace.push(self.tick, code, detail);
    }
}

#[derive(Debug, Clone, Copy)]
struct MockSignatures;

impl SignatureVerifier for MockSignatures {
    fn verify(
        &self,
        validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        signature == &mock_signature_for(validator, *signing_root)
    }
}

fn fixture_validator_set(
    count: usize,
    consensus_parameters: &ConsensusParametersV0,
) -> Result<ValidatorSet, ValidationError> {
    let validators = (0..count)
        .map(|index| {
            let marker = u8::try_from(index + 1).expect("validator count is bounded by 100");
            Validator::new(
                ValidatorId::new([marker; 32]),
                ConsensusPublicKey::new([marker.wrapping_add(100); 32]),
                VotingPower::new(1)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ValidatorSet::new(
        GenesisHash::new([0xA5; 32]),
        CHAIN_ID,
        ProtocolVersion::V0,
        Epoch::new(0),
        consensus_parameters.hash(),
        validators,
    )
}

fn fixture_genesis_qc(set: &ValidatorSet) -> Result<GenesisQcV0, ValidationError> {
    GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set)
}

fn signed_vote(
    set: &ValidatorSet,
    view: View,
    height: Height,
    block_id: BlockId,
    author: ValidatorId,
) -> Result<Vote, ValidationError> {
    let root = Vote::signing_root_for_set(set, view, height, block_id)?;
    let validator = set
        .validator(author)
        .ok_or_else(|| ValidationError::UnknownValidator(Box::new(author)))?;
    Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        height,
        block_id,
        set.id(),
        author,
        mock_signature_for(validator, root),
        set,
    )
}

/// Constructs an out-of-model adversarial vote with access to the fixture key.
///
/// Normal node signatures only flow through `Effect::RequestSignature`. This
/// helper is intentionally restricted to explicit Byzantine injection APIs.
fn privileged_forged_vote(
    set: &ValidatorSet,
    view: View,
    height: Height,
    block_id: BlockId,
    author: ValidatorId,
) -> Result<Vote, ValidationError> {
    signed_vote(set, view, height, block_id, author)
}

fn mock_signature_for(validator: &Validator, root: SigningRoot) -> SignatureBytes {
    let mut bytes = [0u8; SIGNATURE_BYTES];
    for (index, chunk) in bytes.chunks_exact_mut(32).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(b"TRNM_POCO_BFT_SIM_SIGNATURE_V0");
        hasher.update([u8::try_from(index).expect("signature has exactly two chunks")]);
        hasher.update(validator.consensus_key().as_bytes());
        hasher.update(root.as_bytes());
        chunk.copy_from_slice(&hasher.finalize());
    }
    SignatureBytes::from_array(bytes)
}

fn first_chain_conflict(
    left: &BTreeMap<Height, BlockId>,
    right: &BTreeMap<Height, BlockId>,
) -> Option<(Height, BlockId, BlockId)> {
    left.iter().find_map(|(height, left_block)| {
        right
            .get(height)
            .filter(|right_block| *right_block != left_block)
            .map(|right_block| (*height, *left_block, *right_block))
    })
}

fn applied_chain_is_complete(chain: &BTreeMap<Height, BlockId>) -> bool {
    let mut expected = 0u64;
    for height in chain.keys() {
        if height.get() != expected {
            return false;
        }
        let Some(next) = expected.checked_add(1) else {
            return false;
        };
        expected = next;
    }
    !chain.is_empty()
}

fn safety_state_trace_digest(state: &SafetyState) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TRNM_POCO_BFT_SIM_SAFETY_STATE_TRACE_V0");
    hasher.update(state.schema_version().to_le_bytes());
    hasher.update((state.chain_id().as_bytes().len() as u64).to_le_bytes());
    hasher.update(state.chain_id().as_bytes());
    hasher.update(state.protocol_version().get().to_le_bytes());
    hasher.update(state.epoch().get().to_le_bytes());
    hasher.update(state.validator_set_id().as_bytes());
    hasher.update(state.genesis_block_id().as_bytes());
    hasher.update(state.current_view().get().to_le_bytes());
    update_optional_view(&mut hasher, state.last_voted_view());
    update_optional_view(&mut hasher, state.last_timeout_view());
    hasher.update(state.high_qc().id().as_bytes());
    hasher.update(state.locked_qc().id().as_bytes());
    let finalized = state.finalized();
    hasher.update(finalized.height().get().to_le_bytes());
    hasher.update(finalized.view().get().to_le_bytes());
    hasher.update(finalized.block_id().as_bytes());
    hasher.update(finalized.timestamp_ms().to_le_bytes());
    hasher.update(state.revision().to_le_bytes());
    hasher.update((state.payload_terminal_facts().len() as u64).to_le_bytes());
    for fact in state.payload_terminal_facts() {
        hasher.update(fact.block_id().as_bytes());
        hasher.update([payload_terminal_tag(fact.result())]);
        match fact.valid_overlay() {
            None => hasher.update([0]),
            Some(overlay) => {
                hasher.update([1]);
                update_overlay_ref_trace_digest(&mut hasher, overlay);
            }
        }
        hasher.update(fact.first_recorded_revision().to_le_bytes());
    }
    hasher.update(b"TRNM_POCO_BFT_SIM_PAYLOAD_VALIDATION_OBLIGATIONS_V0");
    hasher.update((state.payload_validation_obligations().len() as u64).to_le_bytes());
    for obligation in state.payload_validation_obligations() {
        update_payload_validation_obligation_trace_digest(&mut hasher, obligation);
    }
    hasher.update(b"TRNM_POCO_BFT_SIM_PAYLOAD_VALIDATION_COMPLETIONS_V0");
    hasher.update((state.payload_validation_completions().len() as u64).to_le_bytes());
    for completion in state.payload_validation_completions() {
        update_payload_validation_completion_trace_digest(&mut hasher, completion);
    }
    match state.pending_tc_high_qc_sync() {
        None => hasher.update([0]),
        Some(pending) => {
            hasher.update([1]);
            hasher.update(pending.certificate_id().as_bytes());
            hasher.update(pending.timed_out_view().get().to_le_bytes());
            let selected = pending.selected_high_qc();
            let selected_ref = selected.qc_ref();
            hasher.update(selected.id().as_bytes());
            hasher.update(selected_ref.epoch().get().to_le_bytes());
            hasher.update(selected_ref.view().get().to_le_bytes());
            hasher.update(selected_ref.height().get().to_le_bytes());
            hasher.update(selected_ref.block_id().as_bytes());
            hasher.update(selected_ref.validator_set_id().as_bytes());
        }
    }
    match state.pending_standalone_qc_sync() {
        None => hasher.update([0]),
        Some(pending) => {
            hasher.update([1]);
            update_qc_trace_digest(&mut hasher, pending.active());
            hasher.update((pending.backlog().len() as u64).to_le_bytes());
            for certificate in pending.backlog() {
                update_qc_trace_digest(&mut hasher, certificate);
            }
        }
    }
    match state.pending_sign() {
        None => hasher.update([0]),
        Some(SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            signing_root,
        }) => {
            hasher.update([1]);
            hasher.update(authorizing_safety_revision.to_le_bytes());
            hasher.update(view.get().to_le_bytes());
            hasher.update(height.get().to_le_bytes());
            hasher.update(block_id.as_bytes());
            hasher.update(signing_root.as_bytes());
        }
        Some(SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            signing_root,
        }) => {
            hasher.update([2]);
            hasher.update(authorizing_safety_revision.to_le_bytes());
            hasher.update(view.get().to_le_bytes());
            hasher.update(high_qc.qc_digest().as_bytes());
            hasher.update(high_qc.epoch().get().to_le_bytes());
            hasher.update(high_qc.view().get().to_le_bytes());
            hasher.update(high_qc.height().get().to_le_bytes());
            hasher.update(high_qc.block_id().as_bytes());
            hasher.update(high_qc.validator_set_id().as_bytes());
            hasher.update(signing_root.as_bytes());
        }
    }
    update_optional_certificate(
        &mut hasher,
        state.last_finalization_proof().map(FinalityProofV0::id),
    );
    match state.last_finalization() {
        None => hasher.update([0]),
        Some(finalization) => {
            hasher.update([1]);
            let parent = finalization.authenticated_parent();
            hasher.update(parent.height().get().to_le_bytes());
            hasher.update(parent.view().get().to_le_bytes());
            hasher.update(parent.block_id().as_bytes());
            hasher.update(parent.timestamp_ms().to_le_bytes());
        }
    }
    update_optional_certificate(&mut hasher, state.pending_finalize());
    match state.safety_halt() {
        None => hasher.update([0]),
        Some(SafetyHalt::ConflictingQuorumCertificates { first, second }) => {
            hasher.update([1]);
            hasher.update(first.id().as_bytes());
            hasher.update(second.id().as_bytes());
        }
        Some(SafetyHalt::ConflictingPayloadValidation {
            block_id,
            first,
            second,
        }) => {
            hasher.update([2]);
            hasher.update(block_id.as_bytes());
            hasher.update([payload_terminal_tag(*first), payload_terminal_tag(*second)]);
        }
        Some(SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference,
        }) => {
            hasher.update([3]);
            hasher.update(block_id.as_bytes());
            match reference {
                InvalidPayloadReference::QuorumCertificate(certificate) => {
                    hasher.update([1]);
                    hasher.update(certificate.id().as_bytes());
                }
                InvalidPayloadReference::TimeoutCertificate(certificate) => {
                    hasher.update([3]);
                    hasher.update(certificate.id().as_bytes());
                }
                InvalidPayloadReference::PendingVote(intent) => {
                    hasher.update([2]);
                    match intent.as_ref() {
                        SignIntent::Vote {
                            authorizing_safety_revision,
                            view,
                            height,
                            block_id,
                            signing_root,
                        } => {
                            hasher.update([1]);
                            hasher.update(authorizing_safety_revision.to_le_bytes());
                            hasher.update(view.get().to_le_bytes());
                            hasher.update(height.get().to_le_bytes());
                            hasher.update(block_id.as_bytes());
                            hasher.update(signing_root.as_bytes());
                        }
                        SignIntent::TimeoutVote {
                            authorizing_safety_revision,
                            view,
                            high_qc,
                            signing_root,
                        } => {
                            hasher.update([2]);
                            hasher.update(authorizing_safety_revision.to_le_bytes());
                            hasher.update(view.get().to_le_bytes());
                            hasher.update(high_qc.qc_digest().as_bytes());
                            hasher.update(signing_root.as_bytes());
                        }
                    }
                }
            }
        }
    }
    hasher.finalize().into()
}

fn update_payload_validation_obligation_trace_digest(
    hasher: &mut Sha256,
    obligation: &DurablePayloadValidationObligationV0,
) {
    hasher.update([payload_validation_route_tag(obligation.route())]);

    let id = obligation.id();
    hasher.update(id.block_id().as_bytes());
    hasher.update(id.view().get().to_le_bytes());
    hasher.update(id.generation().to_le_bytes());

    let proposal = obligation.proposal();
    let block = proposal.block();
    let header_bytes = block
        .header()
        .try_cev0_bytes()
        .expect("durable validation proposal stores a canonical header");
    update_trace_bytes(hasher, &header_bytes);
    update_trace_bytes(hasher, block.application_payload());
    hasher.update((block.evidence_objects().len() as u64).to_le_bytes());
    for evidence in block.evidence_objects() {
        update_trace_bytes(hasher, evidence);
    }

    let witness = proposal.witness();
    match witness.justify_qc() {
        QcReferenceV0::Ordinary(certificate) => {
            hasher.update([1]);
            let bytes = certificate
                .try_cev0_bytes()
                .expect("durable validation proposal stores a canonical ordinary QC");
            update_trace_bytes(hasher, &bytes);
        }
        QcReferenceV0::Synthetic(anchor) => {
            hasher.update([2]);
            let bytes = anchor
                .try_cev0_bytes()
                .expect("durable validation proposal stores a canonical synthetic QC");
            update_trace_bytes(hasher, &bytes);
        }
    }
    match witness.timeout_certificate() {
        None => hasher.update([0]),
        Some(certificate) => {
            hasher.update([1]);
            let bytes = certificate
                .try_cev0_bytes()
                .expect("durable validation proposal stores a canonical timeout certificate");
            update_trace_bytes(hasher, &bytes);
        }
    }
    match witness.epoch_anchor_authorization() {
        None => hasher.update([0]),
        Some(authorization) => {
            hasher.update([1]);
            let bytes = authorization
                .try_cev0_bytes()
                .expect("durable validation proposal stores a canonical epoch authorization");
            update_trace_bytes(hasher, &bytes);
        }
    }
    update_trace_bytes(hasher, witness.proposer_signature().as_bytes());

    let parent = obligation.parent();
    let tip = parent.tip();
    hasher.update(tip.height().get().to_le_bytes());
    hasher.update(tip.view().get().to_le_bytes());
    hasher.update(tip.block_id().as_bytes());
    hasher.update(tip.timestamp_ms().to_le_bytes());
    match parent.exact_header() {
        None => hasher.update([0]),
        Some(header) => {
            hasher.update([1]);
            let bytes = header
                .try_cev0_bytes()
                .expect("durable validation parent stores a canonical header");
            update_trace_bytes(hasher, &bytes);
        }
    }

    hasher.update(obligation.first_recorded_revision().to_le_bytes());
}

fn update_payload_validation_completion_trace_digest(
    hasher: &mut Sha256,
    completion: &DurablePayloadValidationCompletionV0,
) {
    hasher.update([payload_validation_route_tag(completion.route())]);

    let id = completion.id();
    hasher.update(id.block_id().as_bytes());
    hasher.update(id.view().get().to_le_bytes());
    hasher.update(id.generation().to_le_bytes());

    match completion.result() {
        DurablePayloadValidationResultV1::Valid {
            commitments,
            artifact_ref,
        } => {
            hasher.update([1]);
            hasher.update(commitments.block_id().as_bytes());
            hasher.update(commitments.logical_block_size().to_le_bytes());
            hasher.update(commitments.transaction_count().to_le_bytes());
            hasher.update(commitments.evidence_count().to_le_bytes());
            update_overlay_ref_trace_digest(hasher, artifact_ref.overlay());
            hasher.update(artifact_ref.source_artifact_checksum());
        }
        DurablePayloadValidationResultV1::Unavailable => hasher.update([2]),
        DurablePayloadValidationResultV1::DeterministicallyInvalid => hasher.update([3]),
    }

    hasher.update(completion.first_recorded_revision().to_le_bytes());
}

fn simulated_artifact_ref_v0(
    block_id: BlockId,
    parent_block_id: BlockId,
) -> ValidatedPayloadArtifactRefV0 {
    let overlay_checksum = Sha256::new()
        .chain_update(b"TRNM_POCO_BFT_SIM_OVERLAY_REF_V0")
        .chain_update(block_id.as_bytes())
        .chain_update(parent_block_id.as_bytes())
        .finalize()
        .into();
    let source_artifact_checksum = Sha256::new()
        .chain_update(b"TRNM_POCO_BFT_SIM_SOURCE_ARTIFACT_REF_V0")
        .chain_update(block_id.as_bytes())
        .chain_update(parent_block_id.as_bytes())
        .finalize()
        .into();
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(block_id, parent_block_id, overlay_checksum),
        source_artifact_checksum,
    )
}

fn simulated_finalization_readback_checksum_v0(
    label: &[u8],
    finalization_checksum: [u8; 32],
    route: PayloadValidationRouteV0,
    id: ValidationId,
    source_artifact_checksum: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"TRNM_POCO_BFT_SIM_INERT_FINALIZATION_READBACK_V0");
    hasher.update((CHAIN_ID.as_bytes().len() as u64).to_be_bytes());
    hasher.update(CHAIN_ID.as_bytes());
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(finalization_checksum);
    hasher.update([payload_validation_route_tag(route)]);
    hasher.update(id.block_id().as_bytes());
    hasher.update(id.view().get().to_be_bytes());
    hasher.update(id.generation().to_be_bytes());
    hasher.update(source_artifact_checksum);
    hasher.finalize().into()
}

/// Builds the simulator's deterministic, inert stand-in for one exact
/// ApplicationStore post-commit readback.
///
/// The source identity and artifact checksum come from the Core's durable
/// Valid completion for the exact queue-front overlay. The remaining row-like
/// checksums are domain-separated comparison bytes derived from that source
/// and carrier; no SQLite row, JMT apply, or durable receipt exists here.
fn simulated_application_finalization_readback_v0(
    safety: &SafetyState,
    authority: &CoreIssuedApplicationFinalizationApplyAuthorityV0,
    permit: &CoreIssuedApplicationFinalizationPermitV0,
) -> Result<ApplicationFinalizationApplyReadbackV0, SimError> {
    let finalization = permit.finalization();
    let target = finalization.proof().finalized_block().header();
    let target_overlay = finalization.target_overlay_ref();
    let source = safety
        .payload_validation_completions()
        .iter()
        .find_map(|completion| match completion.result() {
            DurablePayloadValidationResultV1::Valid { artifact_ref, .. }
                if completion.id().block_id() == target.id()
                    && artifact_ref.overlay() == target_overlay =>
            {
                Some((
                    completion.route(),
                    completion.id(),
                    artifact_ref.source_artifact_checksum(),
                ))
            }
            _ => None,
        })
        .ok_or(SimError::InvalidConfig(
            "finalization stand-in lacks the exact durable Valid source",
        ))?;
    let finalization_checksum = native_finalization_applied_checksum_v0(finalization)?;
    let checksum = |label: &[u8]| {
        simulated_finalization_readback_checksum_v0(
            label,
            finalization_checksum,
            source.0,
            source.1,
            source.2,
        )
    };
    authority
        .application_store_apply_readback_v0(
            permit,
            source.0,
            source.1,
            target.height().get(),
            checksum(b"application-host-config"),
            checksum(b"prior-head"),
            checksum(b"new-head"),
            source.2,
            checksum(b"accepted-source"),
            checksum(b"applied-job-row"),
            checksum(b"receipt-row"),
        )
        .map_err(Into::into)
}

fn update_overlay_ref_trace_digest(hasher: &mut Sha256, overlay: BlockIdOverlayRefV0) {
    hasher.update(overlay.block_id().as_bytes());
    hasher.update(overlay.parent_block_id().as_bytes());
    hasher.update(overlay.overlay_checksum());
}

fn update_trace_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn update_qc_trace_digest(hasher: &mut Sha256, certificate: &QuorumCertificate) {
    hasher.update(certificate.id().as_bytes());
    hasher.update(certificate.epoch().get().to_le_bytes());
    hasher.update(certificate.view().get().to_le_bytes());
    hasher.update(certificate.height().get().to_le_bytes());
    hasher.update(certificate.block_id().as_bytes());
    hasher.update(certificate.validator_set_id().as_bytes());
}

const fn payload_terminal_tag(result: trnm_consensus_core::PayloadTerminalResult) -> u8 {
    match result {
        trnm_consensus_core::PayloadTerminalResult::Valid => 1,
        trnm_consensus_core::PayloadTerminalResult::DeterministicallyInvalid => 2,
    }
}

const fn payload_validation_route_tag(route: PayloadValidationRouteV0) -> u8 {
    match route {
        PayloadValidationRouteV0::Proposal => 1,
        PayloadValidationRouteV0::Synced => 2,
    }
}

const fn validation_route_v0(synced: bool) -> PayloadValidationRouteV0 {
    if synced {
        PayloadValidationRouteV0::Synced
    } else {
        PayloadValidationRouteV0::Proposal
    }
}

const fn payload_validation_label(result: PayloadValidationResult) -> &'static str {
    match result {
        PayloadValidationResult::Valid(_) => "valid",
        PayloadValidationResult::Unavailable => "unavailable",
        PayloadValidationResult::DeterministicallyInvalid => "deterministically-invalid",
    }
}

fn materialize_nonvalid_validation_outcome(
    outcome: ScriptedValidationOutcome,
) -> PayloadValidationResult {
    match outcome {
        ScriptedValidationOutcome::MismatchedValid | ScriptedValidationOutcome::Unavailable => {
            PayloadValidationResult::Unavailable
        }
        ScriptedValidationOutcome::DeterministicallyInvalid => {
            PayloadValidationResult::DeterministicallyInvalid
        }
        ScriptedValidationOutcome::Valid => {
            unreachable!("Valid must cross the application-sealed callback boundary")
        }
    }
}

const fn effective_validation_label(outcome: ScriptedValidationOutcome) -> &'static str {
    match outcome {
        ScriptedValidationOutcome::Valid => "valid",
        ScriptedValidationOutcome::MismatchedValid | ScriptedValidationOutcome::Unavailable => {
            payload_validation_label(PayloadValidationResult::Unavailable)
        }
        ScriptedValidationOutcome::DeterministicallyInvalid => {
            payload_validation_label(PayloadValidationResult::DeterministicallyInvalid)
        }
    }
}

const fn scripted_validation_label(result: ScriptedValidationOutcome) -> &'static str {
    match result {
        ScriptedValidationOutcome::Valid => "valid",
        ScriptedValidationOutcome::MismatchedValid => "mismatched-valid",
        ScriptedValidationOutcome::Unavailable => "unavailable",
        ScriptedValidationOutcome::DeterministicallyInvalid => "deterministically-invalid",
    }
}

fn safety_halt_fingerprint(halt: &SafetyHalt) -> String {
    match halt {
        SafetyHalt::ConflictingQuorumCertificates { first, second } => format!(
            "conflicting-qcs:first={}:second={}",
            hex_certificate(first.id()),
            hex_certificate(second.id())
        ),
        SafetyHalt::ConflictingPayloadValidation {
            block_id,
            first,
            second,
        } => format!(
            "conflicting-payload:block={}:first={}:second={}",
            hex_block(*block_id),
            payload_terminal_tag(*first),
            payload_terminal_tag(*second)
        ),
        SafetyHalt::DeterministicallyInvalidPayload {
            block_id,
            reference,
        } => {
            let carrier = match reference {
                InvalidPayloadReference::QuorumCertificate(certificate) => {
                    format!("qc:{}", hex_certificate(certificate.id()))
                }
                InvalidPayloadReference::TimeoutCertificate(certificate) => {
                    format!("tc:{}", hex_certificate(certificate.id()))
                }
                InvalidPayloadReference::PendingVote(intent) => match intent.as_ref() {
                    SignIntent::Vote {
                        authorizing_safety_revision,
                        view,
                        height,
                        block_id,
                        signing_root,
                    } => format!(
                        "pending-vote:revision={authorizing_safety_revision}:view={}:height={}:block={}:root={}",
                        view.get(),
                        height.get(),
                        hex_block(*block_id),
                        hex_bytes(signing_root.as_bytes())
                    ),
                    SignIntent::TimeoutVote {
                        authorizing_safety_revision,
                        view,
                        high_qc,
                        signing_root,
                    } => format!(
                        "pending-timeout:revision={authorizing_safety_revision}:view={}:high-qc={}:root={}",
                        view.get(),
                        hex_certificate(high_qc.qc_digest()),
                        hex_bytes(signing_root.as_bytes())
                    ),
                },
            };
            format!(
                "deterministically-invalid-payload:block={}:carrier={carrier}",
                hex_block(*block_id)
            )
        }
    }
}

fn update_optional_view(hasher: &mut Sha256, view: Option<View>) {
    match view {
        None => hasher.update([0]),
        Some(view) => {
            hasher.update([1]);
            hasher.update(view.get().to_le_bytes());
        }
    }
}

fn update_optional_certificate(hasher: &mut Sha256, certificate: Option<CertificateId>) {
    match certificate {
        None => hasher.update([0]),
        Some(certificate) => {
            hasher.update([1]);
            hasher.update(certificate.as_bytes());
        }
    }
}

fn hex_block(value: BlockId) -> String {
    hex_bytes(value.as_bytes())
}

fn hex_certificate(value: CertificateId) -> String {
    hex_bytes(value.as_bytes())
}

fn hex_validator(value: ValidatorId) -> String {
    hex_bytes(value.as_bytes())
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_layout_requires_snapshot_lead_to_cover_finality() {
        assert!(SimConfig::new(4, 1)
            .expect("valid base config")
            .with_epoch_layout(6, 2)
            .is_err());
        assert!(SimConfig::new(4, 1)
            .expect("valid base config")
            .with_epoch_layout(6, 3)
            .is_ok());
    }

    fn take_synced_validation_callback(
        simulator: &mut Simulator,
        node: NodeId,
        block_id: BlockId,
    ) -> (u64, ValidationId, u64) {
        for _ in 0..8 {
            if let Some((key, event)) =
                simulator.queue.iter().find_map(|(key, event)| match event {
                    Event::PersistAck {
                        node: queued_node, ..
                    } if *queued_node == node => Some((*key, event.clone())),
                    _ => None,
                })
            {
                simulator.queue.remove(&key);
                simulator
                    .handle_event(event)
                    .expect("the synced proposal persistence is acknowledged");
                continue;
            }

            let (key, event) = simulator
                .queue
                .iter()
                .find_map(|(key, event)| match event {
                    Event::Validate {
                        node: queued_node,
                        id,
                        synced: true,
                        ..
                    } if *queued_node == node && id.block_id() == block_id => {
                        Some((*key, event.clone()))
                    }
                    _ => None,
                })
                .expect("the core emits a real synced validation request");
            simulator.queue.remove(&key);
            let Event::Validate {
                incarnation,
                id,
                replay_generation: Some(replay_generation),
                ..
            } = event
            else {
                panic!("selected event is the expected synced validation callback");
            };
            return (incarnation, id, replay_generation);
        }
        panic!(
            "synced validation request did not emerge after bounded persistence acknowledgements"
        );
    }

    fn acknowledge_next_persistence(simulator: &mut Simulator, node: NodeId) -> SafetyState {
        let (key, event, state) = simulator
            .queue
            .iter()
            .find_map(|(key, event)| match event {
                Event::PersistAck {
                    node: queued_node,
                    state,
                    ..
                } if *queued_node == node => Some((*key, event.clone(), state.as_ref().clone())),
                _ => None,
            })
            .expect("the core cleanup is waiting on a persistence acknowledgement");
        simulator.queue.remove(&key);
        simulator
            .handle_event(event)
            .expect("the cleanup persistence is acknowledged");
        state
    }

    fn take_next_current_finalization_event(
        simulator: &mut Simulator,
        selected_node: Option<NodeId>,
    ) -> (NodeId, u64, DurableFinalizationV0, u8) {
        simulator.start();
        for _ in 0..100_000 {
            let Some((key, event)) = simulator.queue.pop_first() else {
                panic!("the running simulator exhausted its queue before finalization");
            };
            simulator.tick = key.0;
            match event {
                Event::FinalizationApplied {
                    node,
                    incarnation,
                    proof,
                    attempt,
                } if simulator.incarnation_is_current(node, incarnation)
                    && selected_node.is_none_or(|selected| selected == node) =>
                {
                    return (node, incarnation, *proof, attempt);
                }
                event => simulator
                    .handle_event(event)
                    .expect("events preceding the selected finalization remain safe"),
            }
        }
        panic!("the simulator did not expose finalization within the bounded event budget");
    }

    fn register_real_synced_validation(
        simulator: &mut Simulator,
        node: NodeId,
    ) -> (SignedProposalV0, u64, ValidationId, u64) {
        let view = simulator.nodes[node].safety().current_view();
        let leader = leader_for(&simulator.validator_set, view);
        let leader_node = simulator
            .nodes
            .iter()
            .position(|candidate| candidate.validator == leader)
            .expect("the scheduled leader is present");
        let proposal = simulator
            .build_proposal(leader_node)
            .expect("the proposal fixture is valid")
            .expect("the initial view needs no timeout certificate");
        let block_id = proposal.block().id();
        simulator.proposals.insert(block_id, proposal.clone());
        let effects = simulator.nodes[node]
            .core
            .as_mut()
            .expect("the target node is online")
            .step(
                Input::SyncedProposal(Box::new(proposal.clone())),
                &MockSignatures,
            )
            .expect("the real synced proposal is accepted");
        simulator
            .process_effects(node, effects)
            .expect("the real synced validation effect is scheduled");
        let (incarnation, id, replay_generation) =
            take_synced_validation_callback(simulator, node, block_id);
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("the target node remains online")
                .pending_validation_count(),
            1
        );
        (proposal, incarnation, id, replay_generation)
    }

    #[test]
    fn conflicting_applied_tips_at_different_heights_are_detected() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 7).expect("valid config")).expect("valid simulator");
        simulator.nodes[0]
            .applied
            .insert(Height::new(1), BlockId::new([0xA1; 32]));
        simulator.nodes[1]
            .applied
            .insert(Height::new(1), BlockId::new([0xB1; 32]));
        simulator.nodes[1]
            .applied
            .insert(Height::new(2), BlockId::new([0xB2; 32]));

        assert!(simulator.has_conflicting_finality());
    }

    #[test]
    fn different_height_tips_on_one_prefix_are_not_conflicting() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 8).expect("valid config")).expect("valid simulator");
        let first = BlockId::new([0xA1; 32]);
        simulator.nodes[0].applied.insert(Height::new(1), first);
        simulator.nodes[1].applied.insert(Height::new(1), first);
        simulator.nodes[1]
            .applied
            .insert(Height::new(2), BlockId::new([0xA2; 32]));

        assert!(!simulator.has_conflicting_finality());
    }

    #[test]
    fn oracle_observes_pending_persistence_and_finalization_outbox() {
        let mut simulator = Simulator::new(
            SimConfig::new(4, 17)
                .expect("valid config")
                .with_timeout_ticks(32)
                .expect("valid timeout"),
        )
        .expect("valid simulator");
        simulator.start();

        assert!(simulator
            .run_until(40_000, |state| {
                state.queue.values().any(|event| {
                    matches!(
                        event,
                        Event::PersistAck { state, .. }
                            if state.finalized().height() > Height::new(0)
                    )
                })
            })
            .expect("simulation remains safe"));
        let observations = simulator
            .finality_observations()
            .expect("pending persistence is observable");
        assert!(observations
            .iter()
            .any(|observation| observation.layer.starts_with("pending-persist:")));

        assert!(simulator
            .run_until(40_000, |state| {
                state
                    .queue
                    .values()
                    .any(|event| matches!(event, Event::FinalizationApplied { .. }))
            })
            .expect("simulation remains safe"));
        let observations = simulator
            .finality_observations()
            .expect("pending finalization is observable");
        assert!(observations
            .iter()
            .any(|observation| observation.layer.starts_with("pending-finalize:")));
    }

    #[test]
    fn public_core_clone_rejects_finalization_receipt_and_preserves_exact_retry_owner() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 41).expect("valid config")).expect("valid simulator");
        let (node, incarnation, proof, attempt) =
            take_next_current_finalization_event(&mut simulator, None);
        simulator
            .prepare_simulated_finalization_receipt_v0(node, &proof)
            .expect("the simulated application applies the exact queue front");
        let expected_readback = simulator.nodes[node]
            .pending_application_finalization_readback
            .clone()
            .expect("the in-memory apply retains its deterministic projection");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_some());

        let original = simulator.nodes[node]
            .core
            .take()
            .expect("the issuing Core is online");
        simulator.nodes[node].core = Some(original.clone());
        let error = simulator
            .handle_finalization(node, incarnation, proof.clone(), attempt)
            .expect_err("a public Core clone has fresh finalization affinities");
        assert!(matches!(
            error,
            SimError::Core(CoreError::ApplicationFinalizationReceiptMismatch)
        ));
        assert_eq!(
            simulator.nodes[node]
                .pending_application_finalization_receipt
                .as_ref()
                .expect("the rejected sole owner is retained")
                .finalization(),
            &proof
        );
        assert_eq!(
            simulator.nodes[node]
                .pending_application_finalization_readback
                .as_ref(),
            Some(&expected_readback),
            "receipt rejection must retain the exact inert readback projection"
        );

        simulator.nodes[node].core = Some(original);
        simulator
            .handle_finalization(node, incarnation, proof, attempt)
            .expect("the same receipt owner retries against its issuing Core");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_readback
            .is_none());
    }

    #[test]
    fn foreign_finalization_receipt_is_rejected_by_exact_carrier_target_core() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 42).expect("valid config")).expect("valid simulator");
        let (node, incarnation, proof, attempt) =
            take_next_current_finalization_event(&mut simulator, None);
        let foreign_core = simulator.nodes[node]
            .core
            .as_ref()
            .expect("the target Core is online")
            .clone();
        let foreign_authority = foreign_core
            .issue_application_finalization_apply_authority_v0()
            .expect("the foreign public clone has one fresh authority");
        let foreign_permit = foreign_core
            .issue_application_finalization_permit_v0()
            .expect("the foreign public clone exposes the same inert queue front");
        assert_eq!(foreign_permit.finalization(), &proof);
        let newly_finalized = simulator
            .collect_newly_finalized(node, &proof)
            .expect("the exact application prefix is available");
        simulator.record_applied_finalization(node, &proof, &newly_finalized);
        let foreign_readback = simulated_application_finalization_readback_v0(
            foreign_core.safety_state(),
            &foreign_authority,
            &foreign_permit,
        )
        .expect("the foreign in-memory host projects its exact queue front");
        simulator.nodes[node].pending_application_finalization_receipt = Some(
            foreign_authority
                .receipt_after_application_store_apply_v0(foreign_permit, foreign_readback.clone())
                .expect("the foreign permit matches its own foreign authority"),
        );
        simulator.nodes[node].pending_application_finalization_readback = Some(foreign_readback);

        let error = simulator
            .handle_finalization(node, incarnation, proof.clone(), attempt)
            .expect_err("equal durable carrier bytes do not confer foreign authority");
        assert!(matches!(
            error,
            SimError::Core(CoreError::ApplicationFinalizationReceiptMismatch)
        ));
        assert_eq!(
            simulator.nodes[node]
                .pending_application_finalization_receipt
                .as_ref()
                .expect("the foreign owner remains intact")
                .finalization(),
            &proof
        );

        let _original = simulator.nodes[node].core.replace(foreign_core);
        simulator.nodes[node].application_finalization_apply_authority = Some(foreign_authority);
        simulator
            .handle_finalization(node, incarnation, proof, attempt)
            .expect("the exact owner succeeds only against its issuing foreign Core");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
    }

    #[test]
    fn finalization_front_rotation_reuses_authority_but_requires_a_fresh_permit() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 43).expect("valid config")).expect("valid simulator");
        let (node, incarnation, first, first_attempt) =
            take_next_current_finalization_event(&mut simulator, None);
        assert!(matches!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("the selected Core is online")
                .issue_application_finalization_apply_authority_v0(),
            Err(CoreError::ApplicationFinalizationApplyAuthorityAlreadyIssued)
        ));
        let first_height = first.finalized_block().header().height();
        simulator
            .handle_finalization(node, incarnation, first, first_attempt)
            .expect("the first exact front is applied");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert!(simulator.nodes[node]
            .application_finalization_apply_authority
            .is_some());

        let (second_node, second_incarnation, second, second_attempt) =
            take_next_current_finalization_event(&mut simulator, Some(node));
        assert_eq!(second_node, node);
        assert!(second.finalized_block().header().height() > first_height);
        simulator
            .handle_finalization(
                second_node,
                second_incarnation,
                second.clone(),
                second_attempt,
            )
            .expect("front rotation permits the next ancestor with the same store authority");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert_eq!(
            simulator.nodes[node]
                .applied
                .get(&second.finalized_block().header().height()),
            Some(&second.finalized_block().header().id())
        );
    }

    #[test]
    fn crash_drops_finalization_capabilities_and_recovery_remints_exact_front() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 44).expect("valid config")).expect("valid simulator");
        let (node, old_incarnation, proof, _) =
            take_next_current_finalization_event(&mut simulator, None);
        simulator
            .prepare_simulated_finalization_receipt_v0(node, &proof)
            .expect("the pre-crash application apply mints one live receipt");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_some());

        simulator.crash(node).expect("the node crashes fail-closed");
        assert!(simulator.nodes[node]
            .application_finalization_apply_authority
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_readback
            .is_none());
        simulator
            .recover(node)
            .expect("the authenticated pending front recovers");
        assert!(simulator.nodes[node]
            .application_finalization_apply_authority
            .is_some());
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_readback
            .is_none());

        let (recovered_node, recovered_incarnation, recovered, recovered_attempt) =
            take_next_current_finalization_event(&mut simulator, Some(node));
        assert_eq!(recovered_node, node);
        assert_ne!(recovered_incarnation, old_incarnation);
        assert_eq!(recovered, proof);
        simulator
            .handle_finalization(
                recovered_node,
                recovered_incarnation,
                recovered,
                recovered_attempt,
            )
            .expect("the recovered Core remints and consumes only the exact durable front");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
    }

    #[test]
    fn busy_finalization_callback_retains_receipt_until_same_core_can_retry() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 45).expect("valid config")).expect("valid simulator");
        let (node, incarnation, proof, attempt) =
            take_next_current_finalization_event(&mut simulator, None);
        simulator
            .prepare_simulated_finalization_receipt_v0(node, &proof)
            .expect("the simulated application applies the exact queue front");
        let original = simulator.nodes[node]
            .core
            .take()
            .expect("the issuing Core is online");
        let mut busy_clone = original.clone();
        let busy_authority = busy_clone
            .issue_application_finalization_apply_authority_v0()
            .expect("the public clone has one independent authority");
        let busy_permit = busy_clone
            .issue_application_finalization_permit_v0()
            .expect("the public clone has one independent front permit");
        let busy_readback = simulated_application_finalization_readback_v0(
            busy_clone.safety_state(),
            &busy_authority,
            &busy_permit,
        )
        .expect("the busy clone projects its exact in-memory queue front");
        let busy_receipt = busy_authority
            .receipt_after_application_store_apply_v0(busy_permit, busy_readback)
            .expect("the busy clone permit matches its own authority");
        let busy_effects = busy_clone
            .step_application_finalization_receipt_v0(busy_receipt, &MockSignatures)
            .expect("the public clone stages its own persistence barrier");
        assert!(busy_effects
            .iter()
            .any(|effect| matches!(effect, Effect::PersistSafetyState(_))));
        simulator.nodes[node].core = Some(busy_clone);

        simulator
            .handle_finalization(node, incarnation, proof.clone(), attempt)
            .expect("Busy retains the owner and schedules an exact retry");
        assert_eq!(
            simulator.nodes[node]
                .pending_application_finalization_receipt
                .as_ref()
                .expect("Busy returned the sole owner")
                .finalization(),
            &proof
        );
        assert_eq!(
            simulator.nodes[node]
                .pending_application_finalization_readback
                .as_ref(),
            simulator.nodes[node]
                .pending_application_finalization_receipt
                .as_ref()
                .map(ApplicationFinalizationReceiptV0::application_store_readback_v0),
            "Busy must retain the exact inert projection beside its sole receipt owner"
        );
        assert!(simulator.trace.entries().iter().any(|entry| {
            entry.code() == "finalization-retry"
                && entry.detail().contains("phase=receipt")
                && entry.detail().contains(&format!("node={node}"))
        }));

        simulator.nodes[node].core = Some(original);
        let (retry_key, retry_event) = simulator
            .queue
            .iter()
            .find_map(|(key, event)| match event {
                Event::FinalizationApplied {
                    node: queued_node,
                    incarnation: queued_incarnation,
                    proof: queued_proof,
                    attempt: retry_attempt,
                } if *queued_node == node
                    && *queued_incarnation == incarnation
                    && queued_proof.as_ref() == &proof
                    && *retry_attempt == attempt + 1 =>
                {
                    Some((*key, event.clone()))
                }
                _ => None,
            })
            .expect("Busy scheduled the exact inert retry event");
        simulator.queue.remove(&retry_key);
        simulator.tick = retry_key.0;
        simulator
            .handle_event(retry_event)
            .expect("the same issuing Core consumes its returned receipt owner");
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_readback
            .is_none());
    }

    #[test]
    fn run_fails_before_processing_an_observed_cross_layer_fork() {
        let mut simulator = Simulator::new(
            SimConfig::new(4, 23)
                .expect("valid config")
                .with_timeout_ticks(32)
                .expect("valid timeout"),
        )
        .expect("valid simulator");
        simulator.start();
        assert!(simulator
            .run_until(40_000, |state| {
                state.nodes.iter().any(|node| {
                    node.core.as_ref().is_some_and(|core| {
                        core.safety_state().finalized().height() > Height::new(0)
                    })
                })
            })
            .expect("simulation reaches volatile finality"));

        let node = simulator
            .nodes
            .iter()
            .position(|node| {
                node.core
                    .as_ref()
                    .is_some_and(|core| core.safety_state().finalized().height() > Height::new(0))
            })
            .expect("one node finalized");
        let tip = simulator.nodes[node]
            .core
            .as_ref()
            .expect("selected node is online")
            .safety_state()
            .finalized();
        let mut conflicting_application = simulator
            .chain_for_finalized_tip(node, "test", tip)
            .expect("simulator knows finalized ancestry");
        let mut conflicting_bytes = *tip.block_id().as_bytes();
        conflicting_bytes[0] ^= 0xFF;
        conflicting_application.insert(tip.height(), BlockId::new(conflicting_bytes));
        simulator.nodes[node].applied = conflicting_application;

        assert!(matches!(
            simulator.run_events(1),
            Err(SimError::ConflictingFinality(conflict)) if conflict.height == tip.height()
        ));
    }

    #[test]
    fn stale_replay_continuation_cannot_complete_a_new_request() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 29).expect("valid config")).expect("valid simulator");
        let node = 0;
        let request = ReplayRequest::Standalone {
            certificate_id: CertificateId::new([0x29; 32]),
        };
        simulator.nodes[node].replaying = true;
        simulator.nodes[node].replay_request = Some(request);
        simulator.nodes[node].replay_generation = 7;
        simulator.nodes[node].replay_queue.clear();
        let incarnation = simulator.nodes[node].incarnation;
        let trace_start = simulator.trace.entries().len();

        simulator
            .handle_replay_next(node, incarnation, 6, 0)
            .expect("a stale continuation is ignored");

        assert!(simulator.nodes[node].replaying);
        assert_eq!(simulator.nodes[node].replay_request, Some(request));
        assert_eq!(simulator.nodes[node].replay_generation, 7);
        assert!(!simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "replay-complete"));
    }

    #[test]
    fn public_core_clone_rejects_sealed_valid_without_destroying_exact_retry() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 27).expect("valid config")).expect("valid simulator");
        let node = 0;
        let (_proposal, incarnation, id, replay_generation) =
            register_real_synced_validation(&mut simulator, node);
        simulator.nodes[node].replaying = true;
        assert_eq!(
            simulator.nodes[node].replay_generation, replay_generation,
            "the affinity test must exercise the current synced callback, not the stale-event gate"
        );
        simulator.nodes[node]
            .scripted_validation_results
            .push_back(ScriptedValidationOutcome::Valid);

        let original = simulator.nodes[node]
            .core
            .take()
            .expect("the issuing Core is online");
        simulator.nodes[node].core = Some(original.clone());
        let error = simulator
            .handle_validation(node, incarnation, id, true, Some(replay_generation))
            .expect_err("a public Core clone has a foreign application/store affinity");
        assert!(matches!(
            error,
            SimError::Core(CoreError::ApplicationSealedValidMismatch(block_id))
                if block_id == id.block_id()
        ));
        let key = SimValidationKeyV0::new(PayloadValidationRouteV0::Synced, id);
        assert!(matches!(
            simulator.nodes[node]
                .validation_callbacks
                .get(&key)
                .map(|callback| &callback.capability),
            Some(SimValidationCapabilityV0::ApplicationSealed(_))
        ));

        simulator.nodes[node].core = Some(original);
        simulator
            .handle_validation(node, incarnation, id, true, Some(replay_generation))
            .expect("the borrowed proof retries against its exact issuing Core");
        assert!(!simulator.nodes[node]
            .validation_callbacks
            .contains_key(&key));
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("the issuing Core remains online")
                .pending_validation_count(),
            0
        );
    }

    #[test]
    fn crash_drops_non_durable_validation_capabilities_and_stale_event() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 28).expect("valid config")).expect("valid simulator");
        let node = 0;
        let (_proposal, incarnation, id, replay_generation) =
            register_real_synced_validation(&mut simulator, node);
        assert_eq!(simulator.nodes[node].validation_callbacks.len(), 1);
        assert!(simulator.nodes[node].application_seal_authority.is_some());
        assert!(simulator.nodes[node]
            .application_finalization_apply_authority
            .is_some());
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        simulator.nodes[node]
            .scripted_validation_results
            .push_back(ScriptedValidationOutcome::Valid);

        simulator.crash(node).expect("the node crashes fail-closed");
        assert!(simulator.nodes[node].validation_callbacks.is_empty());
        assert!(simulator.nodes[node].application_seal_authority.is_none());
        assert!(simulator.nodes[node]
            .application_finalization_apply_authority
            .is_none());
        assert!(simulator.nodes[node]
            .pending_application_finalization_receipt
            .is_none());
        simulator
            .handle_validation(node, incarnation, id, true, Some(replay_generation))
            .expect("the stale-incarnation event is discarded");
        assert_eq!(
            simulator.nodes[node].scripted_validation_results.front(),
            Some(&ScriptedValidationOutcome::Valid)
        );
        assert!(simulator.trace.entries().iter().any(|entry| {
            entry.code() == "local-drop"
                && entry.detail().contains("stale-validation")
                && entry.detail().contains(&format!("node={node}"))
        }));
    }

    #[test]
    fn stale_sync_validation_callback_cannot_consume_or_mutate_a_new_request() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 31).expect("valid config")).expect("valid simulator");
        let node = 0;
        let (_proposal, incarnation, stale_id, stale_generation) =
            register_real_synced_validation(&mut simulator, node);
        let request = ReplayRequest::Standalone {
            certificate_id: CertificateId::new([0x31; 32]),
        };
        simulator.nodes[node].replaying = true;
        simulator.nodes[node].replay_request = Some(request);
        simulator.nodes[node].replay_generation = stale_generation + 1;
        simulator.nodes[node].replay_queue.clear();
        simulator.nodes[node].replay_blocks.clear();
        simulator.nodes[node]
            .scripted_validation_results
            .push_back(ScriptedValidationOutcome::MismatchedValid);
        let safety_before = simulator.nodes[node]
            .core
            .as_ref()
            .expect("node is online")
            .safety_state()
            .clone();
        assert_eq!(safety_before.payload_validation_obligations().len(), 1);
        let trace_start = simulator.trace.entries().len();

        simulator
            .handle_validation(node, incarnation, stale_id, true, Some(stale_generation))
            .expect("a stale validation result is discarded after exact cancellation");
        let canceled = acknowledge_next_persistence(&mut simulator, node);

        assert!(simulator.nodes[node].replaying);
        assert_eq!(simulator.nodes[node].replay_request, Some(request));
        assert_eq!(
            simulator.nodes[node].replay_generation,
            stale_generation + 1
        );
        assert_eq!(
            simulator.nodes[node].scripted_validation_results.front(),
            Some(&ScriptedValidationOutcome::MismatchedValid)
        );
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("node remains online")
                .pending_validation_count(),
            0
        );
        assert!(canceled.payload_validation_obligations().is_empty());
        assert_eq!(canceled.revision(), safety_before.revision() + 1);
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("node remains online")
                .safety_state(),
            &canceled
        );
        assert!(simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "stale-sync-validation-callback"));
        assert!(!simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "sync-validated"));
        assert!(!simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "rebind-sync-validation-callback"));
    }

    #[test]
    fn overlapping_replay_rebinds_stale_validation_without_consuming_its_fault() {
        let mut simulator =
            Simulator::new(SimConfig::new(4, 37).expect("valid config")).expect("valid simulator");
        let node = 0;
        let (proposal, incarnation, stale_id, stale_generation) =
            register_real_synced_validation(&mut simulator, node);
        let block_id = proposal.block().id();
        let current_generation = stale_generation + 1;
        simulator.nodes[node].replaying = true;
        simulator.nodes[node].replay_request = Some(ReplayRequest::Standalone {
            certificate_id: CertificateId::new([0x37; 32]),
        });
        simulator.nodes[node].replay_generation = current_generation;
        simulator.nodes[node].replay_queue.clear();
        simulator.nodes[node].replay_blocks.clear();
        simulator.nodes[node].replay_blocks.insert(block_id);
        simulator.nodes[node]
            .replay_queue
            .push_back(proposal.clone());
        simulator.nodes[node]
            .scripted_validation_results
            .push_back(ScriptedValidationOutcome::Valid);
        let trace_start = simulator.trace.entries().len();

        simulator
            .handle_replay_next(node, incarnation, current_generation, 0)
            .expect("the replacement replay can arrive before the stale callback");
        assert!(simulator.nodes[node].replay_queue.is_empty());
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("node remains online")
                .pending_validation_count(),
            1
        );

        simulator
            .handle_validation(node, incarnation, stale_id, true, Some(stale_generation))
            .expect("the overlapping callback is rebound");
        let canceled = acknowledge_next_persistence(&mut simulator, node);
        assert!(canceled.payload_validation_obligations().is_empty());

        assert_eq!(
            simulator.nodes[node].scripted_validation_results.front(),
            Some(&ScriptedValidationOutcome::Valid)
        );
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("node remains online")
                .pending_validation_count(),
            0
        );
        assert!(simulator.nodes[node]
            .replay_queue
            .iter()
            .any(|queued| queued.block().id() == block_id));

        let (replay_key, replay_event) = simulator
            .queue
            .iter()
            .find_map(|(key, event)| match event {
                Event::ReplayNext {
                    node: queued_node,
                    incarnation: queued_incarnation,
                    replay_generation,
                    ..
                } if *queued_node == node
                    && *queued_incarnation == incarnation
                    && *replay_generation == current_generation =>
                {
                    Some((*key, event.clone()))
                }
                _ => None,
            })
            .expect("the replacement replay is queued");
        simulator.queue.remove(&replay_key);
        simulator
            .handle_event(replay_event)
            .expect("the replacement proposal is replayed into the core");

        let (current_incarnation, current_id, callback_generation) =
            take_synced_validation_callback(&mut simulator, node, block_id);
        assert_ne!(current_id, stale_id);
        assert_eq!(callback_generation, current_generation);
        simulator
            .handle_validation(
                node,
                current_incarnation,
                current_id,
                true,
                Some(callback_generation),
            )
            .expect("the replacement callback consumes the current scripted result");

        assert!(simulator.nodes[node].scripted_validation_results.is_empty());
        assert_eq!(
            simulator.nodes[node]
                .core
                .as_ref()
                .expect("node remains online")
                .pending_validation_count(),
            0
        );
        assert!(simulator
            .run_until(32, |state| !state.nodes[node].replaying)
            .expect("the replacement replay completes"));
        assert!(simulator.nodes[node].replay_request.is_none());
        assert!(simulator.nodes[node].replay_queue.is_empty());
        assert!(simulator.nodes[node].replay_blocks.is_empty());
        assert!(simulator.nodes[node].replay_generation > current_generation);
        assert!(simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "stale-sync-validation-callback"));
        assert!(simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "rebind-sync-validation-callback"));
        assert!(simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "sync-validated"));
        assert!(simulator.trace.entries()[trace_start..]
            .iter()
            .any(|entry| entry.code() == "replay-complete"));
    }

    #[test]
    fn deterministic_mock_signature_is_bound_to_validator_key() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = fixture_validator_set(4, &parameters).expect("valid fixture set");
        let first = &set.validators()[0];
        let second = &set.validators()[1];
        let root = Vote::signing_root_for_set(
            &set,
            View::new(7),
            Height::new(3),
            BlockId::new([0x77; 32]),
        )
        .expect("valid signing root");
        let signature = mock_signature_for(first, root);

        assert!(MockSignatures.verify(first, &root, &signature));
        assert!(!MockSignatures.verify(second, &root, &signature));
    }
}
