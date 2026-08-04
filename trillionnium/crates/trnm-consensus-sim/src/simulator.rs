use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};
use trnm_consensus_core::{
    leader_for, BarrierId, Core, CoreConfig, CoreError, Effect, Input, OutboundMessage,
    SafetyState, SignId, SignIntent, ValidationId,
};
use trnm_consensus_types::{
    Block, BlockHeader, BlockId, BlockKind, CanonicalSignable, CertificateId, ChainId, CommitProof,
    ConsensusParametersHash, ConsensusPublicKey, Epoch, EvidenceRoot, GenesisHash, Height,
    PayloadDigest, Proposal, ProposalJustification, ProtocolVersion, QuorumCertificate,
    ReceiptsRoot, SignatureBytes, SignatureVerifier, SigningRoot, StateRoot, TimeoutCertificate,
    TimeoutVote, ValidationError, Validator, ValidatorId, ValidatorSet, View, Vote, VotingPower,
    SIGNATURE_BYTES,
};

use crate::{Trace, TraceDigest};

pub type NodeId = usize;

const CHAIN_ID: ChainId = ChainId::from_static("trnm-poco-bft-sim-0");
const MAX_EVENT_RETRIES: u8 = 64;
pub const GENESIS_BLOCK_ID: BlockId = BlockId::new([0x42; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimConfig {
    validator_count: usize,
    seed: u64,
    maximum_network_delay: u64,
    timeout_ticks: u64,
    max_blocks: usize,
}

impl SimConfig {
    pub fn new(validator_count: usize, seed: u64) -> Result<Self, SimError> {
        if !(4..=100).contains(&validator_count) {
            return Err(SimError::InvalidConfig(
                "validator_count must be in the frozen 4..=100 range",
            ));
        }
        Ok(Self {
            validator_count,
            seed,
            maximum_network_delay: 3,
            timeout_ticks: 24,
            max_blocks: 256,
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
}

#[derive(Debug)]
pub enum SimError {
    InvalidConfig(&'static str),
    UnknownNode(NodeId),
    Protocol(ValidationError),
    Core(CoreError),
    MissingProposal(BlockId),
    MissingQuorumCertificate(CertificateId),
    NoProposalJustification { node: NodeId, view: View },
    ArithmeticOverflow(&'static str),
}

impl fmt::Display for SimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid simulator config: {reason}"),
            Self::UnknownNode(node) => write!(formatter, "unknown simulator node {node}"),
            Self::Protocol(error) => write!(formatter, "consensus type error: {error}"),
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
        }
    }
}

impl std::error::Error for SimError {}

impl From<ValidationError> for SimError {
    fn from(value: ValidationError) -> Self {
        Self::Protocol(value)
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
    pub durable_halted: bool,
    pub durable_revision: u64,
}

#[derive(Debug, Clone)]
enum WireMessage {
    Proposal(Box<Proposal>),
    Vote(Box<Vote>),
    TimeoutVote(Box<TimeoutVote>),
    QuorumCertificate(Box<QuorumCertificate>),
    TimeoutCertificate(Box<TimeoutCertificate>),
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
                hex_certificate(proposal.justification().certificate_id()),
                proposal
                    .justification()
                    .timeout_certificate_id()
                    .map(hex_certificate)
                .unwrap_or_else(|| "none".to_owned()),
                hex_validator(proposal.proposer()),
                hex_bytes(proposal.signing_root().as_bytes()),
                hex_bytes(proposal.signature().as_bytes())
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
                certificate.view().get(),
                hex_certificate(certificate.id()),
                hex_certificate(certificate.high_qc().id()),
                certificate.referenced_qcs().len(),
                certificate.timeout_votes().len()
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
        proof: Box<CommitProof>,
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
struct SimNode {
    validator: ValidatorId,
    config: CoreConfig,
    core: Option<Core>,
    durable: SafetyState,
    incarnation: u64,
    replaying: bool,
    recovering: bool,
    replay_queue: VecDeque<Proposal>,
    vote_pool: BTreeMap<VoteCoordinate, BTreeMap<ValidatorId, Vote>>,
    timeout_pool: BTreeMap<View, BTreeMap<ValidatorId, TimeoutVote>>,
    timeout_certificates: BTreeMap<View, TimeoutCertificate>,
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
}

#[derive(Debug)]
pub struct Simulator {
    config: SimConfig,
    validator_set: ValidatorSet,
    genesis_qc: QuorumCertificate,
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
    proposals: BTreeMap<BlockId, Proposal>,
    quorum_certificates: BTreeMap<CertificateId, QuorumCertificate>,
    timeout_certificates: BTreeMap<CertificateId, TimeoutCertificate>,
    formed_qcs: BTreeSet<VoteCoordinate>,
    formed_tcs: BTreeSet<View>,
    proposed_views: BTreeSet<(NodeId, View)>,
    gossip: Vec<(NodeId, WireMessage)>,
    gossip_keys: BTreeSet<(NodeId, String)>,
    evidence_count: usize,
}

impl Simulator {
    pub fn new(config: SimConfig) -> Result<Self, SimError> {
        let validator_set = fixture_validator_set(config.validator_count)?;
        let genesis_qc = fixture_genesis_qc(&validator_set)?;
        let mut nodes = Vec::with_capacity(config.validator_count);
        for validator in validator_set.validators() {
            let core_config = CoreConfig::new(
                validator.id(),
                validator_set.clone(),
                GENESIS_BLOCK_ID,
                config.max_blocks,
                4_096,
                4 * 1024 * 1024,
                1_000,
            )?;
            let core = Core::new(core_config.clone(), genesis_qc.clone(), &MockSignatures)?;
            let durable = core.safety_state().clone();
            let mut applied = BTreeMap::new();
            applied.insert(Height::new(0), GENESIS_BLOCK_ID);
            nodes.push(SimNode {
                validator: validator.id(),
                config: core_config,
                core: Some(core),
                durable,
                incarnation: 0,
                replaying: false,
                recovering: false,
                replay_queue: VecDeque::new(),
                vote_pool: BTreeMap::new(),
                timeout_pool: BTreeMap::new(),
                timeout_certificates: BTreeMap::new(),
                applied,
                durably_applied_height: Height::new(0),
                halted: false,
            });
        }
        let mut quorum_certificates = BTreeMap::new();
        quorum_certificates.insert(genesis_qc.id(), genesis_qc.clone());
        let seed = config.seed;
        let mut value = Self {
            config,
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
            quorum_certificates,
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

    pub const fn genesis_qc(&self) -> &QuorumCertificate {
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

    pub fn has_conflicting_finality(&self) -> bool {
        self.nodes.iter().enumerate().any(|(left_index, left)| {
            self.nodes
                .iter()
                .skip(left_index + 1)
                .any(|right| !applied_chains_are_prefix_comparable(&left.applied, &right.applied))
        })
    }

    pub fn latest_qc(&self) -> &QuorumCertificate {
        self.quorum_certificates
            .values()
            .max_by_key(|certificate| {
                (certificate.view(), certificate.block_id(), certificate.id())
            })
            .expect("genesis QC is always present")
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
        let revision = {
            let state = self
                .nodes
                .get_mut(node)
                .ok_or(SimError::UnknownNode(node))?;
            state.core = None;
            state.incarnation = state
                .incarnation
                .checked_add(1)
                .ok_or(SimError::ArithmeticOverflow("node incarnation"))?;
            state.replaying = false;
            state.recovering = false;
            state.replay_queue.clear();
            state.vote_pool.clear();
            state.timeout_pool.clear();
            state.timeout_certificates.clear();
            state.durable.revision()
        };
        self.record("crash", format!("node={node} durable={revision}"));
        Ok(())
    }

    pub fn recover(&mut self, node: NodeId) -> Result<(), SimError> {
        let (incarnation, revision) = {
            let state = self
                .nodes
                .get_mut(node)
                .ok_or(SimError::UnknownNode(node))?;
            let core = Core::recover(state.config.clone(), state.durable.clone(), &MockSignatures)?;
            state.core = Some(core);
            state.incarnation = state
                .incarnation
                .checked_add(1)
                .ok_or(SimError::ArithmeticOverflow("node incarnation"))?;
            state.replaying = false;
            state.recovering = true;
            state.replay_queue.clear();
            state.vote_pool.clear();
            state.timeout_pool.clear();
            state.timeout_certificates.clear();
            (state.incarnation, state.durable.revision())
        };
        self.record("recover", format!("node={node} durable={revision}"));
        self.schedule_after(1, Event::Resume { node, incarnation });
        Ok(())
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
            } => self.handle_validation(node, incarnation, id, synced),
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
            } => self.handle_finalization(node, incarnation, *proof),
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
                attempt,
            } => self.handle_replay_next(node, incarnation, attempt),
        }
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
                        .insert(certificate.view(), certificate.as_ref().clone());
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
        self.record(
            "persist-ack",
            format!(
                "node={node} barrier={} revision={revision} state={}",
                barrier.get(),
                hex_bytes(&state_digest)
            ),
        );
        let resume = self.nodes[node].recovering && effects.is_empty();
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
        let input = if synced {
            Input::SyncedPayloadValidated { id, valid: true }
        } else {
            Input::PayloadValidated { id, valid: true }
        };
        let result = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(input, &MockSignatures);
        match result {
            Ok(effects) => {
                self.record(
                    if synced {
                        "sync-validated"
                    } else {
                        "payload-validated"
                    },
                    format!(
                        "node={node} view={} generation={} block={}",
                        id.view().get(),
                        id.generation(),
                        hex_block(id.block_id())
                    ),
                );
                self.process_effects(node, effects)?;
                if synced {
                    self.schedule_after(
                        1,
                        Event::ReplayNext {
                            node,
                            incarnation,
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
                },
            ),
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
        proof: CommitProof,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) {
            self.record("local-drop", format!("stale-finalization node={node}"));
            return Ok(());
        }
        let newly_finalized = self.collect_newly_finalized(node, &proof)?;
        let effects = self.nodes[node]
            .core
            .as_mut()
            .expect("current incarnation is online")
            .step(
                Input::FinalizationApplied {
                    proof_id: proof.id(),
                },
                &MockSignatures,
            )?;
        self.record_applied_finalization(node, &proof, &newly_finalized);
        self.process_effects(node, effects)
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
                Effect::RequestSafetyReplay { .. } | Effect::ArmViewTimer { .. }
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
        attempt: u8,
    ) -> Result<(), SimError> {
        if !self.incarnation_is_current(node, incarnation) || !self.nodes[node].replaying {
            return Ok(());
        }
        if let Some(proposal) = self.nodes[node].replay_queue.front().cloned() {
            let result = self.nodes[node]
                .core
                .as_mut()
                .expect("current incarnation is online")
                .step(Input::Proposal(Box::new(proposal.clone())), &MockSignatures);
            match result {
                Ok(effects) => {
                    self.nodes[node].replay_queue.pop_front();
                    let waits_for_sync_validation = effects.iter().any(|effect| {
                        matches!(
                            effect,
                            Effect::PersistSafetyState { .. }
                                | Effect::ValidateSyncedPayload { .. }
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
                self.nodes[node].replaying = false;
                self.nodes[node].recovering = false;
                self.record("replay-complete", format!("node={node}"));
                self.process_effects(node, effects)?;
                self.gossip_to(node);
            }
            Err(CoreError::Busy(_)) if attempt < MAX_EVENT_RETRIES => self.schedule_after(
                1,
                Event::ReplayNext {
                    node,
                    incarnation,
                    attempt: attempt + 1,
                },
            ),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

impl Simulator {
    fn process_effects(&mut self, node: NodeId, effects: Vec<Effect>) -> Result<(), SimError> {
        let incarnation = self.nodes[node].incarnation;
        for effect in effects {
            match effect {
                Effect::PersistSafetyState { barrier, state } => {
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
                Effect::ValidatePayload { id, .. } => self.schedule_after(
                    1,
                    Event::Validate {
                        node,
                        incarnation,
                        id,
                        synced: false,
                    },
                ),
                Effect::ValidateSyncedPayload { id, .. } => self.schedule_after(
                    1,
                    Event::Validate {
                        node,
                        incarnation,
                        id,
                        synced: true,
                    },
                ),
                Effect::RequestSignature {
                    id, signing_root, ..
                } => self.schedule_after(
                    1,
                    Event::Signature {
                        node,
                        incarnation,
                        id,
                        root: signing_root,
                    },
                ),
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
                    let replay = self.collect_replay(
                        finalized.block_id(),
                        high_qc.block_id(),
                        locked_qc.block_id(),
                    )?;
                    self.nodes[node].replaying = true;
                    self.nodes[node].replay_queue = replay.into();
                    self.record(
                        "replay-request",
                        format!(
                            "node={node} finalized={} high={} locked={} count={}",
                            hex_block(finalized.block_id()),
                            hex_block(high_qc.block_id()),
                            hex_block(locked_qc.block_id()),
                            self.nodes[node].replay_queue.len()
                        ),
                    );
                    self.schedule_after(
                        1,
                        Event::ReplayNext {
                            node,
                            incarnation,
                            attempt: 0,
                        },
                    );
                }
                Effect::SafetyHalted(_) => {
                    self.nodes[node].halted = true;
                    self.record("safety-halt", format!("node={node}"));
                }
                Effect::Finalize(proof) => {
                    self.record(
                        "finalize-request",
                        format!(
                            "node={node} height={} block={} proof={}",
                            proof.committed().height().get(),
                            hex_block(proof.committed().id()),
                            hex_certificate(proof.id())
                        ),
                    );
                    self.schedule_after(
                        1,
                        Event::FinalizationApplied {
                            node,
                            incarnation,
                            proof,
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
        let mut referenced = BTreeMap::new();
        for vote in votes.values() {
            let digest = vote.high_qc().qc_digest();
            let certificate = self
                .quorum_certificates
                .get(&digest)
                .cloned()
                .ok_or(SimError::MissingQuorumCertificate(digest))?;
            referenced.insert(digest, certificate);
        }
        let selected = referenced
            .values()
            .max_by_key(|certificate| {
                (certificate.view(), certificate.block_id(), certificate.id())
            })
            .expect("a timeout quorum is nonempty")
            .id();
        let certificate = TimeoutCertificate::new_with_referenced_qcs(
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            self.validator_set.id(),
            referenced.into_values().collect(),
            selected,
            votes.values().cloned().collect(),
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
                hex_block(certificate.high_qc().block_id())
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

    fn build_proposal(&mut self, node: NodeId) -> Result<Option<Proposal>, SimError> {
        let safety = self.nodes[node].safety();
        let view = safety.current_view();
        let high_qc = safety.high_qc().clone();
        let justification = if high_qc.view().checked_next()? == view {
            ProposalJustification::quorum(high_qc.clone())
        } else {
            let Some(timeout_view) = view.get().checked_sub(1).map(View::new) else {
                return Err(SimError::NoProposalJustification { node, view });
            };
            let Some(certificate) = self.nodes[node]
                .timeout_certificates
                .get(&timeout_view)
                .filter(|certificate| certificate.high_qc().id() == high_qc.id())
                .cloned()
            else {
                return Ok(None);
            };
            ProposalJustification::timeout(certificate)
        };
        let parent_timestamp = if high_qc.block_id() == GENESIS_BLOCK_ID {
            0
        } else {
            self.proposals
                .get(&high_qc.block_id())
                .ok_or(SimError::MissingProposal(high_qc.block_id()))?
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
        let payload = format!(
            "seed={} node={node} view={} nonce={nonce}",
            self.seed(),
            view.get()
        )
        .into_bytes();
        let proposer = self.nodes[node].validator;
        let height = high_qc.height().checked_next()?;
        let header = BlockHeader::new(
            self.validator_set.genesis_hash(),
            self.validator_set.chain_id(),
            self.validator_set.protocol_version(),
            self.validator_set.epoch(),
            view,
            height,
            BlockKind::Regular,
            high_qc.block_id(),
            proposer,
            self.validator_set.id(),
            self.validator_set.consensus_parameters_hash(),
            PayloadDigest::new(self.derive_root(b"payload", nonce, &payload)),
            StateRoot::new(self.derive_root(b"state", nonce, &payload)),
            ReceiptsRoot::new(self.derive_root(b"receipts", nonce, &payload)),
            EvidenceRoot::new(self.derive_root(b"evidence", nonce, &payload)),
            timestamp_ms,
            None,
        )?;
        let block = Block::new(header, payload)?;
        let root = Proposal::signing_root_for(&block, &justification, None, &self.validator_set)?;
        let proposer_validator = self
            .validator_set
            .validator(proposer)
            .expect("simulator proposer belongs to its validator set");
        Ok(Some(Proposal::new(
            block,
            justification,
            proposer,
            mock_signature_for(proposer_validator, root),
            &self.validator_set,
        )?))
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
    ) -> Result<Vec<Proposal>, SimError> {
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
        proof: &CommitProof,
    ) -> Result<Vec<(Height, BlockId)>, SimError> {
        let mut header = proof.committed().clone();
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
        proof: &CommitProof,
        newly_finalized: &[(Height, BlockId)],
    ) {
        for &(height, block_id) in newly_finalized.iter().rev() {
            self.nodes[node].applied.insert(height, block_id);
        }
        let height = proof.committed().height();
        let block_id = proof.committed().id();
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

fn fixture_validator_set(count: usize) -> Result<ValidatorSet, ValidationError> {
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
        ConsensusParametersHash::new([0x5A; 32]),
        validators,
    )
}

fn fixture_genesis_qc(set: &ValidatorSet) -> Result<QuorumCertificate, ValidationError> {
    let votes = set
        .validators()
        .iter()
        .map(|validator| {
            signed_vote(
                set,
                View::new(0),
                Height::new(0),
                GENESIS_BLOCK_ID,
                validator.id(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(0),
        Height::new(0),
        GENESIS_BLOCK_ID,
        set.id(),
        votes,
        set,
    )
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

fn applied_chains_are_prefix_comparable(
    left: &BTreeMap<Height, BlockId>,
    right: &BTreeMap<Height, BlockId>,
) -> bool {
    if !applied_chain_is_complete(left) || !applied_chain_is_complete(right) {
        return false;
    }
    let left_height = left.keys().next_back().copied().unwrap_or(Height::new(0));
    let right_height = right.keys().next_back().copied().unwrap_or(Height::new(0));
    let (prefix, chain) = if left_height <= right_height {
        (left, right)
    } else {
        (right, left)
    };
    prefix
        .iter()
        .all(|(height, block_id)| chain.get(height) == Some(block_id))
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
    match state.pending_sign() {
        None => hasher.update([0]),
        Some(SignIntent::Vote {
            view,
            height,
            block_id,
            signing_root,
        }) => {
            hasher.update([1]);
            hasher.update(view.get().to_le_bytes());
            hasher.update(height.get().to_le_bytes());
            hasher.update(block_id.as_bytes());
            hasher.update(signing_root.as_bytes());
        }
        Some(SignIntent::TimeoutVote {
            view,
            high_qc,
            signing_root,
        }) => {
            hasher.update([2]);
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
        state.last_finalization_proof().map(CommitProof::id),
    );
    update_optional_certificate(&mut hasher, state.pending_finalize().map(CommitProof::id));
    match state.safety_halt() {
        None => hasher.update([0]),
        Some(halt) => {
            hasher.update([1]);
            hasher.update(halt.first().id().as_bytes());
            hasher.update(halt.second().id().as_bytes());
        }
    }
    hasher.finalize().into()
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
    fn deterministic_mock_signature_is_bound_to_validator_key() {
        let set = fixture_validator_set(4).expect("valid fixture set");
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
