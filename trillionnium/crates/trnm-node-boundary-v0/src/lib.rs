#![forbid(unsafe_code)]
//! Versioned, production-shaped boundaries for PoCO-BFT node decomposition.
//!
//! This crate deliberately contains no filesystem, socket, wall-clock,
//! thread-pool, database, signer, or protocol-activation implementation.  It
//! defines the contracts between a deterministic authority coordinator, a
//! bounded I/O runtime, the persistent host loop, and thin composition/CLI
//! layers.  Concrete adapters remain independently reviewable.

use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fmt};

pub const NODE_BOUNDARY_VERSION_V0: u16 = 0;
pub const MAX_INGRESS_FRAME_BYTES_V0: usize = 4 * 1024 * 1024;
pub const MAX_OUTBOUND_FRAME_BYTES_V0: usize = 4 * 1024 * 1024;
pub const MAX_INGRESS_ITEMS_PER_STEP_V0: u32 = 256;
pub const MAX_OUTBOUND_ITEMS_PER_STEP_V0: u32 = 256;
pub const MAX_INGRESS_BYTES_PER_STEP_V0: u64 = MAX_INGRESS_FRAME_BYTES_V0 as u64 * 8;
pub const MAX_OUTBOUND_BYTES_PER_STEP_V0: u64 = MAX_OUTBOUND_FRAME_BYTES_V0 as u64 * 8;
pub const MAX_AUTHORITY_ADVANCES_PER_STEP_V0: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeIdentityV0 {
    pub chain_id: Digest32V0,
    pub validator_id: Digest32V0,
    pub application_id: Digest32V0,
    pub generation: u64,
}

impl NodeIdentityV0 {
    pub fn validate(self) -> Result<Self, BoundaryErrorV0> {
        if self.chain_id == Digest32V0([0; 32])
            || self.validator_id == Digest32V0([0; 32])
            || self.application_id == Digest32V0([0; 32])
            || self.generation == 0
        {
            return Err(BoundaryErrorV0::InvalidIdentity);
        }
        Ok(self)
    }

    #[must_use]
    pub fn digest(self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.identity.v0",
            &[
                &self.chain_id.0,
                &self.validator_id.0,
                &self.application_id.0,
                &self.generation.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepBudgetV0 {
    pub max_ingress_items: u32,
    pub max_ingress_bytes: u64,
    pub max_authority_advances: u32,
    pub max_outbound_items: u32,
    pub max_outbound_bytes: u64,
}

impl StepBudgetV0 {
    pub fn validate(self) -> Result<Self, BoundaryErrorV0> {
        if self.max_ingress_items == 0
            || self.max_ingress_items > MAX_INGRESS_ITEMS_PER_STEP_V0
            || self.max_authority_advances == 0
            || self.max_authority_advances > MAX_AUTHORITY_ADVANCES_PER_STEP_V0
            || self.max_outbound_items == 0
            || self.max_outbound_items > MAX_OUTBOUND_ITEMS_PER_STEP_V0
            || self.max_ingress_bytes == 0
            || self.max_ingress_bytes > MAX_INGRESS_BYTES_PER_STEP_V0
            || self.max_outbound_bytes == 0
            || self.max_outbound_bytes > MAX_OUTBOUND_BYTES_PER_STEP_V0
        {
            return Err(BoundaryErrorV0::InvalidBudget);
        }
        Ok(self)
    }
}

impl Default for StepBudgetV0 {
    fn default() -> Self {
        Self {
            max_ingress_items: 64,
            max_ingress_bytes: MAX_INGRESS_FRAME_BYTES_V0 as u64 * 8,
            max_authority_advances: 16,
            max_outbound_items: 64,
            max_outbound_bytes: MAX_OUTBOUND_FRAME_BYTES_V0 as u64 * 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorityStageV0 {
    Prepared = 0,
    ApplicationSealed = 1,
    SafetyPersisted = 2,
    SignIntentPersisted = 3,
    SignatureConfirmed = 4,
    FinalityApplied = 5,
    CheckpointConfirmed = 6,
    OutboundPublished = 7,
}

impl AuthorityStageV0 {
    #[must_use]
    pub const fn successor(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::ApplicationSealed),
            Self::ApplicationSealed => Some(Self::SafetyPersisted),
            Self::SafetyPersisted => Some(Self::SignIntentPersisted),
            Self::SignIntentPersisted => Some(Self::SignatureConfirmed),
            Self::SignatureConfirmed => Some(Self::FinalityApplied),
            Self::FinalityApplied => Some(Self::CheckpointConfirmed),
            Self::CheckpointConfirmed => Some(Self::OutboundPublished),
            Self::OutboundPublished => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBindingV0 {
    pub operation_id: Digest32V0,
    pub height: u64,
    pub view: u64,
    pub block_id: Digest32V0,
    pub parent_id: Digest32V0,
    pub proposal_digest: Digest32V0,
}

impl OperationBindingV0 {
    #[must_use]
    pub fn derive(
        identity: NodeIdentityV0,
        height: u64,
        view: u64,
        block_id: Digest32V0,
        parent_id: Digest32V0,
        proposal_digest: Digest32V0,
    ) -> Self {
        let operation_id = Digest32V0::hash(
            b"trnm.node.operation.v0",
            &[
                &identity.digest().0,
                &height.to_be_bytes(),
                &view.to_be_bytes(),
                &block_id.0,
                &parent_id.0,
                &proposal_digest.0,
            ],
        );
        Self {
            operation_id,
            height,
            view,
            block_id,
            parent_id,
            proposal_digest,
        }
    }

    pub fn validate(self, identity: NodeIdentityV0) -> Result<Self, BoundaryErrorV0> {
        identity.validate()?;
        if self.height == 0
            || self.block_id == Digest32V0([0; 32])
            || self.parent_id == Digest32V0([0; 32])
            || self.proposal_digest == Digest32V0([0; 32])
            || self.operation_id
                != Self::derive(
                    identity,
                    self.height,
                    self.view,
                    self.block_id,
                    self.parent_id,
                    self.proposal_digest,
                )
                .operation_id
        {
            return Err(BoundaryErrorV0::InvalidOperationBinding);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressFrameV0 {
    pub peer_id: Digest32V0,
    pub profile_digest: Digest32V0,
    pub replay_nonce: u64,
    pub payload: Vec<u8>,
}

impl IngressFrameV0 {
    pub fn new(
        peer_id: Digest32V0,
        profile_digest: Digest32V0,
        replay_nonce: u64,
        payload: Vec<u8>,
    ) -> Result<Self, BoundaryErrorV0> {
        let frame = Self {
            peer_id,
            profile_digest,
            replay_nonce,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), BoundaryErrorV0> {
        if self.peer_id == Digest32V0([0; 32])
            || self.profile_digest == Digest32V0([0; 32])
            || self.replay_nonce == 0
            || self.payload.is_empty()
            || self.payload.len() > MAX_INGRESS_FRAME_BYTES_V0
        {
            return Err(BoundaryErrorV0::IngressFrameOutOfBounds);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.node.ingress-frame.v0",
            &[
                &self.peer_id.0,
                &self.profile_digest.0,
                &self.replay_nonce.to_be_bytes(),
                &self.payload,
            ],
        )
    }
}

/// An ingress frame bound byte-for-byte to one validated authority operation.
///
/// Construction does not authenticate a peer or establish a durable replay
/// floor.  The concrete M04 adapter must perform those checks before handing
/// this value to the host.  This boundary only proves that the exact ingress
/// digest is the proposal digest committed by `OperationBindingV0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundIngressV0 {
    pub binding: OperationBindingV0,
    pub frame: IngressFrameV0,
}

impl BoundIngressV0 {
    pub fn derive(
        identity: NodeIdentityV0,
        height: u64,
        view: u64,
        block_id: Digest32V0,
        parent_id: Digest32V0,
        frame: IngressFrameV0,
    ) -> Result<Self, BoundaryErrorV0> {
        identity.validate()?;
        frame.validate()?;
        let binding =
            OperationBindingV0::derive(identity, height, view, block_id, parent_id, frame.digest());
        let ingress = Self { binding, frame };
        ingress.validate(identity)?;
        Ok(ingress)
    }

    pub fn validate(&self, identity: NodeIdentityV0) -> Result<(), BoundaryErrorV0> {
        self.frame.validate()?;
        self.binding.validate(identity)?;
        if self.binding.proposal_digest != self.frame.digest() {
            return Err(BoundaryErrorV0::OperationBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn ingress_digest(&self) -> Digest32V0 {
        self.frame.digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundFrameV0 {
    pub operation_id: Digest32V0,
    pub destination: Digest32V0,
    pub payload: Vec<u8>,
}

impl OutboundFrameV0 {
    pub fn new(
        operation_id: Digest32V0,
        destination: Digest32V0,
        payload: Vec<u8>,
    ) -> Result<Self, BoundaryErrorV0> {
        let frame = Self {
            operation_id,
            destination,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), BoundaryErrorV0> {
        if self.operation_id == Digest32V0([0; 32])
            || self.destination == Digest32V0([0; 32])
            || self.payload.is_empty()
            || self.payload.len() > MAX_OUTBOUND_FRAME_BYTES_V0
        {
            return Err(BoundaryErrorV0::OutboundFrameOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDispositionV0 {
    Clean,
    Resume {
        binding: OperationBindingV0,
        durable_stage: AuthorityStageV0,
        durable_sequence: u64,
    },
    Quarantine {
        reason_digest: Digest32V0,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCommandV0 {
    Begin {
        binding: OperationBindingV0,
        ingress_digest: Digest32V0,
    },
    Advance {
        binding: OperationBindingV0,
        expected_stage: AuthorityStageV0,
        next_stage: AuthorityStageV0,
        facts_digest: Digest32V0,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityReceiptV0 {
    pub binding: OperationBindingV0,
    pub durable_stage: AuthorityStageV0,
    pub durable_sequence: u64,
    pub facts_digest: Digest32V0,
    pub record_digest: Digest32V0,
}

pub trait AuthorityCoordinatorV0 {
    type Error: Error + Send + Sync + 'static;

    fn identity(&self) -> NodeIdentityV0;
    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error>;
    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoPollV0 {
    Idle,
    Frames(Vec<IngressFrameV0>),
    Backpressured,
}

pub trait IoRuntimeV0 {
    type Error: Error + Send + Sync + 'static;

    fn poll_ingress(&mut self, budget: StepBudgetV0) -> Result<IoPollV0, Self::Error>;
    fn publish(&mut self, frame: OutboundFrameV0, budget: StepBudgetV0) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostReadinessV0 {
    Recovering,
    Ready,
    Quarantined(Digest32V0),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostStepV0 {
    Idle,
    Backpressured,
    IngressAccepted {
        accepted: u32,
        accepted_bytes: u64,
        aggregate_digest: Digest32V0,
    },
}

#[derive(Debug)]
pub enum HostErrorV0<CoordinatorError, IoError> {
    Boundary(BoundaryErrorV0),
    Coordinator(CoordinatorError),
    Io(IoError),
    NotReady,
}

impl<C: fmt::Display, I: fmt::Display> fmt::Display for HostErrorV0<C, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(f, "node boundary rejected operation: {error}"),
            Self::Coordinator(error) => write!(f, "authority coordinator failed: {error}"),
            Self::Io(error) => write!(f, "I/O runtime failed: {error}"),
            Self::NotReady => f.write_str("persistent validator host is not ready"),
        }
    }
}

impl<C, I> Error for HostErrorV0<C, I>
where
    C: Error + 'static,
    I: Error + 'static,
{
}

pub struct PersistentValidatorHostV0<C, I> {
    coordinator: C,
    io: I,
    budget: StepBudgetV0,
    readiness: HostReadinessV0,
}

impl<C, I> PersistentValidatorHostV0<C, I>
where
    C: AuthorityCoordinatorV0,
    I: IoRuntimeV0,
{
    pub fn new(coordinator: C, io: I, budget: StepBudgetV0) -> Result<Self, BoundaryErrorV0> {
        Ok(Self {
            coordinator,
            io,
            budget: budget.validate()?,
            readiness: HostReadinessV0::Recovering,
        })
    }

    pub fn recover(&mut self) -> Result<HostReadinessV0, HostErrorV0<C::Error, I::Error>> {
        self.readiness = match self
            .coordinator
            .recover()
            .map_err(HostErrorV0::Coordinator)?
        {
            RecoveryDispositionV0::Clean => HostReadinessV0::Ready,
            RecoveryDispositionV0::Resume { binding, .. } => {
                binding
                    .validate(self.coordinator.identity())
                    .map_err(HostErrorV0::Boundary)?;
                HostReadinessV0::Ready
            }
            RecoveryDispositionV0::Quarantine { reason_digest } => {
                HostReadinessV0::Quarantined(reason_digest)
            }
        };
        Ok(self.readiness)
    }

    #[must_use]
    pub fn readiness(&self) -> HostReadinessV0 {
        self.readiness
    }

    /// Persist the exact bound ingress as the first `Prepared` authority record.
    ///
    /// The host validates the operation/frame binding before invoking the
    /// coordinator and then revalidates the returned durable receipt.  It does
    /// not advance application, Safety, signing, finality, checkpoint, or
    /// publication stages.
    pub fn prepare_bound_ingress(
        &mut self,
        ingress: &BoundIngressV0,
    ) -> Result<AuthorityReceiptV0, HostErrorV0<C::Error, I::Error>> {
        if self.readiness != HostReadinessV0::Ready {
            return Err(HostErrorV0::NotReady);
        }

        let identity = self.coordinator.identity();
        ingress.validate(identity).map_err(HostErrorV0::Boundary)?;
        let ingress_digest = ingress.ingress_digest();
        let receipt = self
            .coordinator
            .apply(AuthorityCommandV0::Begin {
                binding: ingress.binding,
                ingress_digest,
            })
            .map_err(HostErrorV0::Coordinator)?;

        if receipt.binding != ingress.binding {
            return Err(HostErrorV0::Boundary(
                BoundaryErrorV0::OperationBindingMismatch,
            ));
        }
        if receipt.durable_stage != AuthorityStageV0::Prepared {
            return Err(HostErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition,
            ));
        }
        if receipt.facts_digest != ingress_digest || receipt.record_digest == Digest32V0([0; 32]) {
            return Err(HostErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution));
        }
        Ok(receipt)
    }

    pub fn step(&mut self) -> Result<HostStepV0, HostErrorV0<C::Error, I::Error>> {
        if self.readiness != HostReadinessV0::Ready {
            return Err(HostErrorV0::NotReady);
        }
        match self.io.poll_ingress(self.budget).map_err(HostErrorV0::Io)? {
            IoPollV0::Idle => Ok(HostStepV0::Idle),
            IoPollV0::Backpressured => Ok(HostStepV0::Backpressured),
            IoPollV0::Frames(frames) => {
                let count = u32::try_from(frames.len())
                    .map_err(|_| HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded))?;
                if count > self.budget.max_ingress_items {
                    return Err(HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded));
                }
                let mut total_bytes = 0_u64;
                let mut digests = Vec::with_capacity(frames.len());
                let mut seen = BTreeSet::new();
                for frame in frames {
                    frame.validate().map_err(HostErrorV0::Boundary)?;
                    if !seen.insert((frame.peer_id, frame.replay_nonce)) {
                        return Err(HostErrorV0::Boundary(BoundaryErrorV0::DuplicateIngress));
                    }
                    let frame_bytes = u64::try_from(frame.payload.len())
                        .map_err(|_| HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded))?;
                    total_bytes = total_bytes
                        .checked_add(frame_bytes)
                        .ok_or(HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded))?;
                    if total_bytes > self.budget.max_ingress_bytes {
                        return Err(HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded));
                    }
                    digests.push(frame.digest());
                }
                let mut aggregate = Sha256::new();
                aggregate.update(b"trnm.node.ingress-batch.v0");
                aggregate.update(count.to_be_bytes());
                for digest in digests {
                    aggregate.update(digest.0);
                }
                Ok(HostStepV0::IngressAccepted {
                    accepted: count,
                    accepted_bytes: total_bytes,
                    aggregate_digest: Digest32V0(aggregate.finalize().into()),
                })
            }
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (C, I) {
        (self.coordinator, self.io)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeLayerRoleV0 {
    KernelHost,
    AuthorityCoordinator,
    IoRuntime,
    Composition,
    Cli,
    LabEvidence,
}

impl NodeLayerRoleV0 {
    #[must_use]
    pub const fn may_own_domain_state(self) -> bool {
        matches!(self, Self::KernelHost | Self::AuthorityCoordinator)
    }

    #[must_use]
    pub const fn production_allowed(self) -> bool {
        !matches!(self, Self::LabEvidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryErrorV0 {
    InvalidIdentity,
    InvalidOperationBinding,
    InvalidBudget,
    BudgetExceeded,
    IngressFrameOutOfBounds,
    OutboundFrameOutOfBounds,
    DuplicateIngress,
    InvalidStageTransition,
    OperationBindingMismatch,
    ReceiptSubstitution,
    SequenceOverflow,
}

impl fmt::Display for BoundaryErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "invalid node identity",
            Self::InvalidOperationBinding => "invalid or substituted operation binding",
            Self::InvalidBudget => "invalid bounded host-step budget",
            Self::BudgetExceeded => "bounded host-step budget exceeded",
            Self::IngressFrameOutOfBounds => "ingress frame length is outside the protocol bound",
            Self::OutboundFrameOutOfBounds => "outbound frame length is outside the protocol bound",
            Self::DuplicateIngress => "duplicate peer replay nonce in one ingress batch",
            Self::InvalidStageTransition => "authority stage transition is not the exact successor",
            Self::OperationBindingMismatch => "operation binding does not match durable authority",
            Self::ReceiptSubstitution => "same authority stage was replayed with different facts",
            Self::SequenceOverflow => "durable authority sequence overflow",
        })
    }
}

impl Error for BoundaryErrorV0 {}

/// Pure reference coordinator used by conformance tests and deterministic
/// adapters.  It is not a durable store and therefore is never sufficient for
/// production authority on its own.
pub struct ReferenceAuthorityCoordinatorV0 {
    identity: NodeIdentityV0,
    current: Option<AuthorityReceiptV0>,
}

impl ReferenceAuthorityCoordinatorV0 {
    #[must_use]
    pub const fn new(identity: NodeIdentityV0) -> Self {
        Self {
            identity,
            current: None,
        }
    }

    #[must_use]
    pub const fn current(&self) -> Option<AuthorityReceiptV0> {
        self.current
    }
}

impl AuthorityCoordinatorV0 for ReferenceAuthorityCoordinatorV0 {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.identity.validate()?;
        Ok(match self.current {
            None => RecoveryDispositionV0::Clean,
            Some(receipt) => {
                receipt.binding.validate(self.identity)?;
                RecoveryDispositionV0::Resume {
                    binding: receipt.binding,
                    durable_stage: receipt.durable_stage,
                    durable_sequence: receipt.durable_sequence,
                }
            }
        })
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        self.identity.validate()?;
        let (binding, stage, facts_digest) = match command {
            AuthorityCommandV0::Begin {
                binding,
                ingress_digest,
            } => {
                binding.validate(self.identity)?;
                if ingress_digest == Digest32V0([0; 32]) {
                    return Err(BoundaryErrorV0::ReceiptSubstitution);
                }
                if let Some(current) = self.current {
                    if current.binding == binding
                        && current.durable_stage == AuthorityStageV0::Prepared
                    {
                        return if current.facts_digest == ingress_digest {
                            Ok(current)
                        } else {
                            Err(BoundaryErrorV0::ReceiptSubstitution)
                        };
                    }
                    let expected_height = current
                        .binding
                        .height
                        .checked_add(1)
                        .ok_or(BoundaryErrorV0::SequenceOverflow)?;
                    if current.durable_stage != AuthorityStageV0::OutboundPublished
                        || binding.height != expected_height
                        || binding.parent_id != current.binding.block_id
                        || binding.operation_id == current.binding.operation_id
                    {
                        return Err(BoundaryErrorV0::InvalidStageTransition);
                    }
                }
                (binding, AuthorityStageV0::Prepared, ingress_digest)
            }
            AuthorityCommandV0::Advance {
                binding,
                expected_stage,
                next_stage,
                facts_digest,
            } => {
                binding.validate(self.identity)?;
                if facts_digest == Digest32V0([0; 32]) {
                    return Err(BoundaryErrorV0::ReceiptSubstitution);
                }
                let current = self
                    .current
                    .ok_or(BoundaryErrorV0::InvalidStageTransition)?;
                if current.binding != binding {
                    return Err(BoundaryErrorV0::OperationBindingMismatch);
                }
                if current.durable_stage == next_stage
                    && expected_stage.successor() == Some(next_stage)
                {
                    return if current.facts_digest == facts_digest {
                        Ok(current)
                    } else {
                        Err(BoundaryErrorV0::ReceiptSubstitution)
                    };
                }
                if current.durable_stage != expected_stage
                    || expected_stage.successor() != Some(next_stage)
                {
                    return Err(BoundaryErrorV0::InvalidStageTransition);
                }
                (binding, next_stage, facts_digest)
            }
        };
        let sequence = self.current.map_or(Ok(0_u64), |receipt| {
            receipt
                .durable_sequence
                .checked_add(1)
                .ok_or(BoundaryErrorV0::SequenceOverflow)
        })?;
        let previous = self
            .current
            .map_or(Digest32V0([0; 32]), |receipt| receipt.record_digest);
        let record_digest = Digest32V0::hash(
            b"trnm.node.authority-record.v0",
            &[
                &self.identity.digest().0,
                &binding.operation_id.0,
                &[stage as u8],
                &sequence.to_be_bytes(),
                &facts_digest.0,
                &previous.0,
            ],
        );
        let receipt = AuthorityReceiptV0 {
            binding,
            durable_stage: stage,
            durable_sequence: sequence,
            facts_digest,
            record_digest,
        };
        self.current = Some(receipt);
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, convert::Infallible};

    fn digest(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: digest(1),
            validator_id: digest(2),
            application_id: digest(3),
            generation: 4,
        }
    }

    fn binding() -> OperationBindingV0 {
        OperationBindingV0::derive(identity(), 10, 11, digest(12), digest(13), digest(14))
    }

    #[test]
    fn authority_chain_is_exactly_monotonic() {
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let binding = binding();
        let first = coordinator
            .apply(AuthorityCommandV0::Begin {
                binding,
                ingress_digest: digest(20),
            })
            .unwrap();
        assert_eq!(first.durable_sequence, 0);
        assert_eq!(first.durable_stage, AuthorityStageV0::Prepared);

        let second = coordinator
            .apply(AuthorityCommandV0::Advance {
                binding,
                expected_stage: AuthorityStageV0::Prepared,
                next_stage: AuthorityStageV0::ApplicationSealed,
                facts_digest: digest(21),
            })
            .unwrap();
        assert_eq!(second.durable_sequence, 1);
        assert_ne!(first.record_digest, second.record_digest);

        let error = coordinator
            .apply(AuthorityCommandV0::Advance {
                binding,
                expected_stage: AuthorityStageV0::ApplicationSealed,
                next_stage: AuthorityStageV0::SignIntentPersisted,
                facts_digest: digest(22),
            })
            .unwrap_err();
        assert_eq!(error, BoundaryErrorV0::InvalidStageTransition);
    }

    #[test]
    fn authority_replay_is_bound_to_retained_facts() {
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let binding = binding();
        let first = coordinator
            .apply(AuthorityCommandV0::Begin {
                binding,
                ingress_digest: digest(20),
            })
            .unwrap();
        assert_eq!(
            coordinator
                .apply(AuthorityCommandV0::Begin {
                    binding,
                    ingress_digest: digest(20),
                })
                .unwrap(),
            first
        );
        assert_eq!(
            coordinator
                .apply(AuthorityCommandV0::Begin {
                    binding,
                    ingress_digest: digest(21),
                })
                .unwrap_err(),
            BoundaryErrorV0::ReceiptSubstitution
        );
    }

    #[test]
    fn authority_allows_only_parent_bound_next_height() {
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let first = binding();
        coordinator
            .apply(AuthorityCommandV0::Begin {
                binding: first,
                ingress_digest: digest(20),
            })
            .unwrap();
        let mut stage = AuthorityStageV0::Prepared;
        while let Some(next) = stage.successor() {
            coordinator
                .apply(AuthorityCommandV0::Advance {
                    binding: first,
                    expected_stage: stage,
                    next_stage: next,
                    facts_digest: Digest32V0::hash(b"test.stage", &[&[next as u8]]),
                })
                .unwrap();
            stage = next;
        }
        let second = OperationBindingV0::derive(
            identity(),
            first.height + 1,
            0,
            digest(30),
            first.block_id,
            digest(31),
        );
        let receipt = coordinator
            .apply(AuthorityCommandV0::Begin {
                binding: second,
                ingress_digest: digest(32),
            })
            .unwrap();
        assert_eq!(receipt.binding, second);
        assert_eq!(receipt.durable_sequence, 8);
    }

    #[test]
    fn host_revalidates_public_ingress_fields_and_batch_replay() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let frame = IngressFrameV0::new(digest(1), digest(2), 1, vec![1]).unwrap();
        let mut io = QueueIo::default();
        io.polls
            .push_back(IoPollV0::Frames(vec![frame.clone(), frame]));
        let mut host =
            PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();
        host.recover().unwrap();
        assert!(matches!(
            host.step(),
            Err(HostErrorV0::Boundary(BoundaryErrorV0::DuplicateIngress))
        ));
    }

    #[derive(Default)]
    struct QueueIo {
        polls: VecDeque<IoPollV0>,
        published: Vec<OutboundFrameV0>,
    }

    impl IoRuntimeV0 for QueueIo {
        type Error = Infallible;

        fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
            Ok(self.polls.pop_front().unwrap_or(IoPollV0::Idle))
        }

        fn publish(
            &mut self,
            frame: OutboundFrameV0,
            _budget: StepBudgetV0,
        ) -> Result<(), Self::Error> {
            self.published.push(frame);
            Ok(())
        }
    }

    #[test]
    fn host_refuses_work_before_recovery() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let io = QueueIo::default();
        let mut host =
            PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();
        assert!(matches!(host.step(), Err(HostErrorV0::NotReady)));
        assert_eq!(host.recover().unwrap(), HostReadinessV0::Ready);
        assert_eq!(host.step().unwrap(), HostStepV0::Idle);
    }

    #[test]
    fn host_enforces_aggregate_byte_budget() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let mut io = QueueIo::default();
        io.polls.push_back(IoPollV0::Frames(vec![
            IngressFrameV0::new(digest(1), digest(2), 1, vec![1; 8]).unwrap(),
            IngressFrameV0::new(digest(1), digest(2), 2, vec![2; 8]).unwrap(),
        ]));
        let budget = StepBudgetV0 {
            max_ingress_items: 2,
            max_ingress_bytes: 15,
            max_authority_advances: 1,
            max_outbound_items: 1,
            max_outbound_bytes: 1,
        };
        let mut host = PersistentValidatorHostV0::new(coordinator, io, budget).unwrap();
        host.recover().unwrap();
        assert!(matches!(
            host.step(),
            Err(HostErrorV0::Boundary(BoundaryErrorV0::BudgetExceeded))
        ));
    }

    #[test]
    fn host_binds_ingress_to_durable_prepared_receipt() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let io = QueueIo::default();
        let frame = IngressFrameV0::new(digest(40), digest(41), 1, vec![42]).unwrap();
        let ingress =
            BoundIngressV0::derive(identity(), 10, 11, digest(12), digest(13), frame).unwrap();
        let mut host =
            PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();

        assert!(matches!(
            host.prepare_bound_ingress(&ingress),
            Err(HostErrorV0::NotReady)
        ));
        assert_eq!(host.recover().unwrap(), HostReadinessV0::Ready);

        let first = host.prepare_bound_ingress(&ingress).unwrap();
        assert_eq!(first.binding, ingress.binding);
        assert_eq!(first.durable_stage, AuthorityStageV0::Prepared);
        assert_eq!(first.facts_digest, ingress.ingress_digest());
        assert_ne!(first.record_digest, Digest32V0([0; 32]));

        let replay = host.prepare_bound_ingress(&ingress).unwrap();
        assert_eq!(replay, first);
    }

    #[test]
    fn host_rejects_substituted_ingress_binding_before_authority_apply() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let io = QueueIo::default();
        let frame = IngressFrameV0::new(digest(40), digest(41), 1, vec![42]).unwrap();
        let other = IngressFrameV0::new(digest(40), digest(41), 2, vec![43]).unwrap();
        let ingress = BoundIngressV0 {
            binding: OperationBindingV0::derive(
                identity(),
                10,
                11,
                digest(12),
                digest(13),
                other.digest(),
            ),
            frame,
        };
        let mut host =
            PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();
        host.recover().unwrap();

        assert!(matches!(
            host.prepare_bound_ingress(&ingress),
            Err(HostErrorV0::Boundary(
                BoundaryErrorV0::OperationBindingMismatch
            ))
        ));
        let (coordinator, _) = host.into_parts();
        assert_eq!(coordinator.current(), None);
    }

    struct SubstitutingCoordinator {
        identity: NodeIdentityV0,
    }

    impl AuthorityCoordinatorV0 for SubstitutingCoordinator {
        type Error = BoundaryErrorV0;

        fn identity(&self) -> NodeIdentityV0 {
            self.identity
        }

        fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
            Ok(RecoveryDispositionV0::Clean)
        }

        fn apply(
            &mut self,
            command: AuthorityCommandV0,
        ) -> Result<AuthorityReceiptV0, Self::Error> {
            let binding = match command {
                AuthorityCommandV0::Begin { binding, .. }
                | AuthorityCommandV0::Advance { binding, .. } => binding,
            };
            Ok(AuthorityReceiptV0 {
                binding,
                durable_stage: AuthorityStageV0::Prepared,
                durable_sequence: 0,
                facts_digest: digest(99),
                record_digest: digest(98),
            })
        }
    }

    #[test]
    fn host_rejects_substituted_prepared_receipt() {
        let coordinator = SubstitutingCoordinator {
            identity: identity(),
        };
        let io = QueueIo::default();
        let frame = IngressFrameV0::new(digest(40), digest(41), 1, vec![42]).unwrap();
        let ingress =
            BoundIngressV0::derive(identity(), 10, 11, digest(12), digest(13), frame).unwrap();
        let mut host =
            PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();
        host.recover().unwrap();

        assert!(matches!(
            host.prepare_bound_ingress(&ingress),
            Err(HostErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution))
        ));
    }

    #[test]
    fn composition_and_cli_cannot_own_domain_state() {
        assert!(!NodeLayerRoleV0::Composition.may_own_domain_state());
        assert!(!NodeLayerRoleV0::Cli.may_own_domain_state());
        assert!(!NodeLayerRoleV0::LabEvidence.production_allowed());
    }
}
