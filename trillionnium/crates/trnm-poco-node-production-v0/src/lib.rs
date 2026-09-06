#![forbid(unsafe_code)]
//! Wiring-only production-shaped composition for PoCO-BFT v0.
//!
//! This crate owns no transaction lifecycle, control-plane state, consensus
//! rules, persistence, networking, execution, signing, state-root construction,
//! migration projection, governance, or laboratory fixture. Domain owners are
//! constructed outside this root and cross only versioned ports.

mod authority_driver;
pub use authority_driver::*;

use std::{error::Error, fmt};
use trnm_node_boundary_v0::{
    AuthorityCommandV0, AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0,
    BoundIngressV0, BoundaryErrorV0, Digest32V0, HostErrorV0, HostReadinessV0, HostStepV0,
    IoRuntimeV0, NodeIdentityV0, NodeLayerRoleV0, OperationBindingV0,
    PersistentValidatorHostV0, RecoveryDispositionV0, StepBudgetV0,
};

pub const PRODUCTION_COMPOSITION_VERSION_V0: u16 = 0;
pub const PRODUCTION_COMPOSITION_ROLE_V0: NodeLayerRoleV0 = NodeLayerRoleV0::Composition;
pub const PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0: bool = false;
pub const PRODUCTION_COMPOSITION_ACTIVATION_V0: bool = false;

pub struct ProductionNodeCompositionV0<C, I> {
    host: PersistentValidatorHostV0<C, I>,
}

impl<C, I> ProductionNodeCompositionV0<C, I>
where
    C: AuthorityCoordinatorV0,
    I: IoRuntimeV0,
{
    pub fn new(
        coordinator: C,
        io: I,
        step_budget: StepBudgetV0,
    ) -> Result<Self, CompositionErrorV0> {
        if PRODUCTION_COMPOSITION_ROLE_V0.may_own_domain_state()
            || !PRODUCTION_COMPOSITION_ROLE_V0.production_allowed()
            || PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0
            || PRODUCTION_COMPOSITION_ACTIVATION_V0
        {
            return Err(CompositionErrorV0::InvalidLayerRole);
        }
        let host = PersistentValidatorHostV0::new(coordinator, io, step_budget)
            .map_err(CompositionErrorV0::HostBoundary)?;
        Ok(Self { host })
    }

    pub fn recover_host(&mut self) -> Result<HostReadinessV0, HostErrorV0<C::Error, I::Error>> {
        self.host.recover()
    }

    pub fn host_step(&mut self) -> Result<HostStepV0, HostErrorV0<C::Error, I::Error>> {
        self.host.step()
    }

    pub const fn host(&self) -> &PersistentValidatorHostV0<C, I> {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut PersistentValidatorHostV0<C, I> {
        &mut self.host
    }

    pub fn into_host(self) -> PersistentValidatorHostV0<C, I> {
        self.host
    }
}

/// Readiness of the complete-receipt recovery session.
///
/// This is a node-local orchestration projection, not protocol or application
/// state. `Recovering` is deliberately sticky after every uncertain adapter
/// response until a fresh complete recovery succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoritySessionReadinessV0 {
    Recovering,
    Ready,
    Quarantined(Digest32V0),
}

/// Authenticates one exact ingress against the current complete authority
/// predecessor. Implementations belong to the transport/replay owner, not this
/// wiring-only crate.
pub trait AuthorityIngressSourceV0 {
    type Error;

    fn verify_ingress(
        &mut self,
        identity: NodeIdentityV0,
        prior: Option<AuthorityReceiptV0>,
        ingress: &BoundIngressV0,
    ) -> Result<(), Self::Error>;
}

/// One-use proof that an ingress source accepted the exact session predecessor
/// and ingress bytes. Fields and constructors remain private, and the token is
/// deliberately not Clone.
#[must_use = "verified ingress must be consumed by begin_verified"]
#[derive(Debug)]
pub struct VerifiedAuthorityIngressV0 {
    identity: NodeIdentityV0,
    prior: Option<AuthorityReceiptV0>,
    ingress: BoundIngressV0,
    ingress_digest: Digest32V0,
}

#[derive(Debug)]
pub enum AuthorityIngressVerificationErrorV0<E> {
    Boundary(BoundaryErrorV0),
    Source(E),
    NotReady,
}

impl<E: fmt::Display> fmt::Display for AuthorityIngressVerificationErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "authority ingress boundary failed: {error}"),
            Self::Source(error) => write!(formatter, "authority ingress source rejected: {error}"),
            Self::NotReady => formatter.write_str("authority session is not recovered and ready"),
        }
    }
}

impl<E: Error + 'static> Error for AuthorityIngressVerificationErrorV0<E> {}

/// Exact claim emitted by one stage-specific domain owner.
///
/// The digest binds the node identity, full operation binding, target stage,
/// source identity, source sequence and payload digest. The claim is only an
/// input to a trusted source port; it is not itself verified authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityFactClaimV0 {
    identity: NodeIdentityV0,
    binding: OperationBindingV0,
    stage: AuthorityStageV0,
    source_id: Digest32V0,
    source_sequence: u64,
    payload_digest: Digest32V0,
    facts_digest: Digest32V0,
}

impl AuthorityFactClaimV0 {
    pub fn new(
        identity: NodeIdentityV0,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        source_id: Digest32V0,
        source_sequence: u64,
        payload_digest: Digest32V0,
    ) -> Result<Self, BoundaryErrorV0> {
        let identity = identity.validate()?;
        binding.validate(identity)?;
        if stage == AuthorityStageV0::Prepared
            || source_id == Digest32V0([0; 32])
            || source_sequence == 0
            || payload_digest == Digest32V0([0; 32])
        {
            return Err(BoundaryErrorV0::ReceiptSubstitution);
        }
        let facts_digest = authority_fact_digest_v0(
            identity,
            binding,
            stage,
            source_id,
            source_sequence,
            payload_digest,
        );
        if facts_digest == Digest32V0([0; 32]) {
            return Err(BoundaryErrorV0::ReceiptSubstitution);
        }
        Ok(Self {
            identity,
            binding,
            stage,
            source_id,
            source_sequence,
            payload_digest,
            facts_digest,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    #[must_use]
    pub const fn binding(&self) -> OperationBindingV0 {
        self.binding
    }

    #[must_use]
    pub const fn stage(&self) -> AuthorityStageV0 {
        self.stage
    }

    #[must_use]
    pub const fn source_id(&self) -> Digest32V0 {
        self.source_id
    }

    #[must_use]
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Digest32V0 {
        self.payload_digest
    }

    #[must_use]
    pub const fn facts_digest(&self) -> Digest32V0 {
        self.facts_digest
    }
}

fn authority_fact_digest_v0(
    identity: NodeIdentityV0,
    binding: OperationBindingV0,
    stage: AuthorityStageV0,
    source_id: Digest32V0,
    source_sequence: u64,
    payload_digest: Digest32V0,
) -> Digest32V0 {
    let stage = [stage as u8];
    Digest32V0::hash(
        b"trnm.authority.fact-claim.v0",
        &[
            &identity.digest().0,
            &binding.operation_id.0,
            &binding.height.to_be_bytes(),
            &binding.view.to_be_bytes(),
            &binding.block_id.0,
            &binding.parent_id.0,
            &binding.proposal_digest.0,
            &stage,
            &source_id.0,
            &source_sequence.to_be_bytes(),
            &payload_digest.0,
        ],
    )
}

/// Authenticates a claim using fresh, stage-specific domain-owner state.
pub trait AuthorityFactSourceV0 {
    type Error;

    fn verify_fact(
        &mut self,
        identity: NodeIdentityV0,
        prior: AuthorityReceiptV0,
        claim: &AuthorityFactClaimV0,
    ) -> Result<(), Self::Error>;
}

/// One-use proof that a source accepted an exact fact claim against one exact
/// durable predecessor. It is deliberately not Clone and has no public
/// constructor.
#[must_use = "verified fact must be consumed by advance_verified"]
#[derive(Debug)]
pub struct VerifiedAuthorityFactV0 {
    identity: NodeIdentityV0,
    prior: AuthorityReceiptV0,
    expected_stage: AuthorityStageV0,
    claim: AuthorityFactClaimV0,
}

#[derive(Debug)]
pub enum AuthorityFactVerificationErrorV0<E> {
    Boundary(BoundaryErrorV0),
    Source(E),
    NotReady,
}

impl<E: fmt::Display> fmt::Display for AuthorityFactVerificationErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(formatter, "authority fact boundary failed: {error}"),
            Self::Source(error) => write!(formatter, "authority fact source rejected: {error}"),
            Self::NotReady => formatter.write_str("authority session is not recovered and ready"),
        }
    }
}

impl<E: Error + 'static> Error for AuthorityFactVerificationErrorV0<E> {}

/// A bounded production-composition session which retains the exact durable
/// authority receipt across stage transitions.
///
/// Existing `RecoveryDispositionV0::Resume` carries only binding, stage and
/// sequence. The supplied readback function must call the durable adapter's
/// authenticated current-receipt API. A summary without that complete receipt
/// never restores write authority. Public mutation requires a non-cloneable
/// verified ingress or fact token; naked caller-supplied digests are crate-local
/// implementation details only.
pub struct ProductionAuthoritySessionV0<C, R> {
    identity: NodeIdentityV0,
    coordinator: C,
    readback: R,
    readiness: AuthoritySessionReadinessV0,
    current: Option<AuthorityReceiptV0>,
}

impl<C, R> ProductionAuthoritySessionV0<C, R>
where
    C: AuthorityCoordinatorV0,
    R: Fn(&C) -> Option<AuthorityReceiptV0>,
{
    pub fn new(coordinator: C, readback: R) -> Result<Self, BoundaryErrorV0> {
        let identity = coordinator.identity().validate()?;
        Ok(Self {
            identity,
            coordinator,
            readback,
            readiness: AuthoritySessionReadinessV0::Recovering,
            current: None,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    #[must_use]
    pub const fn readiness(&self) -> AuthoritySessionReadinessV0 {
        self.readiness
    }

    #[must_use]
    pub const fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.current
    }

    #[must_use]
    pub const fn coordinator(&self) -> &C {
        &self.coordinator
    }

    pub fn into_coordinator(self) -> C {
        self.coordinator
    }

    fn check_identity(&self) -> Result<(), AuthoritySessionErrorV0<C::Error>> {
        let observed = self
            .coordinator
            .identity()
            .validate()
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        if observed != self.identity {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::InvalidIdentity,
            ));
        }
        Ok(())
    }

    fn read_complete_receipt(
        &self,
        binding: OperationBindingV0,
        stage: AuthorityStageV0,
        sequence: u64,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        let receipt = (self.readback)(&self.coordinator).ok_or(
            AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution),
        )?;
        receipt
            .binding
            .validate(self.identity)
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        if receipt.binding != binding
            || receipt.durable_stage != stage
            || receipt.durable_sequence != sequence
            || receipt.facts_digest == Digest32V0([0; 32])
            || receipt.record_digest == Digest32V0([0; 32])
        {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        Ok(receipt)
    }

    fn commit_verified_receipt(
        &mut self,
        returned: AuthorityReceiptV0,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        let readback = self.read_complete_receipt(
            returned.binding,
            returned.durable_stage,
            returned.durable_sequence,
        )?;
        if readback != returned {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        self.current = Some(readback);
        self.readiness = AuthoritySessionReadinessV0::Ready;
        Ok(readback)
    }

    /// Recover exact authority state. A legacy summary alone remains fenced.
    pub fn recover(
        &mut self,
    ) -> Result<AuthoritySessionReadinessV0, AuthoritySessionErrorV0<C::Error>> {
        self.readiness = AuthoritySessionReadinessV0::Recovering;
        self.current = None;
        self.check_identity()?;
        let disposition = self
            .coordinator
            .recover()
            .map_err(AuthoritySessionErrorV0::Coordinator)?;
        self.check_identity()?;
        self.readiness = match disposition {
            RecoveryDispositionV0::Clean => {
                if (self.readback)(&self.coordinator).is_some() {
                    return Err(AuthoritySessionErrorV0::Boundary(
                        BoundaryErrorV0::ReceiptSubstitution,
                    ));
                }
                AuthoritySessionReadinessV0::Ready
            }
            RecoveryDispositionV0::Resume {
                binding,
                durable_stage,
                durable_sequence,
            } => {
                binding
                    .validate(self.identity)
                    .map_err(AuthoritySessionErrorV0::Boundary)?;
                let receipt =
                    self.read_complete_receipt(binding, durable_stage, durable_sequence)?;
                self.current = Some(receipt);
                AuthoritySessionReadinessV0::Ready
            }
            RecoveryDispositionV0::Quarantine { reason_digest } => {
                AuthoritySessionReadinessV0::Quarantined(reason_digest)
            }
        };
        Ok(self.readiness)
    }

    /// Authenticate an ingress against the exact recovered predecessor without
    /// mutating local or durable state.
    pub fn verify_ingress<S>(
        &self,
        ingress: BoundIngressV0,
        source: &mut S,
    ) -> Result<VerifiedAuthorityIngressV0, AuthorityIngressVerificationErrorV0<S::Error>>
    where
        S: AuthorityIngressSourceV0,
    {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthorityIngressVerificationErrorV0::NotReady);
        }
        let observed = self
            .coordinator
            .identity()
            .validate()
            .map_err(AuthorityIngressVerificationErrorV0::Boundary)?;
        if observed != self.identity {
            return Err(AuthorityIngressVerificationErrorV0::Boundary(
                BoundaryErrorV0::InvalidIdentity,
            ));
        }
        ingress
            .validate(self.identity)
            .map_err(AuthorityIngressVerificationErrorV0::Boundary)?;
        let ingress_digest = ingress.ingress_digest();
        if ingress_digest == Digest32V0([0; 32]) {
            return Err(AuthorityIngressVerificationErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        validate_ingress_predecessor_v0(self.current, &ingress, ingress_digest)
            .map_err(AuthorityIngressVerificationErrorV0::Boundary)?;
        source
            .verify_ingress(self.identity, self.current, &ingress)
            .map_err(AuthorityIngressVerificationErrorV0::Source)?;
        Ok(VerifiedAuthorityIngressV0 {
            identity: self.identity,
            prior: self.current,
            ingress,
            ingress_digest,
        })
    }

    /// Consume one exact verified ingress and durably create or replay Prepared.
    pub fn begin_verified(
        &mut self,
        verified: VerifiedAuthorityIngressV0,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthoritySessionErrorV0::NotReady);
        }
        self.check_identity()?;
        if verified.identity != self.identity || verified.prior != self.current {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        verified
            .ingress
            .validate(self.identity)
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        if verified.ingress.ingress_digest() != verified.ingress_digest {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        validate_ingress_predecessor_v0(self.current, &verified.ingress, verified.ingress_digest)
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        self.begin_prepared(verified.ingress.binding, verified.ingress_digest)
    }

    /// Authenticate one exact stage claim against the current complete receipt
    /// without mutating local or durable state.
    pub fn verify_fact<S>(
        &self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<VerifiedAuthorityFactV0, AuthorityFactVerificationErrorV0<S::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthorityFactVerificationErrorV0::NotReady);
        }
        let observed = self
            .coordinator
            .identity()
            .validate()
            .map_err(AuthorityFactVerificationErrorV0::Boundary)?;
        if observed != self.identity || claim.identity != self.identity {
            return Err(AuthorityFactVerificationErrorV0::Boundary(
                BoundaryErrorV0::InvalidIdentity,
            ));
        }
        claim
            .binding
            .validate(self.identity)
            .map_err(AuthorityFactVerificationErrorV0::Boundary)?;
        let recomputed = authority_fact_digest_v0(
            claim.identity,
            claim.binding,
            claim.stage,
            claim.source_id,
            claim.source_sequence,
            claim.payload_digest,
        );
        if recomputed != claim.facts_digest || recomputed == Digest32V0([0; 32]) {
            return Err(AuthorityFactVerificationErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        let prior = self.current.ok_or(AuthorityFactVerificationErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution,
        ))?;
        if prior.binding != claim.binding {
            return Err(AuthorityFactVerificationErrorV0::Boundary(
                BoundaryErrorV0::OperationBindingMismatch,
            ));
        }
        let expected_stage = if prior.durable_stage == claim.stage {
            if prior.facts_digest != claim.facts_digest {
                return Err(AuthorityFactVerificationErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
            authority_predecessor_v0(claim.stage).ok_or(
                AuthorityFactVerificationErrorV0::Boundary(
                    BoundaryErrorV0::InvalidStageTransition,
                ),
            )?
        } else {
            if prior.durable_stage.successor() != Some(claim.stage) {
                return Err(AuthorityFactVerificationErrorV0::Boundary(
                    BoundaryErrorV0::InvalidStageTransition,
                ));
            }
            prior.durable_stage
        };
        source
            .verify_fact(self.identity, prior, &claim)
            .map_err(AuthorityFactVerificationErrorV0::Source)?;
        Ok(VerifiedAuthorityFactV0 {
            identity: self.identity,
            prior,
            expected_stage,
            claim,
        })
    }

    /// Consume a one-use stage token and persist exactly its verified successor
    /// or exact same-stage replay.
    pub fn advance_verified(
        &mut self,
        verified: VerifiedAuthorityFactV0,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthoritySessionErrorV0::NotReady);
        }
        self.check_identity()?;
        if verified.identity != self.identity
            || self.current != Some(verified.prior)
            || verified.claim.identity != self.identity
            || verified.claim.binding != verified.prior.binding
        {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        let recomputed = authority_fact_digest_v0(
            verified.claim.identity,
            verified.claim.binding,
            verified.claim.stage,
            verified.claim.source_id,
            verified.claim.source_sequence,
            verified.claim.payload_digest,
        );
        if recomputed != verified.claim.facts_digest {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        self.advance(
            verified.claim.binding,
            verified.expected_stage,
            verified.claim.stage,
            verified.claim.facts_digest,
        )
    }

    /// Crate-local persistence primitive. External callers must use a verified
    /// ingress token through `begin_verified`.
    pub(crate) fn begin_prepared(
        &mut self,
        binding: OperationBindingV0,
        ingress_digest: Digest32V0,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthoritySessionErrorV0::NotReady);
        }
        self.check_identity()?;
        binding
            .validate(self.identity)
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        if ingress_digest == Digest32V0([0; 32]) {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }

        let prior = self.current;
        let replay = prior.is_some_and(|receipt| {
            receipt.binding == binding && receipt.durable_stage == AuthorityStageV0::Prepared
        });
        if replay && prior.is_some_and(|receipt| receipt.facts_digest != ingress_digest) {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        if let Some(receipt) = prior {
            if !replay && receipt.durable_stage != AuthorityStageV0::OutboundPublished {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::InvalidStageTransition,
                ));
            }
        }

        self.readiness = AuthoritySessionReadinessV0::Recovering;
        self.current = None;
        let returned = self
            .coordinator
            .apply(AuthorityCommandV0::Begin {
                binding,
                ingress_digest,
            })
            .map_err(AuthoritySessionErrorV0::Coordinator)?;
        self.check_identity()?;
        if returned.binding != binding
            || returned.durable_stage != AuthorityStageV0::Prepared
            || returned.facts_digest != ingress_digest
            || returned.record_digest == Digest32V0([0; 32])
        {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        match prior {
            None if returned.durable_sequence != 0 => {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
            Some(previous) if replay && returned != previous => {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
            Some(previous) if !replay => {
                let expected = previous.durable_sequence.checked_add(1).ok_or(
                    AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::SequenceOverflow),
                )?;
                if returned.durable_sequence != expected
                    || returned.record_digest == previous.record_digest
                {
                    return Err(AuthoritySessionErrorV0::Boundary(
                        BoundaryErrorV0::ReceiptSubstitution,
                    ));
                }
            }
            _ => {}
        }
        self.commit_verified_receipt(returned)
    }

    /// Crate-local persistence primitive. External callers must use a verified
    /// stage token through `advance_verified`.
    pub(crate) fn advance(
        &mut self,
        binding: OperationBindingV0,
        expected_stage: AuthorityStageV0,
        next_stage: AuthorityStageV0,
        facts_digest: Digest32V0,
    ) -> Result<AuthorityReceiptV0, AuthoritySessionErrorV0<C::Error>> {
        if self.readiness != AuthoritySessionReadinessV0::Ready {
            return Err(AuthoritySessionErrorV0::NotReady);
        }
        self.check_identity()?;
        binding
            .validate(self.identity)
            .map_err(AuthoritySessionErrorV0::Boundary)?;
        if expected_stage.successor() != Some(next_stage)
            || facts_digest == Digest32V0([0; 32])
        {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition,
            ));
        }
        let prior = self.current.ok_or(AuthoritySessionErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution,
        ))?;
        if prior.binding != binding {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::OperationBindingMismatch,
            ));
        }
        let replay = prior.durable_stage == next_stage;
        if replay {
            if prior.facts_digest != facts_digest {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
        } else if prior.durable_stage != expected_stage {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::InvalidStageTransition,
            ));
        }

        self.readiness = AuthoritySessionReadinessV0::Recovering;
        self.current = None;
        let returned = self
            .coordinator
            .apply(AuthorityCommandV0::Advance {
                binding,
                expected_stage,
                next_stage,
                facts_digest,
            })
            .map_err(AuthoritySessionErrorV0::Coordinator)?;
        self.check_identity()?;
        if returned.binding != binding
            || returned.durable_stage != next_stage
            || returned.facts_digest != facts_digest
            || returned.record_digest == Digest32V0([0; 32])
        {
            return Err(AuthoritySessionErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution,
            ));
        }
        if replay {
            if returned != prior {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
        } else {
            let sequence = prior.durable_sequence.checked_add(1).ok_or(
                AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::SequenceOverflow),
            )?;
            if returned.durable_sequence != sequence
                || returned.record_digest == prior.record_digest
            {
                return Err(AuthoritySessionErrorV0::Boundary(
                    BoundaryErrorV0::ReceiptSubstitution,
                ));
            }
        }
        self.commit_verified_receipt(returned)
    }
}

fn validate_ingress_predecessor_v0(
    prior: Option<AuthorityReceiptV0>,
    ingress: &BoundIngressV0,
    ingress_digest: Digest32V0,
) -> Result<(), BoundaryErrorV0> {
    let Some(receipt) = prior else {
        return Ok(());
    };
    let exact_replay = receipt.binding == ingress.binding
        && receipt.durable_stage == AuthorityStageV0::Prepared
        && receipt.facts_digest == ingress_digest;
    if exact_replay {
        return Ok(());
    }
    let expected_height = receipt
        .binding
        .height
        .checked_add(1)
        .ok_or(BoundaryErrorV0::SequenceOverflow)?;
    if receipt.durable_stage != AuthorityStageV0::OutboundPublished
        || ingress.binding.height != expected_height
        || ingress.binding.parent_id != receipt.binding.block_id
        || ingress.binding.operation_id == receipt.binding.operation_id
    {
        return Err(BoundaryErrorV0::InvalidStageTransition);
    }
    Ok(())
}

const fn authority_predecessor_v0(stage: AuthorityStageV0) -> Option<AuthorityStageV0> {
    match stage {
        AuthorityStageV0::Prepared => None,
        AuthorityStageV0::ApplicationSealed => Some(AuthorityStageV0::Prepared),
        AuthorityStageV0::SafetyPersisted => Some(AuthorityStageV0::ApplicationSealed),
        AuthorityStageV0::SignIntentPersisted => Some(AuthorityStageV0::SafetyPersisted),
        AuthorityStageV0::SignatureConfirmed => Some(AuthorityStageV0::SignIntentPersisted),
        AuthorityStageV0::FinalityApplied => Some(AuthorityStageV0::SignatureConfirmed),
        AuthorityStageV0::CheckpointConfirmed => Some(AuthorityStageV0::FinalityApplied),
        AuthorityStageV0::OutboundPublished => Some(AuthorityStageV0::CheckpointConfirmed),
    }
}

#[derive(Debug)]
pub enum AuthoritySessionErrorV0<E> {
    Boundary(BoundaryErrorV0),
    Coordinator(E),
    NotReady,
}

impl<E: fmt::Display> fmt::Display for AuthoritySessionErrorV0<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(f, "authority session boundary failed: {error}"),
            Self::Coordinator(error) => write!(f, "authority coordinator failed: {error}"),
            Self::NotReady => f.write_str("authority session is not recovered and ready"),
        }
    }
}

impl<E: Error + 'static> Error for AuthoritySessionErrorV0<E> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionErrorV0 {
    InvalidLayerRole,
    HostBoundary(BoundaryErrorV0),
}

impl fmt::Display for CompositionErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLayerRole => f.write_str("production composition layer owns domain state"),
            Self::HostBoundary(error) => write!(f, "invalid persistent-host boundary: {error}"),
        }
    }
}

impl Error for CompositionErrorV0 {}

/// Compile-time contract surface. These are protocol versions, not service
/// instances, global singletons, activation records, or ownership transfers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionScopedServiceSetV0 {
    pub transaction_lifecycle_protocol_version: u16,
    pub state_sync_protocol_version: u16,
    pub migration_protocol_version: u16,
    pub control_plane_protocol_version: u16,
}

impl Default for SessionScopedServiceSetV0 {
    fn default() -> Self {
        Self {
            transaction_lifecycle_protocol_version: trnm_tx_lifecycle_v0::TX_LIFECYCLE_VERSION_V0,
            state_sync_protocol_version: trnm_state_sync_v0::STATE_SYNC_VERSION_V0,
            migration_protocol_version: trnm_migration_v0::MIGRATION_VERSION_V0,
            control_plane_protocol_version: trnm_control_plane_v0::CONTROL_PLANE_VERSION_V0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use trnm_node_boundary_v0::{
        Digest32V0 as NodeDigest, IoPollV0, NodeIdentityV0, RecoveryDispositionV0,
        ReferenceAuthorityCoordinatorV0,
    };

    struct IdleIo;
    impl IoRuntimeV0 for IdleIo {
        type Error = Infallible;

        fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
            Ok(IoPollV0::Idle)
        }

        fn publish(
            &mut self,
            _frame: trnm_node_boundary_v0::OutboundFrameV0,
            _budget: StepBudgetV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: NodeDigest([1; 32]),
            validator_id: NodeDigest([2; 32]),
            application_id: NodeDigest([3; 32]),
            generation: 1,
        }
    }

    #[test]
    fn composition_is_wiring_only_and_requires_recovery_before_polling() {
        let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        let mut composition =
            ProductionNodeCompositionV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
        const {
            assert!(!PRODUCTION_COMPOSITION_OWNS_DOMAIN_STATE_V0);
            assert!(!PRODUCTION_COMPOSITION_ACTIVATION_V0);
        }
        assert!(composition.host_step().is_err());
        assert_eq!(composition.recover_host().unwrap(), HostReadinessV0::Ready);
        assert_eq!(composition.host_step().unwrap(), HostStepV0::Idle);
        assert_eq!(
            SessionScopedServiceSetV0::default(),
            SessionScopedServiceSetV0 {
                transaction_lifecycle_protocol_version: 0,
                state_sync_protocol_version: 0,
                migration_protocol_version: 0,
                control_plane_protocol_version: 0,
            }
        );
    }

    #[test]
    fn reference_coordinator_recovery_disposition_remains_explicit() {
        let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
        assert_eq!(coordinator.recover().unwrap(), RecoveryDispositionV0::Clean);
    }
}

#[cfg(test)]
mod authority_session_tests;
