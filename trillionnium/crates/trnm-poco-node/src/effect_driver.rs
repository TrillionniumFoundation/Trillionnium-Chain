//! Candidate-only Core effect driver.
//!
//! This module is deliberately behind `g1-process-test-support`.  It is the
//! smallest host seam which can exercise the Core-owned SafetyRules authority
//! without claiming that the PoCO node is production activated.  The driver
//! owns one `Core`, one non-cloneable authority for that Core, and one bounded
//! ingress queue.  Every nondeterministic operation is delegated to an
//! explicit hook; no filesystem, clock, network, or private key is hidden in
//! this module.
//!
//! The important ordering invariant is:
//!
//! ```text
//! Core authority transition -> Safety persistence + readback ->
//! whole-node checkpoint CAS + readback -> signer -> Core SignatureReady ->
//! broadcast/timer
//! ```
//!
//! A checkpoint or signer failure permanently fail-stops the candidate owner.
//! In particular, the signer hook is never called after a failed checkpoint
//! CAS.  The production activation constants remain false even when this
//! feature is enabled.

#![cfg(feature = "g1-process-test-support")]
#![forbid(unsafe_code)]

use std::{collections::VecDeque, error::Error, fmt};

use trnm_consensus_core::{
    Core, CoreError, CoreSafetyRulesAuthorityErrorV1, CoreSafetyRulesAuthorityV1, Effect, Input,
    OutboundMessage, SafetyHalt, SafetyState, SafetyStatePersistenceV0, SignIntent,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_rules::SafetyRulesDurableTransitionStoreV1;
use trnm_consensus_types::{
    CanonicalSignIntentV0, CanonicalSignPreimageV0, CanonicalSignable, Epoch, SignatureBytes,
    SignedProposalV0, SigningRoot, View,
};

/// This module is a candidate composition only.  It must not be interpreted
/// as a production node activation claim.
pub const CANDIDATE_EFFECT_DRIVER_V1: bool = true;

/// The candidate driver has no production activation path.
pub const EFFECT_DRIVER_PRODUCTION_ACTIVATION_V1: bool = false;

/// This seam does not own finality verification or application finalization.
pub const EFFECT_DRIVER_FINALITY_VERIFIED_V1: bool = false;

/// Hard upper bound for the process-local ingress queue.  A caller may select
/// a smaller capacity when constructing a driver, but never a larger one.
pub const EFFECT_DRIVER_MAX_INGRESS_V1: usize = 32;

/// Hard upper bound for effects (including effects returned by a validation
/// hook) processed by one `drive_v1` call.
pub const EFFECT_DRIVER_MAX_EFFECTS_PER_DRIVE_V1: usize = 64;

/// Hook boundary for all nondeterministic work required by Core effects.
///
/// Implementations own the actual SafetyStore, application, signer/HSM,
/// whole-node checkpoint, network, and timer resources.  The driver passes
/// the exact opaque Core carriers and immutable signer intent; a hook must not
/// replace those values with caller-selected lookalikes.  In particular,
/// `compare_and_advance_whole_node_checkpoint_v1` must perform its own durable
/// compare-and-set and fresh readback before returning `Ok(())`.
///
/// The trait intentionally contains no default signer, no private-key type,
/// and no production constructor.  A concrete adapter can use the
/// `ValidatePayload` effect to join an existing application P/D/C/K pipeline
/// and return the exact follow-up Core effects.  Returning `Ok(Vec::new())`
/// leaves the Core's validation obligation pending, which is safe but not a
/// liveness claim.
pub trait CandidateEffectDriverHooksV1 {
    type Error: fmt::Debug;

    /// Durably persist the exact SafetyState carried by this effect.
    fn persist_safety_state_v1(
        &mut self,
        request: &SafetyStatePersistenceV0,
    ) -> Result<(), Self::Error>;

    /// Freshly read back and authenticate the exact expected SafetyState.
    fn confirm_safety_state_v1(&mut self, expected: &SafetyState) -> Result<(), Self::Error>;

    /// Resolve one Core-issued validation effect.  The effect is passed as a
    /// whole value so route, validation identity, block, and parent binding
    /// remain together.  The mutable Core is the only place from which a
    /// valid callback can obtain the next opaque Core carrier.
    fn validate_payload_v1(
        &mut self,
        effect: Effect,
        core: &mut Core,
    ) -> Result<Vec<Effect>, Self::Error>;

    /// Compare-and-set the exact whole-node checkpoint successor and perform
    /// a fresh readback.  This hook is called before every signer invocation.
    fn compare_and_advance_whole_node_checkpoint_v1(
        &mut self,
        core: &Core,
        intent: &CanonicalSignIntentV0,
    ) -> Result<(), Self::Error>;

    /// Sign through an independently durable signer journal/HSM boundary.
    fn sign_v1(&mut self, intent: &CanonicalSignIntentV0) -> Result<SignatureBytes, Self::Error>;

    /// Publish one Core-authenticated outbound message.
    fn broadcast_v1(&mut self, message: OutboundMessage) -> Result<(), Self::Error>;

    /// Arm the host pacemaker for one exact Core epoch/view.
    fn arm_view_timer_v1(&mut self, epoch: Epoch, view: View) -> Result<(), Self::Error>;

    /// Optional diagnostic callback for a durable Core safety halt.  The
    /// default is deliberately inert; the driver still enters its terminal
    /// `Halted` state and rejects all later ingress.
    fn safety_halted_v1(&mut self, _halt: &SafetyHalt) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Candidate ingress accepted by the bounded driver queue.
///
/// `AuthorityVote` is intentionally distinct from `Proposal`: it is for a
/// proposal which has already crossed the application-valid/retention
/// boundary and therefore may be handed to the Core-owned SafetyRules
/// authority.  A normal `Proposal` is sent through `Core::step` and can emit a
/// validation effect for the hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateEffectDriverIngressV1 {
    Proposal {
        generation: u64,
        proposal: Box<SignedProposalV0>,
    },
    SyncedProposal {
        generation: u64,
        proposal: Box<SignedProposalV0>,
    },
    AuthorityVote {
        generation: u64,
        proposal: Box<SignedProposalV0>,
    },
    LocalTimeout {
        generation: u64,
    },
}

impl CandidateEffectDriverIngressV1 {
    fn generation(&self) -> u64 {
        match self {
            Self::Proposal { generation, .. }
            | Self::SyncedProposal { generation, .. }
            | Self::AuthorityVote { generation, .. }
            | Self::LocalTimeout { generation } => *generation,
        }
    }
}

/// Result of trying to enqueue one candidate ingress item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateEffectDriverAdmissionV1 {
    Accepted {
        generation: u64,
        queue_depth: usize,
    },
    StaleGeneration {
        expected_generation: u64,
        received_generation: u64,
    },
    Backpressure {
        capacity: usize,
        queue_depth: usize,
    },
}

/// Terminal/active status of the candidate owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateEffectDriverStatusV1 {
    Active,
    Halted,
    FailStopped,
}

/// Read-only bounded-driver facts.  No field grants Core, signer, or storage
/// authority; the live owner remains inside `CandidateEffectDriverV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateEffectDriverFactsV1 {
    generation: u64,
    queue_depth: usize,
    queue_capacity: usize,
    processed_ingress: u64,
    processed_effects: u64,
    stale_generation_rejections: u64,
    backpressure_rejections: u64,
    status: CandidateEffectDriverStatusV1,
}

impl CandidateEffectDriverFactsV1 {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn queue_depth(self) -> usize {
        self.queue_depth
    }

    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    pub const fn processed_ingress(self) -> u64 {
        self.processed_ingress
    }

    pub const fn processed_effects(self) -> u64 {
        self.processed_effects
    }

    pub const fn stale_generation_rejections(self) -> u64 {
        self.stale_generation_rejections
    }

    pub const fn backpressure_rejections(self) -> u64 {
        self.backpressure_rejections
    }

    pub const fn status(self) -> CandidateEffectDriverStatusV1 {
        self.status
    }

    pub const fn candidate_only(self) -> bool {
        CANDIDATE_EFFECT_DRIVER_V1 && !EFFECT_DRIVER_PRODUCTION_ACTIVATION_V1
    }

    pub const fn finality_verified(self) -> bool {
        EFFECT_DRIVER_FINALITY_VERIFIED_V1
    }
}

/// Closed error surface for the candidate driver.  Any error while crossing a
/// nondeterministic boundary puts the owner in `FailStopped`.
#[derive(Debug)]
pub enum CandidateEffectDriverErrorV1 {
    InvalidQueueCapacity {
        requested: usize,
        maximum: usize,
    },
    AuthorityNotIssued,
    DriverStopped,
    GenerationOverflow,
    Core(CoreError),
    Authority(String),
    Hook {
        operation: &'static str,
        detail: String,
    },
    PersistenceAffinityMismatch,
    PersistenceStateMismatch,
    SignIntentMismatch,
    OutboundMessageMismatch,
    UnsupportedEffect(&'static str),
    EffectBudgetExceeded {
        limit: usize,
    },
}

impl fmt::Display for CandidateEffectDriverErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueueCapacity { requested, maximum } => write!(
                formatter,
                "candidate effect-driver queue capacity {requested} exceeds maximum {maximum}"
            ),
            Self::AuthorityNotIssued => {
                formatter.write_str("Core-owned SafetyRules authority was not issued")
            }
            Self::DriverStopped => formatter.write_str("candidate effect driver is stopped"),
            Self::GenerationOverflow => {
                formatter.write_str("candidate ingress generation overflowed")
            }
            Self::Core(error) => write!(formatter, "Core effect-driver transition failed: {error}"),
            Self::Authority(detail) => {
                write!(formatter, "Core SafetyRules authority failed: {detail}")
            }
            Self::Hook { operation, detail } => {
                write!(formatter, "effect-driver hook {operation} failed: {detail}")
            }
            Self::PersistenceAffinityMismatch => {
                formatter.write_str("Safety persistence effect belongs to another Core")
            }
            Self::PersistenceStateMismatch => {
                formatter.write_str("Safety persistence effect differs from the live Core state")
            }
            Self::SignIntentMismatch => {
                formatter.write_str("signer intent does not match Core's pending authorization")
            }
            Self::OutboundMessageMismatch => {
                formatter.write_str("broadcast message does not match the just-released signature")
            }
            Self::UnsupportedEffect(kind) => write!(formatter, "unsupported Core effect: {kind}"),
            Self::EffectBudgetExceeded { limit } => {
                write!(formatter, "Core effect budget exceeded ({limit})")
            }
        }
    }
}

impl Error for CandidateEffectDriverErrorV1 {}

impl From<CoreError> for CandidateEffectDriverErrorV1 {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

/// One process-local candidate driver.  The fields are private so callers
/// cannot replace the Core, authority, queue generation, or hooks after
/// construction.
pub struct CandidateEffectDriverV1<S, H>
where
    S: SafetyRulesDurableTransitionStoreV1,
    H: CandidateEffectDriverHooksV1,
{
    core: Core,
    authority: CoreSafetyRulesAuthorityV1<S>,
    hooks: H,
    ingress: VecDeque<QueuedIngressV1>,
    generation: u64,
    queue_capacity: usize,
    status: CandidateEffectDriverStatusV1,
    processed_ingress: u64,
    processed_effects: u64,
    stale_generation_rejections: u64,
    backpressure_rejections: u64,
    pending_signed_outbound: Option<PendingSignedOutboundV1>,
}

/// Internal queue carrier for authenticated transport ingress.  Keeping this
/// variant out of the public [`CandidateEffectDriverIngressV1`] enum is
/// intentional: callers cannot label an arbitrary `Input` as authenticated
/// peer evidence.  Only the node-owned P2P boundary can mint this carrier
/// after socket, session, lease, and replay checks have completed.
enum QueuedIngressV1 {
    Public(CandidateEffectDriverIngressV1),
    AuthenticatedPeer { generation: u64, input: Box<Input> },
}

impl QueuedIngressV1 {
    fn generation(&self) -> u64 {
        match self {
            Self::Public(ingress) => ingress.generation(),
            Self::AuthenticatedPeer { generation, .. } => *generation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSignedOutboundV1 {
    signing_root: SigningRoot,
    signature: SignatureBytes,
}

impl<S, H> CandidateEffectDriverV1<S, H>
where
    S: SafetyRulesDurableTransitionStoreV1,
    S::Error: fmt::Debug,
    H: CandidateEffectDriverHooksV1,
{
    /// Construct an active driver around a Core which already issued its sole
    /// Core-owned SafetyRules authority.
    pub fn new(
        core: Core,
        authority: CoreSafetyRulesAuthorityV1<S>,
        hooks: H,
        queue_capacity: usize,
    ) -> Result<Self, CandidateEffectDriverErrorV1> {
        Self::new_with_generation(core, authority, hooks, queue_capacity, 0)
    }

    /// As `new`, but resumes an externally authenticated ingress generation.
    /// The generation is only a queue-order fence; it is not consensus state
    /// and does not substitute for SafetyStore/Core recovery.
    pub fn new_with_generation(
        core: Core,
        authority: CoreSafetyRulesAuthorityV1<S>,
        hooks: H,
        queue_capacity: usize,
        initial_generation: u64,
    ) -> Result<Self, CandidateEffectDriverErrorV1> {
        if queue_capacity == 0 || queue_capacity > EFFECT_DRIVER_MAX_INGRESS_V1 {
            return Err(CandidateEffectDriverErrorV1::InvalidQueueCapacity {
                requested: queue_capacity,
                maximum: EFFECT_DRIVER_MAX_INGRESS_V1,
            });
        }
        if !core.safety_rules_authority_issued_v1() {
            return Err(CandidateEffectDriverErrorV1::AuthorityNotIssued);
        }
        // Rebinding is read-only for an idle authority, but it performs the
        // process-local affinity and state-digest check.  Refuse a pair that
        // was accidentally assembled from two different Core instances at
        // construction time rather than waiting for the first ingress.
        let mut authority = authority;
        authority
            .rebind_after_core_persistence_v1(&core, &StrictEd25519Verifier)
            .map_err(Self::map_authority_error)?;
        Ok(Self {
            core,
            authority,
            hooks,
            ingress: VecDeque::with_capacity(queue_capacity),
            generation: initial_generation,
            queue_capacity,
            status: CandidateEffectDriverStatusV1::Active,
            processed_ingress: 0,
            processed_effects: 0,
            stale_generation_rejections: 0,
            backpressure_rejections: 0,
            pending_signed_outbound: None,
        })
    }

    /// Borrow the live Core for read-only host checkpoint comparisons.
    pub const fn core(&self) -> &Core {
        &self.core
    }

    /// Borrow-only status facts.
    pub fn facts_v1(&self) -> CandidateEffectDriverFactsV1 {
        CandidateEffectDriverFactsV1 {
            generation: self.generation,
            queue_depth: self.ingress.len(),
            queue_capacity: self.queue_capacity,
            processed_ingress: self.processed_ingress,
            processed_effects: self.processed_effects,
            stale_generation_rejections: self.stale_generation_rejections,
            backpressure_rejections: self.backpressure_rejections,
            status: self.status,
        }
    }

    /// Enqueue one ingress item if its generation is exactly the next queued
    /// generation.  Stale generations are rejected before any Core clone or
    /// host hook is touched.
    pub fn enqueue_v1(
        &mut self,
        ingress: CandidateEffectDriverIngressV1,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        let generation = ingress.generation();
        self.enqueue_queued_v1(QueuedIngressV1::Public(ingress), generation)
    }

    /// Enqueue one Core input which has crossed the node-owned authenticated
    /// P2P boundary.  This method is crate-private so a caller cannot bypass
    /// the session signature, peer lease, or payload replay owner by handing
    /// the driver a caller-selected `Input`.
    pub(crate) fn enqueue_authenticated_peer_input_v1(
        &mut self,
        generation: u64,
        input: Input,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        if !matches!(
            &input,
            Input::Vote(_)
                | Input::TimeoutVote(_)
                | Input::QuorumCertificate(_)
                | Input::TimeoutCertificate(_)
        ) {
            return Err(
                self.fail_stop(CandidateEffectDriverErrorV1::UnsupportedEffect(
                    "authenticated peer input",
                )),
            );
        }
        self.enqueue_queued_v1(
            QueuedIngressV1::AuthenticatedPeer {
                generation,
                input: Box::new(input),
            },
            generation,
        )
    }

    fn enqueue_queued_v1(
        &mut self,
        ingress: QueuedIngressV1,
        received: u64,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        self.ensure_active()?;
        let expected = match self
            .generation
            .checked_add(self.ingress.len() as u64)
            .and_then(|value| value.checked_add(1))
        {
            Some(value) => value,
            None => {
                return Err(self.fail_stop(CandidateEffectDriverErrorV1::GenerationOverflow));
            }
        };
        if received != expected {
            self.stale_generation_rejections = self.stale_generation_rejections.saturating_add(1);
            return Ok(CandidateEffectDriverAdmissionV1::StaleGeneration {
                expected_generation: expected,
                received_generation: received,
            });
        }
        if self.ingress.len() >= self.queue_capacity {
            self.backpressure_rejections = self.backpressure_rejections.saturating_add(1);
            return Ok(CandidateEffectDriverAdmissionV1::Backpressure {
                capacity: self.queue_capacity,
                queue_depth: self.ingress.len(),
            });
        }
        self.ingress.push_back(ingress);
        Ok(CandidateEffectDriverAdmissionV1::Accepted {
            generation: received,
            queue_depth: self.ingress.len(),
        })
    }

    /// Convenience method for one timeout ingress item.
    pub fn enqueue_timeout_v1(
        &mut self,
        generation: u64,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        self.enqueue_v1(CandidateEffectDriverIngressV1::LocalTimeout { generation })
    }

    /// Convenience method for one Core-routed synced-proposal ingress item.
    ///
    /// A synced proposal is intentionally separate from a normal proposal:
    /// Core may authenticate and application-validate it without implicitly
    /// staging a legacy Vote.  The host can then submit the exact same signed
    /// proposal through [`Self::enqueue_authority_vote_v1`] after the
    /// application-valid boundary has durably completed.
    pub fn enqueue_synced_proposal_v1(
        &mut self,
        generation: u64,
        proposal: SignedProposalV0,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        self.enqueue_v1(CandidateEffectDriverIngressV1::SyncedProposal {
            generation,
            proposal: Box::new(proposal),
        })
    }

    /// Convenience method for the ordinary proposal route.  A host may use
    /// this to expose its application boundary; if no complete application
    /// validation hook is installed, the hook must return an error and the
    /// driver fail-stops before any signer or broadcast effect.
    pub fn enqueue_proposal_v1(
        &mut self,
        generation: u64,
        proposal: SignedProposalV0,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        self.enqueue_v1(CandidateEffectDriverIngressV1::Proposal {
            generation,
            proposal: Box::new(proposal),
        })
    }

    /// Convenience method for one authority-backed Vote ingress item.
    ///
    /// The proposal is not converted into a caller-selected signing intent:
    /// the live Core-owned SafetyRules authority derives and persists the
    /// exact Vote transition before the driver can reach checkpoint/signing.
    pub fn enqueue_authority_vote_v1(
        &mut self,
        generation: u64,
        proposal: SignedProposalV0,
    ) -> Result<CandidateEffectDriverAdmissionV1, CandidateEffectDriverErrorV1> {
        self.enqueue_v1(CandidateEffectDriverIngressV1::AuthorityVote {
            generation,
            proposal: Box::new(proposal),
        })
    }

    /// Drain the bounded queue and process every effect returned by Core or a
    /// validation hook.  Any failure consumes the remaining queue and enters
    /// `FailStopped`; callers must construct a fresh owner after recovery.
    pub fn drive_v1(
        &mut self,
    ) -> Result<CandidateEffectDriverFactsV1, CandidateEffectDriverErrorV1> {
        self.ensure_active()?;
        let mut effects_processed_this_drive = 0usize;
        while let Some(ingress) = self.ingress.pop_front() {
            let expected = self
                .generation
                .checked_add(1)
                .ok_or_else(|| self.fail_stop(CandidateEffectDriverErrorV1::GenerationOverflow))?;
            if ingress.generation() != expected {
                let error = CandidateEffectDriverErrorV1::Authority(format!(
                    "queued generation {} does not follow live generation {}",
                    ingress.generation(),
                    self.generation
                ));
                return Err(self.fail_stop(error));
            }
            let generation = ingress.generation();
            let result = self.process_ingress_v1(ingress, &mut effects_processed_this_drive);
            match result {
                Ok(()) => {
                    self.generation = generation;
                    self.processed_ingress = self.processed_ingress.saturating_add(1);
                }
                Err(error) => return Err(self.fail_stop(error)),
            }
        }
        Ok(self.facts_v1())
    }

    /// Alias useful to hosts whose event loop calls its bounded pump `run`.
    pub fn run_v1(&mut self) -> Result<CandidateEffectDriverFactsV1, CandidateEffectDriverErrorV1> {
        self.drive_v1()
    }

    fn process_ingress_v1(
        &mut self,
        ingress: QueuedIngressV1,
        effects_processed_this_drive: &mut usize,
    ) -> Result<(), CandidateEffectDriverErrorV1> {
        let effects = match ingress {
            QueuedIngressV1::Public(CandidateEffectDriverIngressV1::Proposal {
                proposal, ..
            }) => self
                .core
                .step(Input::Proposal(proposal), &StrictEd25519Verifier)?,
            QueuedIngressV1::Public(CandidateEffectDriverIngressV1::SyncedProposal {
                proposal,
                ..
            }) => self
                .core
                .step(Input::SyncedProposal(proposal), &StrictEd25519Verifier)?,
            QueuedIngressV1::Public(CandidateEffectDriverIngressV1::AuthorityVote {
                proposal,
                ..
            }) => self
                .core
                .step_vote_with_safety_rules_authority_v1(
                    &mut self.authority,
                    proposal.as_ref(),
                    &StrictEd25519Verifier,
                )
                .map_err(Self::map_authority_error)?,
            QueuedIngressV1::Public(CandidateEffectDriverIngressV1::LocalTimeout {
                generation: _,
            }) => self.step_timeout_from_authority_v1()?,
            QueuedIngressV1::AuthenticatedPeer { input, .. } => {
                self.core.step(*input, &StrictEd25519Verifier)?
            }
        };
        self.process_effects_v1(effects, effects_processed_this_drive)
    }

    fn step_timeout_from_authority_v1(
        &mut self,
    ) -> Result<Vec<Effect>, CandidateEffectDriverErrorV1> {
        let epoch = self.core.safety_state().epoch();
        let view = self.core.safety_state().current_view();
        self.core
            .step_timeout_with_safety_rules_authority_v1(
                &mut self.authority,
                epoch,
                view,
                &StrictEd25519Verifier,
            )
            .map_err(Self::map_authority_error)
    }

    fn process_effects_v1(
        &mut self,
        effects: Vec<Effect>,
        effects_processed_this_drive: &mut usize,
    ) -> Result<(), CandidateEffectDriverErrorV1> {
        let mut pending = VecDeque::from(effects);
        while let Some(effect) = pending.pop_front() {
            *effects_processed_this_drive = effects_processed_this_drive.checked_add(1).ok_or(
                CandidateEffectDriverErrorV1::EffectBudgetExceeded {
                    limit: EFFECT_DRIVER_MAX_EFFECTS_PER_DRIVE_V1,
                },
            )?;
            if *effects_processed_this_drive > EFFECT_DRIVER_MAX_EFFECTS_PER_DRIVE_V1 {
                return Err(CandidateEffectDriverErrorV1::EffectBudgetExceeded {
                    limit: EFFECT_DRIVER_MAX_EFFECTS_PER_DRIVE_V1,
                });
            }
            self.processed_effects = self.processed_effects.saturating_add(1);
            match effect {
                Effect::PersistSafetyState(request) => {
                    let follow_up = self.process_persistence_v1(request)?;
                    pending.extend(follow_up);
                }
                Effect::ValidatePayload(request) => {
                    let follow_up = self
                        .hooks
                        .validate_payload_v1(Effect::ValidatePayload(request), &mut self.core)
                        .map_err(|error| Self::hook_error("validate_payload", error))?;
                    pending.extend(follow_up);
                }
                Effect::ValidateSyncedPayload(request) => {
                    let follow_up = self
                        .hooks
                        .validate_payload_v1(Effect::ValidateSyncedPayload(request), &mut self.core)
                        .map_err(|error| Self::hook_error("validate_synced_payload", error))?;
                    pending.extend(follow_up);
                }
                Effect::RequestSignature { intent } => {
                    let follow_up = self.process_signature_v1(intent)?;
                    pending.extend(follow_up);
                }
                Effect::Broadcast(message) => {
                    let expected = self
                        .pending_signed_outbound
                        .take()
                        .ok_or(CandidateEffectDriverErrorV1::OutboundMessageMismatch)?;
                    let matches = match &message {
                        OutboundMessage::Vote(vote) => {
                            vote.signing_root() == expected.signing_root
                                && vote.signature() == &expected.signature
                        }
                        OutboundMessage::TimeoutVote(timeout_vote) => {
                            timeout_vote.signing_root() == expected.signing_root
                                && timeout_vote.signature() == &expected.signature
                        }
                    };
                    if !matches {
                        return Err(CandidateEffectDriverErrorV1::OutboundMessageMismatch);
                    }
                    self.hooks
                        .broadcast_v1(message)
                        .map_err(|error| Self::hook_error("broadcast", error))?;
                }
                Effect::ArmViewTimer { epoch, view } => {
                    self.hooks
                        .arm_view_timer_v1(epoch, view)
                        .map_err(|error| Self::hook_error("arm_view_timer", error))?;
                }
                Effect::SafetyHalted(halt) => {
                    self.hooks
                        .safety_halted_v1(halt.as_ref())
                        .map_err(|error| Self::hook_error("safety_halted", error))?;
                    self.status = CandidateEffectDriverStatusV1::Halted;
                    self.ingress.clear();
                    pending.clear();
                    break;
                }
                Effect::RequestSafetyReplay { .. } => {
                    return Err(CandidateEffectDriverErrorV1::UnsupportedEffect(
                        "RequestSafetyReplay",
                    ));
                }
                Effect::RequestTcHighQcSync { .. } => {
                    return Err(CandidateEffectDriverErrorV1::UnsupportedEffect(
                        "RequestTcHighQcSync",
                    ));
                }
                Effect::RequestStandaloneQcSync { .. } => {
                    return Err(CandidateEffectDriverErrorV1::UnsupportedEffect(
                        "RequestStandaloneQcSync",
                    ));
                }
                Effect::Finalize(_) => {
                    return Err(CandidateEffectDriverErrorV1::UnsupportedEffect("Finalize"));
                }
                Effect::Evidence(_) => {
                    return Err(CandidateEffectDriverErrorV1::UnsupportedEffect("Evidence"));
                }
            }
        }
        Ok(())
    }

    fn process_persistence_v1(
        &mut self,
        request: SafetyStatePersistenceV0,
    ) -> Result<Vec<Effect>, CandidateEffectDriverErrorV1> {
        if !self
            .core
            .safety_state_persistence_binding_v0()
            .accepts(&request)
        {
            return Err(CandidateEffectDriverErrorV1::PersistenceAffinityMismatch);
        }
        if request.state() != self.core.safety_state() {
            return Err(CandidateEffectDriverErrorV1::PersistenceStateMismatch);
        }
        self.hooks
            .persist_safety_state_v1(&request)
            .map_err(|error| Self::hook_error("persist_safety_state", error))?;
        self.hooks
            .confirm_safety_state_v1(request.state())
            .map_err(|error| Self::hook_error("confirm_safety_state", error))?;
        let effects = self.core.step(
            Input::StorageAck {
                barrier: request.barrier(),
            },
            &StrictEd25519Verifier,
        )?;
        // An authority-backed Vote/Timeout leaves a pending signer intent and
        // therefore cannot be rebound yet.  Unrelated Core persistence does
        // not, so refresh the owner digest before the next authority command.
        let has_signature_request = effects
            .iter()
            .any(|effect| matches!(effect, Effect::RequestSignature { .. }));
        if !has_signature_request
            && self.core.safety_state().pending_sign().is_none()
            && self.status == CandidateEffectDriverStatusV1::Active
        {
            self.authority
                .rebind_after_core_persistence_v1(&self.core, &StrictEd25519Verifier)
                .map_err(Self::map_authority_error)?;
        }
        Ok(effects)
    }

    fn process_signature_v1(
        &mut self,
        intent: CanonicalSignIntentV0,
    ) -> Result<Vec<Effect>, CandidateEffectDriverErrorV1> {
        let pending = self
            .core
            .safety_state()
            .pending_sign()
            .ok_or(CandidateEffectDriverErrorV1::SignIntentMismatch)?;
        if !canonical_matches_legacy_intent(
            pending,
            &intent,
            self.core.config().validator_set(),
            self.core.config().local_validator(),
        ) {
            return Err(CandidateEffectDriverErrorV1::SignIntentMismatch);
        }
        // `SignatureReady` clears the durable signer outbox in the live Core
        // but is intentionally a volatile release.  Retain the exact
        // pre-release state so the host can cross the explicit empty
        // persistence barrier before another signing intent is staged.
        let signature_release_predecessor = self.core.safety_state().clone();
        // This call is intentionally before `sign_v1`; a failed/ambiguous
        // whole-node CAS must never reach a signer.
        self.hooks
            .compare_and_advance_whole_node_checkpoint_v1(&self.core, &intent)
            .map_err(|error| Self::hook_error("whole_node_checkpoint_cas", error))?;
        let signature = self
            .hooks
            .sign_v1(&intent)
            .map_err(|error| Self::hook_error("sign", error))?;
        let effects = self.core.step(
            Input::SignatureReady {
                id: intent_sign_id(&intent),
                signature,
            },
            &StrictEd25519Verifier,
        )?;
        if !effects
            .iter()
            .any(|effect| matches!(effect, Effect::Broadcast(_)))
        {
            return Err(CandidateEffectDriverErrorV1::OutboundMessageMismatch);
        }
        self.pending_signed_outbound = Some(PendingSignedOutboundV1 {
            signing_root: intent.signing_root(),
            signature,
        });
        // Do not expose the broadcast to the hook until the cleared signer
        // state has crossed its own durable barrier.  The persistence effect
        // is handled by the same bounded path as every other Core write; its
        // StorageAck then rebinds the Core-owned SafetyRules authority to the
        // post-release digest before the broadcast is delivered.
        let mut release_effects = self
            .core
            .persist_signature_release_v0(&signature_release_predecessor, &StrictEd25519Verifier)?;
        release_effects.extend(effects);
        Ok(release_effects)
    }

    fn ensure_active(&self) -> Result<(), CandidateEffectDriverErrorV1> {
        if self.status == CandidateEffectDriverStatusV1::Active {
            Ok(())
        } else {
            Err(CandidateEffectDriverErrorV1::DriverStopped)
        }
    }

    fn fail_stop(&mut self, error: CandidateEffectDriverErrorV1) -> CandidateEffectDriverErrorV1 {
        self.status = CandidateEffectDriverStatusV1::FailStopped;
        self.ingress.clear();
        error
    }

    fn hook_error<E: fmt::Debug>(
        operation: &'static str,
        error: E,
    ) -> CandidateEffectDriverErrorV1 {
        CandidateEffectDriverErrorV1::Hook {
            operation,
            detail: format!("{error:?}"),
        }
    }

    fn map_authority_error<E: fmt::Debug>(
        error: CoreSafetyRulesAuthorityErrorV1<E>,
    ) -> CandidateEffectDriverErrorV1 {
        CandidateEffectDriverErrorV1::Authority(error.to_string())
    }
}

fn intent_sign_id(intent: &CanonicalSignIntentV0) -> trnm_consensus_core::SignId {
    trnm_consensus_core::SignId::new(intent.signing_root())
}

fn canonical_matches_legacy_intent(
    legacy: &SignIntent,
    canonical: &CanonicalSignIntentV0,
    validator_set: &trnm_consensus_types::ValidatorSet,
    local_validator: trnm_consensus_types::ValidatorId,
) -> bool {
    canonical.validate(validator_set).is_ok()
        && canonical.author() == local_validator
        && legacy_shape_matches(legacy, canonical)
}

fn legacy_shape_matches(legacy: &SignIntent, canonical: &CanonicalSignIntentV0) -> bool {
    if legacy.authorizing_safety_revision() != canonical.authorizing_safety_revision()
        || legacy.view() != canonical.preimage().context().view()
        || legacy.signing_root() != canonical.signing_root()
    {
        return false;
    }
    match (legacy, canonical.preimage()) {
        (
            SignIntent::Vote {
                height, block_id, ..
            },
            CanonicalSignPreimageV0::Vote(preimage),
        ) => *height == preimage.height() && *block_id == preimage.block_id(),
        (
            SignIntent::TimeoutVote { high_qc, .. },
            CanonicalSignPreimageV0::TimeoutVote(preimage),
        ) => *high_qc == preimage.high_qc(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_core::{CoreConfig, CoreSafetyRulesAuthorityV1};
    use trnm_consensus_safety_rules::{
        InertSafetyTransitionV1, SafetyRulesDurableTransitionStoreV1,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, GenesisHash, GenesisQcV0,
        ProtocolVersion, Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;

    #[derive(Default)]
    struct StoreFactsV1 {
        transitions: Vec<InertSafetyTransitionV1>,
    }

    struct RecordingTransitionStoreV1 {
        facts: Arc<Mutex<StoreFactsV1>>,
    }

    impl SafetyRulesDurableTransitionStoreV1 for RecordingTransitionStoreV1 {
        type Error = &'static str;

        fn persist_transition_v1(
            &mut self,
            transition: &InertSafetyTransitionV1,
        ) -> Result<(), Self::Error> {
            self.facts
                .lock()
                .expect("recording transition-store mutex")
                .transitions
                .push(transition.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct HookFactsV1 {
        events: Vec<&'static str>,
        persisted: Option<SafetyState>,
        checkpoint_committed: bool,
        sign_calls: usize,
        broadcasts: usize,
    }

    struct RecordingHooksV1 {
        facts: Arc<Mutex<HookFactsV1>>,
        local_key: SigningKey,
        fail_checkpoint: bool,
    }

    impl CandidateEffectDriverHooksV1 for RecordingHooksV1 {
        type Error = &'static str;

        fn persist_safety_state_v1(
            &mut self,
            request: &SafetyStatePersistenceV0,
        ) -> Result<(), Self::Error> {
            let mut facts = self.facts.lock().expect("recording hook mutex");
            facts.events.push("persist");
            facts.persisted = Some(request.state().clone());
            Ok(())
        }

        fn confirm_safety_state_v1(&mut self, expected: &SafetyState) -> Result<(), Self::Error> {
            let mut facts = self.facts.lock().expect("recording hook mutex");
            let matches = facts.persisted.as_ref() == Some(expected);
            facts.events.push("confirm");
            if matches {
                Ok(())
            } else {
                Err("Safety readback mismatch")
            }
        }

        fn validate_payload_v1(
            &mut self,
            _effect: Effect,
            _core: &mut Core,
        ) -> Result<Vec<Effect>, Self::Error> {
            self.facts
                .lock()
                .expect("recording hook mutex")
                .events
                .push("validate");
            Ok(Vec::new())
        }

        fn compare_and_advance_whole_node_checkpoint_v1(
            &mut self,
            _core: &Core,
            _intent: &CanonicalSignIntentV0,
        ) -> Result<(), Self::Error> {
            let mut facts = self.facts.lock().expect("recording hook mutex");
            facts.events.push("checkpoint_cas");
            if self.fail_checkpoint {
                return Err("checkpoint CAS failed");
            }
            facts.checkpoint_committed = true;
            Ok(())
        }

        fn sign_v1(
            &mut self,
            intent: &CanonicalSignIntentV0,
        ) -> Result<SignatureBytes, Self::Error> {
            let mut facts = self.facts.lock().expect("recording hook mutex");
            if !facts.checkpoint_committed {
                return Err("signer reached before checkpoint CAS");
            }
            facts.events.push("sign");
            facts.sign_calls += 1;
            Ok(SignatureBytes::from_array(
                self.local_key
                    .sign(intent.signing_root().as_bytes())
                    .to_bytes(),
            ))
        }

        fn broadcast_v1(&mut self, _message: OutboundMessage) -> Result<(), Self::Error> {
            let mut facts = self.facts.lock().expect("recording hook mutex");
            facts.events.push("broadcast");
            facts.broadcasts += 1;
            Ok(())
        }

        fn arm_view_timer_v1(&mut self, _epoch: Epoch, _view: View) -> Result<(), Self::Error> {
            self.facts
                .lock()
                .expect("recording hook mutex")
                .events
                .push("timer");
            Ok(())
        }
    }

    type TestDriverV1 = CandidateEffectDriverV1<RecordingTransitionStoreV1, RecordingHooksV1>;

    fn test_driver_v1(
        queue_capacity: usize,
        fail_checkpoint: bool,
    ) -> (
        TestDriverV1,
        Arc<Mutex<StoreFactsV1>>,
        Arc<Mutex<HookFactsV1>>,
    ) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1_u8..=4)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index.saturating_add(40); 32]);
                Validator::new(
                    ValidatorId::new([index; 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive test voting power"),
                )
                .expect("valid strict-ed25519 test validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::from_static("trnm-effect-driver-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid test validator set");
        let config = CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set,
            parameters,
            17,
            32,
            64,
        )
        .expect("valid test Core config");
        let genesis_qc = GenesisQcV0::new(
            config.validator_set().genesis_hash(),
            config.validator_set().chain_id(),
            config.validator_set(),
        )
        .expect("valid test genesis anchor");
        let core = Core::new(config, genesis_qc, &StrictEd25519Verifier)
            .expect("valid strict-ed25519 test Core");
        let store_facts = Arc::new(Mutex::new(StoreFactsV1::default()));
        let authority: CoreSafetyRulesAuthorityV1<RecordingTransitionStoreV1> = core
            .issue_safety_rules_authority_v1(
                RecordingTransitionStoreV1 {
                    facts: Arc::clone(&store_facts),
                },
                &StrictEd25519Verifier,
            )
            .expect("issue one Core-owned SafetyRules authority");
        let hook_facts = Arc::new(Mutex::new(HookFactsV1::default()));
        let hooks = RecordingHooksV1 {
            facts: Arc::clone(&hook_facts),
            local_key: SigningKey::from_bytes(&[41; 32]),
            fail_checkpoint,
        };
        let driver = CandidateEffectDriverV1::new(core, authority, hooks, queue_capacity)
            .expect("construct bounded candidate driver");
        (driver, store_facts, hook_facts)
    }

    fn event_index(events: &[&'static str], expected: &'static str) -> usize {
        events
            .iter()
            .position(|event| *event == expected)
            .unwrap_or_else(|| panic!("missing event {expected}: {events:?}"))
    }

    #[test]
    fn timeout_crosses_durable_authority_and_checkpoint_before_signing() {
        let (mut driver, store_facts, hook_facts) = test_driver_v1(2, false);
        assert_eq!(
            driver.enqueue_timeout_v1(1).expect("enqueue timeout"),
            CandidateEffectDriverAdmissionV1::Accepted {
                generation: 1,
                queue_depth: 1,
            }
        );

        let facts = driver.drive_v1().expect("drive authority timeout");
        assert_eq!(facts.generation(), 1);
        assert_eq!(facts.processed_ingress(), 1);
        assert_eq!(facts.status(), CandidateEffectDriverStatusV1::Active);
        assert!(facts.candidate_only());
        assert!(!facts.finality_verified());
        assert_eq!(
            store_facts
                .lock()
                .expect("recording transition-store mutex")
                .transitions
                .len(),
            1
        );
        let hook_facts = hook_facts.lock().expect("recording hook mutex");
        assert_eq!(hook_facts.sign_calls, 1);
        assert_eq!(hook_facts.broadcasts, 1);
        let events = &hook_facts.events;
        assert!(event_index(events, "persist") < event_index(events, "confirm"));
        assert!(event_index(events, "confirm") < event_index(events, "checkpoint_cas"));
        assert!(event_index(events, "checkpoint_cas") < event_index(events, "sign"));
        assert!(event_index(events, "sign") < event_index(events, "broadcast"));
    }

    #[test]
    fn checkpoint_failure_fail_stops_without_invoking_signer() {
        let (mut driver, _store_facts, hook_facts) = test_driver_v1(2, true);
        driver.enqueue_timeout_v1(1).expect("enqueue timeout");

        let error = driver
            .drive_v1()
            .expect_err("checkpoint failure must fail-stop");
        assert!(matches!(
            error,
            CandidateEffectDriverErrorV1::Hook {
                operation: "whole_node_checkpoint_cas",
                ..
            }
        ));
        assert_eq!(
            driver.facts_v1().status(),
            CandidateEffectDriverStatusV1::FailStopped
        );
        let hook_facts = hook_facts.lock().expect("recording hook mutex");
        assert_eq!(hook_facts.sign_calls, 0);
        assert_eq!(hook_facts.broadcasts, 0);
        assert_eq!(
            hook_facts.events,
            vec!["persist", "confirm", "checkpoint_cas"]
        );
        drop(hook_facts);
        assert!(matches!(
            driver.enqueue_timeout_v1(2),
            Err(CandidateEffectDriverErrorV1::DriverStopped)
        ));
    }

    #[test]
    fn ingress_generation_and_backpressure_are_bounded_before_core_work() {
        let (mut driver, _store_facts, _hook_facts) = test_driver_v1(1, false);
        assert!(matches!(
            driver.enqueue_timeout_v1(1),
            Ok(CandidateEffectDriverAdmissionV1::Accepted { .. })
        ));
        assert_eq!(
            driver
                .enqueue_timeout_v1(3)
                .expect("reject stale generation"),
            CandidateEffectDriverAdmissionV1::StaleGeneration {
                expected_generation: 2,
                received_generation: 3,
            }
        );
        assert_eq!(
            driver.enqueue_timeout_v1(2).expect("reject full queue"),
            CandidateEffectDriverAdmissionV1::Backpressure {
                capacity: 1,
                queue_depth: 1,
            }
        );
        let before = driver.facts_v1();
        assert_eq!(before.generation(), 0);
        assert_eq!(before.queue_depth(), 1);
        assert_eq!(before.stale_generation_rejections(), 1);
        assert_eq!(before.backpressure_rejections(), 1);

        let after = driver.drive_v1().expect("drive sole queued timeout");
        assert_eq!(after.generation(), 1);
        assert_eq!(after.queue_depth(), 0);
        assert_eq!(after.processed_ingress(), 1);
    }

    #[test]
    fn candidate_flags_never_claim_production_or_finality() {
        // Keep the test useful without tripping Clippy's constant-assertion
        // lint: the compile-time contract below is the authoritative check,
        // while the facts API exercises the same values through the owner.
        const {
            assert!(CANDIDATE_EFFECT_DRIVER_V1);
            assert!(!EFFECT_DRIVER_PRODUCTION_ACTIVATION_V1);
            assert!(!EFFECT_DRIVER_FINALITY_VERIFIED_V1);
        }
        let (driver, _store_facts, _hook_facts) = test_driver_v1(1, false);
        let facts = driver.facts_v1();
        assert!(facts.candidate_only());
        assert!(!facts.finality_verified());
    }
}
